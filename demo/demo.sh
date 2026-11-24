#!/usr/bin/env bash

set -Eeuo pipefail

VM_ID="d29803f5-6234-42ed-97f1-b8e74bcf2f6f"
PORT_ID="46ef0919-acaa-4579-afbc-b6b0037749f2"

ORIGINAL_SG="a6feb72b-c3d9-46ac-aa9d-c18487f347ca"
QUARANTINE_SG="ae44f533-c1cb-4d7e-992e-ab862abdbb94"

API="http://127.0.0.1:9876"
TOKEN=""
CLEANUP_READY=0

pause() {
    read -r -p "Premi INVIO per continuare..."
}

cleanup() {
    local result=$?
    trap - EXIT

    if [[ "$CLEANUP_READY" == "1" ]]; then
        echo
        echo "===== RIPRISTINO FINALE ====="

        CURRENT_SG=$(openstack port show "$PORT_ID" \
            -f value -c security_group_ids 2>/dev/null || true)

        if [[ "$CURRENT_SG" == *"$QUARANTINE_SG"* ]]; then
            echo "Ripristino di sicurezza tramite API..."

            curl -fsS -o /dev/null -X POST \
                -H "X-Auth-Token: $TOKEN" \
                -H "Content-Type: application/json" \
                -d '{"dry_run": false}' \
                "$API/restore/$VM_ID" || true
        fi

        openstack server set \
            --property security_profile=general "$VM_ID" || true

        CURRENT_SG=$(openstack port show "$PORT_ID" \
            -f value -c security_group_ids 2>/dev/null || true)

        if [[ "$CURRENT_SG" == *"$ORIGINAL_SG"* ]]; then
            echo "Security Group originale ripristinato."
            sudo systemctl start devstack@guardrail-scheduler.service
            echo "Scheduler riattivato."
        else
            echo "ATTENZIONE: controllare manualmente la porta."
            echo "Scheduler lasciato fermo per sicurezza."
        fi
    fi

    exit "$result"
}

trap cleanup EXIT

echo
echo "======================================"
echo "             DEMO GUARDRAIL"
echo "======================================"

echo
echo "[1/6] VERIFICA DEI SERVIZI"

systemctl is-active --quiet devstack@guardrail-api.service
echo "API Guardrail: attiva"

echo
echo "[2/6] AUTENTICAZIONE"

set +u
source /opt/stack/devstack/openrc admin admin
set -u

TOKEN=$(openstack token issue -f value -c id)

curl -fsS "$API/health" >/dev/null
echo "Autenticazione e API: OK"

echo
echo "[3/6] PREPARAZIONE DELLA VM"

CURRENT_SG=$(openstack port show "$PORT_ID" \
    -f value -c security_group_ids)

if [[ "$CURRENT_SG" != *"$ORIGINAL_SG"* ]]; then
    echo "Errore: la VM non parte dal Security Group originale."
    exit 1
fi

CLEANUP_READY=1

openstack server set \
    --property security_profile=invalid-demo "$VM_ID"

echo "Profilo di sicurezza non valido impostato."
echo "La VM è pronta per il test."

pause

echo
echo "[4/6] SCANSIONE E QUARANTENA"

echo "Avvio della scansione delle istanze..."

SCAN_RESULT=$(curl -fsS -X POST \
    -H "X-Auth-Token: $TOKEN" \
    "$API/scan")

echo "Scansione completata."

echo
echo "Violazioni rilevate sulla VM demo:"

printf '%s\n' "$SCAN_RESULT" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
vm_id = sys.argv[1]

found = False

for violation in data.get("violations", []):
    if violation.get("instance_id") == vm_id:
        rule = violation.get("rule") or violation.get("rule_id")
        message = violation.get("message", "")
        print("- {}: {}".format(rule, message))
        found = True

if not found:
    print("Nessuna violazione rilevata.")
' "$VM_ID"

echo
echo "La regola R6 determina l'attivazione della quarantena."

sleep 2

CURRENT_SG=$(openstack port show "$PORT_ID" \
    -f value -c security_group_ids)

if [[ "$CURRENT_SG" != *"$QUARANTINE_SG"* ]]; then
    echo "Errore: la quarantena non risulta applicata."
    exit 1
fi

echo
echo "Quarantena reale applicata con successo."

openstack port show "$PORT_ID" -c security_group_ids

pause

echo
echo "[5/6] RIPRISTINO DELLA VM"

echo "Richiesta di ripristino tramite API..."

curl -fsS -o /dev/null -X POST \
    -H "X-Auth-Token: $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"dry_run": false}' \
    "$API/restore/$VM_ID"

echo "Richiesta di ripristino completata."

sleep 2

CURRENT_SG=$(openstack port show "$PORT_ID" \
    -f value -c security_group_ids)

if [[ "$CURRENT_SG" != *"$ORIGINAL_SG"* ]]; then
    echo "Errore: il Security Group originale non è stato ripristinato."
    exit 1
fi

echo
echo "Security Group originale ripristinato correttamente."

openstack port show "$PORT_ID" -c security_group_ids

echo
echo "[6/6] DEMO COMPLETATA"

echo "Quarantena e ripristino verificati direttamente su OpenStack."
echo "Guardrail ha completato correttamente il ciclo di protezione."
