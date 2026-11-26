#!/usr/bin/env bash

set -Eeuo pipefail

VM1_ID="d29803f5-6234-42ed-97f1-b8e74bcf2f6f"
PORT1_ID="46ef0919-acaa-4579-afbc-b6b0037749f2"

VM2_ID="1f05a39e-346e-4b5d-bfa2-88e3316b9533"
PORT2_ID="f20e7ae8-cce0-4af3-b9ec-82196abb7b9d"

ORIGINAL_SG="a6feb72b-c3d9-46ac-aa9d-c18487f347ca"
QUARANTINE_SG="ae44f533-c1cb-4d7e-992e-ab862abdbb94"

API="http://127.0.0.1:9876"
TOKEN=""
CLEANUP_READY=0
SCHEDULER_WAS_ACTIVE=0

pause() {
    read -r -p "Premi INVIO per continuare..."
}

restore_vm() {
    local vm_id="$1"
    local port_id="$2"
    local current_sg

    current_sg=$(openstack port show "$port_id" \
        -f value -c security_group_ids)

    if [[ "$current_sg" == *"$QUARANTINE_SG"* ]]; then
        echo "Ripristino VM $vm_id..."

        curl -fsS -o /dev/null -X POST \
            -H "X-Auth-Token: $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"dry_run": false}' \
            "$API/restore/$vm_id"

        sleep 2
    elif [[ "$current_sg" == *"$ORIGINAL_SG"* ]]; then
        echo "VM $vm_id: Security Group già originale."
    else
        echo "Errore: Security Group inatteso sulla porta $port_id."
        return 1
    fi

    current_sg=$(openstack port show "$port_id" \
        -f value -c security_group_ids)

    if [[ "$current_sg" != *"$ORIGINAL_SG"* ]]; then
        echo "Errore: ripristino non verificato per VM $vm_id."
        return 1
    fi

    echo "VM $vm_id: Security Group originale ripristinato."
}

cleanup() {
    local result=$?
    trap - EXIT

    if [[ "$CLEANUP_READY" == "1" ]]; then
        echo
        echo "========== RIPRISTINO FINALE DI SICUREZZA =========="

        RESTORE_OK=1

        restore_vm "$VM1_ID" "$PORT1_ID" || RESTORE_OK=0
        restore_vm "$VM2_ID" "$PORT2_ID" || RESTORE_OK=0

        FINAL_SG1=$(openstack port show "$PORT1_ID" \
            -f value -c security_group_ids) || RESTORE_OK=0

        FINAL_SG2=$(openstack port show "$PORT2_ID" \
            -f value -c security_group_ids) || RESTORE_OK=0

        echo
        echo "Stato finale Security Group:"
        echo "VM 1: $FINAL_SG1"
        echo "VM 2: $FINAL_SG2"

        if [[ "$FINAL_SG1" == *"$ORIGINAL_SG"* && \
              "$FINAL_SG2" == *"$ORIGINAL_SG"* && \
              "$RESTORE_OK" == "1" ]]; then

            echo "Ripristino di entrambe le VM verificato."

            if [[ "$SCHEDULER_WAS_ACTIVE" == "1" ]]; then
                sudo systemctl start devstack@guardrail-scheduler.service
                echo "Scheduler riattivato."
            fi
        else
            echo "ATTENZIONE: ripristino non verificato."
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
echo "[1/7] VERIFICA DEI SERVIZI"

systemctl is-active --quiet devstack@guardrail-api.service
echo "API Guardrail: attiva"

echo
echo "[2/7] AUTENTICAZIONE"

set +u
source /opt/stack/devstack/openrc admin admin
set -u

TOKEN=$(openstack token issue -f value -c id)

curl -fsS "$API/health" >/dev/null
echo "Autenticazione e API: OK"

CLEANUP_READY=1

if systemctl is-active --quiet devstack@guardrail-scheduler.service; then
    SCHEDULER_WAS_ACTIVE=1
    sudo systemctl stop devstack@guardrail-scheduler.service
fi

if systemctl is-active --quiet devstack@guardrail-scheduler.service; then
    echo "Errore: impossibile fermare lo scheduler."
    exit 1
fi

echo "Scheduler fermato temporaneamente per la demo."

echo
echo "[3/7] VERIFICA DELLE DUE VM"

VM2_STATUS=$(openstack server show "$VM2_ID" \
    -f value -c status)

echo "VM 1: $(openstack server show "$VM1_ID" -f value -c status)"
echo "VM 2: $VM2_STATUS"

if [[ "$VM2_STATUS" != "ERROR" ]]; then
    echo "Errore: la seconda VM non risulta nello stato ERROR atteso."
    exit 1
fi

echo "La seconda VM è ERROR: il suo stato non verrà modificato."

echo
echo "[4/7] RIPRISTINO INIZIALE DEI SECURITY GROUP"

restore_vm "$VM1_ID" "$PORT1_ID"
restore_vm "$VM2_ID" "$PORT2_ID"

echo
echo "Entrambe le VM partono dai Security Group originali."

pause

echo
echo "[5/7] SCANSIONE E QUARANTENA"

echo "Avvio della scansione globale..."

SCAN_RESULT=$(curl -fsS -X POST \
    -H "X-Auth-Token: $TOKEN" \
    "$API/scan")

echo "Scansione completata."

echo
echo "Violazioni rilevate:"

printf '%s\n' "$SCAN_RESULT" | python3 -c '
import json
import sys

data = json.load(sys.stdin)

vms = {
    sys.argv[1]: "VM 1",
    sys.argv[2]: "VM 2",
}

for vm_id, label in vms.items():
    print("\n{}:".format(label))
    found = False

    for violation in data.get("violations", []):
        if violation.get("instance_id") == vm_id:
            rule = violation.get("rule") or violation.get("rule_id")
            message = violation.get("message", "")
            print("- {}: {}".format(rule, message))
            found = True

    if not found:
        print("Nessuna violazione rilevata.")
' "$VM1_ID" "$VM2_ID"

echo
echo "Verifica della quarantena..."

sleep 2

for PORT_ID in "$PORT1_ID" "$PORT2_ID"; do
    CURRENT_SG=$(openstack port show "$PORT_ID" \
        -f value -c security_group_ids)

    if [[ "$CURRENT_SG" != *"$QUARANTINE_SG"* ]]; then
        echo "Errore: quarantena non verificata sulla porta $PORT_ID."
        exit 1
    fi

    echo "Porta $PORT_ID: quarantena applicata."
done

echo
echo "Quarantena reale verificata su entrambe le VM."

pause

echo
echo "[6/7] RIPRISTINO DELLE DUE VM"

restore_vm "$VM1_ID" "$PORT1_ID"
restore_vm "$VM2_ID" "$PORT2_ID"

echo
echo "Security Group originali ripristinati su entrambe le VM."

echo
echo "[7/7] VERIFICA FINALE"

VM2_STATUS=$(openstack server show "$VM2_ID" \
    -f value -c status)

if [[ "$VM2_STATUS" != "ERROR" ]]; then
    echo "Errore: lo stato della seconda VM è cambiato."
    exit 1
fi

echo "VM 1 - Security Group:"
openstack port show "$PORT1_ID" -c security_group_ids

echo
echo "VM 2 - Security Group:"
openstack port show "$PORT2_ID" -c security_group_ids

echo
echo "VM 2 - Stato: $VM2_STATUS"
echo
echo "DEMO COMPLETATA."
echo "Quarantena e ripristino verificati su entrambe le VM."
echo "La seconda VM è rimasta nello stato ERROR."
