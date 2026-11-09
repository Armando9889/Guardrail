#!/bin/bash

# Guardrail DevStack plugin

if is_service_enabled guardrail; then

    # ---------------------------------------------------------
    # INSTALL
    # ---------------------------------------------------------
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo "Guardrail: install phase"

        if [[ ! -x "$GUARDRAIL_PYTHON" ]]; then
            die $LINENO "Guardrail: Python virtual environment non trovato."
        fi

        "$GUARDRAIL_PYTHON" -c "import flask, openstack" || \
            die $LINENO "Guardrail: dipendenze Python mancanti."
    fi

    # ---------------------------------------------------------
    # POST-CONFIG
    # ---------------------------------------------------------
    if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo "Guardrail: post-config phase"

        install -d -o "$STACK_USER" -g "$STACK_USER" -m 0750 \
            "$GUARDRAIL_CONF_DIR" \
            "$GUARDRAIL_LOG_DIR" \
            "$(dirname "$GUARDRAIL_DB_FILE")"

        if [[ ! -f "$GUARDRAIL_CONFIG" ]]; then
            install -o "$STACK_USER" -g "$STACK_USER" -m 0640 \
                "$GUARDRAIL_DIR/etc/config.json" \
                "$GUARDRAIL_CONFIG"
        fi

        if [[ ! -f "$GUARDRAIL_DB_FILE" ]]; then
            touch "$GUARDRAIL_DB_FILE"
        fi

        chown "$STACK_USER:$STACK_USER" "$GUARDRAIL_DB_FILE"
        chmod 0640 "$GUARDRAIL_DB_FILE"
    fi

    # ---------------------------------------------------------
    # EXTRA
    # ---------------------------------------------------------
    if [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo "Guardrail: extra phase"

        run_process guardrail-api \
            "$GUARDRAIL_PYTHON -m guardrail.api" \
            "" "$STACK_USER" \
            "PYTHONPATH=$GUARDRAIL_DIR GUARDRAIL_CONFIG=$GUARDRAIL_CONFIG GUARDRAIL_DB_FILE=$GUARDRAIL_DB_FILE GUARDRAIL_PORT=$GUARDRAIL_PORT GUARDRAIL_API_HOST=$GUARDRAIL_API_HOST"

        run_process guardrail-scheduler \
            "$GUARDRAIL_PYTHON -m guardrail.scheduler" \
            "" "$STACK_USER" \
            "PYTHONPATH=$GUARDRAIL_DIR GUARDRAIL_CONFIG=$GUARDRAIL_CONFIG GUARDRAIL_DB_FILE=$GUARDRAIL_DB_FILE"
    fi

    # ---------------------------------------------------------
    # UNSTACK
    # ---------------------------------------------------------
    if [[ "$1" == "unstack" ]]; then
        echo "Guardrail: stopping services"

        stop_process guardrail-api
        stop_process guardrail-scheduler
    fi

fi
