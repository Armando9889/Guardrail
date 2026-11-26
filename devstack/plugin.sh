#!/bin/bash

# Guardrail DevStack plugin

if is_service_enabled guardrail; then

    # ---------------------------------------------------------
    # INSTALLAZIONE DASHBOARD HORIZON
    # ---------------------------------------------------------
    install_guardrail_horizon() {
        local horizon_dir="${DEST:-/opt/stack}/horizon"
        local panel_dir="$horizon_dir/openstack_dashboard/dashboards/project/guardrail"
        local enabled_dir="$horizon_dir/openstack_dashboard/local/enabled"
        local source_dir="$GUARDRAIL_DIR/dashboard/horizon"

        echo "Guardrail: installazione pannello Horizon"

        if [[ ! -d "$horizon_dir/openstack_dashboard" ]]; then
            die $LINENO "Guardrail: directory Horizon non trovata: $horizon_dir"
        fi

        if [[ ! -f "$source_dir/guardrail/views.py" ||
              ! -f "$source_dir/guardrail/panel.py" ||
              ! -f "$source_dir/guardrail/urls.py" ||
              ! -f "$source_dir/guardrail/templates/project/guardrail/index.html" ||
              ! -f "$source_dir/_50_project_guardrail.py" ]]; then
            die $LINENO "Guardrail: file di integrazione Horizon mancanti in $source_dir"
        fi

        install -d -o "$STACK_USER" -g "$STACK_USER" -m 0755 \
            "$panel_dir/templates/project/guardrail" \
            "$enabled_dir"

        install -o "$STACK_USER" -g "$STACK_USER" -m 0644 \
            "$source_dir/guardrail/__init__.py" \
            "$source_dir/guardrail/panel.py" \
            "$source_dir/guardrail/urls.py" \
            "$source_dir/guardrail/views.py" \
            "$panel_dir/"

        install -o "$STACK_USER" -g "$STACK_USER" -m 0644 \
            "$source_dir/guardrail/templates/project/guardrail/index.html" \
            "$panel_dir/templates/project/guardrail/index.html"

        install -o "$STACK_USER" -g "$STACK_USER" -m 0644 \
            "$source_dir/_50_project_guardrail.py" \
            "$enabled_dir/_50_project_guardrail.py"

        echo "Guardrail: pannello Horizon Project installato."
    }


    # ---------------------------------------------------------
    # INSTALL
    # ---------------------------------------------------------
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo "Guardrail: install phase"

        if [[ ! -x "$GUARDRAIL_PYTHON" ]]; then
            die $LINENO "Guardrail: Python virtual environment non trovato."
        fi

        "$GUARDRAIL_PYTHON" -c "import flask, openstack; from keystonemiddleware.auth_token import AuthProtocol" || \
            die $LINENO "Guardrail: dipendenze Python mancanti."
    fi

    # ---------------------------------------------------------
    # POST-CONFIG
    # ---------------------------------------------------------
    if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo "Guardrail: post-config phase"

        install_guardrail_horizon

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
