#!/bin/bash

# Guardrail Lite DevStack plugin

if is_service_enabled guardrail; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo "Guardrail Lite: install phase"
    fi

    if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo "Guardrail Lite: post-config phase"
    fi

    if [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo "Guardrail Lite: extra phase"
    fi
fi
