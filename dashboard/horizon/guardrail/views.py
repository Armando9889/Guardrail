import re
import logging

import requests

from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from horizon.decorators import require_auth
from openstack_auth import policy


LOG = logging.getLogger(__name__)

API_URL = "http://127.0.0.1:9876"


@require_auth
@require_http_methods(["GET"])
def index(request):
    """Mostra la dashboard integrata nel layout Horizon."""

    get_token(request)

    return render(
        request,
        "project/guardrail/index.html",
        {"page_title": "Guardrail"},
    )


@require_auth
def api_proxy(request, path):
    """Inoltra esclusivamente le API Guardrail autorizzate."""

    method = request.method.upper()

    allowed = (
        (method == "GET" and path in {
            "health",
            "auth-info",
            "dashboard-data",
            "quarantine-events",
            "audit-events",
        })
        or (method == "POST" and path == "scan")
        or (
            method == "POST"
            and re.fullmatch(r"restore/[^/]+", path) is not None
        )
    )

    if not allowed:
        return JsonResponse(
            {"error": "Endpoint o metodo non consentito."},
            status=404,
        )

    if method == "POST":
        if not policy.check((("identity", "admin_required"),), request):
            return JsonResponse(
                {"error": "Operazione riservata agli amministratori."},
                status=403,
            )

    try:
        token = request.user.token.id
    except (AttributeError, TypeError):
        return JsonResponse(
            {"error": "Token Keystone non disponibile nella sessione."},
            status=401,
        )

    headers = {
        "X-Auth-Token": token,
        "Accept": "application/json",
    }

    if request.content_type:
        headers["Content-Type"] = request.content_type

    try:
        response = requests.request(
            method=method,
            url=f"{API_URL}/{path}",
            headers=headers,
            params=request.GET,
            data=request.body if method != "GET" else None,
            timeout=(3, 20),
            allow_redirects=False,
        )

        return HttpResponse(
            response.content,
            status=response.status_code,
            content_type=response.headers.get(
                "Content-Type",
                "application/json",
            ),
        )

    except requests.RequestException:
        LOG.exception("Errore nel collegamento con l'API Guardrail")
        return JsonResponse(
            {"error": "API Guardrail temporaneamente non disponibile."},
            status=502,
        )
