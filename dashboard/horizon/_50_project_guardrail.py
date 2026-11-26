# Guardrail - Horizon integration

PANEL = "guardrail"
PANEL_DASHBOARD = "project"
PANEL_GROUP = "compute"

ADD_PANEL = (
    "openstack_dashboard.dashboards.project.guardrail.panel.Guardrail"
)

ADD_INSTALLED_APPS = [
    "openstack_dashboard.dashboards.project.guardrail",
]
