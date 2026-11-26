import horizon
from django.utils.translation import gettext_lazy as _
from openstack_dashboard.dashboards.project import dashboard


class Guardrail(horizon.Panel):
    name = _("Guardrail")
    slug = "guardrail"


dashboard.Project.register(Guardrail)
