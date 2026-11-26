from django.urls import re_path
from openstack_dashboard.dashboards.project.guardrail import views

urlpatterns = [
    re_path(r"^$", views.index, name="index"),
    re_path(r"^api/(?P<path>.+)$", views.api_proxy, name="api"),
]
