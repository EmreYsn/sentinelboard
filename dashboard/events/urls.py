from django.urls import path, include
from rest_framework.routers import DefaultRouter

from events.views import (
    EventViewSet, AlertViewSet, dashboard_stats,
    dashboard_view, analyze_alert_view, chat_view,
    explain_event_view,
)

router = DefaultRouter()
router.register("events", EventViewSet, basename="event")
router.register("alerts", AlertViewSet, basename="alert")

urlpatterns = [
    path("", dashboard_view, name="dashboard"),
    path("stats/", dashboard_stats, name="dashboard-stats"),
    path("alerts/<uuid:alert_id>/analyze/", analyze_alert_view, name="analyze-alert"),
    path("", include(router.urls)),
    path("chat/", chat_view, name="chat"),
    path("events/<uuid:event_id>/explain/", explain_event_view, name="explain-event"),
]