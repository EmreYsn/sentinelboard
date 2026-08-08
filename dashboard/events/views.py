from datetime import timedelta

from django.utils import timezone
from django.db.models import Count, Q
from django.shortcuts import render

from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response
from alerts.llm_analyzer import analyze_alert
from alerts.chat import chat

from events.models import Event, Alert
from events.serializers import (
    EventSerializer,
    AlertSerializer,
    AlertUpdateSerializer,
)


class EventViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = EventSerializer
    ordering = ["-timestamp"]

    def get_queryset(self):
        queryset = Event.objects.all().order_by("-timestamp")

        severity = self.request.query_params.get("severity")
        source = self.request.query_params.get("source")
        event_type = self.request.query_params.get("event_type")
        src_ip = self.request.query_params.get("src_ip")
        search = self.request.query_params.get("search")
        hours = self.request.query_params.get("hours")

        if severity:
            queryset = queryset.filter(severity=severity)
        if source:
            queryset = queryset.filter(source=source)
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        if src_ip:
            queryset = queryset.filter(src_ip=src_ip)
        if search:
            queryset = queryset.filter(
                Q(raw__icontains=search) |
                Q(message__icontains=search) |
                Q(user__icontains=search) |
                Q(src_ip__icontains=search)
            )
        if hours:
            try:
                h = int(hours)
                since = timezone.now() - timedelta(hours=h)
                queryset = queryset.filter(timestamp__gte=since)
            except ValueError:
                pass

        return queryset


class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AlertSerializer
    ordering = ["-created_at"]

    def get_queryset(self):
        queryset = Alert.objects.all().order_by("-created_at")

        severity = self.request.query_params.get("severity")
        status_filter = self.request.query_params.get("status")
        rule_id = self.request.query_params.get("rule_id")

        if severity:
            queryset = queryset.filter(severity=severity)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if rule_id:
            queryset = queryset.filter(rule_id=rule_id)

        return queryset

    @action(detail=True, methods=["patch"], url_path="status")
    def update_status(self, request, pk=None):
        alert = self.get_object()
        serializer = AlertUpdateSerializer(alert, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(AlertSerializer(alert).data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
def dashboard_stats(request):
    now = timezone.now()
    last_hour = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)

    total_events = Event.objects.count()
    total_alerts = Alert.objects.count()
    new_alerts = Alert.objects.filter(status="new").count()
    high_alerts = Alert.objects.filter(
        severity__in=["high", "critical"],
        status="new",
    ).count()
    events_last_hour = Event.objects.filter(timestamp__gte=last_hour).count()

    top_ips = (
        Event.objects
        .filter(timestamp__gte=last_24h, src_ip__isnull=False)
        .values("src_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    top_source_ips = [
        {"ip": item["src_ip"], "count": item["count"]}
        for item in top_ips
    ]

    severity_dist = dict(
        Event.objects
        .filter(timestamp__gte=last_24h)
        .values_list("severity")
        .annotate(count=Count("id"))
        .order_by("severity")
    )

    source_dist = dict(
        Event.objects
        .filter(timestamp__gte=last_24h)
        .values_list("source")
        .annotate(count=Count("id"))
        .order_by("source")
    )

    data = {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "high_severity_alerts": high_alerts,
        "events_last_hour": events_last_hour,
        "top_source_ips": top_source_ips,
        "events_by_severity": severity_dist,
        "events_by_source": source_dist,
    }

    return Response(data)

@api_view(["POST"])
def analyze_alert_view(request, alert_id):
    try:
        alert = Alert.objects.get(id=alert_id)
    except Alert.DoesNotExist:
        return Response(
            {"error": "Alert not found"},
            status=status.HTTP_404_NOT_FOUND,
        )
    result = analyze_alert(alert)
    return Response(result)

@api_view(["POST"])
def chat_view(request):
    question = request.data.get("question", "")
    if not question:
        return Response({"error": "Question is required"}, status=status.HTTP_400_BAD_REQUEST)
    result = chat(question)
    return Response(result)

def dashboard_view(request):
    """Ana dashboard sayfasını render eder."""
    return render(request, "dashboard.html")