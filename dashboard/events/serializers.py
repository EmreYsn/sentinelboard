from rest_framework import serializers
from events.models import Event, Alert


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = [
            "id", "timestamp", "collected_at", "created_at",
            "source", "host", "event_type", "severity",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "user", "process", "pid", "message", "raw", "extra",
        ]


class AlertSerializer(serializers.ModelSerializer):
    event_count = serializers.SerializerMethodField()
    # Analiz metninin kendisi listeye konmuyor: 200 alert'lik bir
    # listede her biri birkaç kilobayt metin taşırsa yanıt şişer.
    # Panelin listede ihtiyacı olan tek şey analizin VAR olup olmadığı.
    has_analysis = serializers.BooleanField(read_only=True)

    class Meta:
        model = Alert
        fields = [
            "id", "created_at", "rule_id", "rule_title",
            "severity", "message", "src_ip", "user",
            "tags", "status", "event_count",
            "has_analysis", "llm_analyzed_at",
        ]

    def get_event_count(self, obj):
        return obj.related_events.count()


class AlertUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ["status"]


class StatsSerializer(serializers.Serializer):
    total_events = serializers.IntegerField()
    total_alerts = serializers.IntegerField()
    new_alerts = serializers.IntegerField()
    high_severity_alerts = serializers.IntegerField()
    events_last_hour = serializers.IntegerField()
    top_source_ips = serializers.ListField()
    events_by_severity = serializers.DictField()
    events_by_source = serializers.DictField()