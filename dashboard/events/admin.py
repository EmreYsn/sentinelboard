"""
Django Admin — tarayıcıdan logları görüntüleme

Django admin otomatik bir yönetim paneli sağlar.
http://localhost:8000/admin/ adresinden logları görebilir,
filtreleyebilir ve arayabilirsin. Dashboard'u yazmadan
önce bile verileri kontrol etmek için çok faydalı.
"""

from django.contrib import admin
from events.models import Event, Alert


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    # Listede hangi sütunlar görünsün
    list_display = [
        "timestamp", "severity", "source",
        "event_type", "src_ip", "user", "host",
    ]

    # Sağ tarafta filtre paneli
    list_filter = ["severity", "source", "event_type"]

    # Arama çubuğunda hangi field'larda aransın
    search_fields = ["src_ip", "user", "raw", "message"]

    # Sayfa başına kaç kayıt
    list_per_page = 50

    # Detay sayfasında düzenleme yapılmasın (loglar immutable olmalı)
    readonly_fields = [
        "id", "timestamp", "collected_at", "created_at",
        "source", "host", "event_type", "severity",
        "src_ip", "dst_ip", "src_port", "dst_port",
        "user", "process", "pid", "message", "raw", "extra",
    ]

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = [
        "created_at", "severity", "rule_title",
        "src_ip", "user", "status",
    ]
    list_filter = ["severity", "status", "rule_id"]
    search_fields = ["message", "src_ip", "user", "rule_title"]
    list_per_page = 50
    readonly_fields = [
        "id", "created_at", "rule_id", "rule_title",
        "severity", "message", "src_ip", "user",
        "related_events", "tags",
    ]