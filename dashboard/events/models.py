"""
Event modeli — normalleştirilmiş logların veritabanı tablosu

Her log satırı parse edildikten sonra bir Event kaydı olarak
PostgreSQL'e yazılır. Bu model o kaydın şemasını tanımlar.

Django ORM nedir?
    Object-Relational Mapping — Python sınıflarıyla veritabanı
    tabloları tanımlarsın, SQL yazmana gerek kalmaz.
    Event sınıfı = events_event tablosu
    Her field = tablodaki bir sütun
    Event.objects.filter(...) = SELECT ... WHERE ...
"""

import uuid
from django.db import models


class Event(models.Model):
    """
    Normalleştirilmiş bir log kaydı.

    Neden UUID kullanıyoruz (auto-increment ID yerine)?
        1. Tahmin edilemez — saldırgan ID'leri enumerate edemez
        2. Dağıtık sistemlerde çakışma olmaz
        3. Güvenlik yazılımında best practice
    """

    # ── Kimlik ──────────────────────────────────
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    # ── Zaman ───────────────────────────────────
    # timestamp: olayın gerçekleştiği zaman (log dosyasındaki)
    # collected_at: collector'ın yakaladığı zaman
    # created_at: veritabanına yazıldığı zaman
    # Neden üçü de var? Aralarındaki fark gecikmeyi ölçer.
    # timestamp ile collected_at arasında 2 saniye varsa normal.
    # 2 dakika varsa → collector geride kalmış, sorun var.
    timestamp = models.DateTimeField(db_index=True)
    collected_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # ── Kaynak ──────────────────────────────────
    # db_index=True → bu sütunda index oluştur
    # Index nedir? Kitabın arkasındaki dizin gibi. "auth" kaynaklı
    # logları bulmak için TÜM tabloyu taramak yerine index'e bakarsın.
    # Sorgu süresini O(n) → O(log n)'e düşürür.
    source = models.CharField(max_length=50, db_index=True)
    host = models.CharField(max_length=255, default="unknown")

    # ── Olay Bilgisi ────────────────────────────
    event_type = models.CharField(max_length=100, db_index=True)

    SEVERITY_CHOICES = [
        ("info", "Info"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default="info",
        db_index=True,
    )

    # ── Ağ Bilgisi ──────────────────────────────
    # GenericIPAddressField: hem IPv4 hem IPv6 destekler
    # null=True: her log'da IP olmayabilir (cron job'lar gibi)
    src_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)

    # ── Kullanıcı & Process ─────────────────────
    user = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    process = models.CharField(max_length=255, null=True, blank=True)
    pid = models.IntegerField(null=True, blank=True)

    # ── Mesaj ───────────────────────────────────
    message = models.TextField(null=True, blank=True)

    # ── Ham Log ─────────────────────────────────
    # Orijinal log satırını saklıyoruz. Neden?
    # Parser hata yapabilir, yeni pattern ekleyince eski logları
    # tekrar parse edebilirsin. Forensic analiz için ham veri kritik.
    raw = models.TextField()

    # ── Ekstra Veriler ──────────────────────────
    # JSONField: yapılandırılmamış ekstra verileri saklar.
    # Örnek: nginx'in user_agent'ı, auth'un auth_method'u
    # Her event tipi için ayrı sütun açmak yerine esnek bir alan.
    extra = models.JSONField(default=dict, blank=True)

    class Meta:
        # Veritabanı seviyesinde optimizasyonlar
        ordering = ["-timestamp"]  # Yeni olaylar önce
        indexes = [
            # Composite index: source + event_type birlikte sorgulanınca hızlı
            # "auth kaynağından auth_failure olanları getir" gibi
            models.Index(fields=["source", "event_type"]),
            # Zaman aralığı + severity: "son 1 saatteki high severity"
            models.Index(fields=["-timestamp", "severity"]),
            # IP bazlı arama: "bu IP'den gelen tüm olaylar"
            models.Index(fields=["src_ip", "-timestamp"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.source}/{self.event_type} @ {self.timestamp}"

class Alert(models.Model):
    """
    Korelasyon motoru veya ML modülü tarafından üretilen alert.

    Event ile Alert arasındaki fark:
        Event = tek bir log kaydı (bir satır)
        Alert = bir veya birden fazla event'in birlikte
                değerlendirilmesiyle üretilen tehdit bildirimi

    Örnek:
        10 tane auth_failure event'i → 1 tane "SSH Brute Force" alert'i
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    # Hangi kural tetikledi?
    rule_id = models.CharField(max_length=100, db_index=True)
    rule_title = models.CharField(max_length=255)

    SEVERITY_CHOICES = [
        ("info", "Info"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, db_index=True)

    # Alert mesajı — kural tetiklendiğinde ne olduğunu anlatan metin
    message = models.TextField()

    # Hangi IP/kullanıcı tetikledi (hızlı filtreleme için)
    src_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user = models.CharField(max_length=255, null=True, blank=True)

    # Bu alert'i tetikleyen event'ler (many-to-many ilişki)
    # Bir alert birden fazla event'ten oluşabilir
    # Bir event birden fazla alert'i tetikleyebilir
    related_events = models.ManyToManyField(Event, blank=True, related_name="alerts")

    # MITRE ATT&CK tag'leri (kuraldan gelir)
    tags = models.JSONField(default=list, blank=True)

    # Kullanıcı bu alert'i gördü mü?
    STATUS_CHOICES = [
        ("new", "New"),
        ("acknowledged", "Acknowledged"),
        ("resolved", "Resolved"),
        ("false_positive", "False Positive"),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="new", db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"[{self.severity}] {self.rule_title} @ {self.created_at}"