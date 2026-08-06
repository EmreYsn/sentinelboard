"""
features.py — Log verilerinden sayısal özellikler (feature) çıkarır

Feature Engineering nedir?
    Ham veriyi (log satırları) ML modelinin anlayacağı sayılara
    çevirme işlemi. ML'in en kritik adımı — iyi feature'lar
    kötü bir modeli bile iyi yapar, kötü feature'lar iyi bir
    modeli bile işe yaramaz hale getirir.

Zaman penceresi (time window) nedir?
    Logları belirli zaman dilimlerine ayırıyoruz.
    Örneğin 10 dakikalık pencereler:
        09:00-09:10 → pencere 1: 25 event, 3 IP, 0 failure
        09:10-09:20 → pencere 2: 30 event, 4 IP, 2 failure
        09:20-09:30 → pencere 3: 200 event, 45 IP, 150 failure ← ANOMALİ!

    Her pencere için feature vektörü çıkarıyoruz.
    Model bu vektörlerin "normal" halini öğreniyor.
"""

import logging
from datetime import timedelta
from dataclasses import dataclass

from django.utils import timezone
from django.db.models import Count, Q

from events.models import Event

logger = logging.getLogger("sentinelboard.ml.features")


@dataclass
class FeatureVector:
    """
    Bir zaman penceresi için çıkarılan özellik vektörü.

    Her field bir "feature" — modelin baktığı bir sayı.
    Hepsinin birlikte değerlendirilmesi anomali tespitini sağlar.
    Tek başına "50 event" anormal olmayabilir ama
    "50 event + 40 benzersiz IP + %80 failure oranı" kesinlikle anormal.
    """
    # Pencerenin zaman aralığı
    window_start: str
    window_end: str

    # ── Hacim Metrikleri ──
    # Toplam olay sayısı — ani artış DDoS veya tarama belirtisi
    total_events: int = 0

    # Benzersiz kaynak IP sayısı — çok fazla farklı IP = botnet/tarama
    unique_src_ips: int = 0

    # Benzersiz hedef port sayısı — çok fazla port = port scan
    unique_dst_ports: int = 0

    # ── Auth Metrikleri ──
    # Başarısız giriş sayısı
    auth_failures: int = 0

    # Başarılı giriş sayısı
    auth_successes: int = 0

    # Başarısız/toplam oranı (0.0-1.0)
    # 0.9 = girişlerin %90'ı başarısız → brute force
    auth_failure_ratio: float = 0.0

    # ── HTTP Metrikleri ──
    # Şüpheli HTTP istek sayısı
    suspicious_requests: int = 0

    # HTTP 4xx hata sayısı (tarama belirtisi)
    http_4xx_count: int = 0

    # ── Firewall Metrikleri ──
    # Engellenen bağlantı sayısı
    firewall_blocks: int = 0

    # ── Çeşitlilik Metrikleri ──
    # Farklı event tipi sayısı — anormal çeşitlilik şüpheli
    unique_event_types: int = 0

    # Sudo komut sayısı — privilege escalation belirtisi
    sudo_count: int = 0

    def to_list(self) -> list[float]:
        """
        Feature'ları sıralı bir listeye çevirir.

        ML modelleri (scikit-learn) input olarak sayı listesi
        veya numpy array ister. Bu metod dataclass'ı o formata
        çevirir.

        Sıralama ÖNEMLİ — eğitim ve tahmin sırasında aynı
        sırada olması lazım. Sıra değişirse model yanlış
        feature'a bakıp yanlış sonuç üretir.
        """
        return [
            float(self.total_events),
            float(self.unique_src_ips),
            float(self.unique_dst_ports),
            float(self.auth_failures),
            float(self.auth_successes),
            float(self.auth_failure_ratio),
            float(self.suspicious_requests),
            float(self.http_4xx_count),
            float(self.firewall_blocks),
            float(self.unique_event_types),
            float(self.sudo_count),
        ]

    @staticmethod
    def feature_names() -> list[str]:
        """Feature isimlerini döner (grafik ve debug için)."""
        return [
            "total_events",
            "unique_src_ips",
            "unique_dst_ports",
            "auth_failures",
            "auth_successes",
            "auth_failure_ratio",
            "suspicious_requests",
            "http_4xx_count",
            "firewall_blocks",
            "unique_event_types",
            "sudo_count",
        ]


def extract_features(window_start, window_end) -> FeatureVector:
    """
    Belirli bir zaman penceresi için feature vektörü çıkarır.

    Args:
        window_start: Pencerenin başlangıç zamanı (datetime)
        window_end: Pencerenin bitiş zamanı (datetime)

    Bu fonksiyon veritabanına birkaç sorgu atıyor:
    1. Toplam event sayısı ve benzersiz değerler
    2. Auth failure/success sayıları
    3. HTTP ve firewall metrikleri

    Her sorgu Django ORM ile yapılıyor. SQL karşılıklarını
    yorumlarda yazdım — ne olduğunu anlamak için faydalı.
    """
    # Zaman aralığındaki tüm event'ler
    events = Event.objects.filter(
        timestamp__gte=window_start,
        timestamp__lt=window_end,
    )

    total = events.count()

    if total == 0:
        return FeatureVector(
            window_start=str(window_start),
            window_end=str(window_end),
        )

    # ── Benzersiz değerler ──
    # SQL: SELECT COUNT(DISTINCT src_ip) FROM events WHERE ...
    unique_ips = events.filter(
        src_ip__isnull=False
    ).values("src_ip").distinct().count()

    unique_ports = events.filter(
        dst_port__isnull=False
    ).values("dst_port").distinct().count()

    unique_types = events.values("event_type").distinct().count()

    # ── Auth metrikleri ──
    auth_failures = events.filter(event_type="auth_failure").count()
    auth_successes = events.filter(event_type="auth_success").count()

    auth_total = auth_failures + auth_successes
    auth_failure_ratio = auth_failures / auth_total if auth_total > 0 else 0.0

    # ── HTTP metrikleri ──
    # Şüpheli istekler: extra JSON'daki is_suspicious field'ı
    suspicious = events.filter(extra__is_suspicious=True).count()

    # 4xx hatalar: status_code extra'da saklanıyor
    # Django JSON lookup: extra__status_code__gte=400
    http_4xx = events.filter(
        event_type="http_request",
        extra__status_code__gte=400,
        extra__status_code__lt=500,
    ).count()

    # ── Firewall metrikleri ──
    fw_blocks = events.filter(event_type="firewall_block").count()

    # ── Sudo metrikleri ──
    sudo = events.filter(event_type="sudo_command").count()

    return FeatureVector(
        window_start=str(window_start),
        window_end=str(window_end),
        total_events=total,
        unique_src_ips=unique_ips,
        unique_dst_ports=unique_ports,
        auth_failures=auth_failures,
        auth_successes=auth_successes,
        auth_failure_ratio=round(auth_failure_ratio, 4),
        suspicious_requests=suspicious,
        http_4xx_count=http_4xx,
        firewall_blocks=fw_blocks,
        unique_event_types=unique_types,
        sudo_count=sudo,
    )


def extract_feature_series(
    hours: int = 24,
    window_minutes: int = 10,
) -> list[FeatureVector]:
    """
    Son X saat için pencere pencere feature çıkarır.

    Args:
        hours: Kaç saatlik veriyi tara (varsayılan 24)
        window_minutes: Her pencere kaç dakika (varsayılan 10)

    Dönen: FeatureVector listesi — her biri bir zaman penceresi

    Örnek (hours=2, window_minutes=10):
        12 pencere döner:
        [08:00-08:10], [08:10-08:20], ..., [09:50-10:00]

        Her birinin feature vektörü var.
        Bu seri ML modeline "normal davranış" olarak verilir.

    Neden 10 dakika?
        Çok kısa (1dk) → gürültü çok, false positive artar
        Çok uzun (1saat) → anomali sinyali seyreltilir, kaçırılır
        10 dakika iyi bir denge — saldırılar genelde dakikalar
        içinde gerçekleşir, 10dk'lık pencere bunu yakalar.
    """
    now = timezone.now()
    start = now - timedelta(hours=hours)

    features = []
    window_start = start

    while window_start < now:
        window_end = window_start + timedelta(minutes=window_minutes)
        fv = extract_features(window_start, window_end)
        features.append(fv)
        window_start = window_end

    logger.info(
        f"Extracted {len(features)} feature vectors "
        f"({hours}h, {window_minutes}m windows)"
    )

    return features