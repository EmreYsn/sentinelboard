"""
matcher.py — Sigma kurallarını veritabanındaki loglarla eşleştirir

Bu dosya ne yapıyor?
    1. Her kural için: selection kriterlerine uyan event'leri DB'den çeker
    2. Condition'ı değerlendirir (count, threshold kontrolü)
    3. Eşleşme varsa Alert kaydı oluşturur

Condition formatı nasıl çalışıyor?
    Sigma'da condition şöyle yazılır:
        "selection | count(src_ip) > 10"

    Bu şu anlama gelir:
        1. "selection" → selection kriterlerine uyan event'leri al
        2. "|" → pipe (bu event'leri şu işleme sok)
        3. "count(src_ip)" → src_ip field'ına göre grupla ve say
        4. "> 10" → sayı 10'dan büyükse eşleşme var

    Biz bu string'i parse edip Django ORM sorgusuna çevireceğiz.

Cooldown nedir?
    Aynı kural + aynı IP için sürekli alert üretmek istemeyiz.
    Örneğin brute force devam ediyorsa her 10 saniyede alert
    üretmek anlamsız — sadece alert yorgunluğu (alert fatigue) yaratır.
    Cooldown süresi içinde aynı kural+IP için tekrar alert üretmeyiz.
"""

import re
import logging
from datetime import timedelta

from django.utils import timezone
from django.db.models import Count

from events.models import Event, Alert
from engine.loader import SigmaRule, parse_timeframe
from alerts.telegram_bot import send_alert

logger = logging.getLogger("sentinelboard.engine.matcher")

# Condition string'ini parse eden regex
# "selection | count(src_ip) > 10" → groups: field=src_ip, operator=>, value=10
CONDITION_PATTERN = re.compile(
    r"selection\s*\|\s*count\((\w+)\)\s*(>|>=|<|<=|==)\s*(\d+)"
)

# Cooldown süresi (saniye) — aynı kural+IP için tekrar alert üretme
ALERT_COOLDOWN = 300  # 5 dakika


def build_selection_query(selection: dict) -> dict:
    """
    Sigma selection'ını Django ORM filter kwargs'ına çevirir.

    Önemli detay: Event modelinde her field için sütun yok.
    Modelde olmayan field'lar extra JSONField'ın içinde saklanıyor.
    Bu durumda Django'nun JSON lookup özelliğini kullanıyoruz:
        extra__is_suspicious=True
    Bu SQL'de şuna dönüşür:
        WHERE extra->>'is_suspicious' = 'true'
    """
    # Event modelindeki gerçek sütunlar
    model_fields = {
        "timestamp", "collected_at", "created_at", "source", "host",
        "event_type", "severity", "src_ip", "dst_ip", "src_port",
        "dst_port", "user", "process", "pid", "message", "raw",
    }

    query = {}
    for field_name, value in selection.items():
        # Sigma'da "service" bizde "process"
        if field_name == "service":
            field_name = "process"

        # Boolean string dönüşümü
        if isinstance(value, str) and value.lower() in ("true", "false"):
            value = value.lower() == "true"

        # Field modelde varsa direkt kullan, yoksa extra__field olarak ara
        if field_name in model_fields:
            query[field_name] = value
        else:
            query[f"extra__{field_name}"] = value

    return query


def parse_condition(condition: str) -> dict | None:
    """
    Condition string'ini parçalarına ayırır.

    Gelen: "selection | count(src_ip) > 10"

    Dönen: {
        "group_by": "src_ip",    # Hangi field'a göre grupla
        "operator": ">",         # Karşılaştırma operatörü
        "threshold": 10          # Eşik değeri
    }

    Neden regex kullanıyoruz?
        Condition formatı her zaman aynı pattern'ı takip ediyor.
        Regex bu pattern'ı güvenilir şekilde yakalar.
        İleride daha karmaşık condition'lar için parser genişletilebilir.
    """
    match = CONDITION_PATTERN.search(condition)
    if not match:
        logger.warning(f"Cannot parse condition: {condition}")
        return None

    return {
        "group_by": match.group(1),    # "src_ip"
        "operator": match.group(2),     # ">"
        "threshold": int(match.group(3)), # 10
    }


def check_threshold(count: int, operator: str, threshold: int) -> bool:
    """
    Sayı eşik değerini geçiyor mu kontrol eder.

    Basit ama ayrı fonksiyon olması test edilebilirliği artırır.
    """
    if operator == ">":
        return count > threshold
    elif operator == ">=":
        return count >= threshold
    elif operator == "<":
        return count < threshold
    elif operator == "<=":
        return count <= threshold
    elif operator == "==":
        return count == threshold
    return False


def is_in_cooldown(rule_id: str, src_ip: str) -> bool:
    """
    Bu kural+IP kombinasyonu için yakın zamanda alert üretilmiş mi?

    Son ALERT_COOLDOWN saniye içinde aynı rule_id ve src_ip ile
    alert varsa True döner → yeni alert üretme.

    Neden buna ihtiyacımız var?
        Brute force saldırısı devam ediyorsa, matcher her çalıştığında
        aynı koşul sağlanacak. Cooldown olmadan dakikada 6 alert
        üretirsin (10 saniyede bir çalışıyorsa). Bu kullanıcıyı
        boğar ve gerçek tehditleri kaçırmasına neden olur.
    """
    cooldown_start = timezone.now() - timedelta(seconds=ALERT_COOLDOWN)
    return Alert.objects.filter(
        rule_id=rule_id,
        src_ip=src_ip,
        created_at__gte=cooldown_start,
    ).exists()


def evaluate_rule(rule: SigmaRule) -> list[Alert]:
    """
    Tek bir kuralı değerlendirir ve eşleşme varsa alert üretir.

    Bu fonksiyon matcher'ın kalbi. Akışı:
        1. Timeframe'e göre zaman penceresi belirle
        2. Selection kriterlerine uyan event'leri çek
        3. Condition'ı parse et
        4. Event'leri group_by field'ına göre grupla ve say
        5. Threshold'u geçen gruplar için alert üret

    Returns:
        Oluşturulan Alert listesi (boş olabilir)
    """
    # 1. Zaman penceresi
    timeframe_seconds = parse_timeframe(rule.timeframe)
    window_start = timezone.now() - timedelta(seconds=timeframe_seconds)

    # 2. Selection'a uyan event'leri çek
    selection_query = build_selection_query(rule.selection)
    events = Event.objects.filter(
        timestamp__gte=window_start,
        **selection_query,
    )

    event_count = events.count()
    if event_count == 0:
        return []  # Hiç eşleşen event yok

    # 3. Condition'ı parse et
    condition = parse_condition(rule.condition)
    if condition is None:
        # Condition parse edilemedi — basit selection match olarak değerlendir
        # (event var ve selection'a uyuyor = eşleşme)
        logger.debug(f"Rule {rule.id}: no parseable condition, skipping")
        return []

    group_by = condition["group_by"]      # "src_ip"
    operator = condition["operator"]       # ">"
    threshold = condition["threshold"]     # 10

    # 4. Group by + count
    # Django ORM'de:
    #   Event.objects.filter(...).values("src_ip").annotate(count=Count("id"))
    # SQL karşılığı:
    #   SELECT src_ip, COUNT(id) as count FROM events
    #   WHERE ... GROUP BY src_ip
    #
    # values() → GROUP BY hangi field'a göre
    # annotate(Count) → her grup için COUNT hesapla
    groups = (
        events
        .values(group_by)
        .annotate(event_count=Count("id"))
        .order_by("-event_count")
    )

    # 5. Her grup için threshold kontrolü
    alerts_created = []

    for group in groups:
        group_value = group[group_by]       # örn: "45.33.32.156"
        count = group["event_count"]        # örn: 15

        if not check_threshold(count, operator, threshold):
            continue  # Bu grup eşiği aşmamış

        # Cooldown kontrolü
        if group_value and is_in_cooldown(rule.id, str(group_value)):
            logger.debug(
                f"Rule {rule.id}: cooldown active for {group_value}, skipping"
            )
            continue

        # Alert mesajını oluştur
        message = (
            f"{rule.title}: {count} events detected from "
            f"{group_by}={group_value} in last {rule.timeframe}"
        )

        # Alert kaydını oluştur
        alert = Alert.objects.create(
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.level,
            message=message,
            src_ip=group_value if group_by == "src_ip" else None,
            tags=rule.tags,
            status="new",
        )

        # Bu alert'i tetikleyen event'leri ilişkilendir
        # Sadece bu group_value'ya ait event'leri bağla
        related = events.filter(**{group_by: group_value})
        alert.related_events.set(related)

        send_alert(alert)
        alerts_created.append(alert)
        logger.warning(
            f"ALERT [{rule.level}] {rule.title}: "
            f"{count} events from {group_value}"
        )

    return alerts_created


def run_all_rules(rules: list[SigmaRule]) -> list[Alert]:
    """
    Tüm kuralları sırayla değerlendirir.

    Args:
        rules: Loader'dan gelen SigmaRule listesi

    Returns:
        Bu çalıştırmada oluşturulan tüm Alert'ler
    """
    all_alerts = []

    for rule in rules:
        try:
            alerts = evaluate_rule(rule)
            all_alerts.extend(alerts)
        except Exception as e:
            # Bir kuralın hatası diğerlerini etkilemesin
            logger.error(f"Error evaluating rule {rule.id}: {e}")

    return all_alerts