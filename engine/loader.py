"""
loader.py — Sigma kurallarını YAML dosyalarından yükler

Sigma nedir?
    Güvenlik dünyasının evrensel detection rule formatı.
    YARA kuralları dosya/malware tespiti için neyse,
    Sigma kuralları log tespiti için odur.

    Avantajları:
    - Platform bağımsız (Splunk, ELK, QRadar hepsine çevrilebilir)
    - Topluluk tarafından binlerce hazır kural yazılmış
    - YAML formatı → insan tarafından okunabilir

Bu loader ne yapıyor?
    1. engine/rules/ klasöründeki tüm .yml dosyalarını tarar
    2. Her dosyayı YAML olarak parse eder
    3. İçeriğini SigmaRule dataclass'ına dönüştürür
    4. Geçersiz kuralları uyarıyla atlar (hata toleransı)

Dataclass nedir?
    Python 3.7+ ile gelen bir özellik. Sadece veri taşıyan sınıflar
    için __init__, __repr__, __eq__ gibi metodları otomatik oluşturur.
    Normal class yazmaktan çok daha kısa ve temiz.

    @dataclass
    class Point:
        x: float
        y: float

    p = Point(x=3, y=4)  # __init__ otomatik oluştu
    print(p)              # Point(x=3, y=4) — __repr__ otomatik
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger("sentinelboard.engine.loader")


@dataclass
class SigmaRule:
    """
    Bir Sigma kuralının Python temsili.

    Her field YAML dosyasındaki bir key'e karşılık gelir.
    ssh_brute_force.yml dosyasını hatırla:

        title: SSH Brute Force Detection
        id: sentinel-001
        level: high
        detection:
          selection:
            event_type: auth_failure
            service: sshd
          condition: selection | count(src_ip) > 10
          timeframe: 5m
    """

    # ── Kimlik ──
    id: str                        # "sentinel-001"
    title: str                     # "SSH Brute Force Detection"
    description: str = ""

    # ── Tespit ──
    status: str = "active"         # active, testing, deprecated
    level: str = "medium"          # info, low, medium, high, critical

    # ── Detection (en önemli kısım) ──
    # selection: hangi event'leri arıyoruz
    # condition: bu event'ler hangi koşulda alert üretir
    # timeframe: kaç dakikalık pencerede bakacağız
    selection: dict = field(default_factory=dict)
    condition: str = ""
    timeframe: str = "5m"

    # Bu kural icin alert tekrar araligi ("6h", "1d"...).
    # Bos birakilirsa motorun varsayilani (ALERT_COOLDOWN) kullanilir.
    # Neden kural basina? 24 saatlik pencereye bakan bir kural, 5 dakikalik
    # varsayilan cooldown ile ayni alert'i gun boyu tekrar uretir.
    cooldown: str = ""

    # ── Tepki ──
    response: dict = field(default_factory=dict)

    # ── Meta ──
    tags: list = field(default_factory=list)
    falsepositives: list = field(default_factory=list)
    author: str = ""

    # ── Kaynak dosya yolu (debug için) ──
    source_file: str = ""


def parse_timeframe(timeframe_str: str) -> int:
    """
    Timeframe string'ini saniyeye çevirir.

    Örnekler:
        "5m"  → 300 saniye
        "1h"  → 3600 saniye
        "30s" → 30 saniye
        "1d"  → 86400 saniye

    Neden saniyeye çeviriyoruz?
        Veritabanı sorgusunda "son X saniye" olarak kullanacağız.
        Django'da: Event.objects.filter(timestamp__gte=now - timedelta(seconds=300))
    """
    if not timeframe_str:
        return 300  # Varsayılan 5 dakika

    unit = timeframe_str[-1].lower()  # Son karakter: m, h, s, d
    try:
        value = int(timeframe_str[:-1])  # Son karakter hariç sayı
    except ValueError:
        logger.warning(f"Invalid timeframe: {timeframe_str}, using 5m")
        return 300

    multipliers = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }

    return value * multipliers.get(unit, 60)


def load_rule_from_file(filepath: str) -> Optional[SigmaRule]:
    """
    Tek bir YAML dosyasını okur ve SigmaRule'a dönüştürür.

    Neden Optional dönüyor?
        Dosya bozuk olabilir, gerekli field'lar eksik olabilir.
        Bu durumda None döneriz ve o kuralı atlarız.
        Bir bozuk kural yüzünden tüm sistem çökmemeli.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            logger.warning(f"Empty or invalid YAML: {filepath}")
            return None

        # Gerekli field'ları kontrol et
        if "title" not in data:
            logger.warning(f"Rule missing 'title': {filepath}")
            return None

        if "detection" not in data:
            logger.warning(f"Rule missing 'detection': {filepath}")
            return None

        detection = data.get("detection", {})

        rule = SigmaRule(
            id=data.get("id", os.path.basename(filepath)),
            title=data["title"],
            description=data.get("description", ""),
            status=data.get("status", "active"),
            level=data.get("level", "medium"),
            selection=detection.get("selection", {}),
            condition=detection.get("condition", ""),
            timeframe=detection.get("timeframe", "5m"),
            cooldown=data.get("response", {}).get("cooldown", ""),
            response=data.get("response", {}),
            tags=data.get("tags", []),
            falsepositives=data.get("falsepositives", []),
            author=data.get("author", ""),
            source_file=filepath,
        )

        return rule

    except yaml.YAMLError as e:
        logger.error(f"YAML parse error in {filepath}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to load rule {filepath}: {e}")
        return None


def load_all_rules(rules_dir: str = None) -> list[SigmaRule]:
    """
    Belirtilen klasördeki tüm .yml dosyalarını yükler.

    Args:
        rules_dir: Kuralların bulunduğu klasör yolu.
                   None ise varsayılan engine/rules/ kullanılır.

    Returns:
        Başarıyla yüklenen SigmaRule listesi.

    Neden listeye topluyoruz?
        Korelasyon motoru her çalıştığında tüm kuralları
        tekrar dosyadan okumak yavaş olur. Bir kere yükleyip
        bellekte tutuyoruz. Yeni kural eklediğinde motoru
        restart etmen yeterli (veya ileride hot-reload ekleriz).
    """
    if rules_dir is None:
        # Varsayılan: engine/rules/ klasörü
        rules_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "rules",
        )

    if not os.path.isdir(rules_dir):
        logger.error(f"Rules directory not found: {rules_dir}")
        return []

    rules = []
    loaded = 0
    skipped = 0

    # Klasördeki tüm .yml ve .yaml dosyalarını tara
    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith((".yml", ".yaml")):
            continue

        filepath = os.path.join(rules_dir, filename)
        rule = load_rule_from_file(filepath)

        if rule:
            # Sadece aktif kuralları yükle
            if rule.status == "active":
                rules.append(rule)
                loaded += 1
                logger.info(f"Loaded rule: [{rule.level}] {rule.title}")
            else:
                skipped += 1
                logger.debug(f"Skipped inactive rule: {rule.title}")
        else:
            skipped += 1

    logger.info(f"Rule loading complete: {loaded} active, {skipped} skipped")
    return rules