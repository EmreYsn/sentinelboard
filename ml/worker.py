"""
ml/worker.py — ML anomali tespitini periyodik çalıştıran servis

Engine worker kuralları kontrol ediyordu.
ML worker ise istatistiksel anomali tespiti yapıyor.

İkisi paralel çalışır:
    Engine worker: "bu pattern bir kuralla eşleşiyor mu?" (bilinen tehditler)
    ML worker: "bu davranış normale göre sapma mı?" (bilinmeyen tehditler)

Çalışma döngüsü:
    1. Başlangıçta baseline var mı kontrol et
       - Varsa → yükle
       - Yoksa → geçmiş veriden oluştur
    2. Her döngüde:
       a. Son pencereyi (10dk) analiz et
       b. Anomali varsa → alert üret + Telegram bildirim
    3. Her gün baseline'ı güncelle (yeni veriyi öğren)

Nasıl çalıştırılır?
    cd sentinelboard
    python -m ml.worker
"""

import os
import sys
import signal
import logging
import time
from datetime import timedelta

import django
from dotenv import load_dotenv

# Django setup
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "dashboard"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

load_dotenv(os.path.join(project_root, ".env"))
django.setup()

from django.utils import timezone

from events.models import Alert
from ml.features import extract_features, extract_feature_series
from ml.detector import AnomalyDetector
from alerts.telegram_bot import send_alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelboard.ml.worker")

# ── Ayarlar ──
WINDOW_MINUTES = 10           # Her pencere kaç dakika
CHECK_INTERVAL = 60           # Kaç saniyede bir kontrol et
ALERT_COOLDOWN = 1800         # Aynı anomali için tekrar bildirim arası (30 dk)
BASELINE_PATH = os.path.join(project_root, "ml", "models", "baseline.json")
BASELINE_HOURS = 24           # Baseline için kaç saatlik veri kullan
RETRAIN_INTERVAL = 3600 * 6   # Kaç saniyede bir baseline güncelle (6 saat)


def build_anomaly_message(result, window_start, window_end) -> str:
    """
    Anomali sonucundan okunabilir alert mesajı oluşturur.

    Mesajda hangi feature'ların anormal olduğunu gösteriyoruz.
    SOC analisti bu mesajı okuyunca ne olduğunu anlayabilmeli.
    """
    lines = [
        f"ML Anomaly detected (score={result.score:.2f}, method={result.method})",
        f"Window: {window_start} — {window_end}",
        "",
    ]

    # Z-score detayları
    z_info = result.details.get("z_score", {})
    anomalous = z_info.get("anomalous_features", {})

    if anomalous:
        lines.append("Anomalous features:")
        for name, info in anomalous.items():
            lines.append(
                f"  {name}: value={info['value']}, "
                f"mean={info['mean']:.1f}, z={info['z_score']}"
            )

    # Isolation Forest detayı
    iso_info = result.details.get("isolation_forest", {})
    if iso_info:
        lines.append(f"\nIsolation Forest: {iso_info.get('prediction', 'N/A')}")

    return "\n".join(lines)


def is_in_cooldown() -> bool:
    """
    Son ALERT_COOLDOWN saniye içinde zaten bir ML anomali alert'i
    üretildiyse True döner → yenisini üretme.

    Neden gerekli?
        Anomali bir anlık olay değil, bir durumdur. Saldırı 20 dakika
        sürüyorsa her kontrol turunda (60 saniyede bir) aynı sapma
        görülür. Cooldown olmadan tek bir olay için 20 ayrı bildirim
        gider; analist bir süre sonra bildirimlere bakmayı bırakır ve
        asıl kritik olanı kaçırır. Engine tarafında aynı koruma
        rule_id + src_ip bazında zaten var.
    """
    cooldown_start = timezone.now() - timedelta(seconds=ALERT_COOLDOWN)
    return Alert.objects.filter(
        rule_id="ml-anomaly",
        created_at__gte=cooldown_start,
    ).exists()


def create_ml_alert(result, window_start, window_end):
    """
    ML anomali sonucundan Alert kaydı oluşturur ve Telegram'a gönderir.

    Cooldown süresi dolmadıysa hiçbir şey yapmaz ve None döner.
    """
    if is_in_cooldown():
        logger.info("ML anomaly detected but still in cooldown, skipping alert")
        return None

    message = build_anomaly_message(result, window_start, window_end)

    # Hangi feature en çok sapmış? Severity'yi ona göre belirle
    score = result.score
    if score >= 0.8:
        severity = "high"
    elif score >= 0.5:
        severity = "medium"
    else:
        severity = "low"

    alert = Alert.objects.create(
        rule_id="ml-anomaly",
        rule_title="ML Anomaly Detection",
        severity=severity,
        message=message,
        tags=["ml", "anomaly", result.method],
        status="new",
    )

    # Telegram bildirimi
    send_alert(alert)

    logger.warning(f"ML ALERT [{severity}] score={score:.2f}")
    return alert


def main():
    logger.info("=" * 60)
    logger.info("SentinelBoard ML Worker starting...")
    logger.info("=" * 60)

    detector = AnomalyDetector(z_threshold=2.5)

    # ── Baseline yükle veya oluştur ──
    if detector.load_baseline(BASELINE_PATH):
        logger.info("Existing baseline loaded")
    else:
        logger.info("No baseline found, building from historical data...")
        features = extract_feature_series(
            hours=BASELINE_HOURS,
            window_minutes=WINDOW_MINUTES,
        )
        vectors = [f.to_list() for f in features if f.total_events > 0]

        if detector.fit(vectors):
            detector.save_baseline(BASELINE_PATH)
            logger.info("Initial baseline created and saved")
        else:
            logger.warning(
                "Not enough data for baseline. "
                "ML worker will retry after collecting more logs. "
                "Rule-based detection (engine worker) is still active."
            )

    # ── Graceful shutdown ──
    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        shutdown = True
        logger.info("Shutdown signal received...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # ── Ana döngü ──
    cycle = 0
    total_anomalies = 0
    last_retrain = time.time()

    logger.info(f"ML Worker running (check every {CHECK_INTERVAL}s)")
    logger.info("Press Ctrl+C to stop")

    while not shutdown:
        cycle += 1

        try:
            # Son pencereyi analiz et
            now = timezone.now()
            window_end = now
            window_start = now - timedelta(minutes=WINDOW_MINUTES)

            fv = extract_features(window_start, window_end)

            # Boş pencereyi atla (gece gibi)
            if fv.total_events > 0 and detector.is_fitted:
                result = detector.predict(fv.to_list())

                if result.is_anomaly:
                    # Cooldown aktifse alert üretilmez, sayacı da artırmayalım
                    if create_ml_alert(result, window_start, window_end):
                        total_anomalies += 1

            # Periyodik baseline güncelleme
            elapsed = time.time() - last_retrain
            if elapsed >= RETRAIN_INTERVAL:
                logger.info("Retraining baseline with recent data...")
                features = extract_feature_series(
                    hours=BASELINE_HOURS,
                    window_minutes=WINDOW_MINUTES,
                )
                vectors = [f.to_list() for f in features if f.total_events > 0]

                if detector.fit(vectors):
                    detector.save_baseline(BASELINE_PATH)

                last_retrain = time.time()

            # Alive mesajı (her 5 döngüde bir)
            if cycle % 5 == 0:
                status = "fitted" if detector.is_fitted else "waiting for data"
                logger.info(
                    f"ML Worker alive — cycle {cycle}, "
                    f"anomalies: {total_anomalies}, "
                    f"model: {status}"
                )

        except Exception as e:
            logger.error(f"ML Worker error: {e}")

        # Bekle
        for _ in range(CHECK_INTERVAL * 2):
            if shutdown:
                break
            time.sleep(0.5)

    logger.info(f"ML Worker stopped. Total anomalies: {total_anomalies}")


if __name__ == "__main__":
    main()