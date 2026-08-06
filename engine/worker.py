"""
engine/worker.py — Korelasyon motorunu periyodik çalıştıran servis

Bu dosya ne yapıyor?
    1. Başlangıçta tüm Sigma kurallarını yükler
    2. Her X saniyede (varsayılan 10) tüm kuralları değerlendirir
    3. Eşleşme bulunca alert üretir
    4. Ctrl+C ile düzgün kapanır

Parser worker ile farkı:
    Parser worker: Redis → DB (veri taşıma)
    Engine worker: DB'deki verileri analiz et → alert üret (tespit)

    İkisi paralel çalışır:
    - Parser sürekli yeni logları DB'ye yazar
    - Engine sürekli DB'deki logları tareyip pattern arar

Nasıl çalıştırılır?
    cd sentinelboard
    python -m engine.worker
"""

import os
import sys
import signal
import logging
import time

import django
from dotenv import load_dotenv

# Django setup
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "dashboard"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

load_dotenv(os.path.join(project_root, ".env"))
django.setup()

from engine.loader import load_all_rules
from engine.matcher import run_all_rules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelboard.engine.worker")

# Kaç saniyede bir kuralları çalıştırsın
EVALUATION_INTERVAL = 10


def main():
    logger.info("=" * 60)
    logger.info("SentinelBoard Correlation Engine starting...")
    logger.info("=" * 60)

    # Kuralları yükle
    rules = load_all_rules()

    if not rules:
        logger.error("No active rules found. Exiting.")
        sys.exit(1)

    logger.info(f"Engine running with {len(rules)} rule(s)")
    logger.info(f"Evaluation interval: {EVALUATION_INTERVAL}s")
    logger.info("Press Ctrl+C to stop")

    # Graceful shutdown
    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        shutdown = True
        logger.info("Shutdown signal received...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # ── Ana Döngü ─────────────────────────────────────────────
    # Her iterasyonda:
    #   1. Tüm kuralları değerlendir
    #   2. Üretilen alert sayısını logla
    #   3. EVALUATION_INTERVAL kadar bekle
    #   4. Tekrarla
    cycle = 0
    total_alerts = 0

    while not shutdown:
        cycle += 1

        try:
            alerts = run_all_rules(rules)

            if alerts:
                total_alerts += len(alerts)
                for alert in alerts:
                    logger.warning(
                        f"NEW ALERT [{alert.severity}] "
                        f"{alert.rule_title} — {alert.src_ip}"
                    )
            else:
                # Her 6 döngüde bir (60 saniye) "alive" mesajı bas
                # Sürekli "no alerts" yazmak log kirliliği yaratır
                if cycle % 6 == 0:
                    logger.info(
                        f"Engine alive — cycle {cycle}, "
                        f"total alerts: {total_alerts}"
                    )

        except Exception as e:
            logger.error(f"Engine error: {e}")

        # Bekle — ama shutdown gelirse hemen çık
        # time.sleep yerine bu pattern kullanıyoruz
        # çünkü sleep sırasında Ctrl+C'ye hemen tepki vermez
        for _ in range(EVALUATION_INTERVAL * 2):
            if shutdown:
                break
            time.sleep(0.5)

    logger.info(f"Engine stopped. Total alerts produced: {total_alerts}")


if __name__ == "__main__":
    main()