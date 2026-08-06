"""
worker.py — Redis'ten ham logları çeker, PostgreSQL'e yazar

Bu dosya ne yapıyor?
    Collector'lar logları Redis Stream'e bastı.
    Bu worker o stream'den logları çeker (consume eder),
    Django ORM ile Event modeline yazar.

Redis Streams Consumer Group nedir?
    Birden fazla worker aynı stream'den okuyabilir.
    Consumer group sayesinde her mesaj sadece BİR worker'a gider.
    Yani 3 worker çalıştırırsan, iş yükü otomatik bölünür.
    
    Ayrıca "acknowledgement" mekanizması var:
    Worker mesajı aldığında XACK gönderir → "bu mesajı aldım, işledim"
    Worker çökerse → mesaj başka worker'a teslim edilir
    Bu sayede mesaj kaybı olmaz.

Nasıl çalıştırılır?
    cd sentinelboard
    python -m parser.worker
"""

import os
import sys
import json
import signal
import logging
import time
from datetime import datetime, timezone

import django
import redis as redis_lib
from dotenv import load_dotenv

# ── Django Setup ──────────────────────────────────────────────
# Django'yu standalone script'ten kullanabilmek için bu setup şart.
# Normalde Django manage.py üzerinden çalışır ama biz worker'ı
# ayrı bir process olarak çalıştırıyoruz.
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "dashboard"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

load_dotenv(os.path.join(project_root, ".env"))
django.setup()

# Django setup'tan SONRA import ediyoruz — sıralama önemli!
from events.models import Event

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelboard.parser.worker")

# ── Sabitler ──────────────────────────────────────────────────
STREAM_KEY = "sentinelboard:raw_logs"
GROUP_NAME = "parser_workers"
CONSUMER_NAME = f"worker-{os.getpid()}"  # Her process benzersiz isim alır
BATCH_SIZE = 50  # Her seferde kaç mesaj çek

# ── Event tipine göre extra field'lar ─────────────────────────
# Event modeline her field için sütun açmadık. event_type'a özel
# field'lar (user_agent, auth_method, command vs.) extra JSON'a gider.
CORE_FIELDS = {
    "timestamp", "collected_at", "source", "host", "event_type",
    "severity", "src_ip", "dst_ip", "src_port", "dst_port",
    "user", "process", "pid", "message", "raw",
}


def ensure_consumer_group(r: redis_lib.Redis):
    """
    Consumer group yoksa oluşturur.

    MKSTREAM=True → stream yoksa onu da oluşturur.
    "0" → stream'in en başından oku (mevcut mesajları da al).
    "$" → sadece yeni mesajları al (eskiler atlanır).
    Biz "0" kullanıyoruz çünkü worker yeniden başladığında
    kaçırılmış mesajları da işlesin istiyoruz.
    """
    try:
        r.xgroup_create(STREAM_KEY, GROUP_NAME, id="0", mkstream=True)
        logger.info(f"Consumer group '{GROUP_NAME}' created")
    except redis_lib.ResponseError as e:
        if "BUSYGROUP" in str(e):
            # Grup zaten var — sorun değil
            pass
        else:
            raise


def parse_event_data(raw_data: dict) -> dict | None:
    """
    Redis'ten gelen ham veriyi Event modeline uygun dict'e çevirir.

    Redis'ten gelen format (collector'ın gönderdiği):
        {
            "source": "auth",
            "collected_at": "2026-06-09T14:23:01.500Z",
            "data": '{"timestamp": "...", "event_type": "...", ...}'  ← JSON string
        }

    Çıktı: Event.objects.create(**output) ile DB'ye yazılabilecek dict
    """
    try:
        # "data" field'ı JSON string olarak geliyor, parse et
        data = json.loads(raw_data.get("data", "{}"))

        # Timestamp'i datetime objesine çevir
        # Django DateTimeField string kabul etmez, datetime ister
        timestamp_str = data.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        collected_str = raw_data.get("collected_at", "")
        try:
            collected_at = datetime.fromisoformat(collected_str)
        except (ValueError, TypeError):
            collected_at = None

        # Core field'ları ayır, gerisini extra'ya koy
        event_dict = {
            "timestamp": timestamp,
            "collected_at": collected_at,
            "source": raw_data.get("source", "unknown"),
            "host": data.get("host", "unknown"),
            "event_type": data.get("event_type", "unknown"),
            "severity": data.get("severity", "info"),
            "src_ip": data.get("src_ip"),
            "dst_ip": data.get("dst_ip"),
            "src_port": data.get("src_port"),
            "dst_port": data.get("dst_port"),
            "user": data.get("user"),
            "process": data.get("process"),
            "pid": data.get("pid"),
            "message": data.get("message", ""),
            "raw": data.get("raw", ""),
        }

        # Core'da olmayan field'ları extra JSON'a topla
        extra = {k: v for k, v in data.items() if k not in CORE_FIELDS and v is not None}
        event_dict["extra"] = extra

        return event_dict

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.error(f"Failed to parse event data: {e}")
        return None


def process_messages(r: redis_lib.Redis):
    """
    Redis Stream'den mesajları çeker ve DB'ye yazar.

    XREADGROUP ne yapar?
        Consumer group üzerinden mesaj okur.
        ">" = henüz hiçbir consumer'a teslim edilmemiş mesajlar
        count = en fazla kaç mesaj getir
        block = mesaj yoksa kaç ms bekle (0 = sonsuza kadar)
              biz 2000ms = 2 saniye bekliyoruz, sonra döngü tekrar döner
              bu sayede shutdown sinyalini kontrol edebiliyoruz

    Neden bulk_create kullanıyoruz?
        50 mesajı tek tek INSERT yapmak = 50 DB round-trip
        bulk_create ile hepsini TEK seferde INSERT = 1 DB round-trip
        Bu 50x performans farkı demek.
    """
    results = r.xreadgroup(
        GROUP_NAME, CONSUMER_NAME,
        {STREAM_KEY: ">"},
        count=BATCH_SIZE,
        block=2000,  # 2 saniye bekle
    )

    if not results:
        return 0  # Yeni mesaj yok

    events_to_create = []
    message_ids = []

    for stream_name, messages in results:
        for msg_id, msg_data in messages:
            event_dict = parse_event_data(msg_data)
            if event_dict:
                events_to_create.append(Event(**event_dict))
                message_ids.append(msg_id)
            else:
                # Parse edilemeyen mesajı da acknowledge et
                # yoksa sürekli tekrar denenir (poison message)
                message_ids.append(msg_id)

    # Toplu DB yazma
    if events_to_create:
        try:
            Event.objects.bulk_create(events_to_create)
            logger.info(f"Wrote {len(events_to_create)} events to database")
        except Exception as e:
            logger.error(f"DB write failed: {e}")
            return 0

    # Mesajları acknowledge et → "bu mesajları aldım, işledim"
    if message_ids:
        r.xack(STREAM_KEY, GROUP_NAME, *message_ids)

    return len(events_to_create)


def main():
    logger.info("=" * 60)
    logger.info("SentinelBoard Parser Worker starting...")
    logger.info("=" * 60)

    r = redis_lib.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        db=int(os.getenv("REDIS_DB", 0)),
        decode_responses=True,
    )

    try:
        r.ping()
        logger.info("Redis connection OK")
    except redis_lib.ConnectionError:
        logger.error("Cannot connect to Redis")
        sys.exit(1)

    ensure_consumer_group(r)

    # Graceful shutdown
    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        shutdown = True
        logger.info("Shutdown signal received...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Ana döngü
    total_processed = 0
    while not shutdown:
        try:
            count = process_messages(r)
            total_processed += count
        except Exception as e:
            logger.error(f"Processing error: {e}")
            time.sleep(5)  # Hata sonrası 5 saniye bekle

    r.close()
    logger.info(f"Worker stopped. Total events processed: {total_processed}")


if __name__ == "__main__":
    main()