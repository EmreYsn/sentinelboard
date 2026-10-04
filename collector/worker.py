"""
worker.py — Collector ana süreci

Ne yapıyor?
    config/settings.yaml'daki her log kaynağı için uygun collector'ı
    kurar, dosyaları saniyede bir yoklar, yeni satırları ayrıştırıp
    Redis Stream'e basar. Zincirin ilk halkası:

        [collector] → Redis Stream → [parser] → DB → [engine] + [ml]

Çalıştırma:
    python -m collector.worker                    # normal mod (Redis'e yazar)
    python -m collector.worker --dry-run          # Redis yok, ekrana yazar
    python -m collector.worker --from-start       # dosyaları baştan oku
    python -m collector.worker --config other.yaml

--dry-run neden var?
    Redis kurulu olmayan bir makinede (ör. geliştirme yaparken)
    ayrıştırma mantığını test edebilmek için. Gerçek Redis yerine
    ekrana basan sahte bir client veriyoruz. BaseCollector zaten
    redis_client'ı dışarıdan aldığı için tek satır değişiyor —
    dependency injection'ın somut faydası.
"""

import os
import sys
import json
import time
import signal
import logging
import argparse

import yaml
from dotenv import load_dotenv

# Proje kökünü import yoluna ekle ki "collector.x" çalışsın
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from collector.tailer import FileTailer          # noqa: E402
from collector.auth import AuthCollector         # noqa: E402
from collector.nginx import NginxCollector       # noqa: E402
from collector.syslog import SyslogCollector     # noqa: E402

load_dotenv(os.path.join(BASE_DIR, ".env"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelboard.collector.worker")

DEFAULT_CONFIG = os.path.join(BASE_DIR, "config", "settings.yaml")
POLL_INTERVAL = 1.0  # saniye — dosyaları ne sıklıkta yoklayalım
STATS_INTERVAL = 300   # Kaç saniyede bir özet logu yazılsın

# config'teki "type" değeri → hangi collector sınıfı
COLLECTOR_TYPES = {
    "syslog": None,          # aşağıda isme göre auth/syslog ayrımı yapılıyor
    "nginx_combined": NginxCollector,
    "nginx_error": NginxCollector,
}


class DryRunRedis:
    """
    Redis yerine geçen sahte client — gelen kaydı ekrana yazar.

    Gerçek Redis client'ın sadece xadd metodunu taklit ediyor,
    çünkü BaseCollector.emit() yalnızca onu çağırıyor.
    """

    def __init__(self):
        self.count = 0

    def xadd(self, stream_key: str, envelope: dict):
        self.count += 1
        data = json.loads(envelope["data"])
        print(
            f"[{self.count:3d}] {envelope['source']:12s} "
            f"{data.get('event_type', '?'):18s} "
            f"src={data.get('src_ip') or '-':15s} "
            f"user={data.get('user') or '-':12s} "
            f"{data.get('message', '')[:60]}"
        )
        return f"dry-{self.count}"


def build_collector(source_cfg: dict, redis_client):
    """
    Kaynak ayarına bakıp doğru collector sınıfını seçer.

    auth.log ile syslog aynı formatta ama farklı içerik taşır:
    auth.log'da sshd/sudo olayları, syslog'da firewall/servis
    olayları var. O yüzden tip "syslog" olduğunda kaynağın adına
    bakıp ayrım yapıyoruz.
    """
    src_type = source_cfg.get("type", "syslog")
    name = source_cfg.get("name", "")

    if src_type == "syslog":
        cls = AuthCollector if "auth" in name else SyslogCollector
    else:
        cls = COLLECTOR_TYPES.get(src_type)

    if cls is None:
        logger.warning(f"Unknown source type '{src_type}' for '{name}', skipping")
        return None

    return cls(source_cfg, redis_client=redis_client)


def load_sources(config_path: str, allow_env_override: bool = True) -> list[dict]:
    """settings.yaml'dan etkin log kaynaklarını okur."""
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_path}")
        return []

    sources = (cfg.get("collector") or {}).get("sources") or []
    enabled = [s for s in sources if s.get("enabled", True)]

    # .env'deki LOG_SOURCES varsa yaml'daki yolları ezer.
    # Böylece sunucuda kodu değiştirmeden yol değiştirilebilir.
    override = os.getenv("LOG_SOURCES", "").strip() if allow_env_override else ""
    if not allow_env_override:
        logger.info("Explicit --config given, LOG_SOURCES override disabled")
    if override:
        paths = [p.strip() for p in override.split(",") if p.strip()]
        if len(paths) == len(enabled):
            for src, path in zip(enabled, paths):
                src["path"] = path
            logger.info("Log paths overridden from LOG_SOURCES")
        else:
            logger.warning(
                f"LOG_SOURCES has {len(paths)} paths but config has "
                f"{len(enabled)} enabled sources — ignoring override"
            )

    return enabled


def connect_redis():
    """Gerçek Redis bağlantısını kurar."""
    import redis as redis_lib

    host = os.getenv("REDIS_HOST", "localhost")
    port = int(os.getenv("REDIS_PORT", 6379))
    db = int(os.getenv("REDIS_DB", 0))

    client = redis_lib.Redis(host=host, port=port, db=db, decode_responses=True)
    client.ping()  # bağlantı kurulamazsa burada patlar — erken hata iyidir
    logger.info(f"Connected to Redis at {host}:{port}/{db}")
    return client


def main():
    ap = argparse.ArgumentParser(description="SentinelBoard log collector")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="settings.yaml yolu")
    ap.add_argument("--dry-run", action="store_true",
                    help="Redis'e yazma, ekrana bas (test için)")
    ap.add_argument("--from-start", action="store_true",
                    help="Dosyaları sonundan değil başından oku")
    ap.add_argument("--once", action="store_true",
                    help="Tek tur oku ve çık (test için)")
    args = ap.parse_args()

    # Kullanıcı açıkça bir config verdiyse, oradaki yollar geçerlidir.
    # .env'deki LOG_SOURCES yalnızca varsayılan config'i ezebilir.
    sources = load_sources(args.config, allow_env_override=(args.config == DEFAULT_CONFIG))
    if not sources:
        logger.error("No enabled log sources found in config")
        return 1

    # Redis bağlantısı (veya sahtesi)
    if args.dry_run:
        redis_client = DryRunRedis()
        logger.info("DRY-RUN mode: parsed events will be printed, not sent to Redis")
    else:
        try:
            redis_client = connect_redis()
        except Exception as e:
            logger.error(f"Cannot connect to Redis: {e}")
            logger.error("Redis çalışmıyor olabilir. Test için --dry-run kullanın.")
            return 1

    # Her kaynak için collector + tailer çifti kur
    watchers = []
    for src in sources:
        collector = build_collector(src, redis_client)
        if collector is None:
            continue
        tailer = FileTailer(src["path"], from_start=args.from_start or args.once)
        collector.start()
        watchers.append((collector, tailer))

    if not watchers:
        logger.error("No collectors could be started")
        return 1

    # Ctrl+C ve systemd stop sinyallerini düzgün karşıla
    running = {"value": True}

    def handle_signal(signum, frame):
        logger.info("Shutdown signal received, stopping collectors...")
        running["value"] = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    logger.info(f"Collector started with {len(watchers)} source(s)")

    total = 0
    last_stats = time.time()
    try:
        while running["value"]:
            for collector, tailer in watchers:
                for line in tailer.read_new_lines():
                    if collector.should_ignore(line):
                        continue
                    parsed = collector.parse_line(line)
                    if parsed:
                        collector.emit(parsed)
                        total += 1

            if args.once:
                break

            # Periyodik özet: kaç olay geçti, kaçı elendi.
            # Sessizce veri düşüren bir collector tehlikelidir —
            # filtrenin fazla geniş kaldığını buradan fark edersin.
            if time.time() - last_stats >= STATS_INTERVAL:
                ignored = {
                    c.get_source_name(): c.ignored_count
                    for c, _ in watchers if c.ignored_count
                }
                logger.info(f"Emitted: {total}, filtered: {ignored or 'none'}")
                last_stats = time.time()

            time.sleep(POLL_INTERVAL)
    finally:
        for collector, tailer in watchers:
            collector.stop()
            tailer.close()
        logger.info(f"Collector stopped. Total events emitted: {total}")

    return 0


if __name__ == "__main__":
    sys.exit(main())