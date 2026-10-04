"""
Base Collector — Tüm log collector'ların türediği temel sınıf.

"Abstract Base Class" (ABC) kullanıyoruz. Bu ne demek?
- BaseCollector'ı doğrudan kullanamazsın
- Ondan türeyen her sınıf (AuthCollector, NginxCollector vs.)
  belirli metodları ZORUNLU olarak implement etmek zorunda
- Bu sayede her collector aynı interface'e sahip olur
  ve sistem hepsini aynı şekilde yönetebilir

Örnek akış:
  collector = AuthCollector(config)
  collector.start()   → dosyayı izlemeye başlar
  # yeni satır gelir → parse_line() çağrılır
  # parse_line() ham satırı → dict'e çevirir
  # dict Redis'e gönderilir
  collector.stop()    → izlemeyi durdurur
"""

import re
import abc
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentinelboard.collector")


class BaseCollector(abc.ABC):
    """
    Tüm log collector'ların implement etmesi gereken temel yapı.

    Her alt sınıf şu iki metodu tanımlamak ZORUNDA:
    - parse_line(line): Ham log satırını dict'e çevirir
    - get_source_name(): Bu collector'ın adını döner (ör: "auth", "nginx")
    """

    def __init__(self, config: dict, redis_client=None):
        """
        Args:
            config: settings.yaml'dan gelen bu kaynağa ait ayarlar
            redis_client: Redis bağlantısı (dependency injection)

        Dependency Injection nedir?
            Redis client'ı dışarıdan alıyoruz, içeride oluşturmuyoruz.
            Bu sayede test yazarken gerçek Redis yerine sahte (mock) bir
            client verebiliriz. Test edilebilirlik için çok önemli.
        """
        self.config = config
        self.redis = redis_client
        self.running = False
        self.stream_key = "sentinelboard:raw_logs"  # Redis stream adı
        self._ignore_patterns = [re.compile(p) for p in (config.get("ignore") or [])]
        self.ignored_count = 0

    def should_ignore(self, line: str) -> bool:
        """
        Satır yapılandırmadaki eleme desenlerinden birine uyuyor mu?

        Neden ham satıra bakıyoruz, parse edilmiş olaya değil?
            Elenecek satır için parse maliyetini hiç ödememek
            istiyoruz. Saniyede binlerce satırda fark ediyor.

        Neden sayaç tutuyoruz?
            Sessizce veri düşüren bir SIEM tehlikelidir. Ne kadar
            satırın elendiği görünür olmalı ki filtre fazla geniş
            kaldığında fark edebilesin.
        """
        if not self._ignore_patterns:
            return False
        if any(p.search(line) for p in self._ignore_patterns):
            self.ignored_count += 1
            return True
        return False

    @abc.abstractmethod
    def parse_line(self, line: str) -> dict | None:
        """
        Ham log satırını yapılandırılmış bir dict'e çevirir.

        Args:
            line: Ham log satırı, örn:
                  "Jun  9 14:23:01 vps sshd[12345]: Failed password for root..."

        Returns:
            dict: Yapılandırılmış log verisi, örn:
                  {"timestamp": "...", "source": "sshd", "message": "..."}
            None: Satır parse edilemezse (bozuk satır, boş satır vs.)

        Her alt sınıf kendi log formatına göre implement eder.
        """
        ...

    @abc.abstractmethod
    def get_source_name(self) -> str:
        """Bu collector'ın kaynak adını döner (ör: 'auth', 'nginx')."""
        ...

    def emit(self, parsed: dict) -> None:
        """
        Parse edilmiş log kaydını Redis Stream'e gönderir.

        Redis Streams nedir?
            Redis'in append-only log yapısı. Kafka'ya benzer ama çok
            daha hafif. XADD komutuyla mesaj eklenir, XREAD ile okunur.
            Her mesajın otomatik bir ID'si olur (timestamp-sequence).

        Neden dict'i JSON string'e çeviriyoruz?
            Redis Streams field-value çiftleri kabul eder ama
            iç içe dict desteklemez. JSON string olarak gönderip
            parser tarafında tekrar dict'e çeviriyoruz.
        """
        if self.redis is None:
            logger.warning("Redis client not connected, dropping log entry")
            return

        # Metadata ekle: hangi collector gönderdi, ne zaman gönderdi
        envelope = {
            "source": self.get_source_name(),
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(parsed, ensure_ascii=False),
        }

        try:
            self.redis.xadd(self.stream_key, envelope)
        except Exception as e:
            logger.error(f"Failed to emit log to Redis: {e}")

    def start(self):
        """Collector'ı başlat — alt sınıflar override edebilir."""
        self.running = True
        logger.info(f"Collector [{self.get_source_name()}] started")

    def stop(self):
        """Collector'ı durdur."""
        self.running = False
        logger.info(f"Collector [{self.get_source_name()}] stopped")
