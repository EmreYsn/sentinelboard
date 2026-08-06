"""
SentinelBoard — Log Collector Module

Bu modül log kaynaklarını izler ve yeni satırları Redis kuyruğuna gönderir.

Nasıl çalışır:
1. config/settings.yaml'dan izlenecek log dosyalarını okur
2. Her dosya için bir "watcher" thread başlatır (watchdog kütüphanesi)
3. Yeni satır geldiğinde, ham satırı + metadata'yı (kaynak, timestamp) JSON olarak paketler
4. Redis Stream'e XADD komutuyla gönderir

Neden doğrudan DB'ye yazmıyoruz:
- Log kaynakları çok hızlı üretebilir (saniyede binlerce satır)
- DB yazma işlemi yavaştır (disk I/O, index güncelleme)
- Redis bellek üzerinde çalışır, çok hızlıdır
- Bu "producer-consumer" pattern sayesinde collector ve parser
  birbirinden bağımsız hızda çalışır
"""
