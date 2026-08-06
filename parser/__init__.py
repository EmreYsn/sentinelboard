"""
SentinelBoard — Parser & Normalization Module

Bu modül Redis'ten ham logları çeker ve normalleştirilmiş formata dönüştürür.

Normalizasyon neden gerekli?
    auth.log şöyle yazar:   "Jun  9 14:23:01 vps sshd[12345]: Failed password..."
    nginx şöyle yazar:      '192.168.1.1 - - [09/Jun/2026:14:23:01] "GET /api..."'
    syslog şöyle yazar:     "Jun  9 14:23:01 vps kernel: [UFW BLOCK]..."

    Her biri farklı format, farklı tarih yazımı, farklı field'lar.
    Korelasyon motoru bunları karşılaştırabilmesi için HEPSİNİN
    aynı formatta olması lazım.

Normalleştirilmiş format (ECS-inspired):
    {
        "timestamp": "2026-06-09T14:23:01Z",   # ISO 8601, UTC
        "source": "auth",                       # Hangi collector'dan geldi
        "event_type": "auth_failure",           # Olay kategorisi
        "severity": "medium",                   # info/low/medium/high/critical
        "host": "vps",                          # Kaynak makine
        "src_ip": "192.168.1.100",             # Varsa kaynak IP
        "user": "root",                         # Varsa kullanıcı
        "process": "sshd",                      # Varsa process adı
        "message": "Failed password for root",  # Okunabilir mesaj
        "raw": "Jun  9 14:23:01 vps sshd..."   # Orijinal ham satır
    }

ECS nedir?
    Elastic Common Schema — Elasticsearch'ün log normalizasyon standardı.
    Biz birebir ECS kullanmıyoruz ama benzer bir yaklaşım izliyoruz.
    Bu field isimlerini tanıyan insanlar sektörde çok fazla.
"""
