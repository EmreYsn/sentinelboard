# SentinelBoard — Architecture Document

## Overview

SentinelBoard is a lightweight, open-source SIEM platform designed for
single-server or small-infrastructure deployments. It combines rule-based
detection with ML-powered anomaly detection.

## Design Principles

### 1. Modular & Decoupled
Her katman bağımsız çalışır. Collector Redis'e yazar, Parser Redis'ten
okur — birbirlerini doğrudan çağırmazlar. Bu sayede:
- Bir katman çökerse diğerleri çalışmaya devam eder
- Her katmanı bağımsız test edebilirsin
- İstersen collector'ı başka bir makineye taşıyabilirsin

### 2. Configuration over Code
Davranış değişiklikleri kod değiştirmeden yapılabilir. Yeni bir log
kaynağı eklemek = config'e bir entry eklemek. Yeni bir kural eklemek =
rules/ klasörüne bir YAML dosyası koymak.

### 3. Defense in Depth
İki tespit mekanizması paralel çalışır:
- Rule-based: bilinen tehditleri kesin yakalar
- ML-based: bilinmeyen tehditleri probability ile yakalar

---

## Technology Decisions

### PostgreSQL vs Elasticsearch
| Kriter          | PostgreSQL    | Elasticsearch  |
|-----------------|---------------|----------------|
| Setup zorluğu   | Düşük         | Yüksek (JVM)   |
| RAM kullanımı    | ~50MB idle    | ~1GB idle      |
| JSON desteği     | jsonb — iyi   | Native — mükemmel |
| Full-text search | tsvector      | Native          |
| Bilgi düzeyi     | Yüksek (Django) | Yeni öğrenilmesi gerek |

**Karar: PostgreSQL.** Tek sunucu deployment'ı için ES overkill.
PostgreSQL'in jsonb tipi ve GIN indexleri yeterli performans sağlar.
İleride ES'e geçiş yapılabilir — parser output formatı değişmeyeceği
için migration kolay olur.

### Redis Streams vs RabbitMQ vs Kafka
| Kriter         | Redis Streams | RabbitMQ       | Kafka          |
|----------------|---------------|----------------|----------------|
| Kurulum        | Zaten var     | Ayrı servis    | Ayrı cluster   |
| Overhead       | Çok düşük     | Orta           | Yüksek         |
| Persistence    | Opsiyonel     | Evet           | Evet           |
| Consumer groups| Evet          | Evet           | Evet           |
| Use case fit   | Mükemmel      | İyi            | Overkill       |

**Karar: Redis Streams.** Django Channels için zaten Redis kullanıyoruz.
İkinci bir message broker kurmak gereksiz karmaşıklık. Redis Streams
consumer group desteği ile birden fazla parser worker çalıştırabiliyoruz.

### Sigma vs Custom Rule Format
**Karar: Sigma-compatible.** Sektör standardı. Binlerce hazır kural var.
Kendi formatımızı yazmak daha kolay olurdu ama Sigma desteği projeye
büyük değer katıyor — topluluktan kural import edebilmek = instant value.

---

## Data Flow

```
[Log File] → (tail) → [Collector] → (XADD) → [Redis Stream]
                                                     │
                                              (XREADGROUP)
                                                     │
                                                     ▼
                                               [Parser]
                                                     │
                                              (INSERT)
                                                     │
                                      ┌──────────────┼──────────────┐
                                      ▼              ▼              ▼
                                 [PostgreSQL]   [Correlator]   [ML Module]
                                      │              │              │
                                      └──────────────┴──────┬───────┘
                                                            ▼
                                                    [Alert Manager]
                                                      │        │
                                                      ▼        ▼
                                                [Dashboard] [Telegram]
```

## Normalized Log Schema

```json
{
  "id": "uuid-v4",
  "timestamp": "2026-06-09T14:23:01.000Z",
  "collected_at": "2026-06-09T14:23:01.500Z",
  "source": "auth",
  "event_type": "auth_failure",
  "severity": "medium",
  "host": "vps",
  "src_ip": "192.168.1.100",
  "dst_ip": null,
  "src_port": null,
  "dst_port": 22,
  "user": "root",
  "process": "sshd",
  "pid": 12345,
  "message": "Failed password for root from 192.168.1.100 port 22 ssh2",
  "raw": "Jun  9 14:23:01 vps sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
  "tags": ["ssh", "brute_force"],
  "extra": {}
}
```

## Alert Lifecycle

1. **Detection** — Rule match veya ML anomaly score > threshold
2. **Deduplication** — Aynı kural+IP için cooldown kontrolü
3. **Enrichment** — GeoIP lookup, hostname resolution (future)
4. **Notification** — Severity'ye göre kanal seçimi
5. **Storage** — Alert DB'ye kaydet (dashboard için)
6. **Acknowledgement** — Kullanıcı dashboard'dan acknowledge eder

## Future Improvements

- [ ] GeoIP integration (IP → country/city mapping)
- [ ] MITRE ATT&CK dashboard mapping
- [ ] Multi-node collector support
- [ ] Elasticsearch backend option
- [ ] Automated response (IP ban, firewall rule)
- [ ] Threat intelligence feed integration (with ThreatLens!)
