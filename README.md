# SentinelBoard

Sıfırdan yazılmış, tek bir Linux sunucusunda üretimde çalışan hafif bir SIEM.
`auth.log`, nginx ve syslog/UFW loglarını toplar, hepsini ortak bir olay
şemasına normalleştirir, Sigma biçimindeki kurallarla korele eder ve bunun
üzerine istatistiksel/ML tabanlı ikinci bir tespit katmanı çalıştırır.

Canlı adres: **siem.ysnemre.com** (HTTP Basic Auth arkasında, dışarıya açık
değil).

~6.800 satır Python · 103 otomatik test · 6 tespit kuralı · beş bağımsız
systemd servisi.

---

## Neden böyle göründüğü

Bu proje bir şartnameye göre yazılmadı. Gerçek, internete açık tek bir sunucuya
karşı yazıldı ve o sunucu bir tasarımın yanlış olduğunu her gösterdiğinde
değişti. Aşağıdakilerin çoğu, önce bir şey bozulduğu için var —
[üretimden çıkan kararlar](#üretimden-çıkan-mühendislik-kararları) bölümü bu
bozulmaları saklamak yerine kaydediyor, çünkü okunmaya değer kısım orası.

---

## Mimari

```
/var/log/auth.log        /var/log/nginx/access.log        /var/log/syslog
        │                          │                            │
        └──────────────┬───────────┴────────────────────────────┘
                       ▼
              ┌──────────────────┐
              │    collector     │  inode tabanlı takip, logrotate'i atlatır
              └────────┬─────────┘  kaynak başına yok sayma desenleri
                       ▼
              ┌──────────────────┐
              │  Redis Streams   │  toplamayı işlemeden ayırır
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │      parser      │  ham satır → ortak olay şeması
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │  SQLite (Django) │
              └───┬───────────┬──┘
                  │           │
        ┌─────────▼──┐   ┌────▼───────────┐
        │   engine   │   │       ml       │
        │ Sigma kur. │   │ Z-score +      │
        │ MITRE etik.│   │ Isolation For. │
        └─────────┬──┘   └────┬───────────┘
                  │           │
                  └─────┬─────┘
                        ▼
        ┌───────────────────────────────┐
        │  Django + DRF + React panel   │
        │  Telegram uyarıları · LLM     │
        └───────────────────────────────┘
```

Her kutu ayrı bir systemd servisi. Aralarında yalnızca veritabanını ve Redis
akışını paylaşırlar; biri çökünce diğerleri ayakta kalır.

---

## Tespit katmanları

### Kural tabanlı (Sigma biçimi)

Kurallar YAML, çalışma anında yükleniyor ve MITRE ATT&CK tekniklerine
eşleniyor.

| ID | Kural | Seviye | Teknik |
|---|---|---|---|
| sentinel-001 | SSH Brute Force Detection | high | T1110 |
| sentinel-002 | Web Application Scanning Detected | high | T1595 |
| sentinel-003 | Firewall Block Flood (Possible Port Scan) | medium | T1046 |
| sentinel-004 | Suspicious Sudo Activity | high | T1548 |
| sentinel-005 | New User Account Created | critical | T1136.001 |
| sentinel-006 | Failed Sudo Attempt | high | T1548.003 |

```yaml
title: Failed Sudo Attempt
id: sentinel-006
level: high
detection:
  selection:
    event_type: sudo_failure
  condition: selection | count(user) > 0
  timeframe: 1h
response:
  alert: true
  cooldown: 1h
```

### Anomali tabanlı

10 dakikalık pencereler üzerinden 11 boyutlu öznitelik vektörü çıkarılıyor:
toplam olay, benzersiz kaynak IP ve hedef port sayısı, kimlik doğrulama
başarı/başarısızlıkları ve oranı, şüpheli istekler, HTTP 4xx sayısı, firewall
blokları, olay tipi çeşitliliği ve sudo hacmi. Her pencereyi iki yöntem
puanlıyor:

* **Z-score** — kayan bir taban çizgisine göre sapma
* **Isolation Forest** (scikit-learn)

Bir pencere yalnızca **iki yöntem de aynı yönde işaret verdiğinde** ve mutlak
sapma bir tabanı geçtiğinde raporlanıyor. Gerekçesi ve ölçümleri aşağıda.

---

## LLM katmanı

Uyarı analizi, tek olay açıklaması ve saklanan olaylar üzerinde RAG tabanlı
doğal dil sorgu arayüzü.

Sağlayıcı yapılandırılabilir: OpenAI uyumlu `/chat/completions` uç noktası
sunan her şey çalışır. Varsayılan Groq; `LLM_BASE_URL`'i yerel bir Ollama
örneğine çevirmek için kod değişikliği de API anahtarı da gerekmiyor.

```bash
LLM_BASE_URL=http://127.0.0.1:11434/v1   # yerel model
LLM_MODEL=qwen2.5:7b
```

**Sağlayıcıya gönderilen veri önce minimize ediliyor.** Ham log satırları hiç
gönderilmiyor. IP adresleri ve kullanıcı adları tutarlı takma adlarla
değiştiriliyor (`IP_1`, `USER_1`), komut argümanları ve dosya yolları
ayıklanıyor, sistem hesapları (`root`, `www-data`) olduğu gibi bırakılıyor —
analitik anlam taşıyorlar ve kimseyi tanımlamıyorlar. Sunucudan çıkan şey
pratikte bir kural adı, bir sayı ve bir MITRE etiketinden ibaret.

Dürüst boşluk şu: chatbot'a yazılan sorunun kendisi temizlenmiyor, çünkü onu
kullanıcı yazıyor. Bu sınır üstü örtülmek yerine kodda işaretli.

---

## Üretimden çıkan mühendislik kararları

**Sistem kendi loglarıyla besleniyordu.** Syslog'a yazılan her uyarı,
collector üzerinden yeni bir olay olarak geri geliyordu — yaz, logla, oku, yaz.
Çözüm `config/settings.yaml` içindeki kaynak başına yok sayma listesi; aynı
liste saniyede bir POST atıp ML taban çizgisini şişiren bir CasaOS sağlık
kontrolünü de eliyor.

**Bir kural tasarlandı, ölçüldü ve çöpe atıldı.** Yavaş kaba kuvvet kuralı
(düşük istek hızı, yüksek ısrar) açıkça doğru görünüyordu. 31 günlük gerçek
trafiğe karşı ölçülünce değildi: 3.549 farklı kaynak IP, bunların 972'si üç
veya daha fazla günde, 46'sı 25 veya daha fazla günde görülüyor. Yavaş
tarayıcıyı yakalayan her eşik günde 171'den fazla uyarı üretiyordu. İnternete
açık bir sunucuda başarısız SSH girişleri fon gürültüsüdür. Kural atıldı ve
emek erişim sonrası tespitlere kaydı — `sentinel-005` ve `sentinel-006` o
ölçüm yüzünden var.

**Cooldown yanlış sütuna bakıyordu.** Sorgu `src_ip` sütununu okuyordu, oysa
kullanıcıya göre gruplanan uyarılarda o sütun `NULL`. Cooldown bu uyarılar için
hiç devreye girmedi ve motor aynı uyarıyı her 10 saniyede bir yeniden üretti;
Telegram'a dokuz kopya düştü. Uyarılar artık açık bir `group_value` taşıyor ve
bir test davranışı kilitliyor. Tip uyuşmazlığını SQLite sessizce yuttu,
PostgreSQL hata verirdi.

**Bir kural var olmayan bir alanı sorguluyordu.** `extra__http_status` yerine
`extra__status_code` — aylarca hiçbir şeyle eşleşmeyen ve hiçbir testi
düşürmeyen bir filtre, çünkü sıfır satır dönen bir sorgu hata değildir. Artık
kaynak kodu `ast` ile ayrıştırıp bir kuralın referans verdiği her alanın
parser'ın gerçekten ürettiği bir alan olduğunu doğrulayan bir sözleşme testi
var.

**ML katmanı sezgiyle değil ölçümle ayarlandı.** Önce Z-score eşiğini
yükseltmek denendi ve ölçülerek işe yaramadığı görüldü: z > 5'te 74 uyarının
37'si hayatta kalıyordu. Isolation Forest, Z-score ile yalnızca 74 vakanın
24'ünde hemfikirdi. Aday politikalar saklanan uyarılar üzerinde simüle edildi:
uzlaşma şartı → 20, uzlaşma artı mutlak sapma tabanı → 13. İkincisi yayına
alındı.

**Başarısız bir istek, karşılığında hiçbir şey vermeden API kotası yaktı.**
Gunicorn'un worker timeout'u LLM çağrısından kısaydı; worker cevap üretilirken
öldürüldü, kullanıcı 502 gördü ve tekrar denedi — ama her sessiz başarısızlık o
ana kadar üretilen token'ları çoktan harcamıştı. Üç deneme, dakikalık 1.000
token'lık bütçeyi bitirdi.

Düzeltme sıralamadır ve ilk tahminden bir katman daha derindir: istek iç içe
geçmiş **üç** zaman aşımından geçiyor — HTTP istemcisi, uygulama sunucusu ve
önündeki ters vekil. **Ters piramit kuralı: en içteki en kısa olmalı, dışa
doğru her katman daha uzun.** Bu sıra bozulduğunda hata, kendi hata
yönetimimize ulaşamadan dışarıdan kesilir ve kullanıcı anlamsız bir 502 ya da
504 görür.

| Katman | Süre |
|---|---|
| `requests` (uygulama kodu) | 60 sn |
| Gunicorn `--timeout` | 120 sn |
| nginx `proxy_read_timeout` | 180 sn |

Üçüncü katman ilk düzeltmede atlanmıştı: nginx'in varsayılan
`proxy_read_timeout` değeri 60 saniyedir, yani uygulama koduyla tam olarak aynı
anda yarışıyordu. Sonuç 504'tü — ve o 504'ü sistemin kendi olay akışında
görerek bulduk. Kural, yönettiği kodun yanında `alerts/llm_client.py` içinde
yazılı.

**Üretilen analizler saklanıyor.** Öncesinde bir uyarıyı yeniden açmak aynı
metni tam maliyetle yeniden ürettiriyordu. Panel artık hangi uyarının kayıtlı
analizi olduğunu gösteriyor ve yeniden üretmek ayrı, bilinçli bir eylem.

---

## Test yaklaşımı

103 test, `pytest` ile çalışıyor. Üç türü var:

* **Davranış** — korelasyon, cooldown, saklama süresi, ML puanlama
* **Sözleşme** — "şu veri şu sınırı geçmez": LLM'e hiçbir ham log satırı
  ulaşmaz, hiçbir kural parser'ın üretmediği bir alana referans vermez
* **Değişmez kontrolleri** — örneğin bir kuralın `cooldown` süresi
  `timeframe` süresinden kısa olamaz; ilk örneği düzeltildikten hemen sonra
  aynı hatanın ikinci, daha eski bir örneği bu testle bulundu

Bu depodaki her düzeltme **yanlışlama** ile doğrulandı: düzeltmeyi geri al,
testin kırmızıya düştüğünü gör, sonra geri koy. Hiç kırmızı görülmemiş bir test
hiçbir şey kanıtlamaz.

---

## Çalıştırma

Python 3.12+ ve Redis gerekiyor.

```bash
git clone https://github.com/EmreYsn/sentinelboard.git
cd sentinelboard

python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # Telegram token ve LLM anahtarını doldur
docker compose up -d          # sadece Redis; veritabanı SQLite

cd dashboard && python manage.py migrate && cd ..
```

Sonra dört worker ve web uygulaması. Her biri ayrı bir süreç; üretimde her biri
ayrı bir systemd birimi:

```bash
python -m collector.worker     # log dosyalarını takip et → Redis
python -m parser.worker        # Redis → normalleştirilmiş olay → veritabanı
python -m engine.worker        # Sigma kuralları → uyarılar
python -m ml.worker            # anomali tespiti
python dashboard/manage.py runserver
```

`/var/log/auth.log` dosyasını okumak için çalıştıran kullanıcının `adm`
grubunda (ya da root) olması gerekir. Olmazsa collector sorunsuz başlar ve
sessizce hiçbir şey görmez.

### İşletim

```bash
# saklama süresi — önce uyarıları, sonra yalnızca hiçbir uyarının referans
# vermediği olayları siler; bir uyarıya bağlı kanıt asla öksüz kalmaz
python dashboard/manage.py prune_events --days 30 --vacuum --dry-run
```

Üretimde: Unix soketi üzerinden nginx + Gunicorn, Let's Encrypt, panelin
önünde HTTP Basic Auth, saklama süresi için bir systemd timer'ı ve her gece
iki veritabanının `sqlite3.Connection.backup()` ile yedeği.

---

## Proje yapısı

```
collector/   log takibi, kaynak başına parser'lar, yok sayma filtreleri
parser/      Redis tüketicisi → ortak olay şeması
engine/      Sigma kural yükleyici, korelasyon, cooldown
  rules/     YAML tespit kuralları
ml/          öznitelik çıkarımı, Z-score + Isolation Forest
alerts/      Telegram, LLM istemcisi, veri minimizasyonu, RAG sohbet
dashboard/   Django + DRF + React panel
config/      settings.yaml — kaynaklar, yok sayma desenleri, eşikler
tests/       103 test
docs/        mimari notları
```

---

## Bilinen sınırlar

* **SQLite.** Tek sunucu için doğru tercih ve bu hacimde tek yazar modeli bir
  kısıt oluşturmadı. Çok sunuculu toplama PostgreSQL gerektirir.
* **Tek sunucudan toplama.** Henüz uzak ajan veya ileticisi yok.
* **ML severity her zaman `high`**, çünkü uzlaşma şartı puanı 1.0'da
  doyuruyor. Puanın anlamlı olması için yeniden ölçeklenmesi gerekiyor.
* **`web_scan` gürültülü.** İnternete açık bir sunucuda cooldown hacmi
  sınırlıyor ama uyarılar yine de birikiyor.
* **Panel yoklama (polling) yapıyor**; WebSocket akışı yok.
* **Zaman damgası işleme modern rsyslog varsayıyor.** BSD biçimli damgalar
  artık UTC değil yerel saat olarak ayrıştırılıyor (RFC 3164), ama o yol
  yalnızca testlerle çalıştırılıyor — bu sunucu offset'li ISO damgası yazıyor.

---

## Lisans

MIT — `LICENSE` dosyasına bakın.

## Yazar

Yasin Emre Karabacak — siber güvenlik ve adli bilişim
[ysnemre.com](https://ysnemre.com) · [@EmreYsn](https://github.com/EmreYsn)