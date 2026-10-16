"""
timeparse.py — Log zaman damgalarını ISO 8601 formatına çevirir.

Neden ayrı bir dosya?
    Her collector aynı zaman problemiyle boğuşuyor. Tek yerde
    çözüp hepsinin kullanması, aynı hatayı üç kez yapmaktan iyi.

Syslog'un yıl problemi:
    Klasik syslog satırı "Jun  9 14:23:01" der — yıl YOK.
    Yıl olmadan datetime üretemeyiz. Çözüm: içinde bulunduğumuz
    yılı varsaymak. Ama bir tuzak var: 31 Aralık gecesi yazılmış
    bir log 1 Ocak'ta okunursa, bugünün yılını eklersek log
    gelecekte görünür. O yüzden "hesapladığım tarih bugünden
    belirgin şekilde ileride mi?" diye bakıp gerekirse bir yıl
    geri alıyoruz.

Neden ISO string?
    parser/worker.py satırı `datetime.fromisoformat(...)` ile
    okuyor. Aynı dili konuşmamız gerekiyor.
"""

from datetime import datetime, timezone, timedelta, tzinfo

# "Jun  9 14:23:01" biçimi — %d tek haneli günde de çalışır
# çünkü strptime baştaki boşlukları tolere eder.
_SYSLOG_FMT = "%b %d %H:%M:%S"

# Ayrıştırma sırasında yıl eklemek için kullanılan biçim (bkz. aşağıdaki
# 29 Şubat açıklaması).
_SYSLOG_FMT_YILLI = _SYSLOG_FMT + " %Y"

# Nginx: "09/Jun/2026:14:23:01 +0300"
_NGINX_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _yerele_bagla(naive: datetime, local_tz: tzinfo | None) -> datetime:
    """Saat dilimi taşımayan bir damgayı yerel saat kabul edip bağlar.

    local_tz verilmezse naive.astimezone() kullanılıyor: Python bunu
    "bu değer yerel saattir" diye yorumlar ve O TARİHTEKİ doğru offset'i
    sistemin tz veritabanından okur. Sabit bir offset hesaplayıp saklamak
    yaz saati geçişlerinde bir saatlik hata bırakırdı.
    """
    if local_tz is not None:
        return naive.replace(tzinfo=local_tz)
    return naive.astimezone()


def parse_syslog_timestamp(
    ts: str,
    now: datetime | None = None,
    local_tz: tzinfo | None = None,
) -> str:
    """
    Syslog zaman damgasını ISO 8601 string'e çevirir.

    İki biçimi de kabul eder:
        "2026-10-04T00:00:49.417217+02:00"  → ISO (Ubuntu 23.10+)
        "Jun  9 14:23:01"                   → klasik BSD (yılsız)

    BSD biçimi ve saat dilimi:
        Klasik syslog damgası ne yıl ne de saat dilimi taşır ve
        gönderen makinenin YEREL saatiyle yazılır (RFC 3164). Bir
        süre bu değer doğrudan UTC olarak etiketlendi; sunucu
        Europe/Berlin (+02:00) olduğu için her BSD biçimli olay
        gerçeğinden iki saat ileri kaydı. Hata canlıya yansımadı
        çünkü bu sistemin rsyslog'u ISO biçimi yazıyor — ama başka
        bir makineden BSD biçimli syslog alındığında ortaya çıkardı.

    Args:
        ts: Ham zaman damgası
        now: Referans an (test için enjekte edilebilir)
        local_tz: BSD damgalarının hangi saat diliminde okunacağı.
            Verilmezse sistemin yerel saati kullanılır ve o tarihteki
            doğru offset (yaz saati dahil) tz veritabanından alınır.
            Parametre testler için var: testin sonucu, testi çalıştıran
            makinenin saat dilimine göre değişmemeli.

    Returns:
        "2026-06-09T14:23:01+02:00" biçiminde ISO string.
        Parse edilemezse şu anın zamanı döner — log kaybetmektense
        zamanı yaklaşık olsun.
    """
    now = now or datetime.now(timezone.utc)
    ts = ts.strip()

    # ISO biçimi zaten istediğimiz formatta: yıl ve saat dilimi dahil.
    # Tahmin yapmaya gerek yok, doğrudan doğrula ve geri ver.
    if len(ts) > 4 and ts[4] == "-":
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return now.isoformat()

    # Yıl, ayrıştırma SIRASINDA veriliyor; sonradan replace ile değil.
    # Sebep: strptime yılsız bir damgada varsayılan olarak 1900 kullanır,
    # 1900 artık yıl olmadığı için "Feb 29 ..." ayrıştırılamaz ve olay
    # sessizce şimdiki zamana düşerdi. Ayrıca Python 3.15 yılsız
    # ayrıştırmayı tamamen değiştiriyor (DeprecationWarning).
    naive = None
    for yil in (now.year, now.year - 1):
        try:
            naive = datetime.strptime(f"{ts} {yil}", _SYSLOG_FMT_YILLI)
            break
        except ValueError:
            continue
    if naive is None:
        return now.isoformat()

    # Değer bu aşamada naive, yani "yerel duvar saati".
    dt = _yerele_bagla(naive, local_tz)

    # Yıl dönümü düzeltmesi: tarih bugünden 1 günden fazla ileride
    # çıktıysa, bu aslında geçen yılın logu demektir.
    # Saat dilimi bağlama işlemi naive değer üzerinden tekrarlanıyor:
    # aware bir datetime'da yılı değiştirmek eski offset'i taşır ve
    # yaz saati sınırını geçen tarihlerde bir saatlik hata bırakır.
    if dt > now + timedelta(days=1):
        try:
            dt = _yerele_bagla(naive.replace(year=naive.year - 1), local_tz)
        except ValueError:
            pass  # 29 Şubat bir önceki yılda yok; olduğu gibi bırak

    return dt.isoformat()


def parse_nginx_timestamp(ts: str, now: datetime | None = None) -> str:
    """
    Nginx erişim logu damgasını ISO 8601'e çevirir.

    Nginx yılı da saat dilimini de yazar, o yüzden tahmine gerek yok.
    """
    try:
        dt = datetime.strptime(ts.strip(), _NGINX_FMT)
        return dt.isoformat()
    except ValueError:
        return (now or datetime.now(timezone.utc)).isoformat()