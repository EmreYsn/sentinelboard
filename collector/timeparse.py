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

from datetime import datetime, timezone, timedelta

# "Jun  9 14:23:01" biçimi — %d tek haneli günde de çalışır
# çünkü strptime baştaki boşlukları tolere eder.
_SYSLOG_FMT = "%b %d %H:%M:%S"

# Nginx: "09/Jun/2026:14:23:01 +0300"
_NGINX_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_syslog_timestamp(ts: str, now: datetime | None = None) -> str:
    """
    Syslog zaman damgasını ISO 8601 string'e çevirir.

    İki biçimi de kabul eder:
        "2026-10-04T00:00:49.417217+02:00"  → ISO (Ubuntu 23.10+)
        "Jun  9 14:23:01"                   → klasik BSD (yılsız)

    Args:
        ts: Ham zaman damgası
        now: Referans an (test için enjekte edilebilir)

    Returns:
        "2026-06-09T14:23:01+00:00" biçiminde ISO string.
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

    try:
        parsed = datetime.strptime(ts, _SYSLOG_FMT)
    except ValueError:
        return now.isoformat()

    # strptime yıl bilmediği için 1900 koyar; bugünün yılıyla değiştir
    dt = parsed.replace(year=now.year, tzinfo=timezone.utc)

    # Yıl dönümü düzeltmesi: tarih bugünden 1 günden fazla ileride
    # çıktıysa, bu aslında geçen yılın logu demektir.
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=now.year - 1)

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