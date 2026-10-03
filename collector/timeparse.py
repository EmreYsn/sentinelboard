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
    Yılsız syslog zaman damgasını ISO 8601 string'e çevirir.

    Args:
        ts: "Jun  9 14:23:01" biçiminde damga
        now: Referans an (test için enjekte edilebilir)

    Returns:
        "2026-06-09T14:23:01+00:00" biçiminde ISO string.
        Parse edilemezse şu anın zamanı döner — log kaybetmektense
        zamanı yaklaşık olsun.
    """
    now = now or datetime.now(timezone.utc)
    try:
        parsed = datetime.strptime(ts.strip(), _SYSLOG_FMT)
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