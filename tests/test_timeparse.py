"""
Zaman damgası ayrıştırmasının sözleşme testleri.

Neden bu testler?
    `timeparse.py` bugüne kadar hiç test edilmemişti ve içinde sessiz
    bir hata vardı: klasik BSD syslog damgası (`Oct 12 18:15:14`) ne
    yıl ne de saat dilimi taşır ve gönderen makinenin YEREL saatiyle
    yazılır (RFC 3164). Kod ise bu değeri doğrudan UTC olarak
    etiketliyordu. Sunucu Europe/Berlin (+02:00) olduğu için her BSD
    biçimli olay gerçeğinden iki saat ileri kayıyordu.

    Hata canlıya yansımadı, çünkü bu sistemin rsyslog'u ISO biçimi
    yazıyor ve o dal zaten doğruydu. Ama merkezi log toplamaya
    geçildiğinde (başka bir makineden BSD biçimli syslog alındığında)
    ilk patlayacak yer burasıydı. Bir SIEM'de iki saatlik kayma,
    korelasyon pencerelerini ve olay sıralamasını bozar.

Saat dilimi testleri neden sabit offset kullanıyor?
    Testin sonucu, testi çalıştıran makinenin saat dilimine göre
    değişmemeli. Bu yüzden `local_tz` enjekte ediliyor. ZoneInfo yerine
    sabit offset kullanılıyor çünkü Windows'ta tz veritabanı ayrı bir
    paket gerektiriyor; geliştirme Windows'ta, üretim Linux'ta.
"""

from datetime import datetime, timedelta, timezone

import pytest

from collector.timeparse import parse_syslog_timestamp, parse_nginx_timestamp

BERLIN = timezone(timedelta(hours=2))      # CEST
ISTANBUL = timezone(timedelta(hours=3))
NOW = datetime(2026, 10, 12, 16, 15, 0, tzinfo=timezone.utc)


def _utc(iso_str: str) -> datetime:
    return datetime.fromisoformat(iso_str).astimezone(timezone.utc)


# ── BSD biçimi: asıl düzeltme ────────────────────────────────

def test_bsd_damgasi_yerel_saat_olarak_okunur():
    """
    "Oct 12 18:15:14" +02:00 bir makinede yazıldıysa, bu an UTC'de
    16:15:14'tür. Hatalı sürüm 18:15:14 UTC üretiyordu — iki saat ileri.
    """
    sonuc = parse_syslog_timestamp("Oct 12 18:15:14", now=NOW, local_tz=BERLIN)
    assert _utc(sonuc) == datetime(2026, 10, 12, 16, 15, 14, tzinfo=timezone.utc), (
        "BSD damgası yerel saat yerine UTC sanılmış; olaylar saat dilimi "
        "farkı kadar ileri kayıyor"
    )


def test_bsd_damgasi_utc_etiketlenmez():
    """Düzeltmenin doğrudan karşıtı: çıktı UTC offset'i taşımamalı."""
    sonuc = parse_syslog_timestamp("Oct 12 18:15:14", now=NOW, local_tz=BERLIN)
    assert datetime.fromisoformat(sonuc).utcoffset() == timedelta(hours=2)


def test_farkli_saat_dilimleri_farkli_an_uretir():
    """
    Saat diliminin gerçekten kullanıldığının kanıtı: aynı dize, farklı
    dilimde okunduğunda farklı bir ana denk gelmeli. Kod saat dilimini
    yok sayarsa bu test düşer.
    """
    berlin = _utc(parse_syslog_timestamp("Oct 12 18:15:14", now=NOW, local_tz=BERLIN))
    istanbul = _utc(parse_syslog_timestamp("Oct 12 18:15:14", now=NOW, local_tz=ISTANBUL))
    assert berlin - istanbul == timedelta(hours=1)


def test_local_tz_verilmezse_sistem_saati_kullanilir():
    """
    Üretimde local_tz verilmiyor; sistemin yerel saati kullanılmalı.
    Hangi makinede koştuğumuzu bilmediğimiz için offset'i sabitlemek
    yerine, çıktının naive OLMADIĞINI doğruluyoruz: eski hata zaten
    her ortamda UTC'ye sabitlemekti.
    """
    sonuc = datetime.fromisoformat(
        parse_syslog_timestamp("Oct 12 18:15:14", now=NOW)
    )
    assert sonuc.tzinfo is not None, "Çıktı saat dilimi taşımıyor"
    assert sonuc.hour == 18, "Duvar saati korunmalı, kaydırılmamalı"


# ── Yıl dönümü ───────────────────────────────────────────────

def test_yil_donumu_geriye_alinir():
    """
    31 Aralık gecesi yazılmış bir satır 1 Ocak'ta okunursa, bugünün
    yılını eklemek logu bir yıl ileri atardı.
    """
    ocak = datetime(2027, 1, 1, 10, 0, tzinfo=timezone.utc)
    sonuc = parse_syslog_timestamp("Dec 31 23:59:59", now=ocak, local_tz=BERLIN)
    assert sonuc.startswith("2026-12-31"), f"Yıl düzeltilmemiş: {sonuc}"


def test_normal_tarih_yili_degismez():
    sonuc = parse_syslog_timestamp("Oct 12 18:15:14", now=NOW, local_tz=BERLIN)
    assert sonuc.startswith("2026-10-12")


# ── ISO biçimi: dokunulmamalı ────────────────────────────────

def test_iso_damgasi_offsetiyle_korunur():
    """
    Modern rsyslog offset'i satırın içinde yazar. Bu dal zaten doğruydu
    ve düzeltme onu bozmamalı.
    """
    sonuc = parse_syslog_timestamp("2026-10-04T13:11:41.024+02:00", now=NOW)
    assert _utc(sonuc) == datetime(2026, 10, 4, 11, 11, 41, 24000,
                                   tzinfo=timezone.utc)


def test_iso_z_son_eki_kabul_edilir():
    sonuc = parse_syslog_timestamp("2026-10-04T11:11:41Z", now=NOW)
    assert _utc(sonuc) == datetime(2026, 10, 4, 11, 11, 41, tzinfo=timezone.utc)


# ── Bozuk girdi ──────────────────────────────────────────────

@pytest.mark.parametrize("bozuk", [
    "bu bir tarih degil",
    "",
    "2026-13-45T99:99:99+02:00",
    "Foo 99 99:99:99",
])
def test_bozuk_girdi_simdiki_zamani_doner(bozuk):
    """
    Ayrıştırılamayan satır için olayı DÜŞÜRMEK yerine yaklaşık zaman
    veriliyor: bir SIEM'de kaybolan olay, zamanı birkaç saniye şaşan
    olaydan daha pahalıdır.
    """
    assert parse_syslog_timestamp(bozuk, now=NOW) == NOW.isoformat()


# ── Nginx ────────────────────────────────────────────────────

def test_nginx_damgasi_kendi_offsetini_kullanir():
    """Nginx yılı da offset'i de yazar; tahmine gerek yok."""
    sonuc = parse_nginx_timestamp("09/Jun/2026:14:23:01 +0300")
    assert _utc(sonuc) == datetime(2026, 6, 9, 11, 23, 1, tzinfo=timezone.utc)


def test_nginx_bozuk_girdi_simdiki_zamani_doner():
    assert parse_nginx_timestamp("bozuk", now=NOW) == NOW.isoformat()


# ── 29 Şubat ─────────────────────────────────────────────────

def test_artik_gun_ayristirilir():
    """
    Eski kod yılsız ayrıştırıp varsayılan yıl 1900'ü kullanıyordu;
    1900 artık yıl olmadığı için "Feb 29" ValueError veriyor ve olay
    sessizce şimdiki zamana düşüyordu. Dört yılda bir, bir günlük
    log'un zamanı bozuluyordu.
    """
    artik = datetime(2028, 3, 1, 10, 0, tzinfo=timezone.utc)
    sonuc = parse_syslog_timestamp("Feb 29 03:14:00", now=artik, local_tz=BERLIN)
    assert sonuc.startswith("2028-02-29T03:14:00"), f"29 Şubat kaybedildi: {sonuc}"


def test_artik_olmayan_yilda_29_subat_simdiye_dusmez_eger_onceki_yil_artiksa():
    """2028 artık yıl; 2029'da okunan 'Feb 29' 2028'e ait olmalı."""
    sonuc = parse_syslog_timestamp(
        "Feb 29 03:14:00",
        now=datetime(2029, 1, 2, 10, 0, tzinfo=timezone.utc),
        local_tz=BERLIN,
    )
    assert sonuc.startswith("2028-02-29"), sonuc