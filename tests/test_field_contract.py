"""
Collector'larin URETTIGI alan adlariyla, tuketicilerin SORGULADIGI
alan adlarinin ortustugunu dogrular.

Neden boyle bir test?
    SentinelBoard'da olaylar serbest bicimli bir JSON sutununda
    (`Event.extra`) saklaniyor. Bu esneklik bir bedelle geliyor:
    yanlis bir alan adi sorgulamak HATA VERMEZ, sessizce sifir sonuc
    doner. Her iki taraf da tek basina dogru gorunur.

    Gerçekte yasandi: collector "http_status" uretiyordu,
    ml/features.py "status_code" sorguluyordu. 4xx sayaci aylarca
    sifir kaldi, ML baseline'i bozuk ogrendi ve kimse fark etmedi.
    Bu test o hatayi ilk calistirmada yakalar.

Nasil calisiyor?
    1) Tuketici modullerini (engine/, ml/) ast ile ayristirip
       "extra__..." ile baslayan TUM anahtar kelime argumanlarini topluyor.
       ast kullanmamizin sebebi: yorum satirlarindaki ornekleri
       gercek sorgu sanmamak.
    2) Collector'lari ornek log satirlariyla calistirip urettikleri
       alan adlarini topluyor.
    3) Sorgulanan her alan, uretilenler arasinda olmali.
"""

import ast
import pathlib

import pytest

from collector.auth import AuthCollector
from collector.nginx import NginxCollector
from collector.syslog import SyslogCollector

KOK = pathlib.Path(__file__).resolve().parent.parent


def _core_fields() -> set[str]:
    """
    parser/worker.py icindeki CORE_FIELDS kumesini KAYNAKTAN okur.

    Neden import etmiyoruz? parser.worker Django'yu yukluyor; bu test
    veritabani ve ayar dosyasi olmadan, saniyenin altinda calismali.
    ast ile okumak hem bagimsiz tutuyor hem de kaynak degisince
    testin kendiliginden guncel kalmasini sagliyor.
    """
    agac = ast.parse((KOK / "parser" / "worker.py").read_text(encoding="utf-8"))
    for dugum in ast.walk(agac):
        if (isinstance(dugum, ast.Assign)
                and any(getattr(h, "id", None) == "CORE_FIELDS" for h in dugum.targets)):
            return set(ast.literal_eval(dugum.value))
    raise AssertionError("parser/worker.py icinde CORE_FIELDS bulunamadi")


CORE_FIELDS = _core_fields()

# Django'nun arama ekleri — alan adinin sonundan temizlenmeli
LOOKUPS = {
    "gte", "lte", "gt", "lt", "exact", "iexact", "contains", "icontains",
    "in", "startswith", "istartswith", "endswith", "isnull", "range",
}

# Her olay tipini tetikleyen ornek satirlar: collector'in uretebilecegi
# tum alan adlarini gormek icin kapsam genis tutuldu.
ORNEK_SATIRLAR = {
    AuthCollector: [
        "2026-10-04T13:11:41+02:00 v sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "2026-10-04T13:11:41+02:00 v sshd[1]: Accepted publickey for yasin from 1.2.3.4 port 22 ssh2",
        "2026-10-04T13:11:41+02:00 v sshd[1]: Invalid user admin from 1.2.3.4 port 22",
        "2026-10-04T13:11:41+02:00 v sshd[1]: Connection closed by 1.2.3.4 port 22",
        "2026-10-04T13:11:41+02:00 v sshd[1]: pam_unix: authentication failure; rhost=1.2.3.4 user=root",
        "2026-10-04T13:11:41+02:00 v sudo:  yasin : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        "2026-10-04T13:11:41+02:00 v sudo:  yasin : 3 incorrect password attempts",
        "2026-10-04T13:11:41+02:00 v useradd[1]: new user: name=test, UID=1001",
        "2026-10-04T13:11:41+02:00 v systemd[1]: Started something",
    ],
    NginxCollector: [
        '1.2.3.4 - - [04/Oct/2026:13:11:41 +0200] "GET /wp-admin HTTP/1.1" 404 162 "-" "sqlmap"',
        '1.2.3.4 - yasin [04/Oct/2026:13:11:41 +0200] "POST /api HTTP/1.1" 200 15 "r" "Mozilla/5.0"',
    ],
    SyslogCollector: [
        "2026-10-04T13:11:41+02:00 v kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 "
        "PROTO=TCP SPT=1 DPT=22",
        "2026-10-04T13:11:41+02:00 v systemd[1]: Started nginx.service",
    ],
}


def _sorgulanan_alanlar() -> dict[str, set[str]]:
    """Tuketici modullerdeki extra__ sorgularini dosya bazinda toplar."""
    bulunan: dict[str, set[str]] = {}
    for yol in sorted(KOK.glob("engine/*.py")) + sorted(KOK.glob("ml/*.py")):
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        for dugum in ast.walk(agac):
            if not isinstance(dugum, ast.keyword) or not dugum.arg:
                continue
            if not dugum.arg.startswith("extra__"):
                continue
            parcalar = dugum.arg.split("__")[1:]      # "extra" atilir
            while parcalar and parcalar[-1] in LOOKUPS:
                parcalar.pop()                        # __gte, __lt gibi ekleri at
            if parcalar:
                bulunan.setdefault("__".join(parcalar), set()).add(yol.name)
    return bulunan


def _uretilen_alanlar() -> set[str]:
    """Collector'larin extra'ya gonderdigi tum alan adlari."""
    alanlar: set[str] = set()
    for sinif, satirlar in ORNEK_SATIRLAR.items():
        c = sinif({"name": "test"})
        for satir in satirlar:
            olay = c.parse_line(satir)
            if olay:
                alanlar |= {k for k, v in olay.items()
                            if k not in CORE_FIELDS and v is not None}
    return alanlar


def test_sorgulanan_her_alan_uretiliyor():
    sorgulanan = _sorgulanan_alanlar()
    uretilen = _uretilen_alanlar()

    assert sorgulanan, "Hic extra__ sorgusu bulunamadi — test kendi kendini dogrulayamiyor"

    eksik = {ad: dosyalar for ad, dosyalar in sorgulanan.items() if ad not in uretilen}
    if eksik:
        satirlar = [f"  extra__{ad}  ({', '.join(sorted(d))})" for ad, d in sorted(eksik.items())]
        pytest.fail(
            "Hicbir collector'in uretmedigi alanlar sorgulaniyor "
            "(bu sorgular sessizce HER ZAMAN sifir doner):\n"
            + "\n".join(satirlar)
            + f"\n\nCollector'larin urettigi alanlar: {sorted(uretilen)}"
        )