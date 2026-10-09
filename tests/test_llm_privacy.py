"""
LLM'e giden veriyi kilitleyen sozlesme testleri.

Neden bu testler?
    SentinelBoard alert analizini bir LLM'e yaptiriyor. Saglayici
    bulutta oldugunda gonderilen her sey sunucudan cikiyor. Bir SIEM'in
    elindeki veri ise en hassas veri turu: kullanici adlari, ic IP'ler,
    calistirilan komutlar, dosya yollari.

    Uzun sure prompt'a ham syslog satiri (`event.raw`) konuyordu. Yani
    "sudo: yasin : PWD=/home/yasin ; COMMAND=/usr/bin/apt install ..."
    satirinin tamami uc ayri yerden disariya gidiyordu.

    Bu testler o kapinin tekrar acilmasini engelliyor. Asagidakiler
    *davranis* testi degil, *sozlesme* testi: "su veri su sinirdan
    gecmez" diyor. Biri ileride performans icin prompt'a raw eklemek
    isterse test kirmizi dusuyor ve nedenini sebebiyle birlikte soyluyor.
"""

import ast
import pathlib

import pytest

from django.utils import timezone

from alerts import llm_client
from alerts.chat import gather_context
from alerts.llm_analyzer import build_analysis_prompt
from alerts.sanitize import Pseudonymizer, scrub_event_line
from events.models import Event

# Dokumantasyon araliklari (RFC 5737: 198.51.100.0/24, 203.0.113.0/24)
# burada ISE YARAMIYOR: Python'un ipaddress modulu onlari is_private
# kabul ediyor, dolayisiyla "harici" degil "yerel" etiketleniyorlar.
# Harici siniflandirmasini test etmek icin gercekten global olarak
# yonlendirilebilir adresler gerekiyor.
HARICI_IP = "185.199.108.153"
IKINCI_IP = "140.82.121.4"
YEREL_IP = "10.0.0.5"

GERCEK_KULLANICI = "yasin"
RAW_IMZASI = "COKGIZLIHAMSATIRIMZASI"


# ── Sahte modeller ───────────────────────────────────────────
# Veritabani gerekmiyor: build_analysis_prompt sadece attribute
# okuyor. Testi DB'den bagimsiz tutmak onu hizli ve kirilgan
# olmayan tarafta tutuyor.

class SahteEvent:
    def __init__(self, **alanlar):
        self.severity = "high"
        self.event_type = "sudo_command"
        self.src_ip = HARICI_IP
        self.user = GERCEK_KULLANICI
        self.timestamp = "2026-10-09 14:23:01"
        self.source = "auth"
        self.process = "sudo"
        self.message = (
            f"{GERCEK_KULLANICI} : TTY=pts/0 ; PWD=/home/{GERCEK_KULLANICI} ; "
            f"USER=root ; COMMAND=/usr/bin/apt install /home/{GERCEK_KULLANICI}/gizli.deb"
        )
        self.raw = f"Oct  9 14:23:01 vps sudo: {RAW_IMZASI}"
        self.__dict__.update(alanlar)


class SahteAlert:
    def __init__(self, **alanlar):
        self.id = "test-alert"
        self.rule_id = "sentinel-004"
        self.rule_title = "Suspicious Sudo Activity"
        self.severity = "high"
        self.src_ip = HARICI_IP
        self.user = GERCEK_KULLANICI
        self.message = f"{GERCEK_KULLANICI} kullanicisi 8 sudo komutu calistirdi"
        self.tags = ["attack.privilege_escalation", "attack.t1548.003"]
        self.created_at = "2026-10-09 14:25:00"
        self.__dict__.update(alanlar)


# ── Prompt'tan ne cikiyor ────────────────────────────────────

def test_prompt_ham_satiri_tasimaz():
    """
    `event.raw` prompt'a hic girmemeli. Ham syslog satiri komut
    argumanlarini ve dosya yollarini oldugu gibi tasir; analiz icin
    gerekli degil, sizdirilmasi en pahali kisim.
    """
    prompt = build_analysis_prompt(SahteAlert(), [SahteEvent()])
    assert RAW_IMZASI not in prompt, (
        "Ham syslog satiri prompt'a girmis. event.raw asla gonderilmemeli; "
        "parse edilmis alanlar ayni analizi uretir."
    )


def test_prompt_gercek_ip_tasimaz():
    """IP oktetleri disari cikmamali — yerel/harici ayrimi yeterli."""
    prompt = build_analysis_prompt(SahteAlert(), [SahteEvent()])
    assert HARICI_IP not in prompt, "Gercek IP adresi prompt'ta kalmis"
    assert "IP_1" in prompt, "Takma ad uretilmemis"
    assert "harici" in prompt, (
        "Yerel/harici ayrimi kaybolmus. Takma adlamanin bedeli bu bilgi "
        "olmamali; LLM'in kaynak disaridan mi geliyor bilmesi gerekiyor."
    )


def test_prompt_gercek_kullanici_adi_tasimaz():
    """Kisiye ozel kullanici adi disari cikmamali."""
    prompt = build_analysis_prompt(SahteAlert(), [SahteEvent()])
    assert GERCEK_KULLANICI not in prompt, (
        "Gercek kullanici adi prompt'ta kalmis. Alan olarak degistirilip "
        "mesaj icinde atlanmis olabilir — text() ikisini de kapsamali."
    )
    assert "USER_1" in prompt


def test_prompt_sistem_hesabini_korur():
    """
    "root" takma adlanmamali. Her sistemde var, kimseyi tanimlamaz,
    ama yetki yukseltme analizinin merkezinde. Gizlemek analizi
    gereksiz yere korlestirir.
    """
    prompt = build_analysis_prompt(SahteAlert(), [SahteEvent()])
    assert "USER=root" in prompt, "Sistem hesabi gereksiz yere takma adlanmis"


def test_prompt_komut_argumanlarini_ve_yollari_atar():
    """Binary adi kalir, argumanlar ve dosya yollari gider."""
    prompt = build_analysis_prompt(SahteAlert(), [SahteEvent()])
    assert "gizli.deb" not in prompt, "Komut argumani sizmis"
    assert "/home/yasin" not in prompt, "Ev dizini yolu sizmis"
    assert "COMMAND=apt" in prompt, (
        "Komutun binary adi kaybolmus. Argumanlari atmak analizi "
        "bozmamali: 'apt' ile 'apt install x' ayni tehdit sinyalini verir."
    )


def test_prompt_tag_ve_kural_bilgisini_korur():
    """Gizleme fazla ileri gitmemeli: public bilgi prompt'ta kalmali."""
    prompt = build_analysis_prompt(SahteAlert(), [SahteEvent()])
    assert "sentinel-004" in prompt
    assert "attack.t1548.003" in prompt
    assert "Suspicious Sudo Activity" in prompt


def test_prompt_takma_adlari_aciklar():
    """
    LLM'e takma adin ne oldugunu soylemek gerekiyor. Soylenmezse
    "IP_1" ifadesini anlamsiz bir dize sanip yorumu zayiflatir ya
    da gercek bir deger uydurur.
    """
    prompt = build_analysis_prompt(SahteAlert(), [SahteEvent()])
    assert "takma ad" in prompt.lower()


def test_eventsiz_alert_de_temizlenir():
    """Event listesi bos olsa bile alert alanlari takma adlanmali."""
    prompt = build_analysis_prompt(SahteAlert(), [])
    assert GERCEK_KULLANICI not in prompt
    assert HARICI_IP not in prompt


# ── Takma adlandirici davranisi ──────────────────────────────

def test_ayni_deger_ayni_takma_adi_alir():
    """
    Tutarlilik sart: LLM "ayni kaynak tekrar denemis" iliskisini
    ancak ayni etiketi gorerek kurabilir.
    """
    p = Pseudonymizer()
    assert p.ip(HARICI_IP) == p.ip(HARICI_IP)
    assert p.ip(HARICI_IP) != p.ip(IKINCI_IP)
    assert p.user("ahmet") == p.user("ahmet")
    assert p.user("ahmet") != p.user("mehmet")


def test_etiketler_boslukta_numaralanmaz():
    """IP_1, IP_2, IP_3 — araya ifsa edilmis deger girse bile."""
    p = Pseudonymizer()
    p.disclose_ip(YEREL_IP)          # etiket tuketmemeli
    assert "IP_1" in p.ip(HARICI_IP)
    assert "IP_2" in p.ip(IKINCI_IP)


def test_takma_adlama_idempotenttir():
    """
    Bir etiketi tekrar takma adlamak etiketi degistirmemeli.

    Yasanan hata: "Failed password for invalid user admin from ..."
    satiri iki ayri desene uyuyor. Birincisi "admin" yerine USER_1
    yaziyor, ikincisi ayni metinde USER_1'i goruyor ve onu USER_2
    yapiyordu. Sonuc: ayni gercek deger prompt icinde iki farkli
    etiketle gorunuyor, yani LLM'in "ayni kaynak" iliskisini kurmasi
    icin var olan tutarlilik garantisi bozuluyor.
    """
    p = Pseudonymizer()
    etiket = p.user("admin")
    assert p.user(etiket) == etiket, "Etiket tekrar takma adlanmis"

    ip_etiket = p.ip(HARICI_IP)
    assert p.ip(ip_etiket) == ip_etiket

    # Iki desene uyan gercek satir: tek etiket uretilmeli
    cikti = p.text("Failed password for invalid user admin from 10.0.0.5 port 22 ssh2")
    assert "USER_2" not in cikti
    assert cikti.count("USER_1") == 1


def test_yerel_ve_harici_ayirt_edilir():
    p = Pseudonymizer()
    assert "yerel" in p.ip(YEREL_IP)
    assert "harici" in p.ip(HARICI_IP)
    assert "localhost" in p.ip("127.0.0.1")


def test_ifsa_edilmis_deger_oldugu_gibi_kalir():
    """
    Kullanicinin sorusunda gecen IP baglamda da aynen gorunmeli.
    Gizlemek hicbir sey kazandirmaz (deger soruyla birlikte zaten
    disari cikti) ama gelen cevabi okunmaz yapar.
    """
    p = Pseudonymizer()
    assert p.disclose_ip(HARICI_IP) == HARICI_IP
    assert p.text(f"istek {HARICI_IP} adresinden geldi") == (
        f"istek {HARICI_IP} adresinden geldi"
    )
    assert "sorusunda gecen" in p.summary()


def test_saat_damgasi_ip_sanilmaz():
    """
    IPv6 deseni gevsek yakaliyor, dogrulamayi ipaddress yapiyor.
    Dogrulama olmasa "14:23:01" IP sanilip bozulurdu.
    """
    p = Pseudonymizer()
    metin = "Oct  9 14:23:01 vps oturum acildi"
    assert p.text(metin) == metin


def test_gecersiz_oktet_ip_sanilmaz():
    """999 gecerli bir oktet degil — ipaddress dogrulamasi bunu ayikliyor."""
    p = Pseudonymizer()
    metin = "hatali deger 999.1.1.1 goruldu"
    assert p.text(metin) == metin


def test_sshd_mesajindaki_kullanici_adi_yakalanir():
    """
    Kullanici adi alan olarak gelmese bile mesaja gomulu halde
    yakalanmali. "Failed password for invalid user admin from ..."
    satirindaki "admin" prompt'ta kalmamali.
    """
    p = Pseudonymizer()
    cikti = p.text(
        f"Failed password for invalid user admin from {HARICI_IP} port 54321 ssh2"
    )
    assert "admin" not in cikti
    assert "USER_1" in cikti
    assert HARICI_IP not in cikti


def test_pam_ve_useradd_bicimleri_de_yakalanir():
    p = Pseudonymizer()
    assert "kurban" not in p.text("authentication failure; user=kurban")
    assert "arkakapi" not in p.text("new user: name=arkakapi, UID=1001")


def test_scrub_event_line_raw_okumaz():
    """
    Satir ureticisi `raw` alanina hic dokunmamali. Bu testin dustugu
    durum, ham satirin tekrar prompt'a girmesi demektir.
    """
    p = Pseudonymizer()
    satir = scrub_event_line(p, SahteEvent())
    assert RAW_IMZASI not in satir
    assert GERCEK_KULLANICI not in satir


def test_bos_degerler_patlamaz():
    """src_ip ve user NULL olabilir — nginx event'lerinde user yok."""
    p = Pseudonymizer()
    assert p.ip(None) == "N/A"
    assert p.user(None) == "N/A"
    assert p.text(None) == ""
    satir = scrub_event_line(p, SahteEvent(src_ip=None, user=None, message=None))
    assert "N/A" in satir


# ── Chatbot baglami (veritabani gerektirir) ──────────────────

def _gercek_olay(**alanlar) -> Event:
    """Uretimdeki sudo satirina benzeyen gercek bir Event kaydi."""
    varsayilan = {
        "timestamp": timezone.now(),
        "source": "auth",
        "host": "testhost",
        "event_type": "sudo_command",
        "severity": "high",
        "src_ip": HARICI_IP,
        "user": GERCEK_KULLANICI,
        "process": "sudo",
        "message": (
            f"{GERCEK_KULLANICI} : TTY=pts/0 ; PWD=/home/{GERCEK_KULLANICI} ; "
            f"USER=root ; COMMAND=/usr/bin/apt install /home/{GERCEK_KULLANICI}/gizli.deb"
        ),
        "raw": f"Oct  9 14:23:01 vps sudo: {RAW_IMZASI}",
    }
    varsayilan.update(alanlar)
    return Event.objects.create(**varsayilan)


@pytest.mark.django_db
def test_chat_baglami_ham_veri_tasimaz():
    """
    RAG baglamı da temizlenmeli. Burasi prompt'tan ayri bir yol:
    llm_analyzer duzeltilip chat.py atlanirsa sizinti devam eder,
    bu yuzden ayri test ediliyor.
    """
    _gercek_olay()
    baglam = gather_context("son durumu ozetle")

    assert RAW_IMZASI not in baglam, "Ham syslog satiri baglamda"
    assert GERCEK_KULLANICI not in baglam, "Gercek kullanici adi baglamda"
    assert HARICI_IP not in baglam, "Gercek IP baglamda"
    assert "gizli.deb" not in baglam, "Komut argumani baglamda"


@pytest.mark.django_db
def test_chat_baglami_sorulan_ipyi_oldugu_gibi_birakir():
    """
    Kullanicinin sorusunda gecen IP baglamda da aynen gorunmeli.

    Bu bir bosluk degil, kapsamin durust siniri: deger soruyla
    birlikte zaten disari cikti. Takma adlamak hicbir gizlilik
    kazandirmaz, sadece gelen cevabi okunmaz yapar ("IP_1 hakkinda
    sordugunuz..." diye baslayan bir cevap kime ait oldugu belirsiz
    olur).
    """
    _gercek_olay()
    baglam = gather_context(f"{HARICI_IP} adresi ne yapti")

    assert HARICI_IP in baglam, (
        "Kullanicinin kendi yazdigi IP baglamdan silinmis — cevap "
        "hangi adres hakkinda oldugunu kaybeder"
    )
    # Ifsa edilen tek sey o IP; geri kalan hassas veri hala gizli
    assert RAW_IMZASI not in baglam
    assert GERCEK_KULLANICI not in baglam
    assert "gizli.deb" not in baglam


@pytest.mark.django_db
def test_chat_baglami_istatistikleri_korur():
    """Temizleme fazla ileri gitmemeli: sayilar analiz icin gerekli."""
    _gercek_olay()
    _gercek_olay(src_ip=IKINCI_IP, user="baskasi")
    baglam = gather_context("kac event var")

    assert "Toplam event: 2" in baglam
    assert "IP_1" in baglam and "IP_2" in baglam, (
        "Farkli kaynaklar farkli etiket almali, yoksa dagilim bilgisi kaybolur"
    )


# ── Saglayici yapilandirmasi ─────────────────────────────────

def test_taban_adresten_tam_adres_uretilir():
    assert llm_client.resolve_api_url("http://127.0.0.1:11434/v1") == (
        "http://127.0.0.1:11434/v1/chat/completions"
    )
    # Sondaki egik cizgi cift cizgiye yol acmamali
    assert llm_client.resolve_api_url("https://api.groq.com/openai/v1/") == (
        "https://api.groq.com/openai/v1/chat/completions"
    )
    # Tam adres verilmisse oldugu gibi kullanilmali
    tam = "https://ornek.com/v1/chat/completions"
    assert llm_client.resolve_api_url(tam) == tam


@pytest.mark.parametrize(
    "adres,yerel_mi",
    [
        ("http://127.0.0.1:11434/v1", True),
        ("http://localhost:11434/v1", True),
        ("http://ollama.local:11434/v1", True),
        ("https://api.groq.com/openai/v1", False),
        ("https://api.openai.com/v1", False),
    ],
)
def test_yerel_endpoint_tanimi(adres, yerel_mi):
    """
    Yerel modeller API anahtari istemiyor. Bu ayrim olmasa "anahtar
    yok" hatasi Ollama'ya gecisi engellerdi.
    """
    assert llm_client.is_local_endpoint(adres) is yerel_mi


# ── Gerilemeyi onleyen kaynak kodu kontrolu ──────────────────

def test_alerts_modulleri_raw_alanina_dokunmaz():
    """
    Sozlesme testi: alerts/ altindaki hicbir dosya `.raw` okumamali.

    Yukaridaki testler prompt'un *ciktisini* kontrol ediyor. Bu test
    *niyeti* kontrol ediyor: biri yeni bir prompt fonksiyonu yazip
    icine raw koyarsa, o fonksiyonun testi olmasa bile burasi yakalar.
    """
    alerts_dizini = pathlib.Path(__file__).resolve().parents[1] / "alerts"
    ihlaller = []

    for yol in sorted(alerts_dizini.glob("*.py")):
        agac = ast.parse(yol.read_text(encoding="utf-8"), filename=str(yol))
        for dugum in ast.walk(agac):
            if isinstance(dugum, ast.Attribute) and dugum.attr == "raw":
                ihlaller.append(f"{yol.name}:{dugum.lineno}")

    assert not ihlaller, (
        "Ham log satirina erisim geri gelmis: "
        + ", ".join(ihlaller)
        + ". event.raw veritabaninda ve panelde mevcut; LLM'e "
        "gonderilmesi gerekmiyor."
    )