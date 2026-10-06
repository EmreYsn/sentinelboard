"""
Veritabani gerektiren davranis testleri: korelasyon motoru ve temizlik.

Neden bu testler?
    Ucu de gercekten yasanmis bir hatayi ya da kolayca bozulabilecek
    bir sozlesmeyi kilitliyor:

    - Cooldown: Kural "user" alanina gore grupluyorsa, cooldown
      sorgusu da ayni degere bakmali. Bir sure `src_ip` sutununa
      bakti; sudo alert'lerinde o sutun NULL oldugu icin cooldown
      hic devreye girmedi ve motor her 10 saniyede bir ayni alert'i
      uretti. Dokuz kopya Telegram'a gitti.

    - group_value: Cooldown'in dayandigi sutun. Alert olusturulurken
      doldurulmazsa cooldown sessizce ise yaramaz hale gelir.

    - prune: Bir alert'e kanit olarak bagli olaylar, saklama suresi
      dolsa bile silinmemeli. Yoksa panelde "12 ilgili olay" yazan
      ama hicbirini gosteremeyen alert'ler kalir.
"""

from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.utils import timezone

from engine.loader import load_all_rules
from engine.matcher import evaluate_rule, is_in_cooldown
from events.models import Alert, Event

pytestmark = pytest.mark.django_db


# ── Yardimcilar ──────────────────────────────────────────────

def _kural(rule_id: str):
    """rules/ klasorunden gercek Sigma kuralini yukler."""
    for r in load_all_rules():
        if r.id == rule_id:
            return r
    pytest.skip(f"{rule_id} kurali bulunamadi")


def _olay(event_type: str, **alanlar) -> Event:
    """
    Testler icin minimal gecerli bir Event.

    Model alani OLMAYAN seyler (command, http_status gibi) `extra`
    sozlugune verilmeli — uretimde parser da boyle yapiyor.
    """
    varsayilan = {
        "timestamp": timezone.now(),
        "source": "auth",
        "host": "testhost",
        "event_type": event_type,
        "severity": "low",
    }
    varsayilan.update(alanlar)
    return Event.objects.create(**varsayilan)


# ── Cooldown ─────────────────────────────────────────────────

def test_cooldown_user_ile_gruplanan_kuralda_calisir():
    """
    Ayni kosul iki kez degerlendirilirse ikinci seferde alert
    URETILMEMELI. Bu testin dustugu durum, motorun saniyede bir
    ayni alert'i uretmesi demektir.
    """
    kural = _kural("sentinel-004")        # Suspicious Sudo Activity, count(user) > 5

    for i in range(8):
        _olay("sudo_command", user="yasin")

    ilk = evaluate_rule(kural)
    assert len(ilk) == 1, "Esik asildi, bir alert bekleniyordu"

    ikinci = evaluate_rule(kural)
    assert ikinci == [], (
        "Cooldown devreye girmedi — motor ayni alert'i tekrar uretiyor. "
        "is_in_cooldown gruplama degerine bakmali, sabit bir sutuna degil."
    )


def test_cooldown_farkli_kullaniciyi_engellemez():
    """Cooldown kullaniciya ozel olmali; biri susturuldu diye digeri kacmamali."""
    kural = _kural("sentinel-004")

    for i in range(8):
        _olay("sudo_command", user="yasin")
    assert len(evaluate_rule(kural)) == 1

    for i in range(8):
        _olay("sudo_command", user="baskasi")
    ikinci = evaluate_rule(kural)
    assert len(ikinci) == 1, "Farkli kullanici icin yeni alert uretilmeliydi"
    assert ikinci[0].user == "baskasi"


def test_cooldown_suresi_disinda_tekrar_uretir():
    kural = _kural("sentinel-004")
    for i in range(8):
        _olay("sudo_command", user="yasin")
    assert len(evaluate_rule(kural)) == 1

    # Alert'i cooldown penceresinin disina tasi
    Alert.objects.update(created_at=timezone.now() - timedelta(hours=2))
    assert len(evaluate_rule(kural)) == 1, "Cooldown suresi dolunca yeniden uretmeli"


def test_is_in_cooldown_gruplama_degerine_bakar():
    """Alert group_value ile kaydedilmisse cooldown onu bulmali."""
    Alert.objects.create(
        rule_id="sentinel-004", rule_title="t", severity="high",
        message="m", user="yasin", group_value="yasin", status="new",
    )
    assert is_in_cooldown("sentinel-004", "yasin") is True
    assert is_in_cooldown("sentinel-004", "baskasi") is False
    assert is_in_cooldown("baska-kural", "yasin") is False


# ── Alert alanlari ───────────────────────────────────────────

def test_alert_group_value_ve_user_dolduruluyor():
    kural = _kural("sentinel-004")
    for i in range(8):
        _olay("sudo_command", user="yasin")

    alert = evaluate_rule(kural)[0]
    assert alert.group_value == "yasin", "cooldown bu alana dayaniyor"
    assert alert.user == "yasin"
    assert alert.src_ip is None, "user ile gruplanan kuralda src_ip bos kalmali"


def test_src_ip_ile_gruplanan_kuralda_src_ip_dolar():
    kural = _kural("sentinel-001")        # SSH Brute Force, count(src_ip) > 10
    for i in range(12):
        _olay("auth_failure", src_ip="203.0.113.99", process="sshd", user="root")

    alert = evaluate_rule(kural)[0]
    assert alert.src_ip == "203.0.113.99"
    assert alert.group_value == "203.0.113.99"


# ── prune_events ─────────────────────────────────────────────

def test_prune_alert_kanitini_korur(settings):
    """Bir alert'e bagli olay, saklama suresi dolsa bile silinmemeli."""
    settings.EVENT_RETENTION_DAYS = 0      # her olay "eski" sayilsin
    settings.ALERT_RETENTION_DAYS = 365    # alert'ler korunsun

    eski = timezone.now() - timedelta(days=1)
    bagli = _olay("auth_failure", timestamp=eski, src_ip="1.2.3.4")
    bagsiz = _olay("auth_failure", timestamp=eski, src_ip="5.6.7.8")

    alert = Alert.objects.create(
        rule_id="sentinel-001", rule_title="t", severity="high",
        message="m", src_ip="1.2.3.4", group_value="1.2.3.4", status="new",
    )
    alert.related_events.set([bagli])

    call_command("prune_events", stdout=StringIO())

    assert Event.objects.filter(pk=bagli.pk).exists(), (
        "Alert'in kaniti silindi — panelde kanitsiz alert kalir"
    )
    assert not Event.objects.filter(pk=bagsiz.pk).exists(), (
        "Hicbir alert'e bagli olmayan eski olay silinmeliydi"
    )


def test_prune_dry_run_hicbir_sey_silmez(settings):
    settings.EVENT_RETENTION_DAYS = 0
    settings.ALERT_RETENTION_DAYS = 0

    _olay("auth_failure", timestamp=timezone.now() - timedelta(days=1))
    onceki = Event.objects.count()

    call_command("prune_events", "--dry-run", stdout=StringIO())

    assert Event.objects.count() == onceki, "dry-run veri silmemeli"


# ── Yeni kurallar: kalicilik ve yetki yukseltme ──────────────

def test_user_added_tek_olayda_tetiklenir():
    """
    Esigi 0 olan kural: TEK bir kullanici olusturma olayi bile
    alert uretmeli. Digerleri "cok sayida X" arar, bu aramaz.
    """
    kural = _kural("sentinel-005")
    _olay("user_added", user="arkakapi", severity="medium", source="auth")

    alertler = evaluate_rule(kural)
    assert len(alertler) == 1, "Tek kullanici olusturma olayi alert uretmeliydi"
    assert alertler[0].user == "arkakapi"
    assert alertler[0].severity == "critical"


def test_user_added_olay_yoksa_tetiklenmez():
    """Esik 0 diye bos pencerede alert uretmemeli."""
    kural = _kural("sentinel-005")
    assert evaluate_rule(kural) == []


def test_sudo_failure_tetiklenir():
    kural = _kural("sentinel-006")
    _olay("sudo_failure", user="yetkisiz", severity="high")

    alertler = evaluate_rule(kural)
    assert len(alertler) == 1
    assert alertler[0].user == "yetkisiz"


def test_kural_kendi_cooldown_suresini_kullanir():
    """
    sentinel-005 cooldown'i 1 saat. Alert 10 dakika once uretilmis
    olsa bile tekrar uretilmemeli — motorun 5 dakikalik varsayilani
    degil, kuralin kendi suresi gecerli olmali.
    """
    kural = _kural("sentinel-005")
    assert kural.cooldown == "1h", "Kural dosyasinda cooldown tanimli olmali"

    _olay("user_added", user="arkakapi")
    assert len(evaluate_rule(kural)) == 1

    # Varsayilan cooldown (5dk) disina, kural cooldown'i (1s) icine tasi
    Alert.objects.update(created_at=timezone.now() - timedelta(minutes=10))

    assert evaluate_rule(kural) == [], (
        "Kuralin kendi cooldown suresi yok sayildi — motor varsayilani kullaniyor"
    )