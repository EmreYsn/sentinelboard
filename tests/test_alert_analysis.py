"""
Alert LLM analizinin saklanmasina dair davranis testleri.

Neden bu testler?
    Analiz saklanmadigi surece panelde her "AI" tiklamasi saglayiciya
    yeni bir istek gonderiyordu. Ayni alert'i ikinci kez acmak ayni
    metni yeniden urettiriyor, Groq'un dakikalik output token kotasini
    (ucretsiz katmanda 1000) bosa harciyordu. 12.10.2026'da yasanan
    429 zincirinin ikinci sebebi buydu.

    Asagidaki testler "kayitli analiz varken LLM'e GIDILMEZ" sozlesmesini
    kilitliyor. Bu bir hiz optimizasyonu degil, kota korumasi: testin
    dusmesi, panelin yine kota yakmaya basladigi anlamina gelir.
"""

import json

import pytest
from django.urls import reverse
from django.utils import timezone

from events.models import Alert

pytestmark = pytest.mark.django_db


# ── Yardimcilar ──────────────────────────────────────────────

def _alert(**alanlar) -> Alert:
    varsayilan = dict(
        rule_id="sentinel-004",
        rule_title="Suspicious Sudo Activity",
        severity="high",
        message="7 events detected from user=yasin in last 5m",
        tags=["attack.privilege_escalation", "attack.t1548.003"],
    )
    varsayilan.update(alanlar)
    return Alert.objects.create(**varsayilan)


class SayanAnaliz:
    """analyze_alert yerine gecer ve kac kez cagrildigini sayar.

    Gercek fonksiyon aga cikiyor; testin olctugu sey ise cagrinin
    YAPILIP yapilmadigi, yani sayac tam olarak dogru olcum araci.
    """

    def __init__(self, sonuc=None):
        self.cagri = 0
        self.sonuc = sonuc or {
            "success": True, "analysis": "YENI URETILEN ANALIZ", "error": None,
        }

    def __call__(self, alert):
        self.cagri += 1
        return self.sonuc


def _analiz_et(client, alert, force=None):
    url = reverse("analyze-alert", args=[alert.id])
    govde = {} if force is None else {"force": force}
    return client.post(url, data=json.dumps(govde),
                       content_type="application/json")


# ── Kota korumasi ────────────────────────────────────────────

def test_kayitli_analiz_varken_llm_cagrilmaz(client, monkeypatch):
    """
    Bu testin dustugu durum, panelin her tiklamada kota yakmasi demektir.
    """
    sahte = SayanAnaliz()
    monkeypatch.setattr("events.views.analyze_alert", sahte)

    alert = _alert(llm_analysis="ONCEDEN KAYDEDILMIS ANALIZ",
                   llm_analyzed_at=timezone.now())
    yanit = _analiz_et(client, alert)

    assert yanit.status_code == 200
    assert sahte.cagri == 0, (
        "Kayitli analiz varken yine de LLM'e gidilmis — kota bosa harcaniyor"
    )
    veri = yanit.json()
    assert veri["success"] is True
    assert veri["analysis"] == "ONCEDEN KAYDEDILMIS ANALIZ"
    assert veri["cached"] is True
    assert veri["analyzed_at"] is not None


def test_analiz_yokken_bir_kez_cagrilir(client, monkeypatch):
    sahte = SayanAnaliz()
    monkeypatch.setattr("events.views.analyze_alert", sahte)

    alert = _alert()
    veri = _analiz_et(client, alert).json()

    assert sahte.cagri == 1
    assert veri["cached"] is False
    assert veri["analysis"] == "YENI URETILEN ANALIZ"


def test_basarili_analiz_veritabanina_yazilir(client, monkeypatch):
    """Uretilen analiz saklanmazsa bir sonraki tiklama yine kota yakar."""
    monkeypatch.setattr("events.views.analyze_alert", SayanAnaliz())

    alert = _alert()
    _analiz_et(client, alert)

    alert.refresh_from_db()
    assert alert.llm_analysis == "YENI URETILEN ANALIZ"
    assert alert.llm_analyzed_at is not None
    assert alert.has_analysis is True


def test_ikinci_tiklama_llm_cagirmaz(client, monkeypatch):
    """Uctan uca: ayni alert'e iki kez basmak tek cagri yapmali."""
    sahte = SayanAnaliz()
    monkeypatch.setattr("events.views.analyze_alert", sahte)

    alert = _alert()
    _analiz_et(client, alert)
    _analiz_et(client, alert)

    assert sahte.cagri == 1, (
        f"Iki tiklamada {sahte.cagri} cagri yapildi; ikincisi kayittan "
        "donmeliydi"
    )


# ── Bilincli yeniden analiz ──────────────────────────────────

def test_force_ile_yeniden_analiz_yapilir(client, monkeypatch):
    """
    Yeniden analiz mumkun olmali, ama yalnizca acikca istendiginde.
    Kazara tiklamayla kota harcanmamasi icin ayri bir eylem.
    """
    sahte = SayanAnaliz({"success": True, "analysis": "GUNCELLENMIS", "error": None})
    monkeypatch.setattr("events.views.analyze_alert", sahte)

    alert = _alert(llm_analysis="ESKI ANALIZ", llm_analyzed_at=timezone.now())
    veri = _analiz_et(client, alert, force=True).json()

    assert sahte.cagri == 1
    assert veri["cached"] is False
    assert veri["analysis"] == "GUNCELLENMIS"

    alert.refresh_from_db()
    assert alert.llm_analysis == "GUNCELLENMIS", "Yeni analiz kaydedilmemis"


@pytest.mark.parametrize("deger", ["true", "True", "1", "yes", True])
def test_force_farkli_bicimleri_kabul_eder(client, monkeypatch, deger):
    """Istemci true, "true" ya da 1 gonderebilir; hepsi ayni anlama gelir."""
    sahte = SayanAnaliz()
    monkeypatch.setattr("events.views.analyze_alert", sahte)

    alert = _alert(llm_analysis="ESKI", llm_analyzed_at=timezone.now())
    _analiz_et(client, alert, force=deger)

    assert sahte.cagri == 1


@pytest.mark.parametrize("deger", ["false", "0", False, ""])
def test_force_olmayan_degerler_kayittan_doner(client, monkeypatch, deger):
    sahte = SayanAnaliz()
    monkeypatch.setattr("events.views.analyze_alert", sahte)

    alert = _alert(llm_analysis="ESKI", llm_analyzed_at=timezone.now())
    veri = _analiz_et(client, alert, force=deger).json()

    assert sahte.cagri == 0
    assert veri["cached"] is True


# ── Hata durumlari ───────────────────────────────────────────

def test_basarisiz_analiz_kayitli_metni_silmez(client, monkeypatch):
    """
    Yeniden analiz basarisiz olursa (kota, zaman asimi) elindeki
    calisan analizi kaybetmemelisin. Hatanin bedeli veri kaybi olmamali.
    """
    sahte = SayanAnaliz({"success": False, "analysis": "",
                         "error": "LLM saglayicisinin kotasi doldu."})
    monkeypatch.setattr("events.views.analyze_alert", sahte)

    alert = _alert(llm_analysis="CALISAN ESKI ANALIZ",
                   llm_analyzed_at=timezone.now())
    veri = _analiz_et(client, alert, force=True).json()

    assert veri["success"] is False
    alert.refresh_from_db()
    assert alert.llm_analysis == "CALISAN ESKI ANALIZ", (
        "Basarisiz cagri kayitli analizin uzerine yazmis"
    )


def test_basarisiz_analiz_kaydedilmez(client, monkeypatch):
    """Bos analiz saklanirsa sonraki tiklama onu 'kayitli' sanir."""
    monkeypatch.setattr("events.views.analyze_alert",
                        SayanAnaliz({"success": False, "analysis": "",
                                     "error": "zaman asimi"}))
    alert = _alert()
    _analiz_et(client, alert)

    alert.refresh_from_db()
    assert alert.llm_analysis == ""
    assert alert.llm_analyzed_at is None
    assert alert.has_analysis is False


def test_olmayan_alert_404_doner(client):
    import uuid
    url = reverse("analyze-alert", args=[uuid.uuid4()])
    assert client.post(url, data="{}", content_type="application/json").status_code == 404


# ── Liste API'si ─────────────────────────────────────────────

def test_liste_analiz_varligini_bildirir_metni_tasimaz(client):
    """
    Panel, hangi alert'in kayitli analizi oldugunu listeden ogrenmeli ki
    butonu ona gore etiketlesin. Ama analiz METNI listeye konmamali:
    200 alert'lik bir yanitta her biri birkac kilobayt tasirsa yanit siser.
    """
    _alert(llm_analysis="UZUN ANALIZ METNI", llm_analyzed_at=timezone.now())
    _alert(rule_id="sentinel-006", rule_title="Sudo Failure")

    yanit = client.get(reverse("alert-list"))
    assert yanit.status_code == 200

    satirlar = yanit.json()
    satirlar = satirlar.get("results", satirlar)
    bayraklar = sorted(s["has_analysis"] for s in satirlar)
    assert bayraklar == [False, True]
    assert "UZUN ANALIZ METNI" not in yanit.content.decode(), (
        "Analiz metni liste yanitina sizmis"
    )