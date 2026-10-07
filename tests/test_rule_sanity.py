"""
Kural dosyalarinin YAPISAL tutarliligini denetler.

Digerleri kurallarin MANTIGINI test eder ("8 sudo komutu alert uretir mi").
Bu dosya ise kurallarin KENDISINI denetler: yazim hatasi, eksik alan,
birbiriyle celisen ayarlar. Buna "kural linting" denir.

Neden gerekli?
    Tutarsiz bir kural hata vermez — sadece yanlis davranir. Ornegi
    yasandi: user_added kuralinin penceresi 24 saat, cooldown'i 1 saatti.
    Olay 24 saat boyunca pencerede kaldigi icin kural her saat basi
    kendini tekrarladi: tek bir kullanici olusturma olayi 24 bildirim
    uretecekti.

    Kural su: COOLDOWN, PENCEREDEN KISA OLAMAZ. Aksi halde olay
    pencereden dusmeden cooldown doluyor ve ayni olay yeniden
    alert uretiyor.
"""

import pytest

from engine.loader import load_all_rules, parse_timeframe
from engine.matcher import ALERT_COOLDOWN, parse_condition


def _kurallar():
    kurallar = load_all_rules()
    assert kurallar, "Hic kural yuklenemedi"
    return kurallar


def test_cooldown_pencereden_kisa_olamaz():
    """
    Cooldown < timeframe ise ayni olay birden fazla alert uretir.
    Bildirim yagmuru olarak ortaya cikar ve gercek alarmlari bogar.
    """
    hatalar = []
    for k in _kurallar():
        pencere = parse_timeframe(k.timeframe)
        cooldown = parse_timeframe(k.cooldown) if k.cooldown else ALERT_COOLDOWN
        if cooldown < pencere:
            hatalar.append(
                f"  {k.id} ({k.title}): pencere={k.timeframe} "
                f"({pencere}sn) > cooldown={k.cooldown or 'varsayilan'} ({cooldown}sn)"
            )

    if hatalar:
        pytest.fail(
            "Cooldown suresi pencereden kisa olan kurallar var. Bu kurallar "
            "ayni olay icin tekrar tekrar alert uretir:\n" + "\n".join(hatalar)
        )


def test_her_kuralin_condition_i_ayristirilabiliyor():
    """Ayristirilamayan condition sessizce kurali devre disi birakir."""
    for k in _kurallar():
        assert parse_condition(k.condition) is not None, (
            f"{k.id} ({k.title}) condition'i ayristirilamiyor: {k.condition!r}"
        )


def test_kural_id_leri_benzersiz():
    """Ayni id iki kuralda olursa cooldown'lari birbirine karisir."""
    idler = [k.id for k in _kurallar()]
    tekrar = {i for i in idler if idler.count(i) > 1}
    assert not tekrar, f"Tekrar eden kural id'leri: {tekrar}"


def test_her_kuralin_mitre_etiketi_var():
    """
    Tespitleri ATT&CK'e eslemek, 'bu alert neyi anlatiyor' sorusunun
    cevabini kuralin icine koyar. Panelde ve raporda dogrudan kullaniliyor.
    """
    eksik = [f"{k.id} ({k.title})" for k in _kurallar()
             if not any(t.startswith("attack.t") for t in k.tags)]
    assert not eksik, f"MITRE teknik etiketi olmayan kurallar: {eksik}"