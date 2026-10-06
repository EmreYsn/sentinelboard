"""
Tum testler icin ortak ayarlar.

Neden bu dosya var?
    engine/matcher.py bir alert urettiginde send_alert() cagirarak
    Telegram'a bildirim gonderiyor. Testlerde bu cagri GERCEKTEN
    calisiyordu: uydurma kullanici adlariyla ("arkakapi", "yetkisiz")
    olusturulan test alert'leri telefona dusuyordu.

    Bu iki acidan yanlis:
      1) Testin dis dunyaya yan etkisi olmamali. Bildirim kanalinin
         kirlenmesi bir yana, gercek bir olay sanilip panige yol acabilir.
      2) Test agdan bagimsiz olmali. Telegram erisilemezse testler
         yavaslar ya da hata verir — oysa test edilen sey korelasyon
         mantigi, ag degil.

    Asagidaki fixture autouse: her teste otomatik uygulanir, ayrica
    istemek gerekmez.
"""

import sys

import pytest


@pytest.fixture(autouse=True)
def telegram_gondermeyi_kapat(monkeypatch):
    """Testler sirasinda hicbir bildirim disari cikmaz."""

    def _yut(alert):
        return False  # gercek send_alert da basarisizlikta False doner

    # Modul zaten yuklenmisse icindeki ismi degistir.
    # sys.modules uzerinden gidiyoruz ki yan etkisi olabilecek
    # modulleri (ml.worker django.setup() cagiriyor) test ugruna
    # zorla import etmeyelim.
    for modul_adi in ("engine.matcher", "ml.worker", "alerts.telegram_bot"):
        modul = sys.modules.get(modul_adi)
        if modul is not None and hasattr(modul, "send_alert"):
            monkeypatch.setattr(modul, "send_alert", _yut)