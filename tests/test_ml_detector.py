"""
Anomali tespit mantiginin gurultu suzgeclerini dogrular.

Neden bu testler?
    Uc gunde 74 ML bildirimi geldi ve cogu anlamsizdi. Olcunce iki ayri
    sebep cikti:

    1) Varyansi cok dusuk feature'larda z-score patliyor.
       auth_successes ortalamasi 0.035, sapmasi 0.18 — tek bir basarili
       giris z=5 uretiyor. Istatistiksel olarak uc, operasyonel olarak
       hicbir sey. Cozum: mutlak sapma sarti.

    2) Karar tek yonteme birakilmisti. 74 alert'in 70'ini z-score tek
       basina uretmisti, Isolation Forest sadece 24'unu dogruluyordu.
       Cozum: iki yontemin anlasmasi sarti.

    Asagidaki testler ikisini de kilitliyor.
"""

import numpy as np
import pytest

from ml.detector import AnomalyDetector
from ml.features import FeatureVector

ADLAR = FeatureVector.feature_names()
I_AUTH_BASARILI = ADLAR.index("auth_successes")
I_AUTH_HATA = ADLAR.index("auth_failures")


class SahteOrman:
    """Isolation Forest yerine gecen, kararini onceden bildigimiz nesne."""

    def __init__(self, anomali: bool):
        self._tahmin = -1 if anomali else 1

    def predict(self, X):
        return [self._tahmin]

    def decision_function(self, X):
        return [-0.1 if self._tahmin == -1 else 0.1]


def _temel_vektor():
    """Sunucunun 'normal' hali: auth_successes hep 0, digerleri sabit."""
    v = [0.0] * len(ADLAR)
    v[ADLAR.index("total_events")] = 250.0
    v[ADLAR.index("unique_src_ips")] = 38.0
    v[ADLAR.index("unique_dst_ports")] = 30.0
    v[I_AUTH_HATA] = 70.0
    v[I_AUTH_BASARILI] = 0.0
    v[ADLAR.index("auth_failure_ratio")] = 1.0
    v[ADLAR.index("suspicious_requests")] = 12.0
    v[ADLAR.index("firewall_blocks")] = 30.0
    v[ADLAR.index("unique_event_types")] = 6.0
    return v


def _egitilmis(anomali_ormani: bool | None = None, **ayarlar):
    """Kucuk jitter'li 30 pencereyle egitilmis bir dedektor."""
    d = AnomalyDetector(**ayarlar)
    rng = np.random.default_rng(42)
    pencereler = []
    for _ in range(30):
        v = _temel_vektor()
        v[0] += float(rng.normal(0, 5))     # total_events biraz oynasin
        v[1] += float(rng.normal(0, 2))
        pencereler.append(v)
    assert d.fit(pencereler), "Dedektor egitilemedi"

    if anomali_ormani is None:
        d.iso_forest = None
    else:
        d.iso_forest = SahteOrman(anomali_ormani)
    return d


# ── Mutlak sapma suzgeci ────────────────────────────────────

def test_dusuk_varyansli_feature_tek_birimlik_degisimde_alert_uretmez():
    """
    auth_successes hep 0 iken tek bir basarili giris z-score'u patlatiyor
    (std 0.001'e sabitlendigi icin z=1000). Mutlak fark 1 birim; bu,
    'bu sunucuda biri giris yapti' demek — alarm degil.
    """
    d = _egitilmis(anomali_ormani=None)          # tek yontem: sadece z
    v = _temel_vektor()
    v[I_AUTH_BASARILI] = 1.0

    sonuc = d.predict(v)
    assert not sonuc.is_anomaly, (
        "Tek birimlik degisim alert uretti — mutlak sapma suzgeci calismiyor"
    )


def test_gercek_sicrama_hala_yakalaniyor():
    """Suzgec gurultuyu elerken gercek sicramayi elememeli."""
    d = _egitilmis(anomali_ormani=None)
    v = _temel_vektor()
    v[I_AUTH_HATA] = 209.0                       # 70 -> 209

    sonuc = d.predict(v)
    assert sonuc.is_anomaly, "Ortalamanin uc kati bir sicrama kacirildi"
    assert "auth_failures" in sonuc.details["z_score"]["anomalous_features"]


# ── Iki yontemin anlasmasi ──────────────────────────────────

def test_isolation_forest_onaylamazsa_alert_yok():
    """z 'anormal' derken Isolation Forest 'normal' diyorsa susmali."""
    d = _egitilmis(anomali_ormani=False)
    v = _temel_vektor()
    v[I_AUTH_HATA] = 209.0

    sonuc = d.predict(v)
    assert not sonuc.is_anomaly, (
        "Tek yontem karar verdi — anlasma sarti devre disi kalmis"
    )


def test_iki_yontem_anlasinca_alert_var():
    d = _egitilmis(anomali_ormani=True)
    v = _temel_vektor()
    v[I_AUTH_HATA] = 209.0

    sonuc = d.predict(v)
    assert sonuc.is_anomaly
    assert sonuc.score == 1.0, "Iki yontem de isaret ettiyse skor tam olmali"


def test_anlasma_sarti_kapatilabiliyor():
    """Ayar olarak kalmali: baska bir ortamda tek yontem tercih edilebilir."""
    d = _egitilmis(anomali_ormani=False, require_agreement=False)
    v = _temel_vektor()
    v[I_AUTH_HATA] = 209.0

    assert d.predict(v).is_anomaly


def test_isolation_forest_yoksa_z_tek_basina_karar_verir():
    """Model egitilememisse hic uyarmamaktansa z-score ile uyarmak yegdir."""
    d = _egitilmis(anomali_ormani=None)
    v = _temel_vektor()
    v[I_AUTH_HATA] = 209.0

    assert d.predict(v).is_anomaly


def test_normal_pencere_alert_uretmez():
    d = _egitilmis(anomali_ormani=True)
    assert not d.predict(_temel_vektor()).is_anomaly