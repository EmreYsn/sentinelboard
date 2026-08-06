"""
detector.py — Anomali tespit modeli

İki yöntem birlikte çalışır:

1. Z-SCORE (İstatistiksel)
   Her feature için: z = (değer - ortalama) / standart_sapma
   z > threshold → anomali

   Avantaj: basit, hızlı, açıklanabilir
   Dezavantaj: tek feature'a bakar, kombinasyonları kaçırır

2. ISOLATION FOREST (ML)
   Rastgele ağaçlarla veri noktalarını izole eder.
   Normal noktalar: çok bölme gerekir (ağacın derininde)
   Anomali noktalar: az bölme yeter (ağacın tepesinde)

   Avantaj: çok boyutlu, kombinasyonları yakalar
   Dezavantaj: "neden anomali" sorusuna yanıt vermesi zor

İkisini birlikte kullanmak en güçlü yaklaşım.

Baseline nedir?
    Model "normal"in ne olduğunu bilmeli. Bunun için
    geçmiş verilere bakıp ortalama ve standart sapma hesaplar.
    Bu öğrenme sürecine "baseline oluşturma" denir.
    Yeterli geçmiş veri yoksa model çalışmaz — bu normal,
    ilk birkaç gün veri toplamak gerekir.
"""

import logging
import json
import os
import numpy as np
from dataclasses import dataclass

logger = logging.getLogger("sentinelboard.ml.detector")


@dataclass
class AnomalyResult:
    """
    Anomali tespitinin sonucu.

    is_anomaly: anomali var mı?
    score: ne kadar anormal (0-1 arası, 1 = çok anormal)
    details: hangi feature'lar anormal ve neden
    method: hangi yöntem tespit etti
    """
    is_anomaly: bool
    score: float
    details: dict
    method: str
    feature_vector: list


class AnomalyDetector:
    """
    Z-score + Isolation Forest tabanlı anomali tespit motoru.

    Kullanım:
        detector = AnomalyDetector()

        # Baseline oluştur (geçmiş verilerden)
        detector.fit(historical_feature_vectors)

        # Yeni veriyi kontrol et
        result = detector.predict(new_feature_vector)
        if result.is_anomaly:
            print("Anomali tespit edildi!")
    """

    def __init__(self, z_threshold: float = 2.5, contamination: float = 0.1):
        """
        Args:
            z_threshold: Z-score eşiği. Bu değerin üstü = anomali.
                2.0 → %4.6 false positive (hassas, çok alarm)
                2.5 → %1.2 false positive (dengeli)
                3.0 → %0.3 false positive (az alarm, bazı tehditleri kaçırır)

            contamination: Isolation Forest'ın "verideki anomali oranı" tahmini.
                0.1 → verinin %10'u anomali olabilir
                Gerçek dünyada güvenlik loglarında %5-10 makul.
        """
        self.z_threshold = z_threshold
        self.contamination = contamination

        # Baseline istatistikleri (fit() ile doldurulur)
        self.means = None       # Her feature'ın ortalaması
        self.stds = None        # Her feature'ın standart sapması
        self.is_fitted = False  # Model eğitildi mi?

        # Isolation Forest modeli
        self.iso_forest = None

        # Feature isimleri (debug ve raporlama için)
        from ml.features import FeatureVector
        self.feature_names = FeatureVector.feature_names()

    def fit(self, feature_vectors: list[list[float]]) -> bool:
        """
        Geçmiş verilerden baseline oluşturur (modeli eğitir).

        Args:
            feature_vectors: Geçmiş zaman pencerelerinin feature listesi.
                Her eleman bir FeatureVector.to_list() çıktısı.

        Returns:
            True: başarıyla eğitildi
            False: yeterli veri yok

        Minimum veri neden gerekli?
            5 veri noktasıyla ortalama ve standart sapma hesaplamak
            güvenilir değil. En az 10 pencere (100 dakikalık veri)
            olması lazım. İdeal: 24 saatlik veri (144 pencere).
        """
        if len(feature_vectors) < 10:
            logger.warning(
                f"Not enough data for baseline: {len(feature_vectors)} vectors "
                f"(need at least 10). Collecting more data..."
            )
            return False

        # Boş pencereleri filtrele (gece 3'te log olmaz, normal)
        # Ama tamamen boş pencereler istatistiği bozar
        non_empty = [v for v in feature_vectors if sum(v) > 0]

        if len(non_empty) < 5:
            logger.warning("Not enough non-empty windows for baseline")
            return False

        data = np.array(non_empty)

        # ── Z-score baseline ──
        # np.mean → her sütunun (feature'ın) ortalaması
        # np.std → her sütunun standart sapması
        # axis=0 → satırlar üzerinden hesapla (her feature ayrı ayrı)
        self.means = np.mean(data, axis=0)
        self.stds = np.std(data, axis=0)

        # Standart sapma 0 olan feature'lar (hiç değişmemiş)
        # Sıfıra bölme hatası olmasın diye küçük bir değer koy
        self.stds[self.stds == 0] = 0.001

        # ── Isolation Forest ──
        try:
            from sklearn.ensemble import IsolationForest

            self.iso_forest = IsolationForest(
                contamination=self.contamination,
                random_state=42,  # Tekrarlanabilirlik için sabit seed
                n_estimators=100,  # 100 ağaç kullan
            )
            self.iso_forest.fit(data)
            logger.info("Isolation Forest model trained")
        except ImportError:
            logger.warning("scikit-learn not installed, using Z-score only")
            self.iso_forest = None

        self.is_fitted = True
        logger.info(
            f"Baseline created from {len(non_empty)} windows. "
            f"Means: {[round(m, 2) for m in self.means]}"
        )
        return True

    def predict(self, feature_vector: list[float]) -> AnomalyResult:
        """
        Tek bir feature vektörünün anomali olup olmadığını kontrol eder.

        İki yöntemin sonuçları birleştirilir:
        - Z-score herhangi bir feature'da eşiği aşıyorsa → anomali ipucu
        - Isolation Forest anomali diyorsa → anomali ipucu
        - İkisi birden diyorsa → kesin anomali

        Score hesaplama:
            0.0 = tamamen normal
            0.5 = şüpheli
            1.0 = kesinlikle anormal
        """
        if not self.is_fitted:
            return AnomalyResult(
                is_anomaly=False,
                score=0.0,
                details={"error": "Model not fitted yet"},
                method="none",
                feature_vector=feature_vector,
            )

        vector = np.array(feature_vector)
        details = {}
        anomaly_signals = 0
        total_checks = 0

        # ── Z-score kontrolü ──
        z_scores = (vector - self.means) / self.stds
        z_anomalies = {}

        for i, (z, name) in enumerate(zip(z_scores, self.feature_names)):
            if abs(z) > self.z_threshold:
                z_anomalies[name] = {
                    "value": float(vector[i]),
                    "mean": float(self.means[i]),
                    "std": float(self.stds[i]),
                    "z_score": round(float(z), 2),
                }

        if z_anomalies:
            anomaly_signals += 1
            details["z_score"] = {
                "anomalous_features": z_anomalies,
                "threshold": self.z_threshold,
            }

        total_checks += 1

        # ── Isolation Forest kontrolü ──
        if self.iso_forest is not None:
            # predict: 1 = normal, -1 = anomali
            prediction = self.iso_forest.predict([feature_vector])[0]
            # decision_function: ne kadar anormal (negatif = anormal)
            iso_score = self.iso_forest.decision_function([feature_vector])[0]

            if prediction == -1:
                anomaly_signals += 1

            details["isolation_forest"] = {
                "prediction": "anomaly" if prediction == -1 else "normal",
                "score": round(float(iso_score), 4),
            }
            total_checks += 1

        # ── Sonuç birleştirme ──
        # Score: anomali sinyallerinin oranı (0.0 - 1.0)
        score = anomaly_signals / total_checks if total_checks > 0 else 0.0

        # En az bir yöntem anomali dediyse → anomali
        is_anomaly = anomaly_signals > 0

        method = "z_score+isolation_forest" if self.iso_forest else "z_score"

        if is_anomaly:
            logger.warning(
                f"ANOMALY detected (score={score:.2f}): "
                f"{details}"
            )

        return AnomalyResult(
            is_anomaly=is_anomaly,
            score=score,
            details=details,
            method=method,
            feature_vector=feature_vector,
        )

    def save_baseline(self, filepath: str):
        """
        Baseline'ı dosyaya kaydeder.

        Neden kaydetmemiz lazım?
            Model her restart'ta baseline'ı sıfırdan hesaplamak
            yerine kayıtlı baseline'ı yükleyebilir. Bu sayede
            worker restart edilse bile öğrendiğini kaybetmez.
        """
        if not self.is_fitted:
            logger.warning("Cannot save: model not fitted")
            return

        data = {
            "means": self.means.tolist(),
            "stds": self.stds.tolist(),
            "z_threshold": self.z_threshold,
            "contamination": self.contamination,
        }

        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Baseline saved to {filepath}")

    def load_baseline(self, filepath: str) -> bool:
        """Kayıtlı baseline'ı yükler."""
        if not os.path.exists(filepath):
            logger.info(f"No saved baseline at {filepath}")
            return False

        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            self.means = np.array(data["means"])
            self.stds = np.array(data["stds"])
            self.z_threshold = data.get("z_threshold", 2.5)
            self.is_fitted = True

            logger.info(f"Baseline loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False