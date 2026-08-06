"""
SentinelBoard — ML Anomaly Detection Module

Bu modül rule-based tespitlerin yakalayamadığı şeyleri yakalar.

Rule-based vs ML-based tespit farkı:
    Rule-based: "5 dakikada 10+ başarısız giriş = brute force"
        ✅ Kesin, açıklanabilir, hızlı
        ❌ Sadece bildiğin pattern'ları yakalar

    ML-based: "Bu davranış normal baseline'dan sapıyor"
        ✅ Bilinmeyen tehditleri yakalayabilir
        ✅ Kendini adapte eder
        ❌ False positive riski daha yüksek
        ❌ "Neden alarm verdi?" sorusuna yanıt vermek daha zor

    İkisini birlikte kullanmak en güçlü yaklaşım. Kurallar bilinen
    tehditleri yakalar, ML bilinmeyenleri yakalar. Defense in depth.

Nasıl çalışır:
    1. BASELINE OLUŞTURMA (ilk 7 gün)
       - Saatlik event sayısı
       - Benzersiz IP sayısı
       - Başarısız/başarılı giriş oranı
       - Yeni process sayısı
       Bu metriklerin ortalaması ve standart sapması hesaplanır.

    2. ANOMALİ TESPİTİ (baseline'dan sonra)
       Her periyotta mevcut metrikleri baseline ile karşılaştırır.
       Z-score hesaplar: (mevcut - ortalama) / standart_sapma
       Z-score > threshold → anomali

    3. İLERİ SEVİYE (opsiyonel)
       - Isolation Forest: çok boyutlu anomali tespiti
       - LSTM: zaman serisi pattern'ları öğrenme
       - Clustering: benzer olayları gruplama

Z-score nedir?
    Bir değerin ortalamadan kaç standart sapma uzakta olduğu.
    Z-score = 0 → tam ortalama
    Z-score = 1 → ortalamanın 1 std sapma üstünde
    Z-score = 2.5 → ortalamanın 2.5 std sapma üstünde (çok nadir)
    Z-score > 3 → neredeyse kesinlikle anormal (%0.3 olasılık)
"""
