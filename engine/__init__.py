"""
SentinelBoard — Correlation Engine

Bu modül normalleştirilmiş logları YAML kurallarıyla karşılaştırır
ve eşleşme olduğunda alert üretir.

Korelasyon nedir?
    Tek bir log satırı genellikle tek başına tehlikeli değildir.
    "Failed password for root" → olabilir, belki şifreyi yanlış girdin.
    Ama aynı IP'den 5 dakikada 50 tane gelirse → brute force saldırısı.

    Korelasyon motoru birden fazla olayı birlikte değerlendirip
    pattern'ları tespit eder. Bu "bağlam içinde anlam çıkarma" işi.

Sigma Kuralları nedir?
    Sigma, güvenlik dünyasının "YARA for logs" kuralı. Açık kaynak,
    platform bağımsız bir detection rule formatı. Binlerce hazır kural var.
    YAML formatında yazılır, okunması ve yazılması kolay.

    Biz kendi motorumuzu yazacağız ama Sigma formatını destekleyeceğiz.
    Bu çok büyük avantaj — topluluktan hazır kural import edebilirsin.

Nasıl çalışır:
    1. engine/rules/ klasöründeki tüm .yml dosyalarını yükler
    2. Her X saniyede (config'den) DB'deki son logları sorgular
    3. Her kural için: "bu kuralın koşulu sağlandı mı?" kontrol eder
    4. Sağlandıysa alert oluşturur → alerts modülüne gönderir
"""
