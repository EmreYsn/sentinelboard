"""
SentinelBoard — Alert & Notification Module

Bu modül korelasyon motoru veya ML modülü bir tehdit tespit
ettiğinde seni bilgilendirir.

Alert akışı:
    1. Engine/ML bir tehdit tespit eder → Alert nesnesi oluşturur
    2. Alert severity'sine göre kanal seçilir:
       - info/low   → sadece dashboard'da göster
       - medium     → dashboard + email
       - high       → dashboard + Telegram
       - critical   → dashboard + Telegram + email
    3. Cooldown kontrolü: aynı kural aynı IP için son 5 dakikada
       alert verdiyse tekrar vermez (alert fatigue koruması)

Alert Fatigue nedir?
    Çok fazla alarm gelince insanlar alarmlara duyarsızlaşır.
    Gerçek dünyada SOC analistlerinin en büyük sorunu bu.
    O yüzden cooldown mekanizması ve severity seviyeleri kritik.

Neden Telegram?
    - Anlık bildirim (push notification)
    - Ücretsiz, bot API'si çok kolay
    - Telefondan anında görebilirsin
    - Gruplara da gönderebilirsin (takım çalışması için)
"""
