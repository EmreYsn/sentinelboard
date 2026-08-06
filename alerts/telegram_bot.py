"""
telegram_bot.py — Telegram üzerinden alert bildirimi gönderir

Bu dosya ne yapıyor?
    Alert üretildiğinde Telegram'a formatlanmış bir mesaj gönderir.
    Telegram Bot API'si çok basit — tek bir HTTP POST isteği ile
    mesaj gönderiyorsun. Kütüphane bile gerekmez aslında ama
    hata yönetimi ve retry için requests kullanıyoruz.

Telegram Bot API nasıl çalışıyor?
    https://api.telegram.org/bot{TOKEN}/sendMessage
    Bu endpoint'e POST isteği gönderiyorsun:
    {
        "chat_id": 123456789,
        "text": "Mesaj içeriği",
        "parse_mode": "HTML"   ← bold, italic gibi formatlama
    }
    Bu kadar. Başka bir şey yok.

parse_mode: HTML nedir?
    Telegram mesajlarında basit HTML tag'leri kullanabilirsin:
    <b>bold</b>, <i>italic</i>, <code>monospace</code>
    Bu sayede alert mesajları daha okunabilir oluyor.
"""

import os
import logging

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("sentinelboard.alerts.telegram")

# .env'den oku
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Telegram API endpoint
API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"


def format_alert_message(alert) -> str:
    """
    Alert objesini okunabilir Telegram mesajına çevirir.

    Emoji'ler severity seviyesine göre değişir:
        critical → 🔴
        high     → 🟠
        medium   → 🟡
        low      → 🔵
        info     → ⚪

    Neden emoji?
        Telefona bildirim geldiğinde ilk gördüğün şey emoji.
        Kırmızı daire görünce "acil" olduğunu anında anlarsın.
    """
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    emoji = severity_emoji.get(alert.severity, "⚪")

    # MITRE ATT&CK tag'lerini formatlı göster
    tags_str = ""
    if alert.tags:
        tags_str = "\n🏷 " + ", ".join(alert.tags)

    message = (
        f"{emoji} <b>SentinelBoard Alert</b>\n"
        f"\n"
        f"<b>Rule:</b> {alert.rule_title}\n"
        f"<b>Severity:</b> {alert.severity.upper()}\n"
        f"<b>Source IP:</b> <code>{alert.src_ip or 'N/A'}</code>\n"
        f"\n"
        f"<b>Details:</b>\n"
        f"{alert.message}\n"
        f"{tags_str}\n"
        f"\n"
        f"<i>Alert ID: {str(alert.id)[:8]}...</i>"
    )

    return message


def send_alert(alert) -> bool:
    """
    Tek bir alert'i Telegram'a gönderir.

    Args:
        alert: Alert model instance

    Returns:
        True: mesaj başarıyla gönderildi
        False: gönderilemedi (token yok, ağ hatası vs.)

    Neden bool dönüyoruz?
        Çağıran kod (engine worker) bildirim gönderilip
        gönderilmediğini bilmeli. Gönderilemezse loglar
        ama sistemi durdurmaz — alert yine DB'de kayıtlı.
    """
    if not BOT_TOKEN or not CHAT_ID:
        logger.warning("Telegram credentials not configured in .env")
        return False

    text = format_alert_message(alert)

    try:
        response = requests.post(
            API_URL,
            json={
                "chat_id": CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                # Bildirim sesini kapat mı? Hayır — alert önemli
                "disable_notification": False,
            },
            timeout=10,  # 10 saniye bekle, daha fazlası → timeout
        )

        if response.status_code == 200:
            logger.info(f"Telegram alert sent: {alert.rule_title}")
            return True
        else:
            logger.error(
                f"Telegram API error {response.status_code}: "
                f"{response.text}"
            )
            return False

    except requests.exceptions.Timeout:
        logger.error("Telegram API timeout")
        return False
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to Telegram API")
        return False
    except Exception as e:
        logger.error(f"Telegram send error: {e}")
        return False


def send_test_message() -> bool:
    """
    Bağlantı testi için basit bir mesaj gönderir.
    """
    if not BOT_TOKEN or not CHAT_ID:
        print("HATA: TELEGRAM_BOT_TOKEN veya TELEGRAM_CHAT_ID .env'de yok")
        return False

    try:
        response = requests.post(
            API_URL,
            json={
                "chat_id": CHAT_ID,
                "text": "✅ <b>SentinelBoard</b> Telegram entegrasyonu aktif!",
                "parse_mode": "HTML",
            },
            timeout=10,
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Hata: {e}")
        return False