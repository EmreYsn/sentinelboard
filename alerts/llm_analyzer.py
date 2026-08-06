"""
llm_analyzer.py — LLM ile alert analizi (Google Gemini)

Google Gemini API nedir?
    Google'ın LLM'i. Ücretsiz katmanı var ve güvenlik
    analizi için gayet yeterli. REST API ile çalışıyor —
    tek bir HTTP POST isteği ile yanıt alıyorsun.

Neden Gemini?
    - Ücretsiz katman: dakikada 15 istek, yeterli
    - Türkçe desteği iyi
    - API kullanımı çok basit
"""

import os
import logging

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("sentinelboard.alerts.llm_analyzer")

API_KEY = os.getenv("GEMINI_API_KEY", "")
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"


def build_analysis_prompt(alert, events=None) -> str:
    """Alert ve event verilerinden LLM prompt'u oluşturur."""

    event_summary = ""
    if events:
        event_list = list(events[:10])
        event_lines = []
        for ev in event_list:
            event_lines.append(
                f"  - [{ev.severity}] {ev.event_type} | "
                f"IP: {ev.src_ip} | User: {ev.user} | "
                f"Time: {ev.timestamp} | {ev.message or ev.raw[:100]}"
            )
        event_summary = "\n".join(event_lines)
        if events.count() > 10:
            event_summary += f"\n  ... and {events.count() - 10} more events"

    prompt = f"""Sen deneyimli bir SOC (Security Operations Center) analistisin. SentinelBoard SIEM sisteminden gelen bir güvenlik alert'ini inceliyorsun.

## Alert Detayları
- **Kural:** {alert.rule_title}
- **Kural ID:** {alert.rule_id}
- **Severity:** {alert.severity}
- **Kaynak IP:** {alert.src_ip or 'N/A'}
- **Kullanıcı:** {alert.user or 'N/A'}
- **Mesaj:** {alert.message}
- **MITRE ATT&CK Tags:** {', '.join(alert.tags) if alert.tags else 'Yok'}
- **Zaman:** {alert.created_at}

## İlgili Event'ler
{event_summary if event_summary else 'Event detayı mevcut değil.'}

## Analiz Talebi
Lütfen aşağıdaki yapıda Türkçe bir güvenlik analizi yap:

1. **Özet**: Bu alert'in kısa ve net açıklaması (2-3 cümle)

2. **Tehdit Değerlendirmesi**: Bu aktivite neden şüpheli? Saldırgan ne yapmaya çalışıyor olabilir? MITRE ATT&CK framework'üne göre bu hangi saldırı aşamasına denk geliyor?

3. **Risk Seviyesi**: Düşük / Orta / Yüksek / Kritik — ve neden bu seviye?

4. **Önerilen Aksiyonlar**: SOC analisti olarak ne yapılmalı? (en az 3 somut adım)

5. **False Positive Değerlendirmesi**: Bu alert'in false positive olma olasılığı nedir ve nasıl doğrulanır?

Kısa, öz ve aksiyon odaklı yaz."""

    return prompt


def analyze_alert(alert) -> dict:
    """
    Bir alert'i Gemini ile analiz eder.

    Gemini API formatı:
        POST /v1beta/models/gemini-2.0-flash:generateContent?key=API_KEY
        Body: { "contents": [{ "parts": [{ "text": "prompt" }] }] }

    Yanıt formatı:
        { "candidates": [{ "content": { "parts": [{ "text": "yanıt" }] } }] }
    """
    if not API_KEY:
        return {
            "success": False,
            "analysis": "",
            "error": "GEMINI_API_KEY is not set in .env file"
        }

    # İlgili event'leri çek
    events = alert.related_events.all().order_by("-timestamp")
    prompt = build_analysis_prompt(alert, events)

    try:
        response = requests.post(
            f"{API_URL}?key={API_KEY}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{
                    "parts": [{"text": prompt}]
                }],
                "generationConfig": {
                    "maxOutputTokens": 1500,
                    "temperature": 0.3,
                }
            },
            timeout=30,
        )

        if response.status_code == 200:
            data = response.json()
            # Gemini yanıt formatı
            analysis_text = data["candidates"][0]["content"]["parts"][0]["text"]

            logger.info(f"LLM analysis completed for alert {alert.id}")

            return {
                "success": True,
                "analysis": analysis_text,
                "error": None,
            }
        else:
            error_msg = f"API error {response.status_code}: {response.text[:200]}"
            logger.error(error_msg)
            return {
                "success": False,
                "analysis": "",
                "error": error_msg,
            }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "analysis": "",
            "error": "API request timed out (30s)"
        }
    except Exception as e:
        logger.error(f"LLM analysis error: {e}")
        return {
            "success": False,
            "analysis": "",
            "error": str(e),
        }