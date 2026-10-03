import os
import logging

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("sentinelboard.alerts.llm_analyzer")

API_KEY = os.getenv("GROQ_API_KEY", "")
API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")


def build_analysis_prompt(alert, events=None):
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

    prompt = f"""Sen deneyimli bir SOC analistisin. SentinelBoard SIEM sisteminden gelen bir guvenlik alertini inceliyorsun.

## Alert Detaylari
- Kural: {alert.rule_title}
- Kural ID: {alert.rule_id}
- Severity: {alert.severity}
- Kaynak IP: {alert.src_ip or 'N/A'}
- Kullanici: {alert.user or 'N/A'}
- Mesaj: {alert.message}
- MITRE ATT&CK Tags: {', '.join(alert.tags) if alert.tags else 'Yok'}
- Zaman: {alert.created_at}

## Ilgili Eventler
{event_summary if event_summary else 'Event detayi mevcut degil.'}

## Analiz Talebi
Turkce bir guvenlik analizi yap:

1. **Ozet**: Bu alertin kisa aciklamasi (2-3 cumle)
2. **Tehdit Degerlendirmesi**: Bu aktivite neden supheli? Saldirgan ne yapmaya calisiyor olabilir?
3. **Risk Seviyesi**: Dusuk / Orta / Yuksek / Kritik — ve neden?
4. **Onerilen Aksiyonlar**: Ne yapilmali? (en az 3 adim)
5. **False Positive Degerlendirmesi**: Bu alertin false positive olma olasiligi nedir?

Kisa, oz ve aksiyon odakli yaz. Sadece Turkce yaz, baska dil kullanma."""

    return prompt


def analyze_alert(alert):
    if not API_KEY:
        return {
            "success": False,
            "analysis": "",
            "error": "GROQ_API_KEY is not set in .env file"
        }

    events = alert.related_events.all().order_by("-timestamp")
    prompt = build_analysis_prompt(alert, events)

    try:
        response = requests.post(
            API_URL,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 1500,
                "temperature": 0.3,
            },
            timeout=30,
        )

        if response.status_code == 200:
            data = response.json()
            analysis_text = data["choices"][0]["message"]["content"]
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
        return {"success": False, "analysis": "", "error": "API request timed out"}
    except Exception as e:
        logger.error(f"LLM analysis error: {e}")
        return {"success": False, "analysis": "", "error": str(e)}