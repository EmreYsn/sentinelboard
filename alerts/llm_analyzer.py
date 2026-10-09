"""
llm_analyzer.py — Alert'leri LLM ile analiz eder.

Gönderilen veri sanitize.py'den geçiyor: ham syslog satırı hiç
gönderilmiyor, IP ve kullanıcı adları takma adlara çevriliyor.
Sağlayıcı llm_client.py'de tanımlı (Groq varsayılan, yerel modele
geçmek için LLM_BASE_URL yeterli).
"""

import logging

from alerts import llm_client
from alerts.sanitize import Pseudonymizer, scrub_event_line

logger = logging.getLogger("sentinelboard.alerts.llm_analyzer")


def build_analysis_prompt(alert, events=None):
    """Alert'ten LLM prompt'u üretir — temizlenmiş veriyle.

    Takma adlandırma istek anında değil burada yapılıyor: prompt'u
    üreten fonksiyon aynı zamanda "dışarı ne çıkıyor" sorusunun tek
    kaynağı olmalı, yoksa test edilemez.
    """
    pseudo = Pseudonymizer()

    # Alert alanları önce işleniyor: aynı IP/kullanıcı event
    # satırlarında da geçtiğinde aynı takma adı almalı.
    alert_ip = pseudo.ip(alert.src_ip)
    alert_user = pseudo.user(alert.user)
    alert_message = pseudo.text(alert.message)

    event_summary = ""
    if events:
        shown = list(events[:10])
        # QuerySet ise sayımı veritabanına bırak; liste ise elde say.
        total = events.count() if hasattr(events, "model") else len(shown)
        event_summary = "\n".join(scrub_event_line(pseudo, ev) for ev in shown)
        if total > 10:
            event_summary += f"\n  ... ve {total - 10} event daha"

    prompt = f"""Sen deneyimli bir SOC analistisin. SentinelBoard SIEM sisteminden gelen bir guvenlik alertini inceliyorsun.

## Alert Detaylari
- Kural: {alert.rule_title}
- Kural ID: {alert.rule_id}
- Severity: {alert.severity}
- Kaynak IP: {alert_ip}
- Kullanici: {alert_user}
- Mesaj: {alert_message}
- MITRE ATT&CK Tags: {', '.join(alert.tags) if alert.tags else 'Yok'}
- Zaman: {alert.created_at}

## Ilgili Eventler
{event_summary if event_summary else 'Event detayi mevcut degil.'}

## Veri Hakkinda
{pseudo.summary()}

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
    if not llm_client.is_configured():
        return {
            "success": False,
            "analysis": "",
            "error": llm_client.config_error(),
        }

    events = alert.related_events.all().order_by("-timestamp")
    prompt = build_analysis_prompt(alert, events)

    result = llm_client.complete(
        [{"role": "user", "content": prompt}],
        max_tokens=1500,
        temperature=0.3,
        timeout=30,
    )

    if result["success"]:
        logger.info(
            f"LLM analysis completed for alert {alert.id} "
            f"({llm_client.describe()})"
        )
        return {"success": True, "analysis": result["content"], "error": None}

    return {"success": False, "analysis": "", "error": result["error"]}