"""
chat.py — AI Security Chatbot

Bu dosya ne yapıyor?
    Kullanıcının doğal dilde sorduğu güvenlik sorusunu alır,
    veritabanından ilgili verileri çeker, LLM'e bağlam olarak
    gönderir ve anlamlı bir yanıt üretir.

RAG (Retrieval-Augmented Generation) nedir?
    Soru → Veritabanından ilgili veriyi çek → LLM'e veriyle birlikte gönder
    LLM kendi bilgisiyle değil, SENİN verilerinle yanıt üretir.
    Bu sayede "son 1 saatte ne oldu?" sorusuna gerçek veriye dayalı yanıt gelir.
"""

import os
import logging
from datetime import timedelta

import requests
from django.utils import timezone
from django.db.models import Count, Q
from dotenv import load_dotenv

from events.models import Event, Alert

load_dotenv()

logger = logging.getLogger("sentinelboard.alerts.chat")

API_KEY = os.getenv("GROQ_API_KEY", "")
API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")


def gather_context(question: str) -> str:
    """
    Soruya göre veritabanından ilgili verileri toplar.

    Bu fonksiyon RAG'ın "Retrieval" kısmı.
    Sorudaki ipuçlarına göre farklı sorgular çalıştırır.

    Neden her soruya tüm veriyi göndermiyoruz?
        LLM'in token limiti var. 10.000 log satırı göndermek
        hem yavaş hem pahalı hem de gereksiz. Soruyla ilgili
        verileri filtreleyip özetleyerek gönderiyoruz.
    """
    now = timezone.now()
    context_parts = []

    # ── Genel İstatistikler (her zaman ekle) ──
    last_24h = now - timedelta(hours=24)
    last_1h = now - timedelta(hours=1)

    total_events = Event.objects.count()
    events_24h = Event.objects.filter(timestamp__gte=last_24h).count()
    events_1h = Event.objects.filter(timestamp__gte=last_1h).count()
    total_alerts = Alert.objects.count()
    new_alerts = Alert.objects.filter(status="new").count()

    context_parts.append(f"""## Genel Istatistikler
- Toplam event: {total_events}
- Son 24 saat event: {events_24h}
- Son 1 saat event: {events_1h}
- Toplam alert: {total_alerts}
- Yeni (acknowledge edilmemis) alert: {new_alerts}""")

    # ── IP Adresi Soruluyorsa ──
    # Soruda IP adresi geçiyorsa o IP'ye özel veri çek
    import re
    ip_match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', question)
    if ip_match:
        for ip in ip_match:
            ip_events = Event.objects.filter(src_ip=ip)
            ip_count = ip_events.count()
            ip_alerts = Alert.objects.filter(src_ip=ip)

            if ip_count > 0:
                # Son 5 event'i göster
                recent = ip_events.order_by("-timestamp")[:5]
                event_lines = "\n".join([
                    f"  - [{e.severity}] {e.event_type} | {e.timestamp} | {e.message or e.raw[:80]}"
                    for e in recent
                ])

                # Event tipi dağılımı
                type_dist = dict(
                    ip_events.values_list("event_type")
                    .annotate(c=Count("id"))
                )

                context_parts.append(f"""## IP Analizi: {ip}
- Toplam event: {ip_count}
- Event tipleri: {type_dist}
- Alert sayisi: {ip_alerts.count()}
- Son 5 event:
{event_lines}""")

    # ── Son Alert'ler ──
    recent_alerts = Alert.objects.order_by("-created_at")[:5]
    if recent_alerts:
        alert_lines = "\n".join([
            f"  - [{a.severity}] {a.rule_title} | IP: {a.src_ip or 'N/A'} | "
            f"Status: {a.status} | {a.message[:100]}"
            for a in recent_alerts
        ])
        context_parts.append(f"""## Son 5 Alert
{alert_lines}""")

    # ── Severity Dağılımı (son 24 saat) ──
    severity_dist = dict(
        Event.objects
        .filter(timestamp__gte=last_24h)
        .values_list("severity")
        .annotate(c=Count("id"))
    )
    if severity_dist:
        context_parts.append(f"## Severity Dagilimi (24 saat): {severity_dist}")

    # ── Top IP'ler ──
    top_ips = (
        Event.objects
        .filter(timestamp__gte=last_24h, src_ip__isnull=False)
        .values("src_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    if top_ips:
        ip_lines = "\n".join([
            f"  - {item['src_ip']}: {item['count']} event"
            for item in top_ips
        ])
        context_parts.append(f"## En Aktif IP'ler (24 saat)\n{ip_lines}")

    # ── Son Event'ler ──
    recent_events = Event.objects.order_by("-timestamp")[:10]
    if recent_events:
        event_lines = "\n".join([
            f"  - [{e.severity}] {e.source}/{e.event_type} | "
            f"IP: {e.src_ip} | User: {e.user} | {e.timestamp}"
            for e in recent_events
        ])
        context_parts.append(f"## Son 10 Event\n{event_lines}")

    return "\n\n".join(context_parts)


def chat(question: str) -> dict:
    """
    Kullanıcının sorusunu yanıtlar.

    Akış:
    1. Sorudan ipuçları çıkar (IP adresi var mı? zaman var mı?)
    2. Veritabanından ilgili verileri topla (gather_context)
    3. Soru + veri → LLM'e gönder
    4. LLM yanıtını döndür
    """
    if not API_KEY:
        return {
            "success": False,
            "answer": "",
            "error": "GROQ_API_KEY is not set in .env file"
        }

    # Veritabanından bağlam topla
    context = gather_context(question)

    system_prompt = """Sen SentinelBoard SIEM sisteminin yapay zeka guvenlik asistanisin.
Gorevlerin:
- Guvenlik olaylarini analiz etmek
- Alert'ler hakkinda bilgi vermek
- Tehdit degerlendirmesi yapmak
- Oneriler sunmak

Kurallar:
- Sadece Turkce yaz, baska dil kullanma
- Sana verilen veritabani verilerine dayanarak yanit ver
- Veride olmayan seyleri uydurma
- Kisa ve oz yanit ver
- Teknik terimleri acikla"""

    user_prompt = f"""## SentinelBoard Veritabani Verileri
{context}

## Kullanicinin Sorusu
{question}

Yukaridaki verilere dayanarak soruyu yanitla."""

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
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": 1000,
                "temperature": 0.3,
            },
            timeout=30,
        )

        if response.status_code == 200:
            data = response.json()
            answer = data["choices"][0]["message"]["content"]
            logger.info(f"Chat question answered: {question[:50]}")
            return {"success": True, "answer": answer, "error": None}
        else:
            error_msg = f"API error {response.status_code}: {response.text[:200]}"
            return {"success": False, "answer": "", "error": error_msg}

    except requests.exceptions.Timeout:
        return {"success": False, "answer": "", "error": "API timeout"}
    except Exception as e:
        return {"success": False, "answer": "", "error": str(e)}

def explain_event(event) -> dict:
    """
    Tek bir event'i kısa ve öz şekilde açıklar.
    Alert analizi gibi uzun değil — 2-3 cümlelik açıklama.
    """
    if not API_KEY:
        return {"success": False, "explanation": "", "error": "GROQ_API_KEY not set"}

    prompt = f"""Sen bir SOC analistisin. Asagidaki SIEM eventini 2-3 cumlede acikla:
- Bu event ne anlama geliyor?
- Tehlikeli mi, normal mi?
- Varsa onerilen aksiyon

Event:
- Tip: {event.event_type}
- Kaynak: {event.source}
- Severity: {event.severity}
- IP: {event.src_ip or 'N/A'}
- Kullanici: {event.user or 'N/A'}
- Process: {event.process or 'N/A'}
- Mesaj: {event.message or event.raw[:150]}
- Zaman: {event.timestamp}

Sadece Turkce yaz. Cok kisa ve oz tut, maksimum 3 cumle."""

    try:
        response = requests.post(
            API_URL,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
                "temperature": 0.3,
            },
            timeout=15,
        )

        if response.status_code == 200:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            return {"success": True, "explanation": text, "error": None}
        else:
            return {"success": False, "explanation": "", "error": f"API error {response.status_code}"}

    except Exception as e:
        return {"success": False, "explanation": "", "error": str(e)}