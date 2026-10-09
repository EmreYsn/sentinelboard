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

Gizlilik:
    Bağlam sanitize.py'den geçiyor — ham log satırı gönderilmiyor,
    IP ve kullanıcı adları takma adlanıyor. Tek istisna: kullanıcının
    sorusunda geçen IP'ler. Onlar soruyla birlikte zaten dışarı çıktığı
    için bağlamda da olduğu gibi bırakılıyor (bkz. disclose_ip).
    Sorunun kendisi temizlenemez; tam izolasyon isteniyorsa yerel model
    kullanılmalı (LLM_BASE_URL).
"""

import logging
import re
from datetime import timedelta

from django.utils import timezone
from django.db.models import Count

from events.models import Event, Alert

from alerts import llm_client
from alerts.sanitize import Pseudonymizer

logger = logging.getLogger("sentinelboard.alerts.chat")

IP_IN_QUESTION_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def gather_context(question: str, pseudo: Pseudonymizer = None) -> str:
    """
    Soruya göre veritabanından ilgili verileri toplar.

    Bu fonksiyon RAG'ın "Retrieval" kısmı.
    Sorudaki ipuçlarına göre farklı sorgular çalıştırır.

    Neden her soruya tüm veriyi göndermiyoruz?
        LLM'in token limiti var. 10.000 log satırı göndermek
        hem yavaş hem pahalı hem de gereksiz. Soruyla ilgili
        verileri filtreleyip özetleyerek gönderiyoruz.

    pseudo parametresi:
        Takma adlandırıcı. Çağıran taraf verirse aynı nesne prompt'un
        tamamında kullanılır (özet notu doğru sayıları göstersin diye).
        Verilmezse burada açılır — testlerden tek başına çağırmak için.
    """
    if pseudo is None:
        pseudo = Pseudonymizer()

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
    # Soruda IP adresi geçiyorsa o IP'ye özel veri çek.
    # Sorgu gerçek IP ile yapılıyor (yoksa veri bulunmaz), ama metne
    # yazarken disclose_ip kullanılıyor: kullanıcı bu IP'yi kendisi
    # yazdı, gizlemiş gibi davranmak yanıltıcı olur.
    ip_match = IP_IN_QUESTION_RE.findall(question)
    if ip_match:
        for ip in ip_match:
            ip_events = Event.objects.filter(src_ip=ip)
            ip_count = ip_events.count()
            ip_alerts = Alert.objects.filter(src_ip=ip)

            if ip_count > 0:
                ip_label = pseudo.disclose_ip(ip)

                # Son 5 event'i göster
                recent = ip_events.order_by("-timestamp")[:5]
                event_lines = "\n".join(
                    f"  - [{e.severity}] {e.event_type} | {e.timestamp} | "
                    f"{pseudo.text(e.message)}"
                    for e in recent
                )

                # Event tipi dağılımı
                type_dist = dict(
                    ip_events.values_list("event_type")
                    .annotate(c=Count("id"))
                )

                context_parts.append(f"""## IP Analizi: {ip_label}
- Toplam event: {ip_count}
- Event tipleri: {type_dist}
- Alert sayisi: {ip_alerts.count()}
- Son 5 event:
{event_lines}""")

    # ── Son Alert'ler ──
    recent_alerts = Alert.objects.order_by("-created_at")[:5]
    if recent_alerts:
        alert_lines = "\n".join(
            f"  - [{a.severity}] {a.rule_title} | IP: {pseudo.ip(a.src_ip)} | "
            f"Status: {a.status} | {pseudo.text(a.message)[:100]}"
            for a in recent_alerts
        )
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
    # Burada IP'lerin kendisi değil, dağılımı önemli: "bir kaynak 2000
    # istek atmış" bilgisi takma adla da aynı anlamı taşıyor.
    top_ips = (
        Event.objects
        .filter(timestamp__gte=last_24h, src_ip__isnull=False)
        .values("src_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    if top_ips:
        ip_lines = "\n".join(
            f"  - {pseudo.ip(item['src_ip'])}: {item['count']} event"
            for item in top_ips
        )
        context_parts.append(f"## En Aktif IP'ler (24 saat)\n{ip_lines}")

    # ── Son Event'ler ──
    recent_events = Event.objects.order_by("-timestamp")[:10]
    if recent_events:
        event_lines = "\n".join(
            f"  - [{e.severity}] {e.source}/{e.event_type} | "
            f"IP: {pseudo.ip(e.src_ip)} | User: {pseudo.user(e.user)} | "
            f"{e.timestamp}"
            for e in recent_events
        )
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
    if not llm_client.is_configured():
        return {"success": False, "answer": "", "error": llm_client.config_error()}

    # Takma adlandırıcı burada açılıyor ki bağlam ile özet notu
    # aynı nesneyi paylaşsın.
    pseudo = Pseudonymizer()
    context = gather_context(question, pseudo)

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
- Teknik terimleri acikla
- IP_1, USER_2 gibi takma adlari oldugu gibi kullan, gercek deger uydurma"""

    user_prompt = f"""## SentinelBoard Veritabani Verileri
{context}

## Veri Hakkinda
{pseudo.summary()}

## Kullanicinin Sorusu
{question}

Yukaridaki verilere dayanarak soruyu yanitla."""

    result = llm_client.complete(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=1000,
        temperature=0.3,
        timeout=30,
    )

    if result["success"]:
        logger.info(f"Chat question answered: {question[:50]}")
        return {"success": True, "answer": result["content"], "error": None}

    return {"success": False, "answer": "", "error": result["error"]}


def explain_event(event) -> dict:
    """
    Tek bir event'i kısa ve öz şekilde açıklar.
    Alert analizi gibi uzun değil — 2-3 cümlelik açıklama.
    """
    if not llm_client.is_configured():
        return {
            "success": False,
            "explanation": "",
            "error": llm_client.config_error(),
        }

    pseudo = Pseudonymizer()
    # Sıra önemli: alanlar önce, mesaj sonra. Böylece mesaja gömülü
    # aynı değerler aynı takma adı alır.
    ip_label = pseudo.ip(event.src_ip)
    user_label = pseudo.user(event.user)
    message = pseudo.text(event.message)

    prompt = f"""Sen bir SOC analistisin. Asagidaki SIEM eventini 2-3 cumlede acikla:
- Bu event ne anlama geliyor?
- Tehlikeli mi, normal mi?
- Varsa onerilen aksiyon

Event:
- Tip: {event.event_type}
- Kaynak: {event.source}
- Severity: {event.severity}
- IP: {ip_label}
- Kullanici: {user_label}
- Process: {event.process or 'N/A'}
- Mesaj: {message}
- Zaman: {event.timestamp}

{pseudo.summary()}

Sadece Turkce yaz. Cok kisa ve oz tut, maksimum 3 cumle."""

    result = llm_client.complete(
        [{"role": "user", "content": prompt}],
        max_tokens=200,
        temperature=0.3,
        timeout=15,
    )

    if result["success"]:
        return {"success": True, "explanation": result["content"], "error": None}

    return {"success": False, "explanation": "", "error": result["error"]}