"""
llm_client.py — LLM sağlayıcısını tek yerde toplar.

Neden bu dosya var?
    Önce API adresi, model adı ve anahtar iki dosyada (chat.py ve
    llm_analyzer.py) ayrı ayrı tanımlıydı. Sağlayıcıyı değiştirmek iki
    dosyaya dokunmayı gerektiriyordu ve ikisinin birbirinden sapması
    mümkündü. Artık tek kaynak var.

Hangi sağlayıcılar çalışır?
    OpenAI uyumlu /chat/completions endpoint'i sunan her şey:
      Groq    → https://api.groq.com/openai/v1          (varsayılan)
      Ollama  → http://127.0.0.1:11434/v1
      vLLM / LM Studio / llama.cpp server → kendi adresleri

    Yani buluttan yerele geçmek bir .env satırı. Kod değişmiyor.
    Bu, SIEM'in ürettiği log verisinin sunucudan hiç çıkmaması
    gerektiği ortamlar için bilinçli bir kaçış kapısı.

Geriye dönük uyumluluk:
    Sunucudaki mevcut .env dosyası GROQ_API_KEY ve GROQ_MODEL
    kullanıyor. Yeni LLM_* değişkenleri önce okunuyor, yoksa GROQ_*
    değişkenlerine düşülüyor — böylece deploy sırasında .env'e
    dokunmadan da çalışmaya devam eder.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("sentinelboard.alerts.llm_client")

DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "qwen/qwen3.8-27b"

# LLM_* önce, sonra GROQ_* (eski .env dosyaları için)
BASE_URL = (os.getenv("LLM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
MODEL = os.getenv("LLM_MODEL") or os.getenv("GROQ_MODEL") or DEFAULT_MODEL
API_KEY = os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY") or ""

# Üretilecek azami token. Neden merkezi bir sınır var?
#     Groq'un ucretsiz katmaninda dakikalik output token kotasi (OTPM)
#     1000. Bir istek max_tokens=1500 isterse tek basina butun dakikalik
#     butceden buyuk olur ve 429 ile reddedilir. Cagiran taraflar ne
#     kadar istediklerini soyluyor, burasi tiere gore kirpiyor —
#     boylece tier degistiginde (ya da yerel modele gecildiginde, ki
#     orada kota yok) tek bir env degiskeni yetiyor.
DEFAULT_MAX_OUTPUT_TOKENS = 800


def _int_env(isim: str, varsayilan: int) -> int:
    """Hatali env degeri uygulamayi acilista dusurmemeli."""
    try:
        deger = int(os.getenv(isim, ""))
    except ValueError:
        return varsayilan
    return deger if deger > 0 else varsayilan


MAX_OUTPUT_TOKENS = _int_env("LLM_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS)

# HTTP 429: saglayici kota siniri. Ayri ele aliniyor, cunku kullaniciya
# gosterilecek mesaj bir hata degil bir bekleme talimati.
RATE_LIMIT_STATUS = 429


def resolve_api_url(base_url: str = None) -> str:
    """Taban adresten tam chat/completions adresini üretir.

    Ayrı fonksiyon, çünkü testlerde modülü yeniden yüklemeden
    doğrulanabilmesi gerekiyor.
    """
    base = (base_url if base_url is not None else BASE_URL).rstrip("/")
    if base.endswith("/chat/completions"):
        return base  # tam adres verilmişse olduğu gibi kullan
    return f"{base}/chat/completions"


def is_local_endpoint(base_url: str = None) -> bool:
    """Endpoint bu makinede mi çalışıyor?

    Önemli, çünkü yerel modeller (Ollama) API anahtarı istemiyor.
    Anahtar yok diye hata döndürmek yerel kuruluma geçişi engellerdi.
    """
    base = base_url if base_url is not None else BASE_URL
    host = (urlparse(base).hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    return host.endswith(".local") or host.endswith(".internal")


def is_configured() -> bool:
    """LLM çağrısı yapılabilir durumda mı?"""
    return bool(API_KEY) or is_local_endpoint()


def config_error() -> str:
    """is_configured() False ise kullanıcıya gösterilecek mesaj."""
    return (
        "LLM yapilandirilmamis: .env dosyasinda LLM_API_KEY "
        "(veya eski adiyla GROQ_API_KEY) tanimli degil. Yerel bir model "
        "kullanacaksan LLM_BASE_URL=http://127.0.0.1:11434/v1 yeterli, "
        "anahtar gerekmez."
    )


def describe() -> str:
    """Hangi sağlayıcıya bağlı olduğumuzu loglar/panel için özetler."""
    kind = "yerel" if is_local_endpoint() else "bulut"
    return f"{MODEL} @ {urlparse(BASE_URL).hostname} ({kind})"


def complete(
    messages: list[dict],
    *,
    max_tokens: int = 1000,
    temperature: float = 0.3,
    timeout: int = 30,
) -> dict:
    """Tek bir chat completion isteği gönderir.

    Dönüş her zaman aynı şekilde: {"success": bool, "content": str,
    "error": str | None}. Çağıran taraf HTTP ayrıntısıyla uğraşmaz.

    TIMEOUT KURALI (TERS PİRAMİT) — istek iç içe geçmiş ÜÇ zaman
    aşımından geçiyor. En içteki en kısa olmak zorunda; dışa doğru her
    katman daha uzun:

        requests (burası)        60 sn
        Gunicorn --timeout      120 sn
        nginx proxy_read_timeout 180 sn

    Sıra bozulursa hata buradaki hata yönetimine ulaşmadan dışarıdan
    kesilir: kullanıcı anlamsız bir 502/504 görür, aşağıdaki nazik
    mesaj hiç çalışmaz ve daha kötüsü sağlayıcı o ana kadar ürettiği
    token'ları kotadan düşmüş olur — sessiz başarısızlık kotayı yiyip
    karşılığında hiçbir şey vermez.

    İki kez yaşandı:
      09.10.2026 — Gunicorn 30 sn ile yarıştı, iki worker timeout'u
                   arkasından 429 (kota bitti).
      16.10.2026 — nginx'in VARSAYILAN proxy_read_timeout değeri de
                   60 sn; bu katman ilk düzeltmede atlanmıştı ve bu
                   sefer 504 döndü.

    Yerel modeller ilk istekte modeli diske yükler ve yavaş olabilir;
    o yüzden timeout'u çağıran taraf belirliyor.
    """
    if not is_configured():
        return {"success": False, "content": "", "error": config_error()}

    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"

    istenen = min(max_tokens, MAX_OUTPUT_TOKENS)
    if istenen < max_tokens:
        logger.debug(
            f"max_tokens {max_tokens} -> {istenen} olarak kirpildi "
            f"(LLM_MAX_OUTPUT_TOKENS)"
        )

    try:
        response = requests.post(
            resolve_api_url(),
            headers=headers,
            json={
                "model": MODEL,
                "messages": messages,
                "max_tokens": istenen,
                "temperature": temperature,
            },
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        logger.warning(f"LLM istegi zaman asimina ugradi ({describe()})")
        return {
            "success": False,
            "content": "",
            "error": f"LLM istegi {timeout} saniyede yanit vermedi",
        }
    except requests.exceptions.RequestException as exc:
        logger.error(f"LLM baglanti hatasi: {exc}")
        return {"success": False, "content": "", "error": str(exc)}

    if response.status_code == RATE_LIMIT_STATUS:
        # Kota aşımı bir arıza değil, bir bekleme durumu. Kullanıcıya
        # sağlayıcının ham JSON'unu göstermek yerine ne yapması
        # gerektiğini söylüyoruz; teşhis için ham gövde log'a gidiyor.
        logger.warning(
            f"LLM kota siniri asildi ({describe()}): {response.text[:300]}"
        )
        bekleme = (response.headers.get("Retry-After") or "").strip()
        if bekleme.isdigit():
            ek = f"Yaklasik {bekleme} saniye sonra tekrar dene."
        else:
            ek = "Bir dakika sonra tekrar dene."
        return {
            "success": False,
            "content": "",
            "error": f"LLM saglayicisinin kotasi doldu. {ek}",
        }

    if response.status_code != 200:
        # Ham gövde log'da kalsın; kullanıcıya kısa bilgi yeter.
        logger.error(
            f"LLM API hatasi {response.status_code}: {response.text[:300]}"
        )
        return {
            "success": False,
            "content": "",
            "error": f"LLM API hatasi {response.status_code}",
        }

    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        # Farklı sağlayıcılar aynı şemayı birebir uygulamayabilir.
        logger.error(f"LLM yanitı beklenen bicimde degil: {exc}")
        return {
            "success": False,
            "content": "",
            "error": f"Yanit bicimi tanimlanamadi: {exc}",
        }

    return {"success": True, "content": content, "error": None}