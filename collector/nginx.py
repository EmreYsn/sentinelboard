"""
nginx.py — Nginx erişim logu collector'ı

Hangi olayı çıkarıyor?
    http_request → her HTTP isteği, şüpheli olanlar işaretli
                   (web_scan kuralını besler)

Beklenen format (nginx "combined", varsayılan):
    1.2.3.4 - - [09/Jun/2026:14:23:01 +0300] "GET /admin HTTP/1.1" 404 162 "-" "curl/8.0"
    └─ IP ─┘ │ │ └──────── zaman ─────────┘  └─── istek ───────┘ │    │   │      └ user agent
             │ └ kullanıcı (auth varsa)                       durum boyut referer

"Şüpheli istek" nasıl belirleniyor?
    İki sinyale bakıyoruz:
    1) İstenen yol bilinen bir saldırı hedefi mi? (/.env, /wp-admin,
       /phpmyadmin gibi) — tarama araçlarının aradığı klasik yerler.
    2) User-Agent bilinen bir tarama aracı mı? (nikto, sqlmap, nmap…)

    Bu alan `is_suspicious` adıyla boolean olarak gidiyor. Neden
    boolean? engine/matcher.py kuraldaki "True" string'ini boolean'a
    çevirip `extra__is_suspicious=True` diye sorguluyor. String
    gönderseydik kural hiçbir zaman eşleşmezdi.

    Tek bir şüpheli istek alarm değildir — insanlar da yanlış adres
    yazar. Kural 10 dakikada 5'ten fazlasını arıyor; asıl sinyal
    tekrarın kendisi.
"""

import re
import logging

from collector.base import BaseCollector
from collector.timeparse import parse_nginx_timestamp

logger = logging.getLogger("sentinelboard.collector.nginx")


COMBINED_RE = re.compile(
    r"^(?P<src_ip>[\d.a-fA-F:]+)\s+\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S*)\s*(?P<proto>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Saldırganların en sık denediği yollar.
# Kısmi eşleşme arıyoruz: "/wp-admin/install.php" de yakalansın.
SUSPICIOUS_PATHS = (
    "/.env", "/.git", "/.aws", "/.ssh",
    "/wp-admin", "/wp-login", "/wordpress",
    "/phpmyadmin", "/pma", "/adminer",
    "/admin", "/administrator", "/manager/html",
    "/config", "/backup", "/dump", "/.sql", "/db.sql",
    "/shell", "/cmd", "/eval-stdin.php",
    "/vendor/phpunit", "/cgi-bin",
    "/actuator", "/.well-known/security",
)

# Bilinen tarama ve sömürü araçlarının imzaları
SUSPICIOUS_AGENTS = (
    "nikto", "sqlmap", "nmap", "masscan", "zgrab", "nessus",
    "dirbuster", "gobuster", "ffuf", "wpscan", "acunetix",
    "havij", "metasploit", "python-requests", "curl/", "wget/",
)


class NginxCollector(BaseCollector):
    """Nginx combined erişim logunu olaylara çevirir."""

    def get_source_name(self) -> str:
        return self.config.get("name", "nginx")

    def _is_suspicious(self, path: str, agent: str, status: str) -> bool:
        """Bu istek tarama belirtisi taşıyor mu?"""
        lowered_path = (path or "").lower()
        if any(p in lowered_path for p in SUSPICIOUS_PATHS):
            return True

        lowered_agent = (agent or "").lower()
        if any(a in lowered_agent for a in SUSPICIOUS_AGENTS):
            return True

        # Boş veya "-" user agent: normal tarayıcılar her zaman
        # kimliğini bildirir, bildirmeyen çoğunlukla bir script.
        if not agent or agent == "-":
            return True

        return False

    def parse_line(self, line: str) -> dict | None:
        m = COMBINED_RE.match(line)
        if not m:
            return None

        path = m.group("path") or ""
        agent = m.group("agent") or ""
        status = m.group("status")
        suspicious = self._is_suspicious(path, agent, status)

        # Sunucu hatası (5xx) bilgi seviyesinden yüksek sayılır
        if suspicious:
            severity = "low"
        elif status.startswith("5"):
            severity = "medium"
        else:
            severity = "info"

        size = m.group("size")

        return {
            "timestamp": parse_nginx_timestamp(m.group("ts")),
            "host": self.config.get("host", "localhost"),
            "event_type": "http_request",
            "severity": severity,
            "src_ip": m.group("src_ip"),
            "user": None if m.group("user") == "-" else m.group("user"),
            "process": "nginx",
            "message": f"{m.group('method')} {path} → {status}",
            "raw": line,
            # ── extra alanına gidecekler ──
            "http_method": m.group("method"),
            "http_path": path,
            "http_status": int(status),
            "http_size": int(size) if size.isdigit() else 0,
            "user_agent": agent,
            "referer": m.group("referer") or "",
            "is_suspicious": suspicious,   # boolean olmalı — matcher böyle sorguluyor
        }