"""
syslog.py — Genel sistem logu collector'ı (/var/log/syslog)

Hangi olayları çıkarıyor?
    firewall_block → UFW/iptables tarafından engellenen paket
                     (firewall_flood kuralını besler)
    service_event  → servis başlama/durma, kernel mesajları vs.

UFW engelleme satırı neye benzer?
    Jun  9 14:23:01 vps kernel: [12345.67] [UFW BLOCK] IN=eth0 OUT=
    MAC=... SRC=1.2.3.4 DST=5.6.7.8 LEN=60 ... PROTO=TCP SPT=54321 DPT=22 ...

    Bu satır "anahtar=değer" çiftlerinden oluşur. Her anahtarı tek
    tek regex'e yazmak yerine hepsini toplu çekip sözlüğe çeviriyoruz —
    hem kısa hem de iptables sürümü alan eklerse kırılmıyor.

Neden port taraması önemli?
    Tek bir engellenmiş paket gürültüdür; internette sürekli olur.
    Ama aynı IP'den 5 dakikada 20+ farklı porta paket geliyorsa,
    biri kapıları tek tek deniyor demektir. Saldırının keşif
    aşamasıdır ve genelde asıl saldırıdan önce gelir.
"""

import re
import logging

from collector.base import BaseCollector
from collector.timeparse import parse_syslog_timestamp

logger = logging.getLogger("sentinelboard.collector.syslog")


SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-/.]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# [UFW BLOCK] veya [UFW AUDIT] gibi etiketler
UFW_TAG_RE = re.compile(r"\[UFW\s+(?P<action>[A-Z]+)\]")

# iptables tarzı "ANAHTAR=değer" çiftleri (değer boş olabilir: "OUT=")
KV_RE = re.compile(r"\b(?P<key>[A-Z]+)=(?P<value>[^\s]*)")


class SyslogCollector(BaseCollector):
    """Genel syslog satırlarını olaylara çevirir."""

    def get_source_name(self) -> str:
        return self.config.get("name", "syslog")

    def parse_line(self, line: str) -> dict | None:
        m = SYSLOG_RE.match(line)
        if not m:
            return None

        message = m.group("message")
        base = {
            "timestamp": parse_syslog_timestamp(m.group("ts")),
            "host": m.group("host"),
            "process": m.group("process"),
            "pid": int(m.group("pid")) if m.group("pid") else None,
            "message": message,
            "raw": line,
        }

        # ── Firewall engellemesi ──
        tag = UFW_TAG_RE.search(message)
        if tag:
            fields = {kv.group("key"): kv.group("value") for kv in KV_RE.finditer(message)}
            action = tag.group("action")

            return {
                **base,
                "event_type": "firewall_block" if action == "BLOCK" else "firewall_audit",
                "severity": "low",
                "src_ip": fields.get("SRC"),
                "dst_ip": fields.get("DST"),
                "src_port": _as_int(fields.get("SPT")),
                "dst_port": _as_int(fields.get("DPT")),
                # ── extra ──
                "protocol": fields.get("PROTO"),
                "interface_in": fields.get("IN"),
                "interface_out": fields.get("OUT"),
                "fw_action": action,
            }

        # ── Diğer sistem olayları ──
        # Bunları da kaydediyoruz: ML modülü "yeni görülen process
        # sayısı" gibi metrikleri bu satırlardan üretiyor.
        return {**base, "event_type": "service_event", "severity": "info"}


def _as_int(value):
    """Metni sayıya çevirir, olmuyorsa None döner."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None