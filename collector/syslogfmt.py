"""
syslogfmt.py — Syslog satır biçimi (tek merkezden)

Neden ayrı dosya?
    auth.py ve syslog.py aynı satır iskeletini ayrıştırıyor. Aynı
    regex'i iki yere kopyalarsak, biri değişince diğerini unutma
    riski doğar. Tek yerde tutuyoruz.

Desteklenen iki biçim:

  1) Klasik BSD syslog (eski Ubuntu, Debian, CentOS):
     Oct  4 00:00:49 vmi3286839 sshd[3896287]: Connection closed...

  2) ISO 8601 / RFC 3339 (Ubuntu 23.10 ve sonrası):
     2026-10-04T00:00:49.417217+02:00 vmi3286839 sshd[3896287]: ...

    Ubuntu 23.10'da rsyslog'un varsayılan şablonu değişti. Yılı ve
    saat dilimini de yazdığı için aslında daha iyi bir biçim, ama
    eski formatı da desteklemeye devam ediyoruz: sunucu değişebilir,
    başka dağıtımdan log gelebilir.
"""

import re

# Zaman damgası: önce ISO'yu dene, olmazsa klasik biçimi.
# Sıra önemli — ISO daha spesifik, önce o denenmeli.
_TS = (
    r"(?P<ts>"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"  # ISO 8601
    r"|"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"                            # klasik BSD
    r")"
)

SYSLOG_RE = re.compile(
    r"^" + _TS + r"\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-/.]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


def split_syslog_line(line: str) -> dict | None:
    """
    Syslog satırını bileşenlerine ayırır.

    Returns:
        {"ts": ..., "host": ..., "process": ..., "pid": int|None, "message": ...}
        veya satır syslog biçiminde değilse None
    """
    m = SYSLOG_RE.match(line)
    if not m:
        return None

    return {
        "ts": m.group("ts"),
        "host": m.group("host"),
        "process": m.group("process"),
        "pid": int(m.group("pid")) if m.group("pid") else None,
        "message": m.group("message"),
    }