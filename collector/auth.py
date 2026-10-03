"""
auth.py — Linux kimlik doğrulama logu collector'ı (/var/log/auth.log)

Hangi olayları çıkarıyor?
    auth_failure   → Başarısız SSH girişi   (ssh_brute_force kuralını besler)
    auth_success   → Başarılı SSH girişi    (ML baseline için gerekli)
    sudo_command   → sudo ile çalıştırılan komut (sudo_suspicious kuralını besler)
    user_added     → Yeni kullanıcı açılması (kalıcılık belirtisi olabilir)

Örnek satırlar:
    Jun  9 14:23:01 vps sshd[12345]: Failed password for root from 1.2.3.4 port 54321 ssh2
    Jun  9 14:23:02 vps sshd[12345]: Failed password for invalid user admin from 1.2.3.4 port 5432 ssh2
    Jun  9 14:23:10 vps sshd[12346]: Accepted publickey for yasin from 5.6.7.8 port 1234 ssh2
    Jun  9 14:25:00 vps sudo:  yasin : TTY=pts/0 ; PWD=/home/yasin ; USER=root ; COMMAND=/usr/bin/apt

Neden regex?
    Syslog satırları sabit bir şablona uyar. Regex bu şablondan
    alanları çekmenin en doğrudan yolu. Her desen modül seviyesinde
    bir kez derleniyor (re.compile) — satır başına yeniden derlemek
    saniyede binlerce satırda gözle görülür yavaşlık yaratır.
"""

import re
import logging

from collector.base import BaseCollector
from collector.timeparse import parse_syslog_timestamp

logger = logging.getLogger("sentinelboard.collector.auth")


# ── Syslog satırının ortak iskeleti ──────────────────────────
# "Jun  9 14:23:01 vps sshd[12345]: mesaj"
#  └─ tarih ──┘ └host┘ └proc┘└pid┘   └mesaj┘
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-/.]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# ── sshd mesaj desenleri ─────────────────────────────────────
# "invalid user" ibaresi opsiyonel: olmayan bir kullanıcıya giriş
# denenirse sshd araya bu ifadeyi ekler.
FAILED_PASSWORD_RE = re.compile(
    r"Failed (?P<method>password|publickey|none) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<src_ip>[\d.a-fA-F:]+) port (?P<src_port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for (?P<user>\S+) "
    r"from (?P<src_ip>[\d.a-fA-F:]+) port (?P<src_port>\d+)"
)

# Kullanıcı adı geçersizse sshd şifre bile sormadan bunu yazar
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<src_ip>[\d.a-fA-F:]+)(?: port (?P<src_port>\d+))?"
)

# Bağlantı kapandı — tarama botlarının tipik izi
CONN_CLOSED_RE = re.compile(
    r"Connection closed by (?:authenticating |invalid )?user (?P<user>\S+) "
    r"(?P<src_ip>[\d.a-fA-F:]+) port (?P<src_port>\d+)"
)

# ── sudo deseni ──────────────────────────────────────────────
# "yasin : TTY=pts/0 ; PWD=/home/yasin ; USER=root ; COMMAND=/usr/bin/apt update"
SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)

SUDO_FAIL_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?P<reason>\d+ incorrect password attempts?|"
    r"user NOT in sudoers|command not allowed)"
)

# ── Kullanıcı ekleme ─────────────────────────────────────────
USER_ADD_RE = re.compile(r"new user: name=(?P<user>[^,]+)")


class AuthCollector(BaseCollector):
    """/var/log/auth.log satırlarını yapılandırılmış olaylara çevirir."""

    def get_source_name(self) -> str:
        return self.config.get("name", "auth")

    def parse_line(self, line: str) -> dict | None:
        m = SYSLOG_RE.match(line)
        if not m:
            return None  # syslog formatına uymayan satırı atla

        host = m.group("host")
        process = m.group("process")
        pid = int(m.group("pid")) if m.group("pid") else None
        message = m.group("message")
        timestamp = parse_syslog_timestamp(m.group("ts"))

        # Her olayın taşıyacağı ortak alanlar
        base = {
            "timestamp": timestamp,
            "host": host,
            "process": process,
            "pid": pid,
            "message": message,
            "raw": line,
        }

        # sshd satırları
        if process.startswith("sshd"):
            event = self._parse_sshd(message, base)
            if event:
                return event

        # sudo satırları
        if process.startswith("sudo"):
            event = self._parse_sudo(message, base)
            if event:
                return event

        # useradd satırları
        if process.startswith("useradd"):
            um = USER_ADD_RE.search(message)
            if um:
                return {**base, "event_type": "user_added",
                        "severity": "medium", "user": um.group("user")}

        # Tanınmayan ama geçerli syslog satırı: yine de kaydet.
        # Neden? ML modülü "saatlik olay sayısı" gibi metrikleri
        # bunlardan hesaplıyor; attığımız her satır baseline'ı bozar.
        return {**base, "event_type": "auth_other", "severity": "info"}

    def _parse_sshd(self, message: str, base: dict) -> dict | None:
        """sshd mesajını olaya çevirir."""
        fm = FAILED_PASSWORD_RE.search(message)
        if fm:
            return {
                **base,
                "event_type": "auth_failure",
                "severity": "medium",
                "user": fm.group("user"),
                "src_ip": fm.group("src_ip"),
                "src_port": int(fm.group("src_port")),
                "auth_method": fm.group("method"),
            }

        am = ACCEPTED_RE.search(message)
        if am:
            return {
                **base,
                "event_type": "auth_success",
                "severity": "info",
                "user": am.group("user"),
                "src_ip": am.group("src_ip"),
                "src_port": int(am.group("src_port")),
                "auth_method": am.group("method"),
            }

        im = INVALID_USER_RE.search(message)
        if im:
            port = im.group("src_port")
            return {
                **base,
                "event_type": "auth_failure",
                "severity": "medium",
                "user": im.group("user"),
                "src_ip": im.group("src_ip"),
                "src_port": int(port) if port else None,
                "auth_method": "invalid_user",
            }

        cm = CONN_CLOSED_RE.search(message)
        if cm:
            return {
                **base,
                "event_type": "connection_closed",
                "severity": "low",
                "user": cm.group("user"),
                "src_ip": cm.group("src_ip"),
                "src_port": int(cm.group("src_port")),
            }

        return None

    def _parse_sudo(self, message: str, base: dict) -> dict | None:
        """sudo mesajını olaya çevirir."""
        sm = SUDO_RE.match(message)
        if sm:
            return {
                **base,
                "event_type": "sudo_command",
                "severity": "low",
                "user": sm.group("user"),
                "target_user": sm.group("target_user"),
                "command": sm.group("command"),
                "tty": sm.group("tty"),
                "pwd": sm.group("pwd"),
            }

        fm = SUDO_FAIL_RE.match(message)
        if fm:
            return {
                **base,
                "event_type": "sudo_failure",
                "severity": "high",
                "user": fm.group("user"),
                "reason": fm.group("reason"),
            }

        return None