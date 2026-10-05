"""
Collector'larin ham log satirlarini dogru ayristirdigini dogrular.

Neden bu testler?
    Her biri gercekte yasanmis bir hatayi kilitliyor:

    - test_iso_timestamp:  Ubuntu 23.10 rsyslog'un zaman damgasi
      bicimini degistirdi. Regex sadece eski bicimi tanidigi icin
      sunucuda saatlerce SIFIR olay toplandi, ama hicbir hata da
      gorunmedi — collector satirlari sessizce atiyordu.

    - test_nginx_is_suspicious_bool:  Bu alan string olarak gitseydi
      engine/matcher.py'nin `extra__is_suspicious=True` sorgusu hicbir
      zaman eslesmezdi ve web tarama kurali hiç tetiklenmezdi.

    - test_nginx_http_status_int:  Alan adi "http_status" olmak zorunda;
      ml/features.py bir sure "status_code" sorguladi ve 4xx sayaci
      kalici olarak sifir kaldi.
"""

import pytest

from collector.auth import AuthCollector
from collector.nginx import NginxCollector
from collector.syslog import SyslogCollector
from collector.syslogfmt import split_syslog_line


# ── Syslog satir bicimi ──────────────────────────────────────

def test_iso_timestamp_parse():
    """Ubuntu 23.10+ ISO 8601 bicimi taninmali."""
    line = ("2026-10-04T13:11:41.024533702+02:00 vmi3286839 sshd[3896287]: "
            "Failed password for root from 1.2.3.4 port 22 ssh2")
    parts = split_syslog_line(line)
    assert parts is not None, "ISO bicimli satir taninmadi"
    assert parts["host"] == "vmi3286839"
    assert parts["process"] == "sshd"
    assert parts["pid"] == 3896287


def test_bsd_timestamp_parse():
    """Klasik BSD bicimi de calismaya devam etmeli."""
    line = "Oct  4 13:11:41 vps sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
    parts = split_syslog_line(line)
    assert parts is not None, "BSD bicimli satir taninmadi"
    assert parts["process"] == "sshd"


def test_bozuk_satir_none_doner():
    assert split_syslog_line("bu bir syslog satiri degil") is None


# ── auth.log ─────────────────────────────────────────────────

@pytest.fixture
def auth():
    return AuthCollector({"name": "auth"})


def test_failed_password(auth):
    line = ("2026-10-04T13:11:41+02:00 vps sshd[1]: Failed password for root "
            "from 109.160.32.116 port 54321 ssh2")
    e = auth.parse_line(line)
    assert e["event_type"] == "auth_failure"
    assert e["src_ip"] == "109.160.32.116"
    assert e["user"] == "root"
    assert e["process"] == "sshd"   # ssh_brute_force kurali bu alana bakiyor


def test_invalid_user_de_auth_failure(auth):
    line = "2026-10-04T13:11:41+02:00 vps sshd[1]: Invalid user admin from 5.6.7.8 port 22"
    e = auth.parse_line(line)
    assert e["event_type"] == "auth_failure"
    assert e["user"] == "admin"


def test_accepted_publickey(auth):
    line = ("2026-10-04T13:11:41+02:00 vps sshd[1]: Accepted publickey for yasin "
            "from 85.106.7.226 port 1234 ssh2")
    e = auth.parse_line(line)
    assert e["event_type"] == "auth_success"
    assert e["auth_method"] == "publickey"


def test_sudo_komutu(auth):
    line = ("2026-10-04T13:11:41+02:00 vps sudo:  yasin : TTY=pts/0 ; "
            "PWD=/home/yasin ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
    e = auth.parse_line(line)
    assert e["event_type"] == "sudo_command"
    assert e["user"] == "yasin"      # sudo_suspicious kurali user'a gore grupluyor
    assert "systemctl" in e["command"]


# ── nginx access.log ─────────────────────────────────────────

@pytest.fixture
def nginx():
    return NginxCollector({"name": "nginx_access"})


NGINX_TARAMA = ('1.2.3.4 - - [04/Oct/2026:13:11:41 +0200] "GET /wp-admin/install.php '
                'HTTP/1.1" 404 162 "-" "sqlmap/1.7"')
NGINX_NORMAL = ('5.6.7.8 - - [04/Oct/2026:13:11:41 +0200] "GET / HTTP/1.1" 200 5123 '
                '"-" "Mozilla/5.0 (Windows NT 10.0) Chrome/120"')


def test_nginx_is_suspicious_bool(nginx):
    """is_suspicious BOOLEAN olmali — matcher boolean olarak sorguluyor."""
    e = nginx.parse_line(NGINX_TARAMA)
    assert e["is_suspicious"] is True, "string veya truthy deger degil, True olmali"

    n = nginx.parse_line(NGINX_NORMAL)
    assert n["is_suspicious"] is False


def test_nginx_http_status_int(nginx):
    """Alan adi 'http_status', tipi int — ml/features.py boyle sorguluyor."""
    e = nginx.parse_line(NGINX_TARAMA)
    assert "http_status" in e, "alan adi degistiyse ml/features.py kirilir"
    assert e["http_status"] == 404
    assert isinstance(e["http_status"], int)


def test_nginx_bozuk_satir(nginx):
    assert nginx.parse_line("rastgele metin") is None


# ── syslog / UFW ─────────────────────────────────────────────

def test_ufw_block():
    s = SyslogCollector({"name": "syslog"})
    line = ("2026-10-04T13:11:41+02:00 vps kernel: [UFW BLOCK] IN=eth0 OUT= "
            "SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=5555 DPT=22")
    e = s.parse_line(line)
    assert e["event_type"] == "firewall_block"
    assert e["src_ip"] == "1.2.3.4"
    assert e["dst_port"] == 22