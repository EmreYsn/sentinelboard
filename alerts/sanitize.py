"""
sanitize.py — LLM'e gönderilen veriyi minimize eder.

Neden bu dosya var?
    SentinelBoard alert ve event'leri analiz için bir LLM'e gönderiyor.
    Sağlayıcı bulutta olduğunda (Groq gibi) bu veri sunucudan çıkar ve
    üçüncü bir tarafın altyapısına ulaşır. Bir SIEM'in gönderdiği veri
    ise en hassas veri türü: kullanıcı adları, iç IP'ler, çalıştırılan
    komutlar, dosya yolları.

Takma ad vermek analizi bozmaz mı?
    Bozmuyor, çünkü LLM'in görevi bir *tekniği* açıklamak, bir *kişiyi*
    tanımlamak değil. "IP_1 (harici) 3 kez sudo denedi" cümlesi gerçek
    IP ile aynı analizi üretir. Gerçek değerler panelde zaten görünür;
    eşleştirme sunucunun içinde kalır.

Ne korunuyor, ne gizleniyor?
    Gizlenen : gerçek IP oktetleri, kişiye özel kullanıcı adları,
               ham syslog satırı, komut argümanları, ev dizini yolları
    Korunan  : IP'nin yerel mi harici mi olduğu, sistem hesabı adları
               (root, www-data — her sistemde var, kimseyi tanımlamaz
               ama yetki yükseltme analizi için gerekli), komutun
               binary adı, olay tipi, zaman, sayılar, MITRE tag'leri

Kapsam uyarısı:
    Bu katman *bizim* ürettiğimiz metni temizler. Chatbot'a kullanıcının
    kendi yazdığı soru (chat.py) temizlenmez — oraya gerçek bir IP veya
    kullanıcı adı yazarsan o değer dışarı çıkar. Tam sıfır garanti
    isteniyorsa tek çözüm yerel bir model (bkz. LLM_BASE_URL).
"""

from __future__ import annotations

import ipaddress
import os
import re

# Her Linux kurulumunda bulunan hesaplar. Bunlar kişiye özel değil,
# ama analiz için değerli: "root" göründüğünde LLM yetki yükseltme
# olduğunu anlar. Bu yüzden takma ad verilmiyor.
SYSTEM_ACCOUNTS = frozenset(
    {
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
        "mail", "news", "uucp", "proxy", "backup", "list", "irc",
        "gnats", "nobody", "www-data", "nginx", "sshd", "syslog",
        "messagebus", "_apt", "redis", "postgres", "mysql", "tss",
        "landscape", "systemd-network", "systemd-resolve",
        "systemd-timesync", "uuidd", "dnsmasq", "docker", "ftp",
    }
)

# IPv4: gevşek yakala, sonra ipaddress ile doğrula. Doğrulama şart,
# çünkü "1.2.3.999" ya da sürüm numaraları da bu desene uyar.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6: en az üç iki nokta, ya da "::" içeren biçimler. Eşik üç,
# çünkü saat damgası (14:23:01) iki iki nokta içerir ve yanlışlıkla
# IP sanılmamalı. Buna rağmen her eşleşme ipaddress'ten geçiyor.
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:?){0,6}[0-9a-fA-F]{0,4}\b"
)

# Ev dizini yolları kullanıcı adını taşır: /home/yasin → /home/USER_1
HOME_PATH_RE = re.compile(r"/(home|Users)/([A-Za-z0-9._-]+)")

# Kendi ürettiğimiz etiketler. Tanımak zorunlu: aynı metin birden fazla
# desene uyabiliyor ("for invalid user admin from" hem 0. hem 1. desene)
# ve ikinci desen ilkinin koyduğu etiketi tekrar takma adlarsa USER_1
# değeri USER_2 oluyor — yani aynı gerçek değer prompt içinde iki farklı
# etiketle görünüyor. Takma adlandırma idempotent olmak zorunda.
LABEL_USER_RE = re.compile(r"^USER_\d+$")
LABEL_IP_RE = re.compile(r"^IP_\d+(?:\s*\([^)]*\))?$")

# Komut argümanları en hassas kısım. Binary adı analiz için yeterli:
# "apt" ile "apt install --yes /home/yasin/x.deb" aynı tehdit sinyalini
# verir, ikincisi fazladan veri sızdırır.
COMMAND_RE = re.compile(r"(?i)\bCOMMAND=(?P<cmd>.+?)(?=\s*(?:;|$))")

# Çalışma dizini de yol bilgisi taşır, analiz için gereksiz.
PWD_RE = re.compile(r"(?i)\bPWD=(?P<pwd>\S+)")

# Kullanıcı adının serbest metne gömülü hallerini yakalayan desenler.
# Hepsi collector/auth.py'deki gerçek log biçimlerinden türetildi;
# bilerek dar tutuldu ki "user authentication failed" gibi cümlelerde
# rastgele kelimeleri kullanıcı adı sanmasın.
USER_PATTERNS = (
    re.compile(r"(?i)\bfor\s+(?:invalid\s+user\s+)?([A-Za-z0-9._\-$]{1,32})\s+from\b"),
    re.compile(r"(?i)\bInvalid user\s+([A-Za-z0-9._\-$]{1,32})\b"),
    re.compile(r"(?i)\bauthenticating user\s+([A-Za-z0-9._\-$]{1,32})\b"),
    re.compile(r"(?i)\buser=([A-Za-z0-9._\-$]{1,32})"),
    re.compile(r"(?i)\bUSER=([A-Za-z0-9._\-$]{1,32})"),
    re.compile(r"(?i)\bnew user:\s*name=([^,\s]{1,32})"),
    re.compile(r"^\s*([A-Za-z0-9._\-$]{1,32})\s*:\s*(?=TTY=|\d+ incorrect|user NOT in sudoers|command not allowed)"),
)


def _sub_group1(pattern: re.Pattern, text: str, fn) -> str:
    """Desenin sadece 1. yakalama grubunu fn(...) sonucuyla değiştirir.

    Neden böyle? Desenler bağlamı da yakalıyor ("for X from"). Tüm
    eşleşmeyi değiştirmek bağlamı siler, LLM cümleyi okuyamaz hale
    gelir. Bu yüzden eşleşmenin içinden yalnızca adı kesip değiştiriyoruz.
    """

    def repl(m: re.Match) -> str:
        whole = m.group(0)
        start, end = m.start(0), m.end(0)
        if m.start(1) < start or m.end(1) > end:
            return whole
        return (
            whole[: m.start(1) - start]
            + fn(m.group(1))
            + whole[m.end(1) - start:]
        )

    return pattern.sub(repl, text)


class Pseudonymizer:
    """IP ve kullanıcı adlarını tutarlı takma adlara çevirir.

    Tutarlılık tek bir istek boyunca geçerli: aynı IP her yerde IP_1
    olur, böylece LLM "aynı kaynak" ilişkisini kurabilir. Eşleştirme
    sadece bellekte yaşar, isteğin sonunda kaybolur — diske yazılmaz,
    dışarı gönderilmez.
    """

    def __init__(self) -> None:
        self._ips: dict[str, str] = {}
        self._users: dict[str, str] = {}
        # Etiket sayaçları ayrı tutuluyor: "açıkça bildirilmiş" değerler
        # (bkz. disclose_*) haritada yer tutar ama etiket tüketmemeli,
        # yoksa numaralandırma IP_1, IP_3, IP_4 diye boşluklu gider.
        self._ip_counter = 0
        self._user_counter = 0
        self._disclosed = False

    # ── tek değerler ─────────────────────────────────────────

    @staticmethod
    def _scope(value: str) -> str:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return "bilinmiyor"
        if addr.is_loopback:
            return "localhost"
        return "yerel" if addr.is_private else "harici"

    def ip(self, value) -> str:
        """Bir IP'yi takma adına çevirir. Yerel/harici bilgisi korunur."""
        if value in (None, "", "N/A"):
            return "N/A"
        value = str(value)
        if LABEL_IP_RE.match(value):
            return value  # zaten etiket — tekrar etiketlemek tutarlılığı bozar
        if value not in self._ips:
            self._ip_counter += 1
            self._ips[value] = f"IP_{self._ip_counter} ({self._scope(value)})"
        return self._ips[value]

    def disclose_ip(self, value) -> str:
        """Bir IP'yi takma adlamadan geçirir.

        Neden böyle bir kapı var? Chatbot'ta soruyu kullanıcı yazıyor.
        "185.x.y.z ne yaptı" diye sorduysa o IP zaten sorunun içinde
        dışarı çıkmış durumda. Bağlamda takma adlamak hiçbir gizlilik
        kazandırmaz, sadece gelen cevabı okunmaz hale getirir.

        Yani bu bir istisna değil, kapsamın dürüst sınırı: kullanıcının
        kendi ifşa ettiği değer gizlenmiş gibi gösterilmiyor.
        """
        if value in (None, "", "N/A"):
            return "N/A"
        value = str(value)
        self._ips[value] = value
        self._disclosed = True
        return value

    def user(self, value) -> str:
        """Bir kullanıcı adını takma adına çevirir.

        Sistem hesapları olduğu gibi kalır: "root" kimseyi tanımlamaz
        ama yetki yükseltme analizinin merkezinde yer alır.
        """
        if value in (None, "", "N/A"):
            return "N/A"
        value = str(value)
        if value.lower() in SYSTEM_ACCOUNTS:
            return value
        if LABEL_USER_RE.match(value):
            return value  # zaten etiket — bkz. LABEL_USER_RE açıklaması
        if value not in self._users:
            self._user_counter += 1
            self._users[value] = f"USER_{self._user_counter}"
        return self._users[value]

    def disclose_user(self, value) -> str:
        """Bir kullanıcı adını takma adlamadan geçirir. Bkz. disclose_ip."""
        if value in (None, "", "N/A"):
            return "N/A"
        value = str(value)
        self._users[value] = value
        self._disclosed = True
        return value

    # ── serbest metin ────────────────────────────────────────

    def _replace_ips(self, text: str) -> str:
        def repl(m: re.Match) -> str:
            token = m.group(0)
            try:
                ipaddress.ip_address(token)
            except ValueError:
                return token  # IP değil (sürüm no, saat damgası) — dokunma
            return self.ip(token)

        text = IPV4_RE.sub(repl, text)
        return IPV6_RE.sub(repl, text)

    def text(self, value) -> str:
        """Serbest metni temizler: IP, kullanıcı adı, yol ve komut argümanı.

        Sıra önemli: IP'ler önce, çünkü kullanıcı desenleri ("for X from")
        IP'nin yanındaki kelimeyi okuyor. Komut ve yollar en sonda,
        çünkü o noktada kullanıcı adları zaten takma adlı.
        """
        if not value:
            return ""
        out = str(value)

        out = self._replace_ips(out)

        for pattern in USER_PATTERNS:
            out = _sub_group1(pattern, out, self.user)

        # Daha önce takma ad verilmiş adların metinde kalan geçişleri.
        # Uzun adlar önce, böylece "yasin" kısa adı "yasinemre"nin içini
        # bozmaz.
        for real, fake in sorted(self._users.items(), key=lambda kv: -len(kv[0])):
            out = re.sub(rf"(?<![\w.-]){re.escape(real)}(?![\w.-])", fake, out)

        out = HOME_PATH_RE.sub(
            lambda m: f"/{m.group(1)}/{self.user(m.group(2))}", out
        )
        out = PWD_RE.sub("PWD=<gizlendi>", out)
        out = COMMAND_RE.sub(
            lambda m: f"COMMAND={os.path.basename(m.group('cmd').split()[0])}"
            if m.group("cmd").split()
            else "COMMAND=<bos>",
            out,
        )
        return out

    # ── özet ─────────────────────────────────────────────────

    def summary(self) -> str:
        """Prompt'un sonuna eklenecek kısa açıklama.

        LLM'e takma adların ne anlama geldiğini söylemek gerekiyor,
        yoksa "IP_1" ifadesini anlamsız bir dize sanıp yorumu zayıflatır.
        """
        note = (
            f"Not: Gizlilik gerekcesiyle IP adresleri ve kullanici adlari "
            f"takma adlarla verilmistir ({len(self._ips)} farkli IP, "
            f"{len(self._users)} farkli kullanici). Ayni takma ad her yerde "
            f"ayni gercek degeri gosterir. Sistem hesaplari (root, www-data) "
            f"gercek adiyla birakilmistir. Ham log satirlari, komut "
            f"argumanlari ve dosya yollari gonderilmemistir. Takma adlari "
            f"gercek deger sanma, analizini teknige odakla."
        )
        if self._disclosed:
            note += (
                " Kullanicinin sorusunda gecen degerler oldugu gibi "
                "birakilmistir, cevabinda onlari ayni sekilde kullan."
            )
        return note

    def mapping(self) -> dict[str, dict[str, str]]:
        """Takma ad → gerçek değer. Sadece sunucu içi kullanım (debug/panel)."""
        return {
            "ips": {v: k for k, v in self._ips.items()},
            "users": {v: k for k, v in self._users.items()},
        }


def scrub_event_line(pseudo: Pseudonymizer, event) -> str:
    """Bir Event'i tek satırlık, temizlenmiş özete çevirir.

    `raw` alanı bilerek hiç okunmuyor. Ham syslog satırı veritabanında
    duruyor ve panelde görünüyor; LLM'in ona ihtiyacı yok.

    Çağrı sırası önemli: ip() ve user() önce çağrılıyor ki metindeki
    aynı değerler aynı takma adı alsın.
    """
    ip_label = pseudo.ip(event.src_ip)
    user_label = pseudo.user(event.user)
    message = pseudo.text(event.message)
    return (
        f"  - [{event.severity}] {event.event_type} | "
        f"IP: {ip_label} | User: {user_label} | "
        f"Time: {event.timestamp} | {message}"
    )