"""
tailer.py — Log dosyası takipçisi

Bu dosya ne yapıyor?
    `tail -f` komutunun Python karşılığı. Bir log dosyasını açar,
    sonuna gider ve yeni satır yazıldıkça onu okur.

Neden watchdog değil de polling?
    watchdog işletim sisteminin dosya olaylarını dinler. Kulağa daha
    zarif geliyor ama log dosyalarında iki sorunu var:
    1) Bir olay "dosya değişti" der, "şu satır eklendi" demez —
       yine de dosyayı açıp okuman gerekir.
    2) Linux'ta logrotate dosyayı taşıdığında olay akışı kopabilir.
    Saniyede bir dosyanın boyutuna bakmak hem daha basit hem daha
    dayanıklı. Log hacmi çok artarsa bile 1 saniyelik gecikme
    SIEM için fazlasıyla yeterli.

Log rotation nedir, neden önemli?
    Linux log dosyaları sonsuza kadar büyümesin diye belirli
    aralıklarla "döndürülür": auth.log → auth.log.1 olarak taşınır
    ve yerine boş bir auth.log açılır. Biz eski dosyayı okumaya
    devam edersek yeni logları kaçırırız. Bunu anlamanın yolu
    dosyanın inode numarasına (Windows'ta boyutuna) bakmak.
"""

import os
import logging

logger = logging.getLogger("sentinelboard.collector.tailer")


class FileTailer:
    """
    Tek bir log dosyasını takip eder ve yeni satırları verir.

    Kullanım:
        tailer = FileTailer("/var/log/auth.log")
        for line in tailer.read_new_lines():
            print(line)
        # ... 1 saniye bekle, tekrar çağır ...
    """

    def __init__(self, path: str, from_start: bool = False):
        """
        Args:
            path: İzlenecek dosyanın yolu
            from_start: True ise dosyanın başından okur (test için kullanışlı),
                        False ise sadece bundan sonra eklenecek satırları alır.
                        Canlıda False olmalı — yoksa her yeniden başlatmada
                        tüm geçmiş loglar tekrar işlenir.
        """
        self.path = path
        self.from_start = from_start
        self._fh = None          # açık dosya nesnesi
        self._inode = None       # dosya kimliği — rotation tespiti için
        self._open()

    def _file_id(self):
        """
        Dosyanın kimliğini döner.

        Linux'ta inode numarası dosyayı benzersiz tanımlar; dosya
        taşınsa bile inode aynı kalır, yeni dosya farklı inode alır.
        Windows'ta inode kavramı yok (st_ino genelde 0 döner), o yüzden
        orada dosya boyutunu kullanıyoruz: boyut aniden küçüldüyse
        dosya sıfırlanmış demektir.
        """
        try:
            st = os.stat(self.path)
            return st.st_ino if st.st_ino else ("size", st.st_size)
        except OSError:
            return None

    def _open(self):
        """Dosyayı açar ve okuma konumunu ayarlar."""
        try:
            # errors="replace": bozuk byte'lar programı çökertmesin.
            # Log dosyalarında bazen yarım yazılmış satırlar olur.
            self._fh = open(self.path, "r", encoding="utf-8", errors="replace")
            if not self.from_start:
                self._fh.seek(0, os.SEEK_END)  # sona git, geçmişi atla
            self._inode = self._file_id()
            logger.info(f"Tailing {self.path}")
        except FileNotFoundError:
            # Dosya henüz yoksa sorun değil — ileride oluşabilir,
            # her okuma denemesinde tekrar bakacağız.
            self._fh = None
            logger.warning(f"Log file not found (will retry): {self.path}")
        except PermissionError:
            self._fh = None
            logger.error(f"Permission denied: {self.path}")

    def _check_rotation(self):
        """
        Dosya döndürülmüş mü diye bakar, döndürülmüşse yeniden açar.
        """
        current = self._file_id()
        if current is None:
            return  # dosya şu an yok, bir sonraki turda bakarız
        if self._inode is not None and current != self._inode:
            logger.info(f"Log rotation detected: {self.path}")
            if self._fh:
                self._fh.close()
            self.from_start = True  # yeni dosyanın başından başla
            self._open()

    def read_new_lines(self):
        """
        Son çağrıdan beri eklenen satırları döner.

        Returns:
            list[str]: Yeni satırlar (sonundaki \\n temizlenmiş,
                       boş satırlar atılmış)
        """
        # Dosya daha önce açılamadıysa tekrar dene
        if self._fh is None:
            self._open()
            if self._fh is None:
                return []

        self._check_rotation()
        if self._fh is None:
            return []

        lines = []
        try:
            for line in self._fh:
                line = line.rstrip("\n").rstrip("\r")
                if line.strip():
                    lines.append(line)
        except (OSError, ValueError) as e:
            logger.error(f"Read error on {self.path}: {e}")
            self.close()
        return lines

    def close(self):
        """Dosyayı kapatır."""
        if self._fh:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None