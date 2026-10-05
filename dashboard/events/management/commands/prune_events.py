"""
prune_events — Saklama süresi dolmuş olayları ve alert'leri siler.

Neden gerekli?
    SentinelBoard günde ~20 bin olay yazıyor. Hiçbir şey silinmezse
    veritabanı sınırsız büyür. Disk dolduğunda SQLite yazamaz, parser
    durur ve SIEM sessizce körleşir — arızaların en kötü türü, çünkü
    dışarıdan "çalışıyor" görünür.

Neden olaylar ve alert'ler için ayrı süre?
    Olaylar hacimli ve çoğu gürültü. Alert'ler az sayıda ve değerli:
    neyin ne zaman tetiklendiğinin kaydı. Olayları 90 gün, alert'leri
    1 yıl tutmak makul bir denge.

Neden önce alert'ler siliniyor?
    Bir alert'e bağlı olaylar o alert'in kanıtı. Alert hâlâ duruyorken
    kanıtını silersen panelde "12 ilgili olay" yazan ama hiçbirini
    gösteremeyen bir kayıt kalır. O yüzden sıra: önce süresi dolmuş
    alert'leri sil, sonra artık hiçbir alert'e bağlı olmayan eski
    olayları sil.

Neden parça parça?
    Tek seferde yüz binlerce satır silmek SQLite'ı uzun süre kilitler;
    o sırada parser yazamaz ve Redis'te birikme başlar. Partiler hâlinde
    silmek kilidi kısa tutar.

Kullanım:
    python manage.py prune_events --dry-run    # ne silinecek, sadece göster
    python manage.py prune_events              # sil
    python manage.py prune_events --vacuum     # sil + disk alanını geri kazan
"""

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone

from events.models import Alert, Event

BATCH_SIZE = 5000


class Command(BaseCommand):
    help = "Saklama süresi dolmuş olayları ve alert'leri siler."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Hiçbir şey silme, sadece ne silineceğini göster",
        )
        parser.add_argument(
            "--vacuum", action="store_true",
            help="Silme sonrası VACUUM çalıştır (disk alanını işletim sistemine geri verir)",
        )

    def handle(self, *args, **opts):
        now = timezone.now()
        dry = opts["dry_run"]

        alert_cutoff = now - timedelta(days=settings.ALERT_RETENTION_DAYS)
        event_cutoff = now - timedelta(days=settings.EVENT_RETENTION_DAYS)

        # ── 1. Süresi dolmuş alert'ler ──
        old_alerts = Alert.objects.filter(created_at__lt=alert_cutoff)
        n_alerts = old_alerts.count()
        self.stdout.write(
            f"Alert : {alert_cutoff:%Y-%m-%d} tarihinden eski {n_alerts} kayit"
        )
        if not dry and n_alerts:
            self._delete_in_batches(Alert, old_alerts)

        # ── 2. Eski VE hiçbir alert'e bağlı olmayan olaylar ──
        # alerts__isnull=True → bu olayı kanıt olarak kullanan alert yok.
        # Böylece duran bir alert'in kanıtını yanlışlıkla silmiyoruz.
        old_events = Event.objects.filter(
            timestamp__lt=event_cutoff, alerts__isnull=True
        )
        n_events = old_events.count()
        self.stdout.write(
            f"Event : {event_cutoff:%Y-%m-%d} tarihinden eski, alert'e bagli olmayan "
            f"{n_events} kayit"
        )
        if not dry and n_events:
            self._delete_in_batches(Event, old_events)

        if dry:
            self.stdout.write(self.style.WARNING("Dry-run — hicbir sey silinmedi."))
            return

        self.stdout.write(
            self.style.SUCCESS(f"Tamam: {n_alerts} alert, {n_events} olay silindi.")
        )

        if opts["vacuum"]:
            # SQLite silinen satırların yerini kendi içinde yeniden kullanır
            # ama dosyayı küçültmez. VACUUM dosyayı baştan yazar. Bu sırada
            # veritabanı kilitli olur, o yüzden isteğe bağlı bıraktık.
            self.stdout.write("VACUUM calisiyor (veritabani kisa sure kilitli)...")
            with connection.cursor() as cur:
                cur.execute("VACUUM")
            self.stdout.write(self.style.SUCCESS("VACUUM tamam."))

    def _delete_in_batches(self, model, queryset):
        """Queryset'i BATCH_SIZE'lık partiler hâlinde siler."""
        toplam = 0
        while True:
            # Her turda yeniden sorguluyoruz: silinenler kendiliğinden düşer.
            ids = list(queryset.values_list("pk", flat=True)[:BATCH_SIZE])
            if not ids:
                break
            model.objects.filter(pk__in=ids).delete()
            toplam += len(ids)
            self.stdout.write(f"  ... {toplam} silindi")
        return toplam