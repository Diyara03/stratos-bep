"""Remove demo data created by demo_setup. Preserves users."""
from django.core.management.base import BaseCommand

from emails.models import Email


class Command(BaseCommand):
    help = 'Remove demo data. Preserves user accounts.'

    def handle(self, *args, **options):
        # Delete demo emails (cascades to AnalysisResult, QuarantineEntry, Attachments, IOCs)
        count, _ = Email.objects.filter(message_id__startswith='demo-').delete()
        self.stdout.write(f'Deleted {count} demo-related records (emails + cascaded).')

        self.stdout.write(self.style.SUCCESS('Demo data cleared. Users preserved.'))
