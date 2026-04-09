"""
Management command to fetch emails from Gmail.
"""
from django.core.management.base import BaseCommand

from emails.models import Email, EmailAttachment
from emails.services.parser import EmailParser


class Command(BaseCommand):
    help = 'Fetch new emails from Gmail and save to database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--max', type=int, default=10,
            help='Maximum number of emails to fetch (default: 10)'
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Print what would be fetched without saving'
        )

    def handle(self, *args, **options):
        from emails.services.gmail_connector import GmailConnector
        from emails.tasks import analyze_email_task

        max_results = options['max']
        dry_run = options['dry_run']

        try:
            connector = GmailConnector()
        except FileNotFoundError as e:
            self.stdout.write(str(e))
            return

        raw_messages = connector.fetch_new_emails(max_results=max_results)
        parser = EmailParser()

        fetched = 0
        skipped = 0
        errors = 0

        for raw_message in raw_messages:
            try:
                email_instance, attachment_dicts = parser.parse_gmail_message(
                    raw_message
                )

                if dry_run:
                    self.stdout.write(
                        f"  Would save: {email_instance.subject} "
                        f"from {email_instance.from_address}"
                    )
                    fetched += 1
                    continue

                email_instance.gmail_id = raw_message['id']
                email_instance.save()

                for att_dict in attachment_dicts:
                    EmailAttachment.objects.create(
                        email=email_instance,
                        filename=att_dict['filename'],
                        content_type=att_dict['content_type'],
                        size_bytes=att_dict['size_bytes'],
                        sha256_hash=att_dict['sha256_hash'],
                        md5_hash=att_dict['md5_hash'],
                    )

                analyze_email_task.delay(email_instance.id)
                connector.mark_as_read(raw_message['id'])
                fetched += 1

            except Exception as exc:
                self.stderr.write(f"Error processing email: {exc}")
                errors += 1

        if dry_run:
            self.stdout.write(
                f"[DRY RUN] Would fetch {fetched} new emails, "
                f"skipped {skipped} already processed"
            )
        else:
            self.stdout.write(
                f"Fetched {fetched} new emails, "
                f"skipped {skipped} already processed"
            )
