"""
Tests for management commands: seed_demo_data, demo_setup, demo_teardown, fetch_emails.
"""
from io import StringIO
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from emails.models import (
    AnalysisResult, Email, EmailAttachment, ExtractedIOC, QuarantineEntry,
)
from threat_intel.models import (
    BlacklistEntry, MaliciousDomain, MaliciousHash, MaliciousIP,
    WhitelistEntry, YaraRule,
)

User = get_user_model()


class SeedDemoDataTest(TestCase):
    """Test seed_demo_data management command."""

    def test_creates_users(self):
        out = StringIO()
        call_command('seed_demo_data', stdout=out)
        self.assertTrue(User.objects.filter(username='admin').exists())
        self.assertTrue(User.objects.filter(username='analyst').exists())
        self.assertTrue(User.objects.filter(username='viewer').exists())

    def test_creates_correct_roles(self):
        call_command('seed_demo_data', stdout=StringIO())
        self.assertEqual(User.objects.get(username='admin').role, 'ADMIN')
        self.assertEqual(User.objects.get(username='analyst').role, 'ANALYST')
        self.assertEqual(User.objects.get(username='viewer').role, 'VIEWER')

    def test_creates_demo_emails(self):
        call_command('seed_demo_data', stdout=StringIO())
        demo_emails = Email.objects.filter(message_id__startswith='demo-')
        self.assertEqual(demo_emails.count(), 9)

    def test_creates_all_verdicts(self):
        call_command('seed_demo_data', stdout=StringIO())
        demo = Email.objects.filter(message_id__startswith='demo-')
        self.assertEqual(demo.filter(verdict='CLEAN').count(), 3)
        self.assertEqual(demo.filter(verdict='SUSPICIOUS').count(), 3)
        self.assertEqual(demo.filter(verdict='MALICIOUS').count(), 3)

    def test_creates_analysis_results(self):
        call_command('seed_demo_data', stdout=StringIO())
        demo_count = Email.objects.filter(message_id__startswith='demo-').count()
        analysis_count = AnalysisResult.objects.filter(
            email__message_id__startswith='demo-'
        ).count()
        self.assertEqual(analysis_count, demo_count)

    def test_creates_quarantine_entries_for_non_clean(self):
        call_command('seed_demo_data', stdout=StringIO())
        quarantine_count = QuarantineEntry.objects.filter(
            email__message_id__startswith='demo-'
        ).count()
        non_clean = Email.objects.filter(
            message_id__startswith='demo-',
            status__in=['QUARANTINED', 'BLOCKED'],
        ).count()
        self.assertEqual(quarantine_count, non_clean)

    def test_creates_attachments_for_malicious(self):
        call_command('seed_demo_data', stdout=StringIO())
        mal_emails = Email.objects.filter(
            message_id__startswith='demo-', verdict='MALICIOUS'
        )
        for email in mal_emails:
            self.assertTrue(email.attachments.exists())

    def test_creates_ti_records(self):
        call_command('seed_demo_data', stdout=StringIO())
        self.assertGreaterEqual(MaliciousHash.objects.count(), 2)
        self.assertGreaterEqual(MaliciousDomain.objects.count(), 2)

    def test_idempotent_run(self):
        call_command('seed_demo_data', stdout=StringIO())
        count1 = Email.objects.filter(message_id__startswith='demo-').count()
        call_command('seed_demo_data', stdout=StringIO())
        count2 = Email.objects.filter(message_id__startswith='demo-').count()
        self.assertEqual(count1, count2)

    def test_flush_flag(self):
        call_command('seed_demo_data', stdout=StringIO())
        self.assertTrue(Email.objects.filter(message_id__startswith='demo-').exists())
        call_command('seed_demo_data', '--flush', stdout=StringIO())
        self.assertTrue(Email.objects.filter(message_id__startswith='demo-').exists())

    def test_output_contains_success(self):
        out = StringIO()
        call_command('seed_demo_data', stdout=out)
        output = out.getvalue()
        self.assertIn('Demo data seeded', output)


class DemoSetupTest(TestCase):
    """Test demo_setup management command."""

    def test_creates_users_and_emails(self):
        out = StringIO()
        call_command('demo_setup', stdout=out)
        self.assertTrue(User.objects.filter(username='admin').exists())
        self.assertGreater(
            Email.objects.filter(message_id__startswith='demo-').count(), 0
        )

    def test_creates_ti_data(self):
        call_command('demo_setup', stdout=StringIO())
        self.assertGreaterEqual(MaliciousHash.objects.count(), 5)
        self.assertGreaterEqual(MaliciousDomain.objects.count(), 5)
        self.assertGreaterEqual(MaliciousIP.objects.count(), 2)
        self.assertGreaterEqual(YaraRule.objects.count(), 3)

    def test_creates_whitelist_blacklist(self):
        call_command('demo_setup', stdout=StringIO())
        self.assertGreaterEqual(WhitelistEntry.objects.count(), 2)
        self.assertGreaterEqual(BlacklistEntry.objects.count(), 2)

    def test_creates_iocs_for_non_clean(self):
        call_command('demo_setup', stdout=StringIO())
        self.assertGreater(ExtractedIOC.objects.count(), 0)

    def test_demo_emails_have_10_samples(self):
        call_command('demo_setup', stdout=StringIO())
        demo = Email.objects.filter(message_id__startswith='demo-')
        self.assertEqual(demo.count(), 10)

    def test_flush_deletes_old_demo_data(self):
        call_command('demo_setup', stdout=StringIO())
        call_command('demo_setup', '--flush', stdout=StringIO())
        # After flush + reseed, count should still be 10
        demo = Email.objects.filter(message_id__startswith='demo-')
        self.assertEqual(demo.count(), 10)

    def test_output_messages(self):
        out = StringIO()
        call_command('demo_setup', stdout=out)
        output = out.getvalue()
        self.assertIn('Demo setup complete', output)
        self.assertIn('admin/admin123', output)


class DemoTeardownTest(TestCase):
    """Test demo_teardown management command."""

    def test_deletes_demo_emails(self):
        call_command('demo_setup', stdout=StringIO())
        self.assertGreater(
            Email.objects.filter(message_id__startswith='demo-').count(), 0
        )
        call_command('demo_teardown', stdout=StringIO())
        self.assertEqual(
            Email.objects.filter(message_id__startswith='demo-').count(), 0
        )

    def test_cascades_delete(self):
        call_command('demo_setup', stdout=StringIO())
        call_command('demo_teardown', stdout=StringIO())
        self.assertEqual(
            AnalysisResult.objects.filter(
                email__message_id__startswith='demo-'
            ).count(), 0
        )
        self.assertEqual(
            QuarantineEntry.objects.filter(
                email__message_id__startswith='demo-'
            ).count(), 0
        )

    def test_preserves_non_demo_emails(self):
        Email.objects.create(
            message_id='real-email-001',
            from_address='test@example.com',
            subject='Real email',
            received_at='2026-01-01T00:00:00Z',
        )
        call_command('demo_setup', stdout=StringIO())
        call_command('demo_teardown', stdout=StringIO())
        self.assertTrue(Email.objects.filter(message_id='real-email-001').exists())

    def test_output_message(self):
        out = StringIO()
        call_command('demo_teardown', stdout=out)
        self.assertIn('Demo data cleared', out.getvalue())

    def test_teardown_on_empty_db(self):
        out = StringIO()
        call_command('demo_teardown', stdout=out)
        self.assertIn('Deleted 0', out.getvalue())


class FetchEmailsCommandTest(TestCase):
    """Test fetch_emails management command."""

    @patch('emails.services.gmail_connector.GmailConnector')
    @patch('emails.tasks.analyze_email_task')
    def test_fetches_and_saves(self, mock_task, MockConnector):
        mock_conn = MagicMock()
        MockConnector.return_value = mock_conn
        mock_conn.fetch_new_emails.return_value = [{
            'id': 'gmail_123',
            'payload': {
                'headers': [
                    {'name': 'Message-ID', 'value': '<fetch-test@mail>'},
                    {'name': 'From', 'value': 'sender@example.com'},
                    {'name': 'To', 'value': 'me@example.com'},
                    {'name': 'Subject', 'value': 'Fetch Test'},
                    {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
                ],
                'mimeType': 'text/plain',
                'body': {'data': 'SGVsbG8=', 'size': 5},
                'parts': [],
            },
            'internalDate': '1735689600000',
        }]

        out = StringIO()
        call_command('fetch_emails', '--max=5', stdout=out, stderr=StringIO())
        output = out.getvalue()
        self.assertIn('Fetched 1', output)

    @patch('emails.services.gmail_connector.GmailConnector')
    def test_handles_missing_credentials(self, MockConnector):
        MockConnector.side_effect = FileNotFoundError('Gmail credentials not configured: No credentials')
        out = StringIO()
        call_command('fetch_emails', stdout=out)
        self.assertIn('credentials', out.getvalue().lower())

    @patch('emails.services.gmail_connector.GmailConnector')
    def test_dry_run(self, MockConnector):
        mock_conn = MagicMock()
        MockConnector.return_value = mock_conn
        mock_conn.fetch_new_emails.return_value = [{
            'id': 'gmail_dry',
            'payload': {
                'headers': [
                    {'name': 'Message-ID', 'value': '<dry-test@mail>'},
                    {'name': 'From', 'value': 'sender@example.com'},
                    {'name': 'To', 'value': 'me@example.com'},
                    {'name': 'Subject', 'value': 'Dry Run Test'},
                    {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
                ],
                'mimeType': 'text/plain',
                'body': {'data': 'SGVsbG8=', 'size': 5},
                'parts': [],
            },
            'internalDate': '1735689600000',
        }]

        out = StringIO()
        call_command('fetch_emails', '--dry-run', stdout=out, stderr=StringIO())
        output = out.getvalue()
        self.assertIn('DRY RUN', output)
        self.assertEqual(Email.objects.count(), 0)

    @patch('emails.services.gmail_connector.GmailConnector')
    @patch('emails.tasks.analyze_email_task')
    def test_max_argument(self, mock_task, MockConnector):
        mock_conn = MagicMock()
        MockConnector.return_value = mock_conn
        mock_conn.fetch_new_emails.return_value = []
        call_command('fetch_emails', '--max=3', stdout=StringIO())
        mock_conn.fetch_new_emails.assert_called_once_with(max_results=3)
