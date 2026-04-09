"""
Phase 2 tests: Gmail API Ingestion + Email Parser.
All Gmail API calls are mocked -- never call the real Gmail service.
"""
import hashlib
import json
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from emails.models import Email, EmailAttachment
from emails.services.analyzer import EmailAnalyzer
from emails.services.parser import EmailParser


def load_fixture(name):
    """Load a JSON fixture file."""
    fixture_path = os.path.join(
        os.path.dirname(__file__), 'fixtures', name
    )
    with open(fixture_path, 'r') as f:
        return json.load(f)


class TestExtractMessageId(TestCase):
    """T-001: _extract_message_id strips angle brackets."""

    def test_strips_angle_brackets(self):
        parser = EmailParser()
        headers = [{'name': 'Message-ID', 'value': '<msg-001@example.com>'}]
        result = parser._extract_message_id(headers)
        self.assertEqual(result, 'msg-001@example.com')


class TestExtractFrom(TestCase):
    """T-002, T-003: _extract_from parses display name and email."""

    def test_parses_display_name_and_email(self):
        parser = EmailParser()
        headers = [{'name': 'From', 'value': 'John Doe <john.doe@example.com>'}]
        display_name, email_address = parser._extract_from(headers)
        self.assertEqual(display_name, 'John Doe')
        self.assertEqual(email_address, 'john.doe@example.com')

    def test_parses_bare_email(self):
        parser = EmailParser()
        headers = [{'name': 'From', 'value': 'user@example.com'}]
        display_name, email_address = parser._extract_from(headers)
        self.assertEqual(display_name, '')
        self.assertEqual(email_address, 'user@example.com')


class TestExtractSubject(TestCase):
    """T-004: _extract_subject decodes RFC 2047 encoded subjects."""

    def test_decodes_rfc2047(self):
        parser = EmailParser()
        headers = [{'name': 'Subject', 'value': '=?UTF-8?B?SGVsbG8gV29ybGQ=?='}]
        result = parser._extract_subject(headers)
        self.assertEqual(result, 'Hello World')

    def test_plain_subject(self):
        parser = EmailParser()
        headers = [{'name': 'Subject', 'value': 'Quarterly Report Q4 2025'}]
        result = parser._extract_subject(headers)
        self.assertEqual(result, 'Quarterly Report Q4 2025')


class TestExtractDate(TestCase):
    """T-005, T-006: _extract_date returns timezone-aware datetime."""

    def test_returns_timezone_aware(self):
        parser = EmailParser()
        headers = [{'name': 'Date', 'value': 'Mon, 6 Jan 2026 10:30:00 +0000'}]
        result = parser._extract_date(headers)
        self.assertIsNotNone(result.tzinfo)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 6)

    def test_malformed_date_fallback(self):
        parser = EmailParser()
        headers = [{'name': 'Date', 'value': 'not-a-date'}]
        result = parser._extract_date(headers)
        self.assertIsNotNone(result.tzinfo)
        # Should be close to now
        self.assertAlmostEqual(
            result.timestamp(), timezone.now().timestamp(), delta=5
        )


class TestExtractBody(TestCase):
    """T-007, T-008: _extract_body handles multipart and plain text."""

    def test_multipart_alternative(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        body_text, body_html = parser._extract_body(fixture['payload'])
        self.assertIn('quarterly report', body_text.lower())
        self.assertIn('https://example.com/reports', body_text)
        self.assertIn('<a href=', body_html)

    def test_plain_text_only(self):
        parser = EmailParser()
        import base64
        text_data = base64.urlsafe_b64encode(b'Hello plain text').decode()
        payload = {
            'mimeType': 'text/plain',
            'body': {'data': text_data, 'size': 16},
        }
        body_text, body_html = parser._extract_body(payload)
        self.assertEqual(body_text, 'Hello plain text')
        self.assertEqual(body_html, '')


class TestExtractUrls(TestCase):
    """T-009, T-010: _extract_urls finds URLs in text and HTML."""

    def test_finds_urls_in_both(self):
        parser = EmailParser()
        text = 'Visit https://text-url.com for info'
        html = '<a href="https://html-url.com">link</a>'
        urls = parser._extract_urls(text, html)
        self.assertIn('https://text-url.com', urls)
        self.assertIn('https://html-url.com', urls)

    def test_empty_strings_return_empty(self):
        parser = EmailParser()
        urls = parser._extract_urls('', '')
        self.assertEqual(urls, [])

    def test_deduplicates(self):
        parser = EmailParser()
        text = 'Visit https://same-url.com'
        html = '<a href="https://same-url.com">link</a>'
        urls = parser._extract_urls(text, html)
        self.assertEqual(urls.count('https://same-url.com'), 1)


class TestExtractAuthResults(TestCase):
    """T-011, T-012: _extract_auth_results parses Authentication-Results."""

    def test_parses_pass_results(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        headers = fixture['payload']['headers']
        result = parser._extract_auth_results(headers)
        self.assertEqual(result['spf'], 'pass')
        self.assertEqual(result['dkim'], 'pass')
        self.assertEqual(result['dmarc'], 'pass')

    def test_parses_fail_results(self):
        parser = EmailParser()
        fixture = load_fixture('phishing_gmail_message.json')
        headers = fixture['payload']['headers']
        result = parser._extract_auth_results(headers)
        self.assertEqual(result['spf'], 'fail')
        self.assertEqual(result['dkim'], 'fail')
        self.assertEqual(result['dmarc'], 'fail')

    def test_missing_header_returns_none(self):
        parser = EmailParser()
        headers = [{'name': 'From', 'value': 'test@test.com'}]
        result = parser._extract_auth_results(headers)
        self.assertEqual(result, {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'})


class TestExtractReceivedChain(TestCase):
    """T-013: _extract_received_chain returns structured list."""

    def test_returns_chain_with_servers(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        headers = fixture['payload']['headers']
        chain = parser._extract_received_chain(headers)
        self.assertGreaterEqual(len(chain), 2)
        for hop in chain:
            self.assertIn('from_server', hop)
            self.assertIn('by_server', hop)


class TestFixtureParsing(TestCase):
    """T-014 to T-017: Parse test fixtures into correct Email fields."""

    def test_clean_fixture_email_fields(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        email, attachments = parser.parse_gmail_message(fixture)
        self.assertEqual(email.from_address, 'john.doe@example.com')
        self.assertEqual(email.subject, 'Quarterly Report Q4 2025')
        self.assertEqual(email.from_display_name, 'John Doe')

    def test_clean_fixture_attachment(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        email, attachments = parser.parse_gmail_message(fixture)
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['filename'], 'test.pdf')
        self.assertEqual(len(attachments[0]['sha256_hash']), 64)
        self.assertEqual(len(attachments[0]['md5_hash']), 32)

    def test_phishing_fixture_email_fields(self):
        parser = EmailParser()
        fixture = load_fixture('phishing_gmail_message.json')
        email, attachments = parser.parse_gmail_message(fixture)
        self.assertEqual(email.from_address, 'attacker@suspicious-domain.xyz')
        self.assertEqual(email.subject, 'Urgent: Verify your account immediately')

    def test_phishing_fixture_attachment(self):
        parser = EmailParser()
        fixture = load_fixture('phishing_gmail_message.json')
        email, attachments = parser.parse_gmail_message(fixture)
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['filename'], 'invoice.pdf.exe')


class TestComputeHashes(TestCase):
    """T-018, T-019: _compute_hashes returns correct digests."""

    def test_sha256_hash(self):
        parser = EmailParser()
        sha256, md5 = parser._compute_hashes(b'test content')
        expected_sha256 = hashlib.sha256(b'test content').hexdigest()
        self.assertEqual(sha256, expected_sha256)

    def test_md5_hash(self):
        parser = EmailParser()
        sha256, md5 = parser._compute_hashes(b'test content')
        expected_md5 = hashlib.md5(b'test content').hexdigest()
        self.assertEqual(md5, expected_md5)


class TestFetchGmailTask(TestCase):
    """T-020 to T-023: Database persistence and task tests."""

    def _make_mock_connector(self, fixture_name='test_gmail_message.json'):
        """Create a mock GmailConnector that returns fixture data."""
        fixture = load_fixture(fixture_name)
        mock_connector = MagicMock()
        mock_connector.fetch_new_emails.return_value = [fixture]
        mock_connector.mark_as_read.return_value = None
        return mock_connector

    def _run_fetch_task(self, mock_connector_instance):
        """Run fetch_gmail_task with mocked connector."""
        import emails.services.gmail_connector as gc_module
        from emails.tasks import fetch_gmail_task

        original_cls = gc_module.GmailConnector
        gc_module.GmailConnector = MagicMock(return_value=mock_connector_instance)
        try:
            with patch('emails.tasks.analyze_email_task') as mock_analyze:
                mock_analyze.delay = MagicMock()
                result = fetch_gmail_task()
        finally:
            gc_module.GmailConnector = original_cls
        return result

    def test_saves_email_to_db(self):
        result = self._run_fetch_task(self._make_mock_connector())
        self.assertGreaterEqual(Email.objects.count(), 1)
        self.assertEqual(result['fetched'], 1)

    def test_saves_attachments(self):
        self._run_fetch_task(self._make_mock_connector())
        email = Email.objects.first()
        self.assertIsNotNone(email)
        self.assertGreaterEqual(email.attachments.count(), 1)

    def test_no_duplicate_on_second_run(self):
        self._run_fetch_task(self._make_mock_connector())
        count_after_first = Email.objects.count()

        # Second run: connector returns empty (dedup in fetch_new_emails)
        mock_conn2 = MagicMock()
        mock_conn2.fetch_new_emails.return_value = []
        self._run_fetch_task(mock_conn2)
        self.assertEqual(Email.objects.count(), count_after_first)

    def test_missing_credentials_returns_zero(self):
        import emails.services.gmail_connector as gc_module
        from emails.tasks import fetch_gmail_task

        original_cls = gc_module.GmailConnector
        gc_module.GmailConnector = MagicMock(
            side_effect=FileNotFoundError("No credentials")
        )
        try:
            result = fetch_gmail_task()
        finally:
            gc_module.GmailConnector = original_cls
        self.assertEqual(result, {'fetched': 0, 'skipped': 0, 'errors': 0})


class TestManagementCommand(TestCase):
    """T-024 to T-025: Management command tests."""

    def test_dry_run_saves_nothing(self):
        import emails.services.gmail_connector as gc_module
        fixture = load_fixture('test_gmail_message.json')
        mock_conn = MagicMock()
        mock_conn.fetch_new_emails.return_value = [fixture]

        original_cls = gc_module.GmailConnector
        gc_module.GmailConnector = MagicMock(return_value=mock_conn)

        initial_count = Email.objects.count()
        from io import StringIO
        out = StringIO()

        try:
            with patch('emails.tasks.analyze_email_task') as mock_analyze:
                mock_analyze.delay = MagicMock()
                call_command('fetch_emails', dry_run=True, stdout=out)
        finally:
            gc_module.GmailConnector = original_cls

        self.assertEqual(Email.objects.count(), initial_count)
        self.assertIn('DRY RUN', out.getvalue())

    def test_help_shows_arguments(self):
        from io import StringIO
        from emails.management.commands.fetch_emails import Command
        import argparse

        cmd = Command()
        parser = cmd.create_parser('manage.py', 'fetch_emails')
        out = StringIO()
        parser.print_help(out)
        output = out.getvalue()
        self.assertIn('--max', output)
        self.assertIn('--dry-run', output)


class TestAnalyzeEmailTask(TestCase):
    """T-026: analyze_email_task calls EmailAnalyzer.analyze."""

    def test_calls_analyzer(self):
        import emails.services.analyzer as analyzer_module
        from emails.tasks import analyze_email_task

        mock_instance = MagicMock()
        original_cls = analyzer_module.EmailAnalyzer
        analyzer_module.EmailAnalyzer = MagicMock(return_value=mock_instance)

        try:
            result = analyze_email_task(42)
        finally:
            analyzer_module.EmailAnalyzer = original_cls

        mock_instance.analyze.assert_called_once_with(42)
        self.assertEqual(result, {'email_id': 42, 'status': 'analyzed'})


class TestStubAnalyzer(TestCase):
    """T-027: EmailAnalyzer.analyze processes email (Phase 3: stays ANALYZING for normal emails)."""

    def test_sets_status_after_analysis(self):
        email = Email.objects.create(
            message_id='test-analyzer-001',
            from_address='test@example.com',
            subject='Test',
            received_at=timezone.now(),
        )
        analyzer = EmailAnalyzer()
        analyzer.analyze(email.id)
        email.refresh_from_db()
        # After Phase 5 the pipeline completes fully, so status is a final state
        self.assertIn(email.status, ['DELIVERED', 'QUARANTINED', 'BLOCKED'])

    def test_raises_on_invalid_id(self):
        analyzer = EmailAnalyzer()
        with self.assertRaises(Email.DoesNotExist):
            analyzer.analyze(999999)


class TestCeleryBeatSchedule(TestCase):
    """T-028: CELERY_BEAT_SCHEDULE is configured."""

    def test_schedule_exists(self):
        self.assertIn('fetch-gmail-every-10s', settings.CELERY_BEAT_SCHEDULE)
        entry = settings.CELERY_BEAT_SCHEDULE['fetch-gmail-every-10s']
        self.assertEqual(entry['task'], 'emails.tasks.fetch_gmail_task')
        self.assertEqual(entry['schedule'], 10.0)


class TestRequirements(TestCase):
    """T-029: beautifulsoup4 is in requirements.txt."""

    def test_beautifulsoup4_in_requirements(self):
        req_path = os.path.join(settings.BASE_DIR, 'requirements.txt')
        with open(req_path) as f:
            content = f.read()
        self.assertIn('beautifulsoup4==4.12.3', content)


class TestUrlsExtractedPopulated(TestCase):
    """AC-002: Parsed Email has urls_extracted populated."""

    def test_urls_extracted_from_clean_fixture(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        email, _ = parser.parse_gmail_message(fixture)
        self.assertIn('https://example.com/reports', email.urls_extracted)
        self.assertIn('https://example.com/dashboard', email.urls_extracted)


class TestNoAttachments(TestCase):
    """AC-013: Email with no attachments parses cleanly."""

    def test_no_attachments_returns_empty_list(self):
        import base64
        parser = EmailParser()
        text_data = base64.urlsafe_b64encode(b'Hello world').decode()
        raw_message = {
            'id': 'no_attach_001',
            'payload': {
                'mimeType': 'text/plain',
                'headers': [
                    {'name': 'From', 'value': 'test@example.com'},
                    {'name': 'Subject', 'value': 'No attachments'},
                    {'name': 'Date', 'value': 'Mon, 6 Jan 2026 10:30:00 +0000'},
                    {'name': 'Message-ID', 'value': '<no-attach@example.com>'},
                ],
                'body': {'data': text_data, 'size': 11},
            }
        }
        email, attachments = parser.parse_gmail_message(raw_message)
        self.assertEqual(attachments, [])
        self.assertEqual(email.from_address, 'test@example.com')


class TestAllDatetimesTimezoneAware(TestCase):
    """AC-015: All datetimes are timezone-aware."""

    def test_clean_fixture_datetime(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        email, _ = parser.parse_gmail_message(fixture)
        self.assertIsNotNone(email.received_at.tzinfo)

    def test_phishing_fixture_datetime(self):
        parser = EmailParser()
        fixture = load_fixture('phishing_gmail_message.json')
        email, _ = parser.parse_gmail_message(fixture)
        self.assertIsNotNone(email.received_at.tzinfo)


class TestReplyToExtraction(TestCase):
    """Test Reply-To extraction from phishing fixture."""

    def test_reply_to_extracted(self):
        parser = EmailParser()
        fixture = load_fixture('phishing_gmail_message.json')
        email, _ = parser.parse_gmail_message(fixture)
        self.assertEqual(email.reply_to, 'different-reply@evil.com')

    def test_no_reply_to(self):
        parser = EmailParser()
        fixture = load_fixture('test_gmail_message.json')
        email, _ = parser.parse_gmail_message(fixture)
        self.assertIsNone(email.reply_to)
