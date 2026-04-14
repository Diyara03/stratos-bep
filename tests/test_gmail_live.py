"""
Live Gmail smoke tests.
These tests ONLY run when valid Gmail credentials exist on disk.
They verify real connectivity and are meant to be run manually, not in CI.

Run with:
    python manage.py test tests.test_gmail_live --settings=stratos_server.settings.test -v2
"""
import os
import unittest

from django.test import TestCase


def gmail_credentials_available():
    """Check if Gmail credentials files exist."""
    creds_path = os.environ.get('GMAIL_CREDENTIALS_PATH', 'credentials/gmail_credentials.json')
    token_path = os.environ.get('GMAIL_TOKEN_PATH', 'credentials/gmail_token.json')
    return os.path.exists(creds_path) and os.path.exists(token_path)


SKIP_REASON = (
    'Gmail credentials not found. '
    'Set GMAIL_CREDENTIALS_PATH and GMAIL_TOKEN_PATH, or place files in credentials/.'
)


@unittest.skipUnless(gmail_credentials_available(), SKIP_REASON)
class GmailConnectorLiveTest(TestCase):
    """Smoke tests against real Gmail API. Requires valid credentials."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from emails.services.gmail_connector import GmailConnector
        cls.connector = GmailConnector()

    def test_authentication_succeeds(self):
        """Verify OAuth credentials are valid and service object is created."""
        self.assertIsNotNone(self.connector.service)

    def test_fetch_returns_list(self):
        """Verify fetch_new_emails returns a list (may be empty)."""
        messages = self.connector.fetch_new_emails(max_results=3)
        self.assertIsInstance(messages, list)

    def test_message_has_expected_structure(self):
        """Verify fetched messages have Gmail API structure."""
        messages = self.connector.fetch_new_emails(max_results=1)
        if not messages:
            self.skipTest('Inbox is empty — no messages to validate structure.')
        msg = messages[0]
        self.assertIn('id', msg)
        self.assertIn('payload', msg)
        self.assertIn('headers', msg['payload'])

    def test_message_parses_successfully(self):
        """Verify a real message can be parsed by EmailParser."""
        from emails.services.parser import EmailParser
        messages = self.connector.fetch_new_emails(max_results=1)
        if not messages:
            self.skipTest('Inbox is empty — no messages to parse.')
        parser = EmailParser()
        email, attachments = parser.parse_gmail_message(messages[0])
        self.assertIsNotNone(email.message_id)
        self.assertIsNotNone(email.from_address)
        self.assertIsNotNone(email.subject)


@unittest.skipUnless(gmail_credentials_available(), SKIP_REASON)
class GmailFullPipelineLiveTest(TestCase):
    """Smoke test: fetch a real email and run it through the full pipeline."""

    def test_live_pipeline(self):
        """Fetch one real email, save it, analyze it."""
        from emails.services.gmail_connector import GmailConnector
        from emails.services.parser import EmailParser
        from emails.services.analyzer import EmailAnalyzer

        connector = GmailConnector()
        messages = connector.fetch_new_emails(max_results=1)
        if not messages:
            self.skipTest('Inbox is empty.')

        parser = EmailParser()
        email, att_dicts = parser.parse_gmail_message(messages[0])
        email.gmail_id = messages[0]['id']
        email.save()

        from emails.models import EmailAttachment
        for att in att_dicts:
            EmailAttachment.objects.create(
                email=email,
                filename=att['filename'],
                content_type=att['content_type'],
                size_bytes=att['size_bytes'],
                sha256_hash=att['sha256_hash'],
                md5_hash=att['md5_hash'],
            )

        analyzer = EmailAnalyzer()
        analyzer.analyze(email.id)

        email.refresh_from_db()
        self.assertIn(email.verdict, ['CLEAN', 'SUSPICIOUS', 'MALICIOUS'])
        self.assertIn(email.status, ['DELIVERED', 'QUARANTINED', 'BLOCKED'])
        self.assertIsNotNone(email.score)
        self.assertTrue(hasattr(email, 'analysis'))
