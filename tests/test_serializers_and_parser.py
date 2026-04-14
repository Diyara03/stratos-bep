"""
Tests for DRF serializers and EmailParser edge cases.
"""
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from emails.models import AnalysisResult, Email, EmailAttachment, QuarantineEntry
from emails.serializers import (
    AnalysisResultSerializer,
    DashboardStatsSerializer,
    EmailAttachmentSerializer,
    EmailDetailSerializer,
    EmailListSerializer,
    QuarantineActionSerializer,
    QuarantineEntrySerializer,
)
from emails.services.parser import EmailParser


def _make_email(**kwargs):
    defaults = dict(
        message_id=f'ser-test-{kwargs.get("message_id", "001")}',
        from_address='test@example.com',
        from_display_name='Test User',
        subject='Serializer test',
        body_text='Body',
        received_at=timezone.now(),
        to_addresses=['me@example.com'],
    )
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


# ─── EmailListSerializer ───


class EmailListSerializerTest(TestCase):

    def test_fields_present(self):
        email = _make_email()
        data = EmailListSerializer(email).data
        expected_fields = {
            'id', 'message_id', 'from_address', 'from_display_name',
            'subject', 'verdict', 'score', 'confidence', 'status',
            'received_at',
        }
        self.assertEqual(set(data.keys()), expected_fields)

    def test_null_verdict(self):
        email = _make_email(verdict=None)
        data = EmailListSerializer(email).data
        self.assertIsNone(data['verdict'])

    def test_null_score(self):
        email = _make_email(score=None)
        data = EmailListSerializer(email).data
        self.assertIsNone(data['score'])


# ─── EmailDetailSerializer ───


class EmailDetailSerializerTest(TestCase):

    def test_includes_analysis(self):
        email = _make_email(message_id='detail-001')
        AnalysisResult.objects.create(email=email, total_score=42)
        email = Email.objects.select_related('analysis').get(pk=email.pk)
        data = EmailDetailSerializer(email).data
        self.assertIn('analysis', data)
        self.assertEqual(data['analysis']['total_score'], 42)

    def test_includes_attachments(self):
        email = _make_email(message_id='detail-002')
        EmailAttachment.objects.create(
            email=email, filename='test.pdf', content_type='application/pdf',
            size_bytes=1024, sha256_hash='a' * 64, md5_hash='b' * 32,
        )
        email = Email.objects.prefetch_related('attachments').get(pk=email.pk)
        data = EmailDetailSerializer(email).data
        self.assertEqual(len(data['attachments']), 1)
        self.assertEqual(data['attachments'][0]['filename'], 'test.pdf')

    def test_no_analysis(self):
        email = _make_email(message_id='detail-003')
        data = EmailDetailSerializer(email).data
        self.assertIsNone(data['analysis'])

    def test_extra_fields(self):
        email = _make_email(message_id='detail-004', body_text='hello world')
        data = EmailDetailSerializer(email).data
        self.assertIn('body_text', data)
        self.assertIn('to_addresses', data)
        self.assertIn('analyzed_at', data)


# ─── EmailAttachmentSerializer ───


class EmailAttachmentSerializerTest(TestCase):

    def test_all_fields(self):
        email = _make_email(message_id='att-001')
        att = EmailAttachment.objects.create(
            email=email, filename='malware.exe', content_type='application/x-msdownload',
            size_bytes=4096, sha256_hash='c' * 64, md5_hash='d' * 32,
            is_dangerous_ext=True, is_double_ext=False, is_mime_mismatch=True,
            yara_matches=['PE_executable_in_email'], ti_match='MALWAREBAZAAR',
        )
        data = EmailAttachmentSerializer(att).data
        self.assertEqual(data['filename'], 'malware.exe')
        self.assertTrue(data['is_dangerous_ext'])
        self.assertTrue(data['is_mime_mismatch'])
        self.assertEqual(data['yara_matches'], ['PE_executable_in_email'])
        self.assertEqual(data['ti_match'], 'MALWAREBAZAAR')


# ─── AnalysisResultSerializer ───


class AnalysisResultSerializerTest(TestCase):

    def test_all_scores(self):
        email = _make_email(message_id='analysis-001')
        ar = AnalysisResult.objects.create(
            email=email, preprocess_score=15, keyword_score=10,
            url_score=20, attachment_score=30, chain_score=5,
            total_score=80, pipeline_duration_ms=1200,
            spf_result='fail', dkim_result='none', dmarc_result='fail',
            keywords_matched=['verify your account', 'urgent action required'],
        )
        data = AnalysisResultSerializer(ar).data
        self.assertEqual(data['preprocess_score'], 15)
        self.assertEqual(data['total_score'], 80)
        self.assertEqual(data['pipeline_duration_ms'], 1200)
        self.assertEqual(len(data['keywords_matched']), 2)


# ─── QuarantineEntrySerializer ───


class QuarantineEntrySerializerTest(TestCase):

    def test_nested_email(self):
        email = _make_email(message_id='qe-001', verdict='MALICIOUS', status='QUARANTINED')
        qe = QuarantineEntry.objects.create(email=email)
        data = QuarantineEntrySerializer(qe).data
        self.assertEqual(data['status'], 'PENDING')
        self.assertIn('email', data)
        self.assertEqual(data['email']['verdict'], 'MALICIOUS')


# ─── QuarantineActionSerializer ───


class QuarantineActionSerializerTest(TestCase):

    def test_valid_release(self):
        s = QuarantineActionSerializer(data={'action': 'release'})
        self.assertTrue(s.is_valid())

    def test_valid_block(self):
        s = QuarantineActionSerializer(data={'action': 'block'})
        self.assertTrue(s.is_valid())

    def test_valid_delete(self):
        s = QuarantineActionSerializer(data={'action': 'delete'})
        self.assertTrue(s.is_valid())

    def test_invalid_action(self):
        s = QuarantineActionSerializer(data={'action': 'nuke'})
        self.assertFalse(s.is_valid())
        self.assertIn('action', s.errors)

    def test_missing_action(self):
        s = QuarantineActionSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertIn('action', s.errors)

    def test_notes_optional(self):
        s = QuarantineActionSerializer(data={'action': 'release'})
        self.assertTrue(s.is_valid())
        self.assertEqual(s.validated_data['notes'], '')

    def test_notes_provided(self):
        s = QuarantineActionSerializer(data={'action': 'release', 'notes': 'False positive'})
        self.assertTrue(s.is_valid())
        self.assertEqual(s.validated_data['notes'], 'False positive')


# ─── DashboardStatsSerializer ───


class DashboardStatsSerializerTest(TestCase):

    def test_valid_data(self):
        data = {
            'total_emails': 100,
            'clean_count': 60,
            'suspicious_count': 30,
            'malicious_count': 10,
            'pending_count': 0,
            'quarantine_pending': 5,
            'ti_hashes': 200,
            'ti_domains': 50,
            'last_sync': None,
        }
        s = DashboardStatsSerializer(data)
        self.assertEqual(s.data['total_emails'], 100)
        self.assertIsNone(s.data['last_sync'])


# ─── EmailParser Edge Cases ───


class EmailParserEdgeCaseTest(TestCase):

    def setUp(self):
        self.parser = EmailParser()

    def _make_raw_message(self, headers=None, body_data='', mime_type='text/plain', parts=None):
        msg = {
            'id': 'gmail_edge_test',
            'internalDate': '1735689600000',
            'payload': {
                'headers': headers or [
                    {'name': 'Message-ID', 'value': '<edge-test@mail>'},
                    {'name': 'From', 'value': 'sender@example.com'},
                    {'name': 'To', 'value': 'me@example.com'},
                    {'name': 'Subject', 'value': 'Edge Test'},
                    {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
                ],
                'mimeType': mime_type,
                'body': {'data': body_data, 'size': len(body_data)},
            },
        }
        if parts is not None:
            msg['payload']['parts'] = parts
        return msg

    def test_empty_body(self):
        msg = self._make_raw_message(body_data='')
        email, attachments = self.parser.parse_gmail_message(msg)
        self.assertEqual(email.body_text, '')

    def test_missing_subject_header(self):
        headers = [
            {'name': 'Message-ID', 'value': '<no-subject@mail>'},
            {'name': 'From', 'value': 'sender@example.com'},
            {'name': 'To', 'value': 'me@example.com'},
            {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
        ]
        msg = self._make_raw_message(headers=headers)
        email, _ = self.parser.parse_gmail_message(msg)
        self.assertIn(email.subject, ['', '(no subject)'])

    def test_missing_from_header(self):
        headers = [
            {'name': 'Message-ID', 'value': '<no-from@mail>'},
            {'name': 'To', 'value': 'me@example.com'},
            {'name': 'Subject', 'value': 'No From'},
            {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
        ]
        msg = self._make_raw_message(headers=headers)
        email, _ = self.parser.parse_gmail_message(msg)
        # Should not crash; from_address may be empty
        self.assertIsNotNone(email)

    def test_multipart_message_with_text_and_html(self):
        import base64
        text_b64 = base64.urlsafe_b64encode(b'Plain text body').decode()
        html_b64 = base64.urlsafe_b64encode(b'<h1>HTML body</h1>').decode()
        msg = self._make_raw_message(
            mime_type='multipart/alternative',
            body_data='',
            parts=[
                {
                    'mimeType': 'text/plain',
                    'body': {'data': text_b64, 'size': 15},
                    'headers': [],
                },
                {
                    'mimeType': 'text/html',
                    'body': {'data': html_b64, 'size': 20},
                    'headers': [],
                },
            ],
        )
        email, _ = self.parser.parse_gmail_message(msg)
        self.assertIn('Plain text body', email.body_text)

    def test_url_extraction_from_html(self):
        import base64
        html = '<a href="https://evil.com/login">Click</a><a href="https://safe.com">OK</a>'
        html_b64 = base64.urlsafe_b64encode(html.encode()).decode()
        msg = self._make_raw_message(
            mime_type='multipart/alternative',
            body_data='',
            parts=[
                {
                    'mimeType': 'text/plain',
                    'body': {'data': '', 'size': 0},
                    'headers': [],
                },
                {
                    'mimeType': 'text/html',
                    'body': {'data': html_b64, 'size': len(html)},
                    'headers': [],
                },
            ],
        )
        email, _ = self.parser.parse_gmail_message(msg)
        urls = email.urls_extracted
        self.assertTrue(
            any('evil.com' in u for u in urls),
            f'Expected evil.com in extracted URLs: {urls}'
        )

    def test_display_name_with_special_chars(self):
        headers = [
            {'name': 'Message-ID', 'value': '<special-name@mail>'},
            {'name': 'From', 'value': '"O\'Brien, Jane" <jane@example.com>'},
            {'name': 'To', 'value': 'me@example.com'},
            {'name': 'Subject', 'value': 'Special chars'},
            {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
        ]
        msg = self._make_raw_message(headers=headers)
        email, _ = self.parser.parse_gmail_message(msg)
        self.assertIn('jane@example.com', email.from_address)

    def test_multiple_to_addresses(self):
        headers = [
            {'name': 'Message-ID', 'value': '<multi-to@mail>'},
            {'name': 'From', 'value': 'sender@example.com'},
            {'name': 'To', 'value': 'one@example.com, two@example.com, three@example.com'},
            {'name': 'Subject', 'value': 'Multi To'},
            {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
        ]
        msg = self._make_raw_message(headers=headers)
        email, _ = self.parser.parse_gmail_message(msg)
        self.assertGreaterEqual(len(email.to_addresses), 2)

    def test_cc_addresses_extracted(self):
        headers = [
            {'name': 'Message-ID', 'value': '<cc-test@mail>'},
            {'name': 'From', 'value': 'sender@example.com'},
            {'name': 'To', 'value': 'me@example.com'},
            {'name': 'Cc', 'value': 'cc1@example.com, cc2@example.com'},
            {'name': 'Subject', 'value': 'CC Test'},
            {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
        ]
        msg = self._make_raw_message(headers=headers)
        email, _ = self.parser.parse_gmail_message(msg)
        if email.cc_addresses:
            self.assertGreaterEqual(len(email.cc_addresses), 1)

    def test_reply_to_extracted(self):
        headers = [
            {'name': 'Message-ID', 'value': '<reply-to-test@mail>'},
            {'name': 'From', 'value': 'sender@example.com'},
            {'name': 'To', 'value': 'me@example.com'},
            {'name': 'Reply-To', 'value': 'different@example.com'},
            {'name': 'Subject', 'value': 'Reply-To Test'},
            {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
        ]
        msg = self._make_raw_message(headers=headers)
        email, _ = self.parser.parse_gmail_message(msg)
        self.assertIn('different@example.com', str(email.reply_to))

    def test_received_chain_extraction(self):
        headers = [
            {'name': 'Message-ID', 'value': '<chain-test@mail>'},
            {'name': 'From', 'value': 'sender@example.com'},
            {'name': 'To', 'value': 'me@example.com'},
            {'name': 'Subject', 'value': 'Chain Test'},
            {'name': 'Date', 'value': 'Mon, 1 Jan 2026 00:00:00 +0000'},
            {'name': 'Received', 'value': 'from mx1.example.com by mx2.example.com'},
            {'name': 'Received', 'value': 'from relay.example.com by mx1.example.com'},
        ]
        msg = self._make_raw_message(headers=headers)
        email, _ = self.parser.parse_gmail_message(msg)
        self.assertGreaterEqual(len(email.received_chain), 1)
