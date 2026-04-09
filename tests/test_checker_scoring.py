"""
Phase 8 — Checker Scoring Tests.
Direct unit tests on Checker.check_all(email) with controlled inputs.
"""
import uuid

from django.test import TestCase
from django.utils import timezone

from emails.models import Email, EmailAttachment
from emails.services.checker import Checker
from threat_intel.models import MaliciousDomain, MaliciousHash


def _make_email(**kwargs):
    defaults = {
        'message_id': f'<checker-{uuid.uuid4()}@test.com>',
        'from_address': 'sender@example.com',
        'from_display_name': 'Sender',
        'subject': 'Test subject',
        'body_text': 'Test body',
        'received_at': timezone.now(),
        'status': 'PENDING',
        'to_addresses': ['user@example.com'],
        'headers_raw': [],
        'received_chain': [],
        'urls_extracted': [],
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


class CheckerKeywordTests(TestCase):
    """Test keyword scanning and scoring."""

    def test_ac_601_zero_keywords_zero_score(self):
        """AC-601: Clean body with no keywords -> keyword_score=0."""
        email = _make_email(
            subject='Meeting notes',
            body_text='Here are the notes from today.',
        )
        result = Checker().check_all(email)
        self.assertEqual(result.keyword_score, 0)
        self.assertEqual(result.keywords_matched, [])

    def test_ac_602_five_keywords(self):
        """AC-602: 5 keywords in body -> keyword_score=10."""
        email = _make_email(
            subject='verify your account',
            body_text='urgent action required confirm your identity unusual activity suspended account',
        )
        result = Checker().check_all(email)
        # 5 keywords: verify your account, urgent action required, confirm your identity, unusual activity, suspended account
        self.assertEqual(result.keyword_score, 10)
        self.assertEqual(len(result.keywords_matched), 5)

    def test_ac_603_ten_keywords_capped(self):
        """AC-603: 10 keywords -> keyword_score=20 (capped at max)."""
        email = _make_email(
            subject='verify your account urgent action required',
            body_text=(
                'confirm your identity unusual activity suspended account '
                'click here immediately update your payment security alert '
                'unauthorized access reset your password'
            ),
        )
        result = Checker().check_all(email)
        self.assertEqual(len(result.keywords_matched), 10)
        self.assertEqual(result.keyword_score, 20)

    def test_ac_604_fifteen_keywords_still_capped(self):
        """AC-604: 15 keywords -> keyword_score still=20."""
        email = _make_email(
            subject='verify your account urgent action required',
            body_text=(
                'confirm your identity unusual activity suspended account '
                'click here immediately update your payment security alert '
                'unauthorized access reset your password limited time offer '
                'act now your account will be closed verify your information '
                'important security update'
            ),
        )
        result = Checker().check_all(email)
        self.assertGreaterEqual(len(result.keywords_matched), 15)
        self.assertEqual(result.keyword_score, 20)


class CheckerURLTests(TestCase):
    """Test URL analysis and scoring."""

    def test_ac_605_malicious_domain_url(self):
        """AC-605: URL with known MaliciousDomain -> url_score >= 30."""
        MaliciousDomain.objects.create(domain='evil-downloads.com', source='URLHAUS')
        email = _make_email(
            urls_extracted=['http://evil-downloads.com/payload.exe'],
        )
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.url_score, 30)

    def test_ac_606_ip_based_url(self):
        """AC-606: URL with IP address -> url_score >= 10."""
        email = _make_email(
            urls_extracted=['http://192.168.1.100/login'],
        )
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.url_score, 10)

    def test_ac_607_url_shortener(self):
        """AC-607: bit.ly URL -> url_score >= 5."""
        email = _make_email(
            urls_extracted=['http://bit.ly/abc123'],
        )
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.url_score, 5)

    def test_ac_608_url_score_capped_40(self):
        """AC-608: Many bad URLs -> url_score <= 40."""
        MaliciousDomain.objects.create(domain='evil1.com', source='URLHAUS')
        MaliciousDomain.objects.create(domain='evil2.com', source='URLHAUS')
        MaliciousDomain.objects.create(domain='evil3.com', source='URLHAUS')
        email = _make_email(
            urls_extracted=[
                'http://evil1.com/a', 'http://evil2.com/b', 'http://evil3.com/c',
                'http://192.168.1.1/d', 'http://bit.ly/e',
            ],
        )
        result = Checker().check_all(email)
        self.assertLessEqual(result.url_score, 40)


class CheckerAttachmentTests(TestCase):
    """Test attachment analysis and scoring."""

    def test_ac_609_dangerous_ext(self):
        """AC-609: Attachment .exe -> attachment_score >= 15."""
        email = _make_email()
        EmailAttachment.objects.create(
            email=email, filename='setup.exe', content_type='application/octet-stream',
            size_bytes=50000, sha256_hash='c' * 64, md5_hash='d' * 32,
        )
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.attachment_score, 15)

    def test_ac_610_double_ext(self):
        """AC-610: Attachment .pdf.exe -> attachment_score >= 20."""
        email = _make_email()
        EmailAttachment.objects.create(
            email=email, filename='invoice.pdf.exe', content_type='application/octet-stream',
            size_bytes=50000, sha256_hash='e' * 64, md5_hash='f' * 32,
        )
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.attachment_score, 20)

    def test_ac_611_known_malware_hash(self):
        """AC-611: Attachment hash in MaliciousHash -> has_known_malware=True, attachment_score=50."""
        mal_hash = 'a' * 64
        MaliciousHash.objects.create(
            sha256_hash=mal_hash, malware_family='Emotet',
            source='MALWAREBAZAAR', severity='HIGH',
        )
        email = _make_email()
        EmailAttachment.objects.create(
            email=email, filename='report.doc', content_type='application/msword',
            size_bytes=30000, sha256_hash=mal_hash, md5_hash='b' * 32,
        )
        result = Checker().check_all(email)
        self.assertTrue(result.has_known_malware)
        self.assertEqual(result.attachment_score, 50)

    def test_ac_612_attachment_score_capped_50(self):
        """AC-612: Multiple bad attachments -> attachment_score <= 50."""
        email = _make_email()
        for i in range(5):
            EmailAttachment.objects.create(
                email=email, filename=f'file{i}.exe', content_type='application/octet-stream',
                size_bytes=1000, sha256_hash=f'{chr(97+i)}' * 64, md5_hash=f'{chr(97+i)}' * 32,
            )
        result = Checker().check_all(email)
        self.assertLessEqual(result.attachment_score, 50)


class CheckerReceivedChainTests(TestCase):
    """Test received chain anomaly detection."""

    def test_ac_613_many_hops(self):
        """AC-613: 8+ received_chain entries -> chain_score >= 5."""
        chain = [f'from hop{i}.example.com by hop{i+1}.example.com' for i in range(8)]
        email = _make_email(received_chain=chain)
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.chain_score, 5)

    def test_ac_614_private_ip_chain(self):
        """AC-614: Private IP in chain -> chain_score >= 5."""
        email = _make_email(
            received_chain=['from 192.168.1.50 by mail.example.com'],
        )
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.chain_score, 5)

    def test_ac_615_chain_score_capped_15(self):
        """AC-615: All chain anomalies -> chain_score <= 15."""
        chain = [f'from 10.0.0.{i} by 10.0.0.{i+1}' for i in range(10)]
        # Add timestamp disorder
        chain_with_ts = [
            {'from': '10.0.0.1', 'by': '10.0.0.2', 'timestamp': '2026-01-02T00:00:00'},
            {'from': '10.0.0.2', 'by': '10.0.0.3', 'timestamp': '2026-01-01T00:00:00'},
        ]
        # Use string hops (>7 for excessive hops) plus private IPs
        full_chain = chain + chain_with_ts
        email = _make_email(received_chain=full_chain)
        result = Checker().check_all(email)
        self.assertLessEqual(result.chain_score, 15)

    def test_ac_616_no_chain_zero_score(self):
        """AC-616: Empty received_chain -> chain_score=0."""
        email = _make_email(received_chain=[])
        result = Checker().check_all(email)
        self.assertEqual(result.chain_score, 0)

    def test_ac_617_total_check_score_sum(self):
        """AC-617: total_check_score = keyword + url + attachment + chain."""
        email = _make_email(
            subject='verify your account',
            body_text='Normal body.',
            urls_extracted=['http://192.168.1.1/phish'],
            received_chain=['from 10.0.0.1 by mail.example.com'],
        )
        result = Checker().check_all(email)
        expected_total = (
            result.keyword_score
            + result.url_score
            + result.attachment_score
            + result.chain_score
        )
        self.assertEqual(result.total_check_score, expected_total)
