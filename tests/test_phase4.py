"""
Phase 4 tests: Checker Engine -- keywords, URLs, attachments, received chain.
Covers all 16 acceptance criteria from PHASE4_SPEC.md plus edge cases.
"""
import time
from unittest.mock import patch, PropertyMock

from django.test import TestCase
from django.utils import timezone

from emails.models import AnalysisResult, Email, EmailAttachment, ExtractedIOC
from emails.services.analyzer import EmailAnalyzer
from emails.services.checker import Checker, CheckResult
from threat_intel.models import (
    BlacklistEntry, MaliciousDomain, MaliciousHash, WhitelistEntry,
)


def _make_email(**kwargs):
    """Create an Email with sensible defaults for testing."""
    defaults = {
        'message_id': f'test-{timezone.now().timestamp()}@example.com',
        'from_address': 'sender@example.com',
        'from_display_name': 'Test Sender',
        'to_addresses': ['recipient@company.com'],
        'reply_to': '',
        'subject': 'Test Email',
        'body_text': 'Hello, this is a normal email.',
        'headers_raw': [],
        'received_chain': [],
        'urls_extracted': [],
        'received_at': timezone.now(),
        'status': 'PENDING',
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


def _make_attachment(email, **kwargs):
    """Create an EmailAttachment with sensible defaults."""
    defaults = {
        'email': email,
        'filename': 'document.pdf',
        'content_type': 'application/pdf',
        'size_bytes': 1024,
        'sha256_hash': 'a' * 64,
        'md5_hash': 'b' * 32,
    }
    defaults.update(kwargs)
    return EmailAttachment.objects.create(**defaults)


# ---------------------------------------------------------------------------
# Keyword Checker Tests (AC-001, AC-002, AC-003)
# ---------------------------------------------------------------------------

class TestKeywordChecker(TestCase):
    """Tests for keyword scanning."""

    def test_single_keyword_in_subject_scores_2(self):
        """AC-001: Single keyword in subject scores 2."""
        email = _make_email(subject='Please verify your account', body_text='')
        result = Checker().check_all(email)
        self.assertEqual(result.keyword_score, 2)
        self.assertEqual(result.keywords_matched, ['verify your account'])

    def test_single_keyword_in_body_scores_2(self):
        """AC-001: Single keyword in body scores 2."""
        email = _make_email(subject='Hello', body_text='You must take urgent action required now.')
        result = Checker().check_all(email)
        self.assertEqual(result.keyword_score, 2)
        self.assertIn('urgent action required', result.keywords_matched)

    def test_keyword_case_insensitive(self):
        """AC-001: Keywords are matched case-insensitively."""
        email = _make_email(subject='VERIFY YOUR ACCOUNT', body_text='')
        result = Checker().check_all(email)
        self.assertEqual(result.keyword_score, 2)
        self.assertIn('verify your account', result.keywords_matched)

    def test_ten_keywords_capped_at_20(self):
        """AC-002: Score capped at 20 even with 12+ keyword matches."""
        body = ' '.join([
            'verify your account',
            'urgent action required',
            'confirm your identity',
            'unusual activity',
            'suspended account',
            'click here immediately',
            'update your payment',
            'security alert',
            'unauthorized access',
            'reset your password',
            'limited time offer',
            'act now',
        ])
        email = _make_email(subject='', body_text=body)
        result = Checker().check_all(email)
        self.assertEqual(result.keyword_score, 20)
        self.assertGreaterEqual(len(result.keywords_matched), 10)

    def test_no_keywords_scores_zero(self):
        """AC-003: Clean email with no keywords scores 0."""
        email = _make_email(subject='Meeting Tomorrow', body_text='See you at 3pm.')
        result = Checker().check_all(email)
        self.assertEqual(result.keyword_score, 0)
        self.assertEqual(result.keywords_matched, [])


# ---------------------------------------------------------------------------
# URL Checker Tests (AC-004, AC-005, AC-006, AC-015)
# ---------------------------------------------------------------------------

class TestURLChecker(TestCase):
    """Tests for URL analysis."""

    def test_ip_url_scores_10(self):
        """AC-004: IP-based URL scores +10."""
        email = _make_email(urls_extracted=['http://192.168.1.1/login'])
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.url_score, 10)
        types = [f['type'] for f in result.url_findings]
        self.assertIn('ip_url', types)

    def test_shortener_scores_5(self):
        """AC-005: URL shortener scores +5."""
        email = _make_email(urls_extracted=['https://bit.ly/abc123'])
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.url_score, 5)
        types = [f['type'] for f in result.url_findings]
        self.assertIn('shortener', types)

    def test_malicious_domain_scores_30(self):
        """AC-006: Malicious domain match scores +30."""
        MaliciousDomain.objects.create(domain='evil.com', source='URLHAUS')
        email = _make_email(urls_extracted=['http://evil.com/phish'])
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.url_score, 30)
        types = [f['type'] for f in result.url_findings]
        self.assertIn('malicious_domain', types)

    def test_malicious_domain_creates_ioc(self):
        """OQ-003: Malicious domain match creates ExtractedIOC."""
        MaliciousDomain.objects.create(domain='evil.com', source='URLHAUS')
        email = _make_email(urls_extracted=['http://evil.com/phish'])
        Checker().check_all(email)
        ioc = ExtractedIOC.objects.filter(email=email, ioc_type='DOMAIN').first()
        self.assertIsNotNone(ioc)
        self.assertEqual(ioc.value, 'evil.com')
        self.assertEqual(ioc.source_checker, 'url_checker')

    def test_url_score_capped_at_40(self):
        """AC-006: Two malicious domains (+30+30=60) capped at 40."""
        MaliciousDomain.objects.create(domain='evil.com', source='URLHAUS')
        MaliciousDomain.objects.create(domain='bad.org', source='URLHAUS')
        email = _make_email(urls_extracted=[
            'http://evil.com/a', 'http://bad.org/b',
        ])
        result = Checker().check_all(email)
        self.assertEqual(result.url_score, 40)

    def test_no_urls_scores_zero(self):
        """AC-015: Empty urls_extracted scores 0."""
        email = _make_email(urls_extracted=[])
        result = Checker().check_all(email)
        self.assertEqual(result.url_score, 0)
        self.assertEqual(result.url_findings, [])

    def test_multiple_url_types_cumulative(self):
        """AC-004+005: IP URL (+10) and shortener (+5) = 15."""
        email = _make_email(urls_extracted=[
            'http://10.0.0.1/evil',
            'https://bit.ly/abc',
        ])
        result = Checker().check_all(email)
        self.assertEqual(result.url_score, 15)


# ---------------------------------------------------------------------------
# Attachment Checker Tests (AC-007, AC-008, AC-009, AC-010, AC-014)
# ---------------------------------------------------------------------------

class TestAttachmentChecker(TestCase):
    """Tests for attachment inspection."""

    def test_malicious_hash_scores_50(self):
        """AC-007: Known malware hash scores 50, sets has_known_malware."""
        sha = 'deadbeef' * 8  # 64 chars
        MaliciousHash.objects.create(
            sha256_hash=sha, malware_family='Emotet', source='MALWAREBAZAAR', severity='HIGH',
        )
        email = _make_email()
        att = _make_attachment(email, sha256_hash=sha, filename='trojan.bin')
        result = Checker().check_all(email)
        self.assertEqual(result.attachment_score, 50)
        self.assertTrue(result.has_known_malware)
        att.refresh_from_db()
        self.assertEqual(att.ti_match, 'MALWAREBAZAAR')

    def test_malicious_hash_creates_ioc(self):
        """OQ-003: Malicious hash match creates ExtractedIOC."""
        sha = 'deadbeef' * 8
        MaliciousHash.objects.create(
            sha256_hash=sha, malware_family='Emotet', source='MALWAREBAZAAR', severity='CRITICAL',
        )
        email = _make_email()
        _make_attachment(email, sha256_hash=sha, filename='trojan.bin')
        Checker().check_all(email)
        ioc = ExtractedIOC.objects.filter(email=email, ioc_type='HASH').first()
        self.assertIsNotNone(ioc)
        self.assertEqual(ioc.value, sha)
        self.assertEqual(ioc.severity, 'CRITICAL')
        self.assertEqual(ioc.source_checker, 'attachment_checker')

    def test_dangerous_ext_scores_15(self):
        """AC-008: .exe extension scores +15, sets is_dangerous_ext."""
        email = _make_email()
        att = _make_attachment(email, filename='malware.exe')
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.attachment_score, 15)
        att.refresh_from_db()
        self.assertTrue(att.is_dangerous_ext)

    def test_double_ext_scores_20(self):
        """AC-009: report.pdf.exe scores +20, sets is_double_ext."""
        email = _make_email()
        att = _make_attachment(email, filename='report.pdf.exe')
        result = Checker().check_all(email)
        # dangerous ext (+15) + double ext (+20) = 35, capped at 50
        self.assertGreaterEqual(result.attachment_score, 35)
        att.refresh_from_db()
        self.assertTrue(att.is_double_ext)
        self.assertTrue(att.is_dangerous_ext)

    def test_mime_mismatch_flagged(self):
        """AC-010: MIME mismatch when file_magic differs from content_type."""
        email = _make_email()
        att = _make_attachment(
            email,
            filename='document.pdf',
            content_type='application/pdf',
            file_magic='application/x-executable',
        )
        result = Checker().check_all(email)
        att.refresh_from_db()
        self.assertTrue(att.is_mime_mismatch)
        types = [f['type'] for f in result.attachment_findings]
        self.assertIn('mime_mismatch', types)

    def test_mime_mismatch_skipped_when_no_magic(self):
        """OQ-002: When file_magic is None, MIME mismatch is not flagged."""
        email = _make_email()
        att = _make_attachment(email, filename='document.pdf', file_magic=None)
        Checker().check_all(email)
        att.refresh_from_db()
        self.assertFalse(att.is_mime_mismatch)

    def test_no_attachments_scores_zero(self):
        """AC-014: No attachments yields zero."""
        email = _make_email()
        result = Checker().check_all(email)
        self.assertEqual(result.attachment_score, 0)
        self.assertEqual(result.attachment_findings, [])

    def test_attachment_score_capped_at_50(self):
        """AC-007: Known malware (+50) plus dangerous ext (+15) capped at 50."""
        sha = 'deadbeef' * 8
        MaliciousHash.objects.create(
            sha256_hash=sha, malware_family='Emotet', source='MALWAREBAZAAR', severity='HIGH',
        )
        email = _make_email()
        _make_attachment(email, sha256_hash=sha, filename='trojan.exe')
        result = Checker().check_all(email)
        self.assertEqual(result.attachment_score, 50)

    def test_double_ext_detection_three_parts(self):
        """AC-009: archive.tar.gz.exe has 4 parts, last ext is dangerous."""
        email = _make_email()
        att = _make_attachment(email, filename='archive.tar.gz.exe')
        Checker().check_all(email)
        att.refresh_from_db()
        self.assertTrue(att.is_double_ext)

    def test_yara_matches_scored_when_populated(self):
        """YARA matches on attachment are scored at +25 each."""
        email = _make_email()
        att = _make_attachment(email, filename='doc.docm', yara_matches=['VBA_macro_suspicious'])
        result = Checker().check_all(email)
        types = [f['type'] for f in result.attachment_findings]
        self.assertIn('yara_match', types)


# ---------------------------------------------------------------------------
# Received Chain Tests (AC-011, AC-012)
# ---------------------------------------------------------------------------

class TestReceivedChainChecker(TestCase):
    """Tests for received chain anomaly detection."""

    def test_excessive_hops_scores_5(self):
        """AC-011: 8 hops in received_chain scores +5."""
        chain = [{'from': f'server{i}.example.com', 'by': f'relay{i}.example.com',
                   'timestamp': f'2026-01-01T0{i}:00:00Z'} for i in range(8)]
        email = _make_email(received_chain=chain)
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.chain_score, 5)
        self.assertTrue(result.chain_findings.get('excessive_hops'))

    def test_seven_hops_no_score(self):
        """AC-011 neg: 7 hops does not trigger excessive_hops."""
        chain = [{'from': f'server{i}.example.com', 'by': f'relay{i}.example.com',
                   'timestamp': f'2026-01-01T0{i}:00:00Z'} for i in range(7)]
        email = _make_email(received_chain=chain)
        result = Checker().check_all(email)
        self.assertFalse(result.chain_findings.get('excessive_hops', False))

    def test_private_ip_scores_5(self):
        """AC-012: Private IP in chain scores +5."""
        chain = [
            {'from': '10.0.0.1', 'by': 'relay.example.com', 'timestamp': '2026-01-01T01:00:00Z'},
        ]
        email = _make_email(received_chain=chain)
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.chain_score, 5)
        self.assertTrue(result.chain_findings.get('private_ip_in_chain'))

    def test_timestamp_disorder_scores_5(self):
        """Timestamp going backward triggers +5."""
        chain = [
            {'from': 'a.com', 'by': 'b.com', 'timestamp': '2026-01-01T05:00:00Z'},
            {'from': 'b.com', 'by': 'c.com', 'timestamp': '2026-01-01T03:00:00Z'},
        ]
        email = _make_email(received_chain=chain)
        result = Checker().check_all(email)
        self.assertGreaterEqual(result.chain_score, 5)
        self.assertTrue(result.chain_findings.get('timestamp_disorder'))

    def test_empty_chain_scores_zero(self):
        """Empty received_chain yields zero."""
        email = _make_email(received_chain=[])
        result = Checker().check_all(email)
        self.assertEqual(result.chain_score, 0)
        self.assertEqual(result.chain_findings, {})


# ---------------------------------------------------------------------------
# Integration Tests (AC-013, AC-016)
# ---------------------------------------------------------------------------

class TestCheckerIntegration(TestCase):
    """Tests for check_all totals and analyzer integration."""

    def test_check_all_sums_subscores(self):
        """AC-013: total_check_score is the sum of sub-scores."""
        email = _make_email(
            subject='verify your account urgent action required',
            body_text='',
            urls_extracted=['http://10.0.0.1/login'],
            received_chain=[{'from': f's{i}.com', 'by': f'r{i}.com',
                             'timestamp': f'2026-01-01T0{i}:00:00Z'} for i in range(8)],
        )
        result = Checker().check_all(email)
        expected = result.keyword_score + result.url_score + result.attachment_score + result.chain_score
        self.assertEqual(result.total_check_score, expected)

    def test_analyzer_calls_preprocessor_and_checker(self):
        """AC-016: Non-whitelisted email gets both preprocess and checker scores."""
        email = _make_email(
            subject='verify your account',
            body_text='click here immediately',
            headers_raw=[{'name': 'Authentication-Results',
                          'value': 'mx.google.com; spf=fail; dkim=fail; dmarc=fail'}],
        )
        EmailAnalyzer().analyze(email.id)
        analysis = AnalysisResult.objects.get(email=email)
        # Preprocessor should have scored auth failures
        self.assertGreater(analysis.preprocess_score, 0)
        # Checker should have scored keywords
        self.assertGreater(analysis.keyword_score, 0)

    def test_analyzer_whitelisted_skips_checker(self):
        """AC-016 neg: Whitelisted email does not run Checker."""
        WhitelistEntry.objects.create(entry_type='EMAIL', value='safe@trusted.com')
        email = _make_email(
            from_address='safe@trusted.com',
            subject='verify your account',
            body_text='urgent action required',
        )
        EmailAnalyzer().analyze(email.id)
        analysis = AnalysisResult.objects.get(email=email)
        self.assertEqual(analysis.preprocess_score, 0)
        self.assertEqual(analysis.keyword_score, 0)

    def test_analyzer_saves_check_result_to_db(self):
        """AC-016: After analyze(), AnalysisResult has checker fields populated."""
        MaliciousDomain.objects.create(domain='evil.com', source='URLHAUS')
        email = _make_email(
            subject='verify your account and reset your password',
            urls_extracted=['http://evil.com/phish'],
            received_chain=[{'from': f's{i}.com', 'by': f'r{i}.com',
                             'timestamp': f'2026-01-01T0{i}:00:00Z'} for i in range(8)],
        )
        EmailAnalyzer().analyze(email.id)
        analysis = AnalysisResult.objects.get(email=email)
        self.assertGreater(analysis.keyword_score, 0)
        self.assertGreater(analysis.url_score, 0)
        self.assertGreaterEqual(analysis.chain_score, 5)


# ---------------------------------------------------------------------------
# Error Resilience Tests
# ---------------------------------------------------------------------------

class TestCheckerErrorResilience(TestCase):
    """Tests for error handling and robustness."""

    def test_checker_catches_exception_returns_default(self):
        """check_all returns default CheckResult when DB raises."""
        email = _make_email()
        with patch.object(Checker, '_check_keywords', side_effect=Exception('boom')):
            with patch.object(Checker, '_check_urls', side_effect=Exception('boom')):
                with patch.object(Checker, '_check_attachments', side_effect=Exception('boom')):
                    with patch.object(Checker, '_check_received_chain', side_effect=Exception('boom')):
                        result = Checker().check_all(email)
        self.assertEqual(result.total_check_score, 0)

    def test_keyword_check_exception_isolated(self):
        """If _check_keywords raises, other checks still run."""
        email = _make_email(
            urls_extracted=['https://bit.ly/abc'],
            received_chain=[],
        )
        with patch.object(Checker, '_check_keywords', side_effect=Exception('boom')):
            result = Checker().check_all(email)
        self.assertEqual(result.keyword_score, 0)
        # URL check should still have run
        self.assertGreaterEqual(result.url_score, 5)

    def test_checker_with_none_urls_extracted(self):
        """urls_extracted=None (set in memory) does not crash."""
        email = _make_email(urls_extracted=[])
        # Simulate a None value in memory (field is NOT NULL in DB)
        email.urls_extracted = None
        result = Checker().check_all(email)
        self.assertEqual(result.url_score, 0)


# ---------------------------------------------------------------------------
# Performance Test
# ---------------------------------------------------------------------------

class TestCheckerPerformance(TestCase):
    """Performance benchmark for the Checker."""

    def test_checker_under_200ms(self):
        """check_all() completes within 200ms for a complex email."""
        email = _make_email(
            subject='verify your account urgent action required confirm your identity',
            body_text=(
                'unusual activity suspended account click here immediately '
                'update your payment security alert unauthorized access '
                'reset your password limited time offer act now '
                'your account will be closed verify your information '
                'important security update confirm your email '
                'invoice attached wire transfer bank account details '
                'confidential request gift card bitcoin payment '
                'do not share with anyone reply urgently'
            ),
            urls_extracted=[
                'http://10.0.0.1/a', 'https://bit.ly/b', 'http://evil.com/c',
                'http://192.168.1.1/d', 'https://tinyurl.com/e',
            ],
            received_chain=[
                {'from': f'10.0.{i}.1', 'by': f'relay{i}.example.com',
                 'timestamp': f'2026-01-01T{i:02d}:00:00Z'}
                for i in range(10)
            ],
        )
        for i in range(3):
            _make_attachment(email, filename=f'file{i}.pdf', sha256_hash=f'{i:0>64}')

        start = time.time()
        result = Checker().check_all(email)
        elapsed_ms = (time.time() - start) * 1000

        self.assertLess(elapsed_ms, 200)
        self.assertGreater(result.total_check_score, 0)
