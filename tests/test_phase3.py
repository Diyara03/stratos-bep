"""
Phase 3 tests: Preprocessor + SPF/DKIM/DMARC analysis.
Covers all 14 acceptance criteria from PHASE3_SPEC.md.
"""
import time
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from emails.models import AnalysisResult, Email
from emails.services.analyzer import EmailAnalyzer
from emails.services.preprocessor import Preprocessor, PreprocessResult
from threat_intel.models import BlacklistEntry, WhitelistEntry


def _make_email(**kwargs):
    """Create an Email with sensible defaults for testing."""
    defaults = {
        'message_id': f'test-{timezone.now().timestamp()}@example.com',
        'from_address': 'sender@example.com',
        'from_display_name': 'Test Sender',
        'to_addresses': ['recipient@company.com'],
        'reply_to': '',
        'subject': 'Test Email',
        'body_text': 'Hello',
        'headers_raw': [],
        'received_at': timezone.now(),
        'status': 'PENDING',
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


def _auth_headers(spf='pass', dkim='pass', dmarc='pass'):
    """Build a headers_raw list with an Authentication-Results header."""
    value = f'mx.google.com; spf={spf} smtp.mailfrom=example.com; dkim={dkim} header.d=example.com; dmarc={dmarc} header.from=example.com'
    return [{'name': 'Authentication-Results', 'value': value}]


class TestPreprocessorSPF(TestCase):
    """Tests for SPF scoring (AC-001, AC-002, AC-009, AC-012)."""

    def test_spf_fail_scores_15(self):
        email = _make_email(headers_raw=_auth_headers(spf='fail'))
        result = Preprocessor().process(email)
        self.assertEqual(result.spf_result, 'fail')
        self.assertGreaterEqual(result.score, 15)

    def test_spf_softfail_scores_5(self):
        email = _make_email(headers_raw=_auth_headers(spf='softfail'))
        result = Preprocessor().process(email)
        self.assertEqual(result.spf_result, 'softfail')
        self.assertGreaterEqual(result.score, 5)

    def test_spf_pass_scores_0(self):
        email = _make_email(headers_raw=_auth_headers(spf='pass'))
        result = Preprocessor().process(email)
        self.assertEqual(result.spf_result, 'pass')
        # Auth score from SPF pass = 0, but DKIM/DMARC pass also = 0
        auth_contribution = result.findings.get('auth', {}).get('score_contribution', 0)
        # SPF contributes 0 when pass
        self.assertEqual(auth_contribution, 0)

    def test_spf_none_scores_10(self):
        email = _make_email(headers_raw=[])
        result = Preprocessor().process(email)
        self.assertEqual(result.spf_result, 'none')
        # SPF none=+10, DKIM none=+5, DMARC none=+5 = 20 total
        self.assertGreaterEqual(result.score, 10)


class TestPreprocessorDKIM(TestCase):
    """Tests for DKIM scoring."""

    def test_dkim_fail_scores_15(self):
        email = _make_email(headers_raw=_auth_headers(dkim='fail'))
        result = Preprocessor().process(email)
        self.assertEqual(result.dkim_result, 'fail')
        self.assertGreaterEqual(result.score, 15)

    def test_dkim_none_scores_5(self):
        email = _make_email(headers_raw=_auth_headers(spf='pass', dkim='none', dmarc='pass'))
        result = Preprocessor().process(email)
        self.assertEqual(result.dkim_result, 'none')
        self.assertEqual(result.findings['auth']['score_contribution'], 5)


class TestPreprocessorDMARC(TestCase):
    """Tests for DMARC scoring."""

    def test_dmarc_fail_scores_15(self):
        email = _make_email(headers_raw=_auth_headers(dmarc='fail'))
        result = Preprocessor().process(email)
        self.assertEqual(result.dmarc_result, 'fail')
        self.assertGreaterEqual(result.score, 15)

    def test_dmarc_none_scores_5(self):
        email = _make_email(headers_raw=_auth_headers(spf='pass', dkim='pass', dmarc='none'))
        result = Preprocessor().process(email)
        self.assertEqual(result.dmarc_result, 'none')
        self.assertEqual(result.findings['auth']['score_contribution'], 5)


class TestPreprocessorAuthCombined(TestCase):
    """Tests for combined auth scoring (AC-008, AC-009, AC-012)."""

    def test_all_auth_fail_scores_45(self):
        email = _make_email(headers_raw=_auth_headers(spf='fail', dkim='fail', dmarc='fail'))
        result = Preprocessor().process(email)
        self.assertEqual(result.spf_result, 'fail')
        self.assertEqual(result.dkim_result, 'fail')
        self.assertEqual(result.dmarc_result, 'fail')
        self.assertGreaterEqual(result.score, 45)

    def test_all_auth_pass_scores_0(self):
        email = _make_email(headers_raw=_auth_headers(spf='pass', dkim='pass', dmarc='pass'))
        result = Preprocessor().process(email)
        self.assertEqual(result.findings['auth']['score_contribution'], 0)

    def test_no_auth_header_defaults_none(self):
        email = _make_email(headers_raw=[])
        result = Preprocessor().process(email)
        self.assertEqual(result.spf_result, 'none')
        self.assertEqual(result.dkim_result, 'none')
        self.assertEqual(result.dmarc_result, 'none')
        # SPF none=10 + DKIM none=5 + DMARC none=5 = 20
        self.assertEqual(result.findings['auth']['score_contribution'], 20)


class TestPreprocessorWhitelist(TestCase):
    """Tests for whitelist short-circuit (AC-003)."""

    def setUp(self):
        WhitelistEntry.objects.create(entry_type='EMAIL', value='trusted@safe.com')
        WhitelistEntry.objects.create(entry_type='DOMAIN', value='safe.com')

    def test_whitelist_email_match_short_circuits(self):
        email = _make_email(from_address='trusted@safe.com')
        result = Preprocessor().process(email)
        self.assertEqual(result.verdict_override, 'CLEAN')
        self.assertEqual(result.score, 0)
        self.assertTrue(result.findings['whitelist']['matched'])
        self.assertEqual(result.findings['whitelist']['type'], 'EMAIL')

    def test_whitelist_domain_match_short_circuits(self):
        email = _make_email(from_address='unknown@safe.com')
        result = Preprocessor().process(email)
        self.assertEqual(result.verdict_override, 'CLEAN')
        self.assertEqual(result.score, 0)
        self.assertTrue(result.findings['whitelist']['matched'])
        self.assertEqual(result.findings['whitelist']['type'], 'DOMAIN')

    def test_case_insensitive_whitelist_match(self):
        email = _make_email(from_address='Trusted@SAFE.COM')
        result = Preprocessor().process(email)
        self.assertEqual(result.verdict_override, 'CLEAN')
        self.assertEqual(result.score, 0)


class TestPreprocessorBlacklist(TestCase):
    """Tests for blacklist scoring (AC-004, AC-005)."""

    def setUp(self):
        BlacklistEntry.objects.create(entry_type='EMAIL', value='bad@evil.com')
        BlacklistEntry.objects.create(entry_type='DOMAIN', value='evil.com')

    def test_blacklist_email_match_scores_40(self):
        email = _make_email(
            from_address='bad@evil.com',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertGreaterEqual(result.score, 40)
        self.assertTrue(result.findings.get('blacklist_email'))

    def test_blacklist_domain_match_scores_30(self):
        email = _make_email(
            from_address='other@evil.com',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertGreaterEqual(result.score, 30)
        self.assertTrue(result.findings.get('blacklist_domain'))

    def test_blacklist_both_match_scores_70(self):
        email = _make_email(
            from_address='bad@evil.com',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        # 40 (email) + 30 (domain) = 70 from blacklist alone
        self.assertTrue(result.findings.get('blacklist_email'))
        self.assertTrue(result.findings.get('blacklist_domain'))
        self.assertGreaterEqual(result.score, 70)


class TestPreprocessorReplyTo(TestCase):
    """Tests for Reply-To mismatch detection (AC-006)."""

    def test_reply_to_mismatch_scores_10(self):
        email = _make_email(
            from_address='sender@company.com',
            reply_to='attacker@evil.com',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertTrue(result.is_reply_to_mismatch)
        self.assertIn('reply_to_mismatch', result.findings)
        # Score should include +10 for mismatch
        self.assertGreaterEqual(result.score, 10)

    def test_reply_to_none_no_score(self):
        email = _make_email(
            reply_to=None,
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertFalse(result.is_reply_to_mismatch)

    def test_reply_to_same_domain_no_score(self):
        email = _make_email(
            from_address='user1@company.com',
            reply_to='user2@company.com',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertFalse(result.is_reply_to_mismatch)


class TestPreprocessorDisplaySpoof(TestCase):
    """Tests for display name spoof detection (AC-007)."""

    def test_display_spoof_with_at_sign(self):
        email = _make_email(
            from_address='attacker@evil.com',
            from_display_name='ceo@company.com',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertTrue(result.is_display_spoof)
        self.assertIn('display_spoof', result.findings)
        self.assertGreaterEqual(result.score, 10)

    def test_display_spoof_with_domain_pattern(self):
        email = _make_email(
            from_address='attacker@evil.com',
            from_display_name='Support team - company.org',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertTrue(result.is_display_spoof)
        self.assertIn('display_spoof', result.findings)

    def test_display_name_blank_no_score(self):
        email = _make_email(
            from_display_name='',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertFalse(result.is_display_spoof)

    def test_display_name_same_domain_no_spoof(self):
        email = _make_email(
            from_address='user@example.com',
            from_display_name='user@example.com',
            headers_raw=_auth_headers(),
        )
        result = Preprocessor().process(email)
        self.assertFalse(result.is_display_spoof)


class TestPreprocessorErrorResilience(TestCase):
    """Tests for error resilience (AC-013)."""

    def test_preprocessor_catches_exceptions(self):
        """Preprocessor should never raise, even with bad data."""
        email = _make_email(headers_raw=_auth_headers())
        with patch.object(WhitelistEntry.objects, 'filter', side_effect=Exception('DB error')):
            result = Preprocessor().process(email)
        # Should return safe default
        self.assertIsInstance(result, PreprocessResult)
        self.assertEqual(result.score, 0)

    def test_malformed_auth_header_graceful(self):
        """Malformed Authentication-Results header should not crash."""
        email = _make_email(
            headers_raw=[{'name': 'Authentication-Results', 'value': 'totally garbled!!!'}]
        )
        result = Preprocessor().process(email)
        self.assertIsInstance(result, PreprocessResult)
        # Should default to 'none' for all
        self.assertEqual(result.spf_result, 'none')
        self.assertEqual(result.dkim_result, 'none')
        self.assertEqual(result.dmarc_result, 'none')

    def test_empty_headers_raw_dict(self):
        """Empty dict (instead of list) for headers_raw should not crash."""
        email = _make_email(headers_raw={})
        result = Preprocessor().process(email)
        self.assertIsInstance(result, PreprocessResult)
        self.assertEqual(result.spf_result, 'none')


class TestEmailAnalyzerWhitelist(TestCase):
    """Integration tests for EmailAnalyzer with whitelist (AC-010)."""

    def setUp(self):
        WhitelistEntry.objects.create(entry_type='EMAIL', value='trusted@safe.com')

    def test_analyze_whitelisted_email_delivers(self):
        email = _make_email(
            from_address='trusted@safe.com',
            headers_raw=_auth_headers(),
        )
        EmailAnalyzer().analyze(email.id)
        email.refresh_from_db()
        self.assertEqual(email.verdict, 'CLEAN')
        self.assertEqual(email.status, 'DELIVERED')
        self.assertEqual(email.confidence, 'HIGH')
        self.assertEqual(email.score, 0)
        self.assertIsNotNone(email.analyzed_at)
        # AnalysisResult should exist
        self.assertTrue(AnalysisResult.objects.filter(email=email).exists())


class TestEmailAnalyzerNormal(TestCase):
    """Integration tests for EmailAnalyzer normal flow (AC-011)."""

    def test_analyze_normal_email_creates_analysis_result(self):
        email = _make_email(
            headers_raw=_auth_headers(spf='fail', dkim='pass', dmarc='pass'),
        )
        EmailAnalyzer().analyze(email.id)
        email.refresh_from_db()
        # After Phase 5 the pipeline completes fully with a final status and verdict
        self.assertIn(email.status, ['DELIVERED', 'QUARANTINED', 'BLOCKED'])
        self.assertIsNotNone(email.verdict)
        # AnalysisResult should be created with preprocess fields
        analysis = AnalysisResult.objects.get(email=email)
        self.assertEqual(analysis.preprocess_score, 15)  # SPF fail = +15
        self.assertEqual(analysis.spf_result, 'fail')
        self.assertEqual(analysis.dkim_result, 'pass')
        self.assertEqual(analysis.dmarc_result, 'pass')

    def test_analyze_sets_final_status(self):
        """Email status should be a final state after full pipeline completes."""
        email = _make_email(headers_raw=_auth_headers())
        EmailAnalyzer().analyze(email.id)
        email.refresh_from_db()
        self.assertIn(email.status, ['DELIVERED', 'QUARANTINED', 'BLOCKED'])

    def test_analyze_nonexistent_email_raises(self):
        """analyze() should raise Email.DoesNotExist for invalid ID."""
        with self.assertRaises(Email.DoesNotExist):
            EmailAnalyzer().analyze(99999)


class TestPreprocessorPerformance(TestCase):
    """Performance test (AC-014)."""

    def test_preprocessor_under_100ms(self):
        email = _make_email(
            headers_raw=_auth_headers(spf='fail', dkim='fail', dmarc='fail'),
            from_display_name='ceo@spoofed.com',
            reply_to='attacker@evil.com',
        )
        preprocessor = Preprocessor()
        start = time.time()
        for _ in range(10):
            preprocessor.process(email)
        elapsed = (time.time() - start) / 10
        # Average should be under 100ms
        self.assertLess(elapsed, 0.1, f"Preprocessor took {elapsed:.3f}s on average")
