"""
Phase 8 — Preprocessor Scoring Tests.
Direct unit tests on Preprocessor.process(email) with controlled inputs.
"""
import uuid

from django.test import TestCase
from django.utils import timezone

from emails.models import Email
from emails.services.preprocessor import Preprocessor
from threat_intel.models import BlacklistEntry, WhitelistEntry


def _make_email(**kwargs):
    defaults = {
        'message_id': f'<preproc-{uuid.uuid4()}@test.com>',
        'from_address': 'sender@example.com',
        'from_display_name': 'Sender',
        'subject': 'Test subject',
        'body_text': 'Test body',
        'received_at': timezone.now(),
        'status': 'PENDING',
        'to_addresses': ['user@example.com'],
        'headers_raw': [
            {'name': 'Authentication-Results', 'value': 'spf=pass dkim=pass dmarc=pass'},
        ],
        'received_chain': [],
        'urls_extracted': [],
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


class PreprocessorAuthScoringTests(TestCase):
    """Test SPF/DKIM/DMARC scoring in the Preprocessor."""

    def test_ac_501_all_pass_score_zero(self):
        """AC-501: SPF pass + DKIM pass + DMARC pass -> preprocess_score=0."""
        email = _make_email(headers_raw=[
            {'name': 'Authentication-Results', 'value': 'spf=pass dkim=pass dmarc=pass'},
        ])
        result = Preprocessor().process(email)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.spf_result, 'pass')
        self.assertEqual(result.dkim_result, 'pass')
        self.assertEqual(result.dmarc_result, 'pass')

    def test_ac_502_all_fail_score_45(self):
        """AC-502: SPF fail + DKIM fail + DMARC fail -> score=45."""
        email = _make_email(headers_raw=[
            {'name': 'Authentication-Results', 'value': 'spf=fail dkim=fail dmarc=fail'},
        ])
        result = Preprocessor().process(email)
        # SPF fail=15, DKIM fail=15, DMARC fail=15 => 45
        self.assertEqual(result.score, 45)
        self.assertEqual(result.spf_result, 'fail')
        self.assertEqual(result.dkim_result, 'fail')
        self.assertEqual(result.dmarc_result, 'fail')

    def test_ac_503_spf_softfail_only(self):
        """AC-503: SPF softfail with others pass -> score=5."""
        email = _make_email(headers_raw=[
            {'name': 'Authentication-Results', 'value': 'spf=softfail dkim=pass dmarc=pass'},
        ])
        result = Preprocessor().process(email)
        self.assertEqual(result.score, 5)
        self.assertEqual(result.spf_result, 'softfail')

    def test_ac_504_all_none_score_20(self):
        """AC-504: SPF none + DKIM none + DMARC none -> score=20."""
        email = _make_email(headers_raw=[
            {'name': 'Authentication-Results', 'value': 'spf=none dkim=none dmarc=none'},
        ])
        result = Preprocessor().process(email)
        # SPF none=10, DKIM none=5, DMARC none=5 => 20
        self.assertEqual(result.score, 20)

    def test_ac_505_no_auth_headers(self):
        """AC-505: Empty headers_raw -> SPF/DKIM/DMARC all 'none', score=20."""
        email = _make_email(headers_raw=[])
        result = Preprocessor().process(email)
        self.assertEqual(result.spf_result, 'none')
        self.assertEqual(result.dkim_result, 'none')
        self.assertEqual(result.dmarc_result, 'none')
        self.assertEqual(result.score, 20)

    def test_ac_506_clean_email_zero_score(self):
        """AC-506: Normal email with all pass -> score=0."""
        email = _make_email()
        result = Preprocessor().process(email)
        self.assertEqual(result.score, 0)


class PreprocessorBlacklistTests(TestCase):
    """Test blacklist scoring."""

    def test_ac_507_blacklist_email_40(self):
        """AC-507: BlacklistEntry EMAIL match -> score >= 40."""
        BlacklistEntry.objects.create(entry_type='EMAIL', value='bad@evil.com')
        email = _make_email(
            from_address='bad@evil.com',
            headers_raw=[
                {'name': 'Authentication-Results', 'value': 'spf=pass dkim=pass dmarc=pass'},
            ],
        )
        result = Preprocessor().process(email)
        self.assertGreaterEqual(result.score, 40)

    def test_ac_508_blacklist_domain_30(self):
        """AC-508: BlacklistEntry DOMAIN match -> score >= 30."""
        BlacklistEntry.objects.create(entry_type='DOMAIN', value='evil.com')
        email = _make_email(
            from_address='user@evil.com',
            headers_raw=[
                {'name': 'Authentication-Results', 'value': 'spf=pass dkim=pass dmarc=pass'},
            ],
        )
        result = Preprocessor().process(email)
        self.assertGreaterEqual(result.score, 30)

    def test_ac_509_blacklist_email_plus_spf_fail(self):
        """AC-509: Blacklist email + SPF fail -> score >= 55."""
        BlacklistEntry.objects.create(entry_type='EMAIL', value='bad@evil.com')
        email = _make_email(
            from_address='bad@evil.com',
            headers_raw=[
                {'name': 'Authentication-Results', 'value': 'spf=fail dkim=pass dmarc=pass'},
            ],
        )
        result = Preprocessor().process(email)
        # blacklist email=40 + spf fail=15 = 55
        self.assertGreaterEqual(result.score, 55)


class PreprocessorBECSignalTests(TestCase):
    """Test Reply-To mismatch and display name spoof detection."""

    def test_ac_510_reply_to_mismatch(self):
        """AC-510: Different reply-to domain -> +10, is_reply_to_mismatch=True."""
        email = _make_email(
            from_address='boss@company.com',
            reply_to='scammer@evil.com',
        )
        result = Preprocessor().process(email)
        self.assertTrue(result.is_reply_to_mismatch)
        self.assertGreaterEqual(result.score, 10)

    def test_ac_511_display_name_spoof(self):
        """AC-511: @ in display name with different domain -> +10, is_display_spoof=True."""
        email = _make_email(
            from_address='scammer@evil.com',
            from_display_name='boss@company.com',
        )
        result = Preprocessor().process(email)
        self.assertTrue(result.is_display_spoof)
        self.assertGreaterEqual(result.score, 10)

    def test_ac_512_reply_to_plus_display_spoof(self):
        """AC-512: Both reply-to mismatch and display spoof -> +20."""
        email = _make_email(
            from_address='scammer@evil.com',
            from_display_name='boss@company.com',
            reply_to='other@different.com',
        )
        result = Preprocessor().process(email)
        self.assertTrue(result.is_reply_to_mismatch)
        self.assertTrue(result.is_display_spoof)
        self.assertGreaterEqual(result.score, 20)


class PreprocessorWhitelistTests(TestCase):
    """Test whitelist short-circuit behavior."""

    def test_ac_513_whitelist_email(self):
        """AC-513: WhitelistEntry EMAIL match -> score=0, verdict_override='CLEAN'."""
        WhitelistEntry.objects.create(entry_type='EMAIL', value='trusted@partner.com')
        email = _make_email(from_address='trusted@partner.com')
        result = Preprocessor().process(email)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.verdict_override, 'CLEAN')

    def test_ac_514_whitelist_domain(self):
        """AC-514: WhitelistEntry DOMAIN match -> score=0, verdict_override='CLEAN'."""
        WhitelistEntry.objects.create(entry_type='DOMAIN', value='partner.com')
        email = _make_email(from_address='anyone@partner.com')
        result = Preprocessor().process(email)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.verdict_override, 'CLEAN')

    def test_ac_515_whitelist_overrides_blacklist(self):
        """AC-515: Both whitelist and blacklist match -> whitelist wins (checked first)."""
        WhitelistEntry.objects.create(entry_type='EMAIL', value='user@dual.com')
        BlacklistEntry.objects.create(entry_type='EMAIL', value='user@dual.com')
        email = _make_email(from_address='user@dual.com')
        result = Preprocessor().process(email)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.verdict_override, 'CLEAN')
