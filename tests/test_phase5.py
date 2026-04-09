"""
Phase 5 tests: Decider, TI Feed Sync, REST API, and full pipeline integration.
"""
from datetime import timedelta
from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from accounts.models import User
from emails.models import (
    AnalysisResult,
    Email,
    EmailAttachment,
    QuarantineEntry,
)
from emails.services.checker import CheckResult
from emails.services.decider import DecisionResult, Decider
from emails.services.preprocessor import PreprocessResult
from threat_intel.models import MaliciousDomain, MaliciousHash


# ---------------------------------------------------------------------------
# Helper to create Email instances
# ---------------------------------------------------------------------------
def _make_email(**kwargs):
    defaults = {
        'message_id': f'<test-{timezone.now().timestamp()}@example.com>',
        'from_address': 'sender@example.com',
        'from_display_name': 'Sender',
        'subject': 'Test email',
        'body_text': 'Hello world',
        'received_at': timezone.now(),
        'status': 'PENDING',
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


# ===========================================================================
# 1. Decider Unit Tests
# ===========================================================================
class DeciderTests(TestCase):
    """Test the Decider decision logic."""

    def _preprocess(self, score=0, **kwargs):
        return PreprocessResult(score=score, **kwargs)

    def _check(self, total=0, has_known_malware=False, **kwargs):
        return CheckResult(total_check_score=total, has_known_malware=has_known_malware, **kwargs)

    def test_malicious_verdict_for_high_score(self):
        """AC-001: preprocess_score=30 + check_score=50 => MALICIOUS/BLOCK."""
        decision = Decider().decide(self._preprocess(30), self._check(50))
        self.assertEqual(decision.verdict, 'MALICIOUS')
        self.assertEqual(decision.action, 'BLOCK')
        self.assertEqual(decision.total_score, 80)

    def test_suspicious_verdict_for_medium_score(self):
        """AC-002: total_score=30 => SUSPICIOUS/QUARANTINE."""
        decision = Decider().decide(self._preprocess(15), self._check(15))
        self.assertEqual(decision.verdict, 'SUSPICIOUS')
        self.assertEqual(decision.action, 'QUARANTINE')
        self.assertEqual(decision.total_score, 30)
        self.assertEqual(decision.confidence, 'LOW')

    def test_clean_verdict_for_low_score(self):
        """AC-003: total_score=10 => CLEAN/DELIVER."""
        decision = Decider().decide(self._preprocess(5), self._check(5))
        self.assertEqual(decision.verdict, 'CLEAN')
        self.assertEqual(decision.action, 'DELIVER')
        self.assertEqual(decision.total_score, 10)

    def test_known_malware_override(self):
        """AC-004: has_known_malware=True forces MALICIOUS/100/HIGH/BLOCK."""
        decision = Decider().decide(self._preprocess(10), self._check(10, has_known_malware=True))
        self.assertEqual(decision.verdict, 'MALICIOUS')
        self.assertEqual(decision.total_score, 100)
        self.assertEqual(decision.confidence, 'HIGH')
        self.assertEqual(decision.action, 'BLOCK')
        self.assertEqual(decision.override_reason, 'known_malware_hash')

    def test_score_capped_at_100(self):
        """AC-005: raw=140 => total_score=100."""
        decision = Decider().decide(self._preprocess(60), self._check(80))
        self.assertEqual(decision.total_score, 100)

    def test_confidence_levels(self):
        """Test confidence for various score ranges."""
        # HIGH confidence: score >= 90
        d = Decider().decide(self._preprocess(50), self._check(45))
        self.assertEqual(d.confidence, 'HIGH')  # total=95, MALICIOUS
        self.assertEqual(d.verdict, 'MALICIOUS')

        # MEDIUM confidence: score 70-89
        d = Decider().decide(self._preprocess(40), self._check(35))
        self.assertEqual(d.confidence, 'MEDIUM')  # total=75, MALICIOUS
        self.assertEqual(d.verdict, 'MALICIOUS')

        # LOW confidence: SUSPICIOUS range
        d = Decider().decide(self._preprocess(15), self._check(15))
        self.assertEqual(d.confidence, 'LOW')  # total=30, SUSPICIOUS

        # HIGH confidence: score < 10
        d = Decider().decide(self._preprocess(3), self._check(2))
        self.assertEqual(d.confidence, 'HIGH')  # total=5, CLEAN

        # MEDIUM confidence: score 10-24
        d = Decider().decide(self._preprocess(10), self._check(5))
        self.assertEqual(d.confidence, 'MEDIUM')  # total=15, CLEAN

    def test_ac_001_boundary_score_70_is_malicious(self):
        """AC-001 boundary: total=70 is exactly MALICIOUS threshold."""
        decision = Decider().decide(self._preprocess(35), self._check(35))
        self.assertEqual(decision.verdict, 'MALICIOUS')
        self.assertEqual(decision.action, 'BLOCK')
        self.assertEqual(decision.total_score, 70)
        self.assertEqual(decision.confidence, 'MEDIUM')

    def test_ac_002_boundary_score_69_is_suspicious(self):
        """AC-002 boundary: total=69 stays SUSPICIOUS (just below MALICIOUS)."""
        decision = Decider().decide(self._preprocess(34), self._check(35))
        self.assertEqual(decision.verdict, 'SUSPICIOUS')
        self.assertEqual(decision.action, 'QUARANTINE')
        self.assertEqual(decision.total_score, 69)

    def test_ac_002_boundary_score_25_is_suspicious(self):
        """AC-002 boundary: total=25 is exactly SUSPICIOUS threshold."""
        decision = Decider().decide(self._preprocess(15), self._check(10))
        self.assertEqual(decision.verdict, 'SUSPICIOUS')
        self.assertEqual(decision.action, 'QUARANTINE')
        self.assertEqual(decision.total_score, 25)
        self.assertEqual(decision.confidence, 'LOW')

    def test_ac_003_boundary_score_24_is_clean(self):
        """AC-003 boundary: total=24 stays CLEAN (just below SUSPICIOUS)."""
        decision = Decider().decide(self._preprocess(14), self._check(10))
        self.assertEqual(decision.verdict, 'CLEAN')
        self.assertEqual(decision.action, 'DELIVER')
        self.assertEqual(decision.total_score, 24)
        self.assertEqual(decision.confidence, 'MEDIUM')

    def test_ac_003_score_zero_is_clean_high_confidence(self):
        """AC-003: total=0 produces CLEAN with HIGH confidence."""
        decision = Decider().decide(self._preprocess(0), self._check(0))
        self.assertEqual(decision.verdict, 'CLEAN')
        self.assertEqual(decision.action, 'DELIVER')
        self.assertEqual(decision.total_score, 0)
        self.assertEqual(decision.confidence, 'HIGH')

    def test_ac_004_override_ignores_low_raw_score(self):
        """AC-004: known malware override produces total_score=100 even with raw=20."""
        decision = Decider().decide(self._preprocess(5), self._check(15, has_known_malware=True))
        self.assertEqual(decision.total_score, 100)
        self.assertEqual(decision.verdict, 'MALICIOUS')
        self.assertEqual(decision.preprocess_score, 5)
        self.assertEqual(decision.check_score, 15)


# ===========================================================================
# 2. EmailAnalyzer Integration Tests
# ===========================================================================
class EmailAnalyzerIntegrationTests(TestCase):
    """Test the full analysis pipeline with Decider integration."""

    @patch('emails.services.checker.MaliciousDomain.objects')
    @patch('emails.services.checker.MaliciousHash.objects')
    def test_full_pipeline_produces_verdict(self, mock_hash_qs, mock_domain_qs):
        """AC-014: Full pipeline sets verdict, score, status, creates AnalysisResult."""
        mock_hash_qs.filter.return_value.first.return_value = None
        mock_domain_qs.filter.return_value.exists.return_value = False

        from threat_intel.models import BlacklistEntry
        email = _make_email(
            from_address='evil@malware.com',
            subject='verify your account urgent action required',
            body_text='click here immediately to reset your password and confirm your identity',
            headers_raw=[],
            received_chain=[],
            urls_extracted=[],
        )
        # Add blacklist to boost score above 70
        BlacklistEntry.objects.create(entry_type='EMAIL', value='evil@malware.com')
        BlacklistEntry.objects.create(entry_type='DOMAIN', value='malware.com')

        from emails.services.analyzer import EmailAnalyzer
        EmailAnalyzer().analyze(email.id)

        email.refresh_from_db()
        self.assertIsNotNone(email.verdict)
        self.assertIsNotNone(email.score)
        self.assertIsNotNone(email.analyzed_at)
        self.assertIn(email.status, ['DELIVERED', 'QUARANTINED', 'BLOCKED'])

        analysis = AnalysisResult.objects.get(email=email)
        self.assertIsNotNone(analysis.pipeline_duration_ms)
        self.assertGreaterEqual(analysis.pipeline_duration_ms, 0)
        self.assertEqual(analysis.total_score, email.score)

    @patch('emails.services.checker.MaliciousDomain.objects')
    @patch('emails.services.checker.MaliciousHash.objects')
    def test_quarantine_entry_created_for_malicious(self, mock_hash_qs, mock_domain_qs):
        """QuarantineEntry created when verdict is MALICIOUS or SUSPICIOUS (score >= 25)."""
        mock_hash_qs.filter.return_value.first.return_value = None
        mock_domain_qs.filter.return_value.exists.return_value = False

        from threat_intel.models import BlacklistEntry
        email = _make_email(
            from_address='bad@evil.com',
            subject='verify your account urgent action required confirm your identity',
            body_text='click here immediately reset your password suspended account unusual activity update your payment security alert unauthorized access limited time offer act now',
            headers_raw=[],
            received_chain=[],
            urls_extracted=[],
        )
        BlacklistEntry.objects.create(entry_type='EMAIL', value='bad@evil.com')
        BlacklistEntry.objects.create(entry_type='DOMAIN', value='evil.com')

        from emails.services.analyzer import EmailAnalyzer
        EmailAnalyzer().analyze(email.id)

        email.refresh_from_db()
        # Score should be >= 25 at minimum (blacklist email=40 + domain=30 = 70 already)
        self.assertGreaterEqual(email.score, 70)
        self.assertTrue(
            QuarantineEntry.objects.filter(email=email).exists(),
            'QuarantineEntry should be created for high-score emails',
        )

    @patch('emails.services.checker.MaliciousDomain.objects')
    @patch('emails.services.checker.MaliciousHash.objects')
    def test_no_quarantine_for_clean(self, mock_hash_qs, mock_domain_qs):
        """No QuarantineEntry for CLEAN verdict."""
        mock_hash_qs.filter.return_value.first.return_value = None
        mock_domain_qs.filter.return_value.exists.return_value = False

        email = _make_email(
            from_address='friend@safe.com',
            subject='Meeting tomorrow',
            body_text='See you at 3pm',
            headers_raw=[{
                'name': 'Authentication-Results',
                'value': 'spf=pass dkim=pass dmarc=pass',
            }],
            received_chain=[],
            urls_extracted=[],
        )

        from emails.services.analyzer import EmailAnalyzer
        EmailAnalyzer().analyze(email.id)

        email.refresh_from_db()
        self.assertEqual(email.verdict, 'CLEAN')
        self.assertEqual(email.status, 'DELIVERED')
        self.assertFalse(
            QuarantineEntry.objects.filter(email=email).exists(),
            'No QuarantineEntry should exist for CLEAN emails',
        )


# ===========================================================================
# 3. TI Feed Sync Tests (mocked HTTP)
# ===========================================================================
MOCK_MALWAREBAZAAR_CSV = (
    '# MalwareBazaar recent\n'
    '# Generated: 2026-04-07\n'
    'sha256_hash,md5_hash,signature,first_seen\n'
    + 'a' * 64 + ',aabbccdd11223344aabbccdd11223344,Emotet,2026-04-07\n'
    + 'b' * 64 + ',11112222333344445555666677778888,AgentTesla,2026-04-07\n'
    'deadbeef,badhash,Invalid,2026-04-07\n'
    + 'c' * 64 + ',aaaa1111bbbb2222cccc3333dddd4444,Raccoon,2026-04-07\n'
    + 'd' * 64 + ',bbbb2222cccc3333dddd4444eeee5555,Qakbot,2026-04-07\n'
    + 'e' * 64 + ',cccc3333dddd4444eeee5555ffff6666,Formbook,2026-04-07\n'
)

MOCK_URLHAUS_CSV = (
    '# URLhaus recent\n'
    '# Generated: 2026-04-07\n'
    'id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
    '1,2026-04-07,http://evil.com/malware.exe,online,2026-04-07,malware_download,elf,https://urlhaus.abuse.ch/url/1/,reporter1\n'
    '2,2026-04-07,http://bad.org/phish,online,2026-04-07,phishing,phish,https://urlhaus.abuse.ch/url/2/,reporter2\n'
    '3,2026-04-07,http://old.net/dead,offline,2026-04-06,malware_download,exe,https://urlhaus.abuse.ch/url/3/,reporter3\n'
)


class TIFeedSyncTests(TestCase):
    """Test the sync_ti_feeds management command with mocked HTTP."""

    @patch('threat_intel.management.commands.sync_ti_feeds.requests.get')
    def test_sync_command_runs_without_error(self, mock_get):
        """AC-006: call_command completes without exceptions."""
        mock_response = MagicMock()
        mock_response.text = MOCK_MALWAREBAZAAR_CSV
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        out = StringIO()
        call_command('sync_ti_feeds', feed='malwarebazaar', stdout=out)
        output = out.getvalue()
        self.assertIn('MalwareBazaar', output)

    @patch('threat_intel.management.commands.sync_ti_feeds.requests.get')
    def test_malwarebazaar_creates_hashes(self, mock_get):
        """AC-007: 5 valid rows in CSV => at least 5 MaliciousHash records."""
        mock_response = MagicMock()
        mock_response.text = MOCK_MALWAREBAZAAR_CSV
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        call_command('sync_ti_feeds', feed='malwarebazaar')
        # CSV has 5 valid rows (64-char hex) and 1 invalid
        self.assertEqual(MaliciousHash.objects.count(), 5)

    @patch('threat_intel.management.commands.sync_ti_feeds.requests.get')
    def test_invalid_sha256_skipped(self, mock_get):
        """AC-015: Row with sha256 of 8 chars is NOT imported."""
        mock_response = MagicMock()
        mock_response.text = MOCK_MALWAREBAZAAR_CSV
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        call_command('sync_ti_feeds', feed='malwarebazaar')
        self.assertFalse(
            MaliciousHash.objects.filter(sha256_hash='deadbeef').exists(),
        )

    @patch('threat_intel.management.commands.sync_ti_feeds.requests.get')
    def test_urlhaus_only_imports_online(self, mock_get):
        """AC-016: 2 online + 1 offline => MaliciousDomain.count() == 2."""
        mock_response = MagicMock()
        mock_response.text = MOCK_URLHAUS_CSV
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        call_command('sync_ti_feeds', feed='urlhaus')
        self.assertEqual(MaliciousDomain.objects.count(), 2)
        self.assertTrue(MaliciousDomain.objects.filter(domain='evil.com').exists())
        self.assertTrue(MaliciousDomain.objects.filter(domain='bad.org').exists())
        self.assertFalse(MaliciousDomain.objects.filter(domain='old.net').exists())

    @patch('threat_intel.management.commands.sync_ti_feeds.requests.get')
    def test_ac_007_limit_caps_imports(self, mock_get):
        """AC-007: --limit=2 imports only 2 records from MalwareBazaar."""
        mock_response = MagicMock()
        mock_response.text = MOCK_MALWAREBAZAAR_CSV
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        call_command('sync_ti_feeds', feed='malwarebazaar', limit=2)
        self.assertEqual(MaliciousHash.objects.count(), 2)

    @patch('threat_intel.management.commands.sync_ti_feeds.requests.get')
    def test_ac_006_sync_all_feeds(self, mock_get):
        """AC-006: sync_ti_feeds with feed='all' syncs both feeds."""
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            if 'bazaar' in url:
                resp.text = MOCK_MALWAREBAZAAR_CSV
            else:
                resp.text = MOCK_URLHAUS_CSV
            return resp

        mock_get.side_effect = side_effect

        out = StringIO()
        call_command('sync_ti_feeds', feed='all', stdout=out)
        output = out.getvalue()
        self.assertIn('MalwareBazaar', output)
        self.assertIn('URLhaus', output)
        self.assertGreater(MaliciousHash.objects.count(), 0)
        self.assertGreater(MaliciousDomain.objects.count(), 0)


# ===========================================================================
# 4. API Tests
# ===========================================================================
class APIBaseTestCase(APITestCase):
    """Base class with authenticated client setup."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='analyst', password='testpass', role='ANALYST',
        )
        self.viewer = User.objects.create_user(
            username='viewer', password='testpass', role='VIEWER',
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)


class EmailListAPITests(APIBaseTestCase):
    """Test GET /api/emails/"""

    def test_returns_200_paginated(self):
        """AC-008: Authenticated GET returns 200 with paginated results."""
        _make_email(verdict='CLEAN', score=5, confidence='HIGH', status='DELIVERED')
        _make_email(
            message_id='<test2@example.com>',
            verdict='MALICIOUS', score=85, confidence='HIGH', status='BLOCKED',
        )

        response = self.client.get('/api/emails/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertIn('count', response.data)
        self.assertIn('next', response.data)
        self.assertIn('previous', response.data)
        self.assertEqual(response.data['count'], 2)

        # Check fields on first result
        item = response.data['results'][0]
        self.assertIn('id', item)
        self.assertIn('verdict', item)
        self.assertIn('score', item)

    def test_filter_by_verdict(self):
        """Email list filtering by verdict query param."""
        _make_email(verdict='CLEAN', score=5, status='DELIVERED')
        _make_email(
            message_id='<mal@example.com>',
            verdict='MALICIOUS', score=85, status='BLOCKED',
        )

        response = self.client.get('/api/emails/?verdict=CLEAN')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['verdict'], 'CLEAN')

    def test_unauthenticated_returns_401(self):
        """Unauthenticated request returns 401."""
        client = APIClient()
        response = client.get('/api/emails/')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])


class EmailDetailAPITests(APIBaseTestCase):
    """Test GET /api/emails/<pk>/"""

    def test_returns_200_with_nested_data(self):
        """AC-009: Returns full detail with nested analysis and attachments."""
        email = _make_email(
            verdict='MALICIOUS', score=85, confidence='MEDIUM', status='BLOCKED',
        )
        AnalysisResult.objects.create(
            email=email, preprocess_score=35, total_score=85,
            pipeline_duration_ms=145,
        )
        EmailAttachment.objects.create(
            email=email, filename='invoice.pdf', content_type='application/pdf',
            size_bytes=12345, sha256_hash='a' * 64, md5_hash='b' * 32,
        )

        response = self.client.get(f'/api/emails/{email.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('analysis', response.data)
        self.assertEqual(response.data['analysis']['preprocess_score'], 35)
        self.assertEqual(response.data['analysis']['total_score'], 85)
        self.assertIn('attachments', response.data)
        self.assertEqual(len(response.data['attachments']), 1)


class QuarantineListAPITests(APIBaseTestCase):
    """Test GET /api/quarantine/"""

    def test_returns_only_quarantined_blocked(self):
        """AC-010: Only QUARANTINED/BLOCKED emails appear."""
        quarantined_email = _make_email(
            verdict='SUSPICIOUS', score=45, status='QUARANTINED',
        )
        QuarantineEntry.objects.create(email=quarantined_email, status='PENDING', action='QUARANTINE')

        clean_email = _make_email(
            message_id='<clean@example.com>',
            verdict='CLEAN', score=5, status='DELIVERED',
        )

        response = self.client.get('/api/quarantine/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(
            response.data['results'][0]['email']['status'], 'QUARANTINED',
        )


class QuarantineActionAPITests(APIBaseTestCase):
    """Test POST /api/quarantine/<pk>/action/"""

    def test_release_changes_status(self):
        """AC-011: Release changes email status to DELIVERED."""
        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(
            email=email, status='PENDING', action='QUARANTINE',
        )

        response = self.client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'release', 'notes': 'False positive'},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        entry.refresh_from_db()
        email.refresh_from_db()
        self.assertEqual(entry.status, 'RELEASED')
        self.assertEqual(email.status, 'DELIVERED')
        self.assertEqual(entry.notes, 'False positive')
        self.assertIsNotNone(entry.reviewed_at)

    def test_viewer_returns_403(self):
        """AC-012: VIEWER cannot perform quarantine actions."""
        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(
            email=email, status='PENDING', action='QUARANTINE',
        )

        viewer_client = APIClient()
        viewer_client.force_authenticate(user=self.viewer)
        response = viewer_client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'release'},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_permanently_removes_email(self):
        """Delete action permanently removes the email and related records."""
        email = _make_email(verdict='MALICIOUS', score=90, status='BLOCKED')
        entry = QuarantineEntry.objects.create(
            email=email, status='PENDING', action='BLOCK',
        )

        email_id = email.id
        response = self.client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'delete'},
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Email.objects.filter(id=email_id).exists())
        self.assertFalse(QuarantineEntry.objects.filter(id=entry.id).exists())


class QuarantineBlockActionAPITests(APIBaseTestCase):
    """Test POST /api/quarantine/<pk>/action/ with block action."""

    def test_ac_011_block_changes_status(self):
        """Block action changes quarantine status to BLOCKED and email status to BLOCKED."""
        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(
            email=email, status='PENDING', action='QUARANTINE',
        )

        response = self.client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'block', 'notes': 'Confirmed threat'},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        entry.refresh_from_db()
        email.refresh_from_db()
        self.assertEqual(entry.status, 'BLOCKED')
        self.assertEqual(email.status, 'BLOCKED')
        self.assertEqual(entry.notes, 'Confirmed threat')
        self.assertIsNotNone(entry.reviewed_at)

    def test_admin_can_perform_quarantine_action(self):
        """ADMIN role can perform quarantine actions (not just ANALYST)."""
        admin = User.objects.create_user(
            username='admin_user', password='testpass', role='ADMIN',
        )
        admin_client = APIClient()
        admin_client.force_authenticate(user=admin)

        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(
            email=email, status='PENDING', action='QUARANTINE',
        )

        response = admin_client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'release'},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class EmailDetailNotFoundAPITests(APIBaseTestCase):
    """Test GET /api/emails/<pk>/ with invalid pk."""

    def test_returns_404_for_nonexistent_email(self):
        """GET /api/emails/99999/ returns 404."""
        response = self.client.get('/api/emails/99999/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class EmailListFilterAPITests(APIBaseTestCase):
    """Test GET /api/emails/ with various filters."""

    def test_filter_by_status(self):
        """Email list filtering by status query param."""
        _make_email(verdict='CLEAN', score=5, status='DELIVERED')
        _make_email(
            message_id='<blocked@example.com>',
            verdict='MALICIOUS', score=85, status='BLOCKED',
        )

        response = self.client.get('/api/emails/?status=BLOCKED')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['status'], 'BLOCKED')

    def test_filter_by_from_address(self):
        """Email list filtering by from_address (case-insensitive contains)."""
        _make_email(from_address='evil@malicious.com', verdict='MALICIOUS', score=85, status='BLOCKED')
        _make_email(
            message_id='<safe@example.com>',
            from_address='friend@safe.com', verdict='CLEAN', score=5, status='DELIVERED',
        )

        response = self.client.get('/api/emails/?from_address=malicious')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['from_address'], 'evil@malicious.com')


class DashboardStatsAPITests(APIBaseTestCase):
    """Test GET /api/dashboard/stats/"""

    def test_returns_correct_counts(self):
        """AC-013: Correct aggregate counts."""
        # Create 3 CLEAN, 2 SUSPICIOUS, 1 MALICIOUS
        for i in range(3):
            _make_email(
                message_id=f'<clean-{i}@ex.com>',
                verdict='CLEAN', score=5, status='DELIVERED',
            )
        for i in range(2):
            email = _make_email(
                message_id=f'<susp-{i}@ex.com>',
                verdict='SUSPICIOUS', score=45, status='QUARANTINED',
            )
            QuarantineEntry.objects.create(email=email, status='PENDING', action='QUARANTINE')
        _make_email(
            message_id='<mal@ex.com>',
            verdict='MALICIOUS', score=85, status='BLOCKED',
        )

        response = self.client.get('/api/dashboard/stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_emails'], 6)
        self.assertEqual(response.data['clean_count'], 3)
        self.assertEqual(response.data['suspicious_count'], 2)
        self.assertEqual(response.data['malicious_count'], 1)
        self.assertEqual(response.data['pending_count'], 0)
        self.assertEqual(response.data['quarantine_pending'], 2)

    def test_ac_013_pending_count(self):
        """AC-013: pending_count counts emails with no verdict."""
        _make_email(verdict=None, score=None, status='PENDING')
        _make_email(message_id='<analyzed@ex.com>', verdict='CLEAN', score=5, status='DELIVERED')

        response = self.client.get('/api/dashboard/stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_emails'], 2)
        self.assertEqual(response.data['pending_count'], 1)

    def test_ac_013_ti_counts(self):
        """AC-013: ti_hashes and ti_domains reflect TI records in DB."""
        MaliciousHash.objects.create(
            sha256_hash='a' * 64, md5_hash='b' * 32,
            malware_family='Emotet', source='MALWAREBAZAAR',
        )
        MaliciousDomain.objects.create(
            domain='evil.com', category='threat', source='URLHAUS',
        )

        response = self.client.get('/api/dashboard/stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['ti_hashes'], 1)
        self.assertEqual(response.data['ti_domains'], 1)


# ===========================================================================
# 5. Celery Task Tests
# ===========================================================================
class CeleryTaskTests(TestCase):
    """Test TI feed Celery tasks."""

    @patch('threat_intel.tasks.call_command')
    def test_sync_malwarebazaar_task(self, mock_call):
        from threat_intel.tasks import sync_malwarebazaar_task
        result = sync_malwarebazaar_task()
        mock_call.assert_called_once_with('sync_ti_feeds', feed='malwarebazaar')
        self.assertEqual(result, {'status': 'completed', 'feed': 'malwarebazaar'})

    @patch('threat_intel.tasks.call_command')
    def test_sync_urlhaus_task(self, mock_call):
        from threat_intel.tasks import sync_urlhaus_task
        result = sync_urlhaus_task()
        mock_call.assert_called_once_with('sync_ti_feeds', feed='urlhaus')
        self.assertEqual(result, {'status': 'completed', 'feed': 'urlhaus'})
