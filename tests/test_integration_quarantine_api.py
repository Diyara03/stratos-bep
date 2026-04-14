"""
Integration tests for quarantine lifecycle and API filter combinations.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from emails.models import AnalysisResult, Email, EmailAttachment, ExtractedIOC, QuarantineEntry
from threat_intel.models import BlacklistEntry, MaliciousDomain, MaliciousHash

User = get_user_model()


def _make_email(message_id, verdict='CLEAN', status='DELIVERED', score=5, **kwargs):
    defaults = dict(
        from_address='test@example.com',
        from_display_name='Test',
        subject=f'Email {message_id}',
        body_text='test body',
        received_at=timezone.now(),
        to_addresses=['me@example.com'],
        verdict=verdict,
        status=status,
        score=score,
    )
    defaults.update(kwargs)
    return Email.objects.create(message_id=message_id, **defaults)


# ─── Full Quarantine Lifecycle (API) ───


class QuarantineLifecycleAPITest(TestCase):
    """Test quarantine workflows through the REST API."""

    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst', password='pass', role='ANALYST'
        )
        self.token = Token.objects.create(user=self.analyst)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def _quarantine_email(self, msg_id):
        email = _make_email(msg_id, verdict='SUSPICIOUS', status='QUARANTINED', score=55)
        entry = QuarantineEntry.objects.create(email=email)
        return email, entry

    def test_release_lifecycle(self):
        email, entry = self._quarantine_email('lifecycle-release')
        resp = self.client.post(
            f'/api/quarantine/{entry.pk}/action/',
            {'action': 'release', 'notes': 'False positive confirmed'},
        )
        self.assertEqual(resp.status_code, 200)
        entry.refresh_from_db()
        email.refresh_from_db()
        self.assertEqual(entry.status, 'RELEASED')
        self.assertEqual(email.status, 'DELIVERED')
        self.assertEqual(entry.reviewer, self.analyst)
        self.assertIsNotNone(entry.reviewed_at)
        self.assertEqual(entry.notes, 'False positive confirmed')

    def test_block_lifecycle(self):
        email, entry = self._quarantine_email('lifecycle-block')
        resp = self.client.post(
            f'/api/quarantine/{entry.pk}/action/',
            {'action': 'block', 'notes': 'Confirmed phishing'},
        )
        self.assertEqual(resp.status_code, 200)
        entry.refresh_from_db()
        email.refresh_from_db()
        self.assertEqual(entry.status, 'BLOCKED')
        self.assertEqual(email.status, 'BLOCKED')

    def test_delete_lifecycle(self):
        email, entry = self._quarantine_email('lifecycle-delete')
        email_pk = email.pk
        resp = self.client.post(
            f'/api/quarantine/{entry.pk}/action/',
            {'action': 'delete'},
        )
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(Email.objects.filter(pk=email_pk).exists())
        self.assertFalse(QuarantineEntry.objects.filter(pk=entry.pk).exists())

    def test_delete_cascades_analysis_and_iocs(self):
        email, entry = self._quarantine_email('lifecycle-cascade')
        AnalysisResult.objects.create(email=email, total_score=55)
        ExtractedIOC.objects.create(
            email=email, ioc_type='URL', value='https://evil.com', severity='HIGH',
        )
        email_pk = email.pk
        self.client.post(
            f'/api/quarantine/{entry.pk}/action/',
            {'action': 'delete'},
        )
        self.assertFalse(AnalysisResult.objects.filter(email_id=email_pk).exists())
        self.assertFalse(ExtractedIOC.objects.filter(email_id=email_pk).exists())

    def test_viewer_cannot_act(self):
        viewer = User.objects.create_user(username='viewer', password='pass', role='VIEWER')
        viewer_token = Token.objects.create(user=viewer)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Token {viewer_token.key}')

        _, entry = self._quarantine_email('lifecycle-viewer')
        resp = client.post(
            f'/api/quarantine/{entry.pk}/action/',
            {'action': 'release'},
        )
        self.assertEqual(resp.status_code, 403)

    def test_invalid_action(self):
        _, entry = self._quarantine_email('lifecycle-invalid')
        resp = self.client.post(
            f'/api/quarantine/{entry.pk}/action/',
            {'action': 'nuke'},
        )
        self.assertEqual(resp.status_code, 400)

    def test_nonexistent_entry(self):
        resp = self.client.post(
            '/api/quarantine/99999/action/',
            {'action': 'release'},
        )
        self.assertEqual(resp.status_code, 404)


# ─── Quarantine Lifecycle (Template Views) ───


class QuarantineLifecycleUITest(TestCase):
    """Test quarantine workflows through template views."""

    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst', password='pass', role='ANALYST'
        )
        self.client.login(username='analyst', password='pass')

    def _quarantine_email(self, msg_id):
        email = _make_email(msg_id, verdict='SUSPICIOUS', status='QUARANTINED', score=55)
        entry = QuarantineEntry.objects.create(email=email)
        return email, entry

    def test_release_via_ui(self):
        email, entry = self._quarantine_email('ui-release')
        resp = self.client.post(
            f'/quarantine/{entry.pk}/action/',
            {'action': 'release', 'notes': 'FP'},
        )
        self.assertEqual(resp.status_code, 302)
        entry.refresh_from_db()
        email.refresh_from_db()
        self.assertEqual(entry.status, 'RELEASED')
        self.assertEqual(email.status, 'DELIVERED')

    def test_block_via_ui_adds_blacklist(self):
        email, entry = self._quarantine_email('ui-block')
        self.client.post(
            f'/quarantine/{entry.pk}/action/',
            {'action': 'block', 'notes': 'Phishing'},
        )
        entry.refresh_from_db()
        self.assertEqual(entry.status, 'BLOCKED')
        self.assertTrue(
            BlacklistEntry.objects.filter(
                entry_type='EMAIL', value=email.from_address
            ).exists()
        )

    def test_delete_via_ui(self):
        email, entry = self._quarantine_email('ui-delete')
        email_pk = email.pk
        self.client.post(
            f'/quarantine/{entry.pk}/action/',
            {'action': 'delete'},
        )
        self.assertFalse(Email.objects.filter(pk=email_pk).exists())

    def test_viewer_forbidden(self):
        viewer = User.objects.create_user(username='viewer', password='pass', role='VIEWER')
        self.client.login(username='viewer', password='pass')
        _, entry = self._quarantine_email('ui-viewer')
        resp = self.client.post(
            f'/quarantine/{entry.pk}/action/',
            {'action': 'release'},
        )
        self.assertEqual(resp.status_code, 403)

    def test_get_redirects(self):
        _, entry = self._quarantine_email('ui-get')
        resp = self.client.get(f'/quarantine/{entry.pk}/action/')
        self.assertEqual(resp.status_code, 302)


# ─── API Filter Combinations ───


class EmailListAPIFilterTest(TestCase):
    """Test API email list filtering and pagination."""

    def setUp(self):
        self.user = User.objects.create_user(username='u', password='p', role='ANALYST')
        self.token = Token.objects.create(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

        now = timezone.now()
        from datetime import timedelta
        _make_email('filter-clean-1', verdict='CLEAN', status='DELIVERED', score=5,
                     from_address='alice@company.com', received_at=now - timedelta(days=1))
        _make_email('filter-clean-2', verdict='CLEAN', status='DELIVERED', score=8,
                     from_address='bob@company.com', received_at=now - timedelta(days=2))
        _make_email('filter-susp-1', verdict='SUSPICIOUS', status='QUARANTINED', score=50,
                     from_address='phisher@evil.com', received_at=now - timedelta(days=3))
        _make_email('filter-mal-1', verdict='MALICIOUS', status='BLOCKED', score=85,
                     from_address='attacker@evil.com', received_at=now - timedelta(days=4))

    def test_no_filters(self):
        resp = self.client.get('/api/emails/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['count'], 4)

    def test_filter_by_verdict(self):
        resp = self.client.get('/api/emails/', {'verdict': 'CLEAN'})
        self.assertEqual(resp.data['count'], 2)
        for item in resp.data['results']:
            self.assertEqual(item['verdict'], 'CLEAN')

    def test_filter_by_status(self):
        resp = self.client.get('/api/emails/', {'status': 'BLOCKED'})
        self.assertEqual(resp.data['count'], 1)
        self.assertEqual(resp.data['results'][0]['status'], 'BLOCKED')

    def test_filter_by_from_address(self):
        resp = self.client.get('/api/emails/', {'from_address': 'evil'})
        self.assertEqual(resp.data['count'], 2)

    def test_filter_combined(self):
        resp = self.client.get('/api/emails/', {'verdict': 'CLEAN', 'from_address': 'alice'})
        self.assertEqual(resp.data['count'], 1)

    def test_filter_no_match(self):
        resp = self.client.get('/api/emails/', {'verdict': 'CLEAN', 'from_address': 'nonexistent'})
        self.assertEqual(resp.data['count'], 0)

    def test_date_from_filter(self):
        now = timezone.now()
        from datetime import timedelta
        date_str = (now - timedelta(days=2, hours=12)).strftime('%Y-%m-%d')
        resp = self.client.get('/api/emails/', {'date_from': date_str})
        self.assertGreaterEqual(resp.data['count'], 1)

    def test_email_detail(self):
        email = Email.objects.first()
        resp = self.client.get(f'/api/emails/{email.pk}/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['id'], email.pk)

    def test_email_detail_404(self):
        resp = self.client.get('/api/emails/99999/')
        self.assertEqual(resp.status_code, 404)


# ─── Quarantine API List & Filters ───


class QuarantineListAPITest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='u', password='p', role='ANALYST')
        self.token = Token.objects.create(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

        e1 = _make_email('q-pending', verdict='SUSPICIOUS', status='QUARANTINED')
        e2 = _make_email('q-blocked', verdict='MALICIOUS', status='BLOCKED')
        e3 = _make_email('q-delivered', verdict='CLEAN', status='DELIVERED')

        QuarantineEntry.objects.create(email=e1, status='PENDING')
        QuarantineEntry.objects.create(email=e2, status='BLOCKED')

    def test_list_shows_quarantined_and_blocked(self):
        resp = self.client.get('/api/quarantine/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['count'], 2)

    def test_filter_by_status(self):
        resp = self.client.get('/api/quarantine/', {'status': 'PENDING'})
        self.assertEqual(resp.data['count'], 1)
        self.assertEqual(resp.data['results'][0]['status'], 'PENDING')


# ─── Dashboard Stats API ───


class DashboardStatsAPITest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='u', password='p', role='VIEWER')
        self.token = Token.objects.create(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_stats_empty_db(self):
        resp = self.client.get('/api/dashboard/stats/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['total_emails'], 0)
        self.assertEqual(resp.data['clean_count'], 0)
        self.assertIsNone(resp.data['last_sync'])

    def test_stats_with_data(self):
        _make_email('stats-1', verdict='CLEAN')
        _make_email('stats-2', verdict='SUSPICIOUS')
        _make_email('stats-3', verdict='MALICIOUS')
        _make_email('stats-4', verdict=None, status='PENDING')
        MaliciousHash.objects.create(
            sha256_hash='a' * 64, malware_family='Test', source='MANUAL', severity='HIGH'
        )
        MaliciousDomain.objects.create(domain='evil.com', category='phishing', source='MANUAL')

        resp = self.client.get('/api/dashboard/stats/')
        self.assertEqual(resp.data['total_emails'], 4)
        self.assertEqual(resp.data['clean_count'], 1)
        self.assertEqual(resp.data['suspicious_count'], 1)
        self.assertEqual(resp.data['malicious_count'], 1)
        self.assertEqual(resp.data['pending_count'], 1)
        self.assertEqual(resp.data['ti_hashes'], 1)
        self.assertEqual(resp.data['ti_domains'], 1)

    def test_unauthenticated_rejected(self):
        client = APIClient()
        resp = client.get('/api/dashboard/stats/')
        self.assertEqual(resp.status_code, 403)
