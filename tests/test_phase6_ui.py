"""
Phase 6 tests: Dashboard UI template views — auth, dashboard, email list/detail,
quarantine actions, and role-based access control.
"""
import uuid

from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from emails.models import AnalysisResult, Email, QuarantineEntry
from threat_intel.models import BlacklistEntry


def _make_email(verdict='CLEAN', status='DELIVERED', **kwargs):
    """Factory helper for Email instances."""
    defaults = {
        'message_id': f'<{uuid.uuid4()}@test.com>',
        'from_address': 'sender@example.com',
        'from_display_name': 'Sender',
        'subject': 'Test email',
        'body_text': 'Hello world',
        'received_at': timezone.now(),
        'verdict': verdict,
        'status': status,
        'score': 0,
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


class Phase6UIBaseTestCase(TestCase):
    """Base class with common setUp for all Phase 6 UI tests."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin_user', password='testpass123', role='ADMIN',
        )
        self.analyst = User.objects.create_user(
            username='analyst_user', password='testpass123', role='ANALYST',
        )
        self.viewer = User.objects.create_user(
            username='viewer_user', password='testpass123', role='VIEWER',
        )
        # Sample emails covering all verdicts
        self.clean_email = _make_email(verdict='CLEAN', status='DELIVERED')
        self.suspicious_email = _make_email(
            verdict='SUSPICIOUS', status='DELIVERED', score=40,
            subject='Suspicious activity',
        )
        self.malicious_email = _make_email(
            verdict='MALICIOUS', status='QUARANTINED', score=85,
            subject='Malicious payload',
        )
        # Analysis result for the malicious email
        self.analysis = AnalysisResult.objects.create(
            email=self.malicious_email,
            preprocess_score=15,
            spf_result='fail',
            dkim_result='fail',
            dmarc_result='fail',
            keyword_score=10,
            keywords_matched=['verify your account', 'urgent action required'],
            url_score=20,
            url_findings=[{'url': 'http://evil.com', 'source': 'URLhaus'}],
            attachment_score=30,
            attachment_findings=[{'file': 'malware.exe', 'match': 'MalwareBazaar'}],
            chain_score=10,
            chain_findings={'hops': 5, 'anomaly': 'private_ip'},
            total_score=85,
            pipeline_duration_ms=1200,
        )
        # Quarantine entry for the malicious email
        self.quarantine_entry = QuarantineEntry.objects.create(
            email=self.malicious_email,
            status='PENDING',
        )


# ===========================================================================
# 1. Auth Redirect Tests
# ===========================================================================
class AuthRedirectTests(Phase6UIBaseTestCase):
    """Anonymous users must be redirected to the login page."""

    def test_ac_601_dashboard_redirects_anonymous(self):
        """AC-601: GET / as anonymous redirects to /accounts/login/."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)

    def test_ac_602_email_list_redirects_anonymous(self):
        """AC-602: GET /emails/ as anonymous redirects to login."""
        response = self.client.get('/emails/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)

    def test_ac_603_quarantine_redirects_anonymous(self):
        """AC-603: GET /quarantine/ as anonymous redirects to login."""
        response = self.client.get('/quarantine/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)


# ===========================================================================
# 2. Login Page Tests
# ===========================================================================
class LoginPageTests(Phase6UIBaseTestCase):
    """Login page must be accessible."""

    def test_ac_604_login_page_returns_200(self):
        """AC-604: GET /accounts/login/ returns 200."""
        response = self.client.get('/accounts/login/')
        self.assertEqual(response.status_code, 200)


# ===========================================================================
# 3. Dashboard Tests
# ===========================================================================
class DashboardTests(Phase6UIBaseTestCase):
    """Dashboard view for authenticated users."""

    def test_ac_605_dashboard_returns_200(self):
        """AC-605: Logged-in user can access dashboard."""
        self.client.force_login(self.analyst)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_ac_606_dashboard_contains_stats(self):
        """AC-606: Dashboard context includes 'stats' with correct counts."""
        self.client.force_login(self.analyst)
        response = self.client.get('/')
        stats = response.context['stats']
        self.assertEqual(stats['total_emails'], 3)
        self.assertEqual(stats['clean_count'], 1)
        self.assertEqual(stats['suspicious_count'], 1)
        self.assertEqual(stats['malicious_count'], 1)

    def test_ac_607_dashboard_shows_recent_alerts(self):
        """AC-607: Dashboard context has recent_alerts with suspicious/malicious emails."""
        self.client.force_login(self.analyst)
        response = self.client.get('/')
        alerts = list(response.context['recent_alerts'])
        alert_ids = [e.pk for e in alerts]
        self.assertIn(self.suspicious_email.pk, alert_ids)
        self.assertIn(self.malicious_email.pk, alert_ids)
        # Clean email should NOT appear in alerts
        self.assertNotIn(self.clean_email.pk, alert_ids)


# ===========================================================================
# 4. Email List Tests
# ===========================================================================
class EmailListTests(Phase6UIBaseTestCase):
    """Email list view with filtering and pagination."""

    def test_ac_608_email_list_returns_200(self):
        """AC-608: GET /emails/ returns 200 for authenticated user."""
        self.client.force_login(self.analyst)
        response = self.client.get('/emails/')
        self.assertEqual(response.status_code, 200)

    def test_ac_609_email_list_filter_verdict(self):
        """AC-609: Filtering by verdict=CLEAN returns only CLEAN emails."""
        self.client.force_login(self.analyst)
        response = self.client.get('/emails/?verdict=CLEAN')
        page_obj = response.context['page_obj']
        for email in page_obj:
            self.assertEqual(email.verdict, 'CLEAN')
        self.assertEqual(len(page_obj.object_list), 1)

    def test_ac_610_email_list_filter_status(self):
        """AC-610: Filtering by status=QUARANTINED returns only QUARANTINED emails."""
        self.client.force_login(self.analyst)
        response = self.client.get('/emails/?status=QUARANTINED')
        page_obj = response.context['page_obj']
        for email in page_obj:
            self.assertEqual(email.status, 'QUARANTINED')
        self.assertEqual(len(page_obj.object_list), 1)

    def test_ac_611_email_list_pagination(self):
        """AC-611: Email list paginates at 20 items per page."""
        self.client.force_login(self.analyst)
        # Create 25 additional emails (3 already exist from setUp)
        for i in range(25):
            _make_email(subject=f'Bulk email {i}')
        response = self.client.get('/emails/')
        page_obj = response.context['page_obj']
        self.assertTrue(page_obj.has_next())
        self.assertEqual(len(page_obj.object_list), 20)
        # Page 2 should have the rest
        response2 = self.client.get('/emails/?page=2')
        page_obj2 = response2.context['page_obj']
        self.assertEqual(len(page_obj2.object_list), 8)  # 28 total - 20 = 8


# ===========================================================================
# 5. Email Detail Tests
# ===========================================================================
class EmailDetailTests(Phase6UIBaseTestCase):
    """Email detail view."""

    def test_ac_612_email_detail_returns_200(self):
        """AC-612: GET /emails/<pk>/ returns 200."""
        self.client.force_login(self.analyst)
        response = self.client.get(f'/emails/{self.malicious_email.pk}/')
        self.assertEqual(response.status_code, 200)

    def test_ac_613_email_detail_404(self):
        """AC-613: GET /emails/99999/ returns 404."""
        self.client.force_login(self.analyst)
        response = self.client.get('/emails/99999/')
        self.assertEqual(response.status_code, 404)

    def test_ac_614_email_detail_has_analysis(self):
        """AC-614: Email detail context contains email with analysis data."""
        self.client.force_login(self.analyst)
        response = self.client.get(f'/emails/{self.malicious_email.pk}/')
        email_ctx = response.context['email']
        self.assertEqual(email_ctx.pk, self.malicious_email.pk)
        self.assertTrue(hasattr(email_ctx, 'analysis'))
        self.assertEqual(email_ctx.analysis.total_score, 85)

    def test_ac_615_email_detail_raw_tab_viewer(self):
        """AC-615: Viewer gets can_view_raw=False in email detail context."""
        self.client.force_login(self.viewer)
        response = self.client.get(f'/emails/{self.malicious_email.pk}/')
        self.assertFalse(response.context['can_view_raw'])

    def test_ac_616_email_detail_raw_tab_analyst(self):
        """AC-616: Analyst gets can_view_raw=True in email detail context."""
        self.client.force_login(self.analyst)
        response = self.client.get(f'/emails/{self.malicious_email.pk}/')
        self.assertTrue(response.context['can_view_raw'])


# ===========================================================================
# 6. Quarantine Tests
# ===========================================================================
class QuarantineTests(Phase6UIBaseTestCase):
    """Quarantine list and action views."""

    def test_ac_617_quarantine_list_returns_200(self):
        """AC-617: GET /quarantine/ returns 200 for authenticated user."""
        self.client.force_login(self.analyst)
        response = self.client.get('/quarantine/')
        self.assertEqual(response.status_code, 200)

    def test_ac_618_quarantine_action_release(self):
        """AC-618: POST release sets entry.status=RELEASED and email.status=DELIVERED."""
        self.client.force_login(self.analyst)
        url = f'/quarantine/{self.quarantine_entry.pk}/action/'
        response = self.client.post(url, {'action': 'release', 'notes': 'False positive'})
        self.assertEqual(response.status_code, 302)  # redirect after action
        self.quarantine_entry.refresh_from_db()
        self.malicious_email.refresh_from_db()
        self.assertEqual(self.quarantine_entry.status, 'RELEASED')
        self.assertEqual(self.quarantine_entry.action, 'release')
        self.assertEqual(self.quarantine_entry.reviewer, self.analyst)
        self.assertIsNotNone(self.quarantine_entry.reviewed_at)
        self.assertEqual(self.quarantine_entry.notes, 'False positive')
        self.assertEqual(self.malicious_email.status, 'DELIVERED')

    def test_ac_619_quarantine_action_block(self):
        """AC-619: POST block sets entry.status=BLOCKED, email.status=BLOCKED, creates BlacklistEntry."""
        self.client.force_login(self.admin)
        url = f'/quarantine/{self.quarantine_entry.pk}/action/'
        response = self.client.post(url, {'action': 'block', 'notes': 'Confirmed phishing'})
        self.assertEqual(response.status_code, 302)
        self.quarantine_entry.refresh_from_db()
        self.malicious_email.refresh_from_db()
        self.assertEqual(self.quarantine_entry.status, 'BLOCKED')
        self.assertEqual(self.malicious_email.status, 'BLOCKED')
        # BlacklistEntry should have been created for the sender
        bl = BlacklistEntry.objects.filter(
            entry_type='EMAIL', value=self.malicious_email.from_address
        )
        self.assertTrue(bl.exists())
        self.assertEqual(bl.first().added_by, self.admin)

    def test_ac_620_quarantine_action_viewer_forbidden(self):
        """AC-620: Viewer POST to quarantine action returns 403."""
        self.client.force_login(self.viewer)
        url = f'/quarantine/{self.quarantine_entry.pk}/action/'
        response = self.client.post(url, {'action': 'release'})
        self.assertEqual(response.status_code, 403)


# ===========================================================================
# 7. Role-Based UI Tests
# ===========================================================================
class RoleBasedUITests(Phase6UIBaseTestCase):
    """Sidebar and role-gated UI elements."""

    def test_ac_621_admin_sees_admin_sidebar(self):
        """AC-621: Admin user sees 'Django Admin' link in sidebar."""
        self.client.force_login(self.admin)
        response = self.client.get('/')
        content = response.content.decode()
        self.assertIn('Django Admin', content)

    def test_ac_622_viewer_no_admin_sidebar(self):
        """AC-622: Viewer does NOT see 'Django Admin' link in sidebar."""
        self.client.force_login(self.viewer)
        response = self.client.get('/')
        content = response.content.decode()
        self.assertNotIn('Django Admin', content)

    def test_ac_623_quarantine_can_act_false_for_viewer(self):
        """AC-623: Viewer quarantine context has can_act=False."""
        self.client.force_login(self.viewer)
        response = self.client.get('/quarantine/')
        self.assertFalse(response.context['can_act'])

    def test_ac_624_quarantine_can_act_true_for_analyst(self):
        """AC-624: Analyst quarantine context has can_act=True."""
        self.client.force_login(self.analyst)
        response = self.client.get('/quarantine/')
        self.assertTrue(response.context['can_act'])
