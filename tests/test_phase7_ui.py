"""
Phase 7 tests: Threat Intel page, Reports/Export, IOC list, User Management.
25+ tests covering AC-701 through AC-725.
"""
import json
import uuid
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from emails.models import Email, ExtractedIOC
from reports.models import IOCExport, Report
from threat_intel.models import (
    BlacklistEntry, MaliciousDomain, MaliciousHash, MaliciousIP,
    WhitelistEntry, YaraRule,
)


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


class Phase7BaseTestCase(TestCase):
    """Base class with common setUp for all Phase 7 UI tests."""

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

        # 3 emails with different verdicts
        self.clean_email = _make_email(verdict='CLEAN', status='DELIVERED')
        self.suspicious_email = _make_email(
            verdict='SUSPICIOUS', status='DELIVERED', score=40,
            subject='Suspicious activity',
        )
        self.malicious_email = _make_email(
            verdict='MALICIOUS', status='QUARANTINED', score=85,
            subject='Malicious payload',
        )

        # 2 ExtractedIOCs
        self.ioc_url = ExtractedIOC.objects.create(
            email=self.malicious_email, ioc_type='URL',
            value='http://evil.com/phish', severity='HIGH',
            source_checker='URLhaus',
        )
        self.ioc_hash = ExtractedIOC.objects.create(
            email=self.suspicious_email, ioc_type='HASH',
            value='abc123def456' * 5, severity='CRITICAL',
            source_checker='MalwareBazaar',
        )

        # TI data
        self.mal_hash = MaliciousHash.objects.create(
            sha256_hash='a' * 64, malware_family='Emotet', source='MALWAREBAZAAR',
        )
        self.mal_domain = MaliciousDomain.objects.create(
            domain='evil-domain.com', category='phishing', source='URLHAUS',
        )
        self.mal_ip = MaliciousIP.objects.create(
            ip_address='10.0.0.1', category='spam', source='ABUSEIPDB', abuse_score=90,
        )

        # Whitelist / Blacklist
        self.whitelist_entry = WhitelistEntry.objects.create(
            entry_type='DOMAIN', value='safe.example.com',
            reason='Trusted partner', added_by=self.admin,
        )
        self.blacklist_entry = BlacklistEntry.objects.create(
            entry_type='EMAIL', value='bad@evil.com',
            reason='Known phisher', added_by=self.admin,
        )


# ===========================================================================
# 1. Threat Intel Tests
# ===========================================================================
class ThreatIntelTests(Phase7BaseTestCase):
    """Threat Intel page views and actions."""

    def test_ac_701_ti_page_returns_200(self):
        """AC-701: Admin GET /threat-intel/ returns 200."""
        self.client.force_login(self.admin)
        response = self.client.get('/threat-intel/')
        self.assertEqual(response.status_code, 200)

    def test_ac_702_ti_page_has_stat_counts(self):
        """AC-702: TI page context contains hash_count, domain_count, ip_count, yara_active_count."""
        self.client.force_login(self.analyst)
        response = self.client.get('/threat-intel/')
        self.assertEqual(response.context['hash_count'], 1)
        self.assertEqual(response.context['domain_count'], 1)
        self.assertEqual(response.context['ip_count'], 1)
        self.assertEqual(response.context['yara_active_count'], 0)

    @patch('threat_intel.tasks.sync_urlhaus_task')
    @patch('threat_intel.tasks.sync_malwarebazaar_task')
    def test_ac_703_ti_sync_admin_only(self, mock_mb, mock_uh):
        """AC-703: Admin POST /threat-intel/sync/ redirects 302; analyst POST returns 403."""
        # Admin can sync
        self.client.force_login(self.admin)
        response = self.client.post('/threat-intel/sync/')
        self.assertEqual(response.status_code, 302)
        mock_mb.delay.assert_called_once()
        mock_uh.delay.assert_called_once()

        # Analyst cannot sync
        self.client.force_login(self.analyst)
        response = self.client.post('/threat-intel/sync/')
        self.assertEqual(response.status_code, 403)

    def test_ac_704_whitelist_add(self):
        """AC-704: Admin POST /threat-intel/whitelist/add/ creates WhitelistEntry."""
        self.client.force_login(self.admin)
        count_before = WhitelistEntry.objects.count()
        response = self.client.post('/threat-intel/whitelist/add/', {
            'entry_type': 'DOMAIN',
            'value': 'safe.com',
            'reason': 'Verified safe',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(WhitelistEntry.objects.count(), count_before + 1)
        self.assertTrue(WhitelistEntry.objects.filter(value='safe.com').exists())

    def test_ac_705_whitelist_remove(self):
        """AC-705: Admin POST /threat-intel/whitelist/<pk>/remove/ deletes entry."""
        self.client.force_login(self.admin)
        pk = self.whitelist_entry.pk
        response = self.client.post(f'/threat-intel/whitelist/{pk}/remove/')
        self.assertEqual(response.status_code, 302)
        self.assertFalse(WhitelistEntry.objects.filter(pk=pk).exists())

    def test_ac_706_blacklist_add_viewer_forbidden(self):
        """AC-706: Viewer POST /threat-intel/blacklist/add/ returns 403."""
        self.client.force_login(self.viewer)
        response = self.client.post('/threat-intel/blacklist/add/', {
            'entry_type': 'DOMAIN',
            'value': 'block-this.com',
            'reason': 'Malicious',
        })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(BlacklistEntry.objects.filter(value='block-this.com').exists())


# ===========================================================================
# 2. Reports Tests
# ===========================================================================
class ReportsTests(Phase7BaseTestCase):
    """Reports page and export views."""

    def test_ac_707_reports_page_returns_200(self):
        """AC-707: Authenticated user GET /reports/ returns 200."""
        self.client.force_login(self.analyst)
        response = self.client.get('/reports/')
        self.assertEqual(response.status_code, 200)

    def test_ac_708_email_summary_export_csv(self):
        """AC-708: Admin GET /reports/export/emails/ returns 200 with text/csv content type and correct headers."""
        self.client.force_login(self.admin)
        response = self.client.get('/reports/export/emails/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        content = response.content.decode()
        first_line = content.split('\n')[0].strip()
        self.assertIn('ID', first_line)
        self.assertIn('Message ID', first_line)
        self.assertIn('Verdict', first_line)
        self.assertIn('Score', first_line)

    def test_ac_709_email_summary_export_creates_report_record(self):
        """AC-709: After export, Report.objects.count() increases by 1."""
        self.client.force_login(self.admin)
        count_before = Report.objects.count()
        self.client.get('/reports/export/emails/')
        self.assertEqual(Report.objects.count(), count_before + 1)
        report = Report.objects.latest('created_at')
        self.assertEqual(report.report_type, 'EMAIL_SUMMARY')
        self.assertEqual(report.output_format, 'CSV')
        self.assertEqual(report.generated_by, self.admin)
        self.assertEqual(report.record_count, 3)  # 3 emails in setUp

    def test_ac_710_ioc_export_csv(self):
        """AC-710: Analyst GET /reports/export/iocs/ returns 200 with CSV content."""
        self.client.force_login(self.analyst)
        response = self.client.get('/reports/export/iocs/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        content = response.content.decode()
        self.assertIn('IOC Type', content)
        self.assertIn('Value', content)

    def test_ac_711_ti_stats_export_json_admin_only(self):
        """AC-711: Admin GET /reports/export/ti-stats/ returns 200 JSON; analyst returns 403."""
        # Admin can export
        self.client.force_login(self.admin)
        response = self.client.get('/reports/export/ti-stats/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        data = json.loads(response.content)
        self.assertIn('malicious_hashes', data)
        self.assertIn('malicious_domains', data)
        self.assertEqual(data['malicious_hashes']['total'], 1)

        # Analyst cannot export TI stats
        self.client.force_login(self.analyst)
        response = self.client.get('/reports/export/ti-stats/')
        self.assertEqual(response.status_code, 403)

    def test_ac_712_export_viewer_forbidden(self):
        """AC-712: Viewer GET /reports/export/emails/ returns 403."""
        self.client.force_login(self.viewer)
        response = self.client.get('/reports/export/emails/')
        self.assertEqual(response.status_code, 403)


# ===========================================================================
# 3. IOC List Tests
# ===========================================================================
class IOCListTests(Phase7BaseTestCase):
    """IOC list page with filtering."""

    def test_ac_713_ioc_list_returns_200(self):
        """AC-713: Authenticated user GET /iocs/ returns 200."""
        self.client.force_login(self.analyst)
        response = self.client.get('/iocs/')
        self.assertEqual(response.status_code, 200)

    def test_ac_714_ioc_list_filter_type(self):
        """AC-714: GET /iocs/?ioc_type=URL returns only URL IOCs."""
        self.client.force_login(self.analyst)
        response = self.client.get('/iocs/?ioc_type=URL')
        page_obj = response.context['page_obj']
        for ioc in page_obj:
            self.assertEqual(ioc.ioc_type, 'URL')
        self.assertEqual(len(page_obj.object_list), 1)

    def test_ac_715_ioc_list_filter_severity(self):
        """AC-715: GET /iocs/?severity=HIGH returns only HIGH severity IOCs."""
        self.client.force_login(self.analyst)
        response = self.client.get('/iocs/?severity=HIGH')
        page_obj = response.context['page_obj']
        for ioc in page_obj:
            self.assertEqual(ioc.severity, 'HIGH')
        self.assertEqual(len(page_obj.object_list), 1)

    def test_ac_716_ioc_list_has_export_button_analyst(self):
        """AC-716: Analyst sees can_export=True in IOC list context."""
        self.client.force_login(self.analyst)
        response = self.client.get('/iocs/')
        self.assertTrue(response.context['can_export'])


# ===========================================================================
# 4. User Management Tests
# ===========================================================================
class UserManagementTests(Phase7BaseTestCase):
    """User management page and actions."""

    def test_ac_717_users_page_admin_only(self):
        """AC-717: Admin GET /users/ returns 200; analyst GET returns 403."""
        self.client.force_login(self.admin)
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, 200)

        self.client.force_login(self.analyst)
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, 403)

    def test_ac_718_user_add(self):
        """AC-718: Admin POST /users/add/ creates new user with given role."""
        self.client.force_login(self.admin)
        count_before = User.objects.count()
        response = self.client.post('/users/add/', {
            'username': 'newuser',
            'password': 'securepass123',
            'role': 'ANALYST',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(User.objects.count(), count_before + 1)
        new_user = User.objects.get(username='newuser')
        self.assertEqual(new_user.role, 'ANALYST')

    def test_ac_719_user_add_duplicate_rejected(self):
        """AC-719: POST with existing username does not create new user, shows error."""
        self.client.force_login(self.admin)
        count_before = User.objects.count()
        response = self.client.post('/users/add/', {
            'username': 'analyst_user',  # already exists
            'password': 'pass123',
            'role': 'VIEWER',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(User.objects.count(), count_before)

    def test_ac_720_user_edit_role(self):
        """AC-720: Admin POST /users/<pk>/edit-role/ changes target user role."""
        self.client.force_login(self.admin)
        response = self.client.post(f'/users/{self.analyst.pk}/edit-role/', {
            'role': 'ADMIN',
        })
        self.assertEqual(response.status_code, 302)
        self.analyst.refresh_from_db()
        self.assertEqual(self.analyst.role, 'ADMIN')

    def test_ac_721_user_self_demotion_blocked(self):
        """AC-721: Admin POST to edit own role returns error, role unchanged."""
        self.client.force_login(self.admin)
        response = self.client.post(f'/users/{self.admin.pk}/edit-role/', {
            'role': 'VIEWER',
        })
        self.assertEqual(response.status_code, 302)
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, 'ADMIN')

    def test_ac_722_user_toggle_active(self):
        """AC-722: Admin POST /users/<pk>/toggle-active/ deactivates viewer."""
        self.client.force_login(self.admin)
        self.assertTrue(self.viewer.is_active)
        response = self.client.post(f'/users/{self.viewer.pk}/toggle-active/')
        self.assertEqual(response.status_code, 302)
        self.viewer.refresh_from_db()
        self.assertFalse(self.viewer.is_active)

    def test_ac_723_user_self_deactivation_blocked(self):
        """AC-723: Admin POST to toggle own active returns error, still active."""
        self.client.force_login(self.admin)
        response = self.client.post(f'/users/{self.admin.pk}/toggle-active/')
        self.assertEqual(response.status_code, 302)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)


# ===========================================================================
# 5. Auth Redirect Tests
# ===========================================================================
class AuthRedirectTests(Phase7BaseTestCase):
    """Anonymous users must be redirected to login."""

    def test_ac_724_ti_page_redirects_anonymous(self):
        """AC-724: GET /threat-intel/ as anonymous redirects to login."""
        response = self.client.get('/threat-intel/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)

    def test_ac_725_users_page_redirects_anonymous(self):
        """AC-725: GET /users/ as anonymous redirects to login."""
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)
