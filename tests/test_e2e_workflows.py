"""
End-to-end workflow tests using Django test client.
Tests full user journeys: login → navigate → act → verify.
"""
import csv
import json
from io import StringIO

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from emails.models import AnalysisResult, Email, EmailAttachment, ExtractedIOC, QuarantineEntry
from reports.models import Report, IOCExport, ScheduledReport
from threat_intel.models import (
    BlacklistEntry, MaliciousDomain, MaliciousHash, MaliciousIP,
    WhitelistEntry, YaraRule,
)

User = get_user_model()


def _seed_data(admin_user):
    """Create a small but representative dataset."""
    now = timezone.now()
    from datetime import timedelta

    emails = []
    for i, (verdict, status, score) in enumerate([
        ('CLEAN', 'DELIVERED', 5),
        ('CLEAN', 'DELIVERED', 8),
        ('SUSPICIOUS', 'QUARANTINED', 45),
        ('SUSPICIOUS', 'QUARANTINED', 52),
        ('MALICIOUS', 'BLOCKED', 85),
    ]):
        e = Email.objects.create(
            message_id=f'e2e-{i}',
            from_address=f'sender{i}@example.com',
            subject=f'E2E email {i}',
            body_text=f'Body of email {i}',
            received_at=now - timedelta(hours=i),
            to_addresses=['me@example.com'],
            verdict=verdict, status=status, score=score,
        )
        AnalysisResult.objects.create(
            email=e, preprocess_score=score // 2, keyword_score=score // 4,
            total_score=score, spf_result='pass' if verdict == 'CLEAN' else 'fail',
            dkim_result='pass' if verdict == 'CLEAN' else 'fail',
            dmarc_result='pass' if verdict == 'CLEAN' else 'fail',
        )
        if status in ('QUARANTINED', 'BLOCKED'):
            QuarantineEntry.objects.create(email=e)
        if verdict == 'MALICIOUS':
            EmailAttachment.objects.create(
                email=e, filename='payload.exe', content_type='application/x-msdownload',
                size_bytes=4096, sha256_hash='e' * 64, md5_hash='f' * 32,
                is_dangerous_ext=True,
            )
            ExtractedIOC.objects.create(
                email=e, ioc_type='HASH', value='e' * 64, severity='CRITICAL',
                source_checker='attachment_checker',
            )
        emails.append(e)

    MaliciousHash.objects.create(sha256_hash='a' * 64, malware_family='TestRAT', source='MANUAL', severity='HIGH')
    MaliciousDomain.objects.create(domain='evil.com', category='phishing', source='MANUAL')
    WhitelistEntry.objects.create(entry_type='DOMAIN', value='company.com', reason='Internal', added_by=admin_user)

    return emails


class LoginWorkflowTest(TestCase):
    """Test authentication flows."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')

    def test_unauthenticated_redirects_to_login(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp.url)

    def test_login_success(self):
        resp = self.client.post('/accounts/login/', {'username': 'admin', 'password': 'pass'})
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('login', resp.url)

    def test_login_failure(self):
        resp = self.client.post('/accounts/login/', {'username': 'admin', 'password': 'wrong'})
        self.assertEqual(resp.status_code, 200)  # Re-renders login page

    def test_logout(self):
        self.client.login(username='admin', password='pass')
        resp = self.client.post('/accounts/logout/')
        self.assertEqual(resp.status_code, 302)
        # After logout, dashboard should redirect to login
        resp2 = self.client.get('/')
        self.assertIn('login', resp2.url)


class DashboardWorkflowTest(TestCase):
    """Test dashboard page rendering with data."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.client.login(username='admin', password='pass')
        self.emails = _seed_data(self.admin)

    def test_dashboard_loads(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Dashboard')

    def test_dashboard_shows_stats(self):
        resp = self.client.get('/')
        # Template should show counts
        content = resp.content.decode()
        self.assertIn('5', content)  # total_emails=5

    def test_dashboard_shows_recent_alerts(self):
        resp = self.client.get('/')
        content = resp.content.decode()
        # Should show suspicious/malicious emails
        self.assertIn('E2E email', content)


class EmailListWorkflowTest(TestCase):
    """Test email list page with filters."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.client.login(username='admin', password='pass')
        self.emails = _seed_data(self.admin)

    def test_email_list_loads(self):
        resp = self.client.get('/emails/')
        self.assertEqual(resp.status_code, 200)

    def test_filter_by_verdict(self):
        resp = self.client.get('/emails/', {'verdict': 'CLEAN'})
        self.assertEqual(resp.status_code, 200)
        for email in resp.context['page_obj']:
            self.assertEqual(email.verdict, 'CLEAN')

    def test_filter_by_status(self):
        resp = self.client.get('/emails/', {'status': 'QUARANTINED'})
        self.assertEqual(resp.status_code, 200)
        for email in resp.context['page_obj']:
            self.assertEqual(email.status, 'QUARANTINED')

    def test_filter_by_from_address(self):
        resp = self.client.get('/emails/', {'from_address': 'sender0'})
        self.assertEqual(resp.status_code, 200)
        for email in resp.context['page_obj']:
            self.assertIn('sender0', email.from_address)


class EmailDetailWorkflowTest(TestCase):
    """Test email detail page."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.client.login(username='admin', password='pass')
        self.emails = _seed_data(self.admin)

    def test_detail_page_loads(self):
        email = self.emails[0]
        resp = self.client.get(f'/emails/{email.pk}/')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, email.subject)

    def test_detail_shows_analysis(self):
        email = self.emails[4]  # MALICIOUS
        resp = self.client.get(f'/emails/{email.pk}/')
        self.assertEqual(resp.status_code, 200)
        # Admin/analyst can see raw analysis JSON
        self.assertTrue(resp.context['can_view_raw'])
        self.assertIsNotNone(resp.context['analysis_json'])

    def test_detail_viewer_no_raw(self):
        viewer = User.objects.create_user(username='viewer', password='pass', role='VIEWER')
        self.client.login(username='viewer', password='pass')
        email = self.emails[0]
        resp = self.client.get(f'/emails/{email.pk}/')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context['can_view_raw'])

    def test_detail_404(self):
        resp = self.client.get('/emails/99999/')
        self.assertEqual(resp.status_code, 404)


class QuarantineWorkflowTest(TestCase):
    """Test full quarantine UI workflow."""

    def setUp(self):
        self.analyst = User.objects.create_user(username='analyst', password='pass', role='ANALYST')
        self.client.login(username='analyst', password='pass')
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.emails = _seed_data(self.admin)

    def test_quarantine_list_loads(self):
        resp = self.client.get('/quarantine/')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context['can_act'])

    def test_release_and_verify(self):
        entry = QuarantineEntry.objects.filter(status='PENDING').first()
        self.assertIsNotNone(entry)

        # Release
        resp = self.client.post(
            f'/quarantine/{entry.pk}/action/',
            {'action': 'release', 'notes': 'Confirmed safe'},
        )
        self.assertEqual(resp.status_code, 302)

        # Verify the entry is no longer in the quarantine list
        entry.refresh_from_db()
        self.assertEqual(entry.status, 'RELEASED')
        self.assertEqual(entry.email.status, 'DELIVERED')

        # Quarantine list should not show released entries
        resp = self.client.get('/quarantine/')
        quarantine_emails = [
            e.email.message_id for e in resp.context['page_obj']
        ]
        self.assertNotIn(entry.email.message_id, quarantine_emails)

    def test_block_and_verify_blacklist(self):
        entry = QuarantineEntry.objects.filter(status='PENDING').first()
        from_addr = entry.email.from_address

        self.client.post(
            f'/quarantine/{entry.pk}/action/',
            {'action': 'block', 'notes': 'Phishing confirmed'},
        )

        # Verify blacklist entry was created
        self.assertTrue(
            BlacklistEntry.objects.filter(entry_type='EMAIL', value=from_addr).exists()
        )

    def test_viewer_sees_quarantine_but_cannot_act(self):
        viewer = User.objects.create_user(username='viewer', password='pass', role='VIEWER')
        self.client.login(username='viewer', password='pass')

        resp = self.client.get('/quarantine/')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context['can_act'])


class IOCListWorkflowTest(TestCase):
    """Test IOC list page."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.client.login(username='admin', password='pass')
        _seed_data(self.admin)

    def test_ioc_list_loads(self):
        resp = self.client.get('/iocs/')
        self.assertEqual(resp.status_code, 200)

    def test_ioc_filter_by_type(self):
        resp = self.client.get('/iocs/', {'ioc_type': 'HASH'})
        self.assertEqual(resp.status_code, 200)
        for ioc in resp.context['page_obj']:
            self.assertEqual(ioc.ioc_type, 'HASH')


class ReportExportWorkflowTest(TestCase):
    """Test export functionality end-to-end."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.analyst = User.objects.create_user(username='analyst', password='pass', role='ANALYST')
        _seed_data(self.admin)

    def test_email_csv_export(self):
        self.client.login(username='analyst', password='pass')
        resp = self.client.get('/reports/export/emails/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'text/csv')
        self.assertIn('attachment', resp['Content-Disposition'])

        # Parse CSV content
        content = resp.content.decode()
        reader = csv.reader(StringIO(content))
        rows = list(reader)
        self.assertEqual(rows[0][0], 'ID')  # Header
        self.assertEqual(len(rows), 6)  # Header + 5 emails

        # Verify audit record created
        self.assertTrue(Report.objects.filter(report_type='EMAIL_SUMMARY').exists())

    def test_email_csv_with_verdict_filter(self):
        self.client.login(username='analyst', password='pass')
        resp = self.client.get('/reports/export/emails/', {'verdict': 'MALICIOUS'})
        self.assertEqual(resp.status_code, 200)
        content = resp.content.decode()
        reader = csv.reader(StringIO(content))
        rows = list(reader)
        self.assertEqual(len(rows), 2)  # Header + 1 malicious

    def test_ioc_csv_export(self):
        self.client.login(username='analyst', password='pass')
        resp = self.client.get('/reports/export/iocs/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'text/csv')
        self.assertTrue(IOCExport.objects.exists())

    def test_ti_stats_json_export(self):
        self.client.login(username='admin', password='pass')
        resp = self.client.get('/reports/export/ti-stats/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/json')
        data = json.loads(resp.content)
        self.assertIn('malicious_hashes', data)
        self.assertIn('malicious_domains', data)
        self.assertIn('yara_rules', data)

    def test_ti_stats_analyst_forbidden(self):
        self.client.login(username='analyst', password='pass')
        resp = self.client.get('/reports/export/ti-stats/')
        self.assertEqual(resp.status_code, 403)

    def test_export_viewer_forbidden(self):
        viewer = User.objects.create_user(username='viewer', password='pass', role='VIEWER')
        self.client.login(username='viewer', password='pass')
        resp = self.client.get('/reports/export/emails/')
        self.assertEqual(resp.status_code, 403)

    def test_report_list_page(self):
        self.client.login(username='admin', password='pass')
        resp = self.client.get('/reports/')
        self.assertEqual(resp.status_code, 200)


class ThreatIntelWorkflowTest(TestCase):
    """Test threat intelligence management UI."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.client.login(username='admin', password='pass')
        _seed_data(self.admin)

    def test_ti_page_loads(self):
        resp = self.client.get('/threat-intel/')
        self.assertEqual(resp.status_code, 200)

    def test_add_whitelist_entry(self):
        resp = self.client.post('/threat-intel/whitelist/add/', {
            'entry_type': 'DOMAIN',
            'value': 'trusted.com',
            'reason': 'Trusted partner',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(WhitelistEntry.objects.filter(value='trusted.com').exists())

    def test_add_whitelist_invalid_type(self):
        resp = self.client.post('/threat-intel/whitelist/add/', {
            'entry_type': 'INVALID',
            'value': 'test.com',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(WhitelistEntry.objects.filter(value='test.com').exists())

    def test_add_whitelist_empty_value(self):
        before = WhitelistEntry.objects.count()
        self.client.post('/threat-intel/whitelist/add/', {
            'entry_type': 'DOMAIN',
            'value': '',
        })
        self.assertEqual(WhitelistEntry.objects.count(), before)

    def test_remove_whitelist_entry(self):
        entry = WhitelistEntry.objects.first()
        self.assertIsNotNone(entry)
        resp = self.client.post(f'/threat-intel/whitelist/{entry.pk}/remove/')
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(WhitelistEntry.objects.filter(pk=entry.pk).exists())

    def test_add_blacklist_entry(self):
        self.client.post('/threat-intel/blacklist/add/', {
            'entry_type': 'DOMAIN',
            'value': 'bad-domain.com',
            'reason': 'Known phishing',
        })
        self.assertTrue(BlacklistEntry.objects.filter(value='bad-domain.com').exists())

    def test_remove_blacklist_entry(self):
        entry = BlacklistEntry.objects.create(
            entry_type='DOMAIN', value='to-remove.com', reason='test', added_by=self.admin,
        )
        self.client.post(f'/threat-intel/blacklist/{entry.pk}/remove/')
        self.assertFalse(BlacklistEntry.objects.filter(pk=entry.pk).exists())

    def test_duplicate_whitelist_not_created(self):
        self.client.post('/threat-intel/whitelist/add/', {
            'entry_type': 'DOMAIN', 'value': 'company.com', 'reason': 'Dup',
        })
        self.assertEqual(
            WhitelistEntry.objects.filter(entry_type='DOMAIN', value='company.com').count(), 1
        )

    def test_viewer_cannot_add_whitelist(self):
        viewer = User.objects.create_user(username='viewer', password='pass', role='VIEWER')
        self.client.login(username='viewer', password='pass')
        resp = self.client.post('/threat-intel/whitelist/add/', {
            'entry_type': 'DOMAIN', 'value': 'viewer-test.com',
        })
        self.assertEqual(resp.status_code, 403)

    def test_analyst_cannot_manage_ti(self):
        analyst = User.objects.create_user(username='analyst', password='pass', role='ANALYST')
        self.client.login(username='analyst', password='pass')
        # Analyst can VIEW TI page
        resp = self.client.get('/threat-intel/')
        self.assertEqual(resp.status_code, 200)
        # But cannot add whitelist (admin only)
        resp = self.client.post('/threat-intel/whitelist/add/', {
            'entry_type': 'DOMAIN', 'value': 'analyst-test.com',
        })
        self.assertEqual(resp.status_code, 403)


class UserManagementWorkflowTest(TestCase):
    """Test user management UI."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin', password='pass', role='ADMIN', is_staff=True
        )
        self.client.login(username='admin', password='pass')

    def test_user_list_loads(self):
        resp = self.client.get('/users/')
        self.assertEqual(resp.status_code, 200)

    def test_add_user(self):
        resp = self.client.post('/users/add/', {
            'username': 'newuser', 'email': 'new@example.com',
            'password': 'securepass', 'role': 'ANALYST',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(User.objects.filter(username='newuser').exists())
        self.assertEqual(User.objects.get(username='newuser').role, 'ANALYST')

    def test_add_user_missing_fields(self):
        resp = self.client.post('/users/add/', {'username': '', 'password': ''})
        self.assertEqual(resp.status_code, 302)  # Redirect with error message
        self.assertEqual(User.objects.count(), 1)  # Only admin

    def test_add_duplicate_user(self):
        User.objects.create_user(username='existing', password='pass')
        resp = self.client.post('/users/add/', {
            'username': 'existing', 'password': 'pass',
        })
        self.assertEqual(resp.status_code, 302)

    def test_edit_role(self):
        target = User.objects.create_user(username='target', password='pass', role='VIEWER')
        resp = self.client.post(f'/users/{target.pk}/edit-role/', {'role': 'ANALYST'})
        self.assertEqual(resp.status_code, 302)
        target.refresh_from_db()
        self.assertEqual(target.role, 'ANALYST')

    def test_cannot_edit_own_role(self):
        resp = self.client.post(f'/users/{self.admin.pk}/edit-role/', {'role': 'VIEWER'})
        self.assertEqual(resp.status_code, 302)
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, 'ADMIN')

    def test_toggle_active(self):
        target = User.objects.create_user(username='target', password='pass')
        self.assertTrue(target.is_active)
        self.client.post(f'/users/{target.pk}/toggle-active/')
        target.refresh_from_db()
        self.assertFalse(target.is_active)

    def test_cannot_deactivate_self(self):
        self.client.post(f'/users/{self.admin.pk}/toggle-active/')
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_viewer_cannot_manage_users(self):
        viewer = User.objects.create_user(username='viewer', password='pass', role='VIEWER')
        self.client.login(username='viewer', password='pass')
        resp = self.client.get('/users/')
        self.assertEqual(resp.status_code, 403)

    def test_invalid_role_edit(self):
        target = User.objects.create_user(username='target', password='pass', role='VIEWER')
        resp = self.client.post(f'/users/{target.pk}/edit-role/', {'role': 'SUPERADMIN'})
        self.assertEqual(resp.status_code, 302)
        target.refresh_from_db()
        self.assertEqual(target.role, 'VIEWER')


class ScheduledReportWorkflowTest(TestCase):
    """Test scheduled report toggle."""

    def setUp(self):
        self.admin = User.objects.create_user(username='admin', password='pass', role='ADMIN')
        self.client.login(username='admin', password='pass')

    def test_toggle_scheduled_report(self):
        sr = ScheduledReport.objects.create(
            report_type='EMAIL_SUMMARY', schedule='DAILY',
            is_active=True, created_by=self.admin,
        )
        # Deactivate
        self.client.post(f'/reports/scheduled/{sr.pk}/toggle/')
        sr.refresh_from_db()
        self.assertFalse(sr.is_active)
        # Activate
        self.client.post(f'/reports/scheduled/{sr.pk}/toggle/')
        sr.refresh_from_db()
        self.assertTrue(sr.is_active)

    def test_non_admin_cannot_toggle(self):
        analyst = User.objects.create_user(username='analyst', password='pass', role='ANALYST')
        self.client.login(username='analyst', password='pass')
        sr = ScheduledReport.objects.create(
            report_type='EMAIL_SUMMARY', schedule='DAILY',
            is_active=True, created_by=self.admin,
        )
        resp = self.client.post(f'/reports/scheduled/{sr.pk}/toggle/')
        self.assertEqual(resp.status_code, 403)
