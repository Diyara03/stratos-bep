"""
Phase 8 — Export Tests.
Tests CSV/JSON export views in reports/views.py.
"""
import json
import uuid

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.utils import timezone

from emails.models import Email, ExtractedIOC
from reports.models import IOCExport, Report
from threat_intel.models import MaliciousDomain, MaliciousHash, MaliciousIP, YaraRule

User = get_user_model()


def _make_email(**kwargs):
    defaults = {
        'message_id': f'<export-{uuid.uuid4()}@test.com>',
        'from_address': 'sender@example.com',
        'from_display_name': 'Sender',
        'subject': 'Test email',
        'body_text': 'Hello world',
        'received_at': timezone.now(),
        'status': 'DELIVERED',
        'verdict': 'CLEAN',
        'score': 5,
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


class EmailCSVExportTests(TestCase):
    """Test email summary CSV export."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin', password='testpass', role='ADMIN',
        )
        self.analyst = User.objects.create_user(
            username='analyst', password='testpass', role='ANALYST',
        )
        self.viewer = User.objects.create_user(
            username='viewer', password='testpass', role='VIEWER',
        )
        self.client = Client()

    def test_ac_401_email_csv_export_200(self):
        """AC-401: Admin GET /reports/export/emails/ -> 200, text/csv."""
        self.client.force_login(self.admin)
        _make_email()
        response = self.client.get('/reports/export/emails/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

    def test_ac_402_email_csv_headers(self):
        """AC-402: First line of CSV has expected column headers."""
        self.client.force_login(self.admin)
        _make_email()
        response = self.client.get('/reports/export/emails/')
        content = response.content.decode('utf-8')
        first_line = content.split('\r\n')[0]
        self.assertIn('ID', first_line)
        self.assertIn('Message ID', first_line)
        self.assertIn('From', first_line)
        self.assertIn('Subject', first_line)
        self.assertIn('Verdict', first_line)
        self.assertIn('Score', first_line)

    def test_ac_403_email_csv_row_count(self):
        """AC-403: Number of data rows = Email.objects.count()."""
        self.client.force_login(self.admin)
        for i in range(5):
            _make_email()
        response = self.client.get('/reports/export/emails/')
        content = response.content.decode('utf-8')
        lines = [l for l in content.split('\r\n') if l.strip()]
        # 1 header + 5 data rows
        self.assertEqual(len(lines), 6)

    def test_ac_404_email_csv_filter_verdict(self):
        """AC-404: GET ?verdict=MALICIOUS -> only malicious rows."""
        self.client.force_login(self.admin)
        _make_email(verdict='CLEAN', score=5)
        _make_email(verdict='MALICIOUS', score=90, status='BLOCKED')
        _make_email(verdict='MALICIOUS', score=85, status='BLOCKED')

        response = self.client.get('/reports/export/emails/?verdict=MALICIOUS')
        content = response.content.decode('utf-8')
        lines = [l for l in content.split('\r\n') if l.strip()]
        # 1 header + 2 data rows
        self.assertEqual(len(lines), 3)

    def test_ac_405_export_creates_report_record(self):
        """AC-405: After email export, Report.objects.count() increases."""
        self.client.force_login(self.admin)
        initial_count = Report.objects.count()
        _make_email()
        self.client.get('/reports/export/emails/')
        self.assertEqual(Report.objects.count(), initial_count + 1)
        report = Report.objects.latest('created_at')
        self.assertEqual(report.report_type, 'EMAIL_SUMMARY')
        self.assertEqual(report.output_format, 'CSV')

    def test_ac_406_viewer_export_forbidden(self):
        """AC-406: VIEWER GET /reports/export/emails/ -> 403."""
        self.client.force_login(self.viewer)
        response = self.client.get('/reports/export/emails/')
        self.assertEqual(response.status_code, 403)

    def test_ac_407_unauthenticated_export_redirects(self):
        """AC-407: Anonymous GET /reports/export/emails/ -> 302 redirect to login."""
        response = self.client.get('/reports/export/emails/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_ac_408_analyst_can_export(self):
        """AC-408: ANALYST can export emails."""
        self.client.force_login(self.analyst)
        _make_email()
        response = self.client.get('/reports/export/emails/')
        self.assertEqual(response.status_code, 200)


class IOCExportTests(TestCase):
    """Test IOC CSV export."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin', password='testpass', role='ADMIN',
        )
        self.analyst = User.objects.create_user(
            username='analyst', password='testpass', role='ANALYST',
        )
        self.viewer = User.objects.create_user(
            username='viewer', password='testpass', role='VIEWER',
        )
        self.client = Client()

    def test_ac_409_ioc_csv_export_200(self):
        """AC-409: Analyst GET /reports/export/iocs/ -> 200, text/csv."""
        self.client.force_login(self.analyst)
        response = self.client.get('/reports/export/iocs/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

    def test_ac_410_ioc_csv_headers(self):
        """AC-410: IOC CSV has correct column headers."""
        self.client.force_login(self.analyst)
        response = self.client.get('/reports/export/iocs/')
        content = response.content.decode('utf-8')
        first_line = content.split('\r\n')[0]
        self.assertIn('IOC Type', first_line)
        self.assertIn('Value', first_line)
        self.assertIn('Severity', first_line)
        self.assertIn('Source Checker', first_line)

    def test_ac_411_ioc_export_creates_record(self):
        """AC-411: After IOC export, IOCExport.objects.count() increases."""
        self.client.force_login(self.analyst)
        initial_count = IOCExport.objects.count()
        self.client.get('/reports/export/iocs/')
        self.assertEqual(IOCExport.objects.count(), initial_count + 1)

    def test_ac_412_viewer_ioc_export_forbidden(self):
        """AC-412: VIEWER cannot export IOCs."""
        self.client.force_login(self.viewer)
        response = self.client.get('/reports/export/iocs/')
        self.assertEqual(response.status_code, 403)


class TIStatsExportTests(TestCase):
    """Test TI stats JSON export."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin', password='testpass', role='ADMIN',
        )
        self.analyst = User.objects.create_user(
            username='analyst', password='testpass', role='ANALYST',
        )
        self.client = Client()

    def test_ac_413_ti_stats_json_200(self):
        """AC-413: Admin GET /reports/export/ti-stats/ -> 200, application/json."""
        self.client.force_login(self.admin)
        response = self.client.get('/reports/export/ti-stats/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')

    def test_ac_414_ti_stats_json_structure(self):
        """AC-414: Response JSON has expected top-level keys."""
        self.client.force_login(self.admin)
        MaliciousHash.objects.create(
            sha256_hash='a' * 64, malware_family='Test', source='MANUAL',
        )
        MaliciousDomain.objects.create(domain='evil.com', source='URLHAUS')

        response = self.client.get('/reports/export/ti-stats/')
        data = json.loads(response.content)
        self.assertIn('malicious_hashes', data)
        self.assertIn('malicious_domains', data)
        self.assertIn('malicious_ips', data)
        self.assertIn('yara_rules', data)
        self.assertEqual(data['malicious_hashes']['total'], 1)
        self.assertEqual(data['malicious_domains']['total'], 1)

    def test_ac_415_analyst_ti_stats_forbidden(self):
        """AC-415: ANALYST cannot access TI stats (admin only)."""
        self.client.force_login(self.analyst)
        response = self.client.get('/reports/export/ti-stats/')
        self.assertEqual(response.status_code, 403)

    def test_ac_416_ti_stats_creates_report(self):
        """AC-416: TI stats export creates Report record."""
        self.client.force_login(self.admin)
        initial_count = Report.objects.count()
        self.client.get('/reports/export/ti-stats/')
        self.assertEqual(Report.objects.count(), initial_count + 1)
        report = Report.objects.latest('created_at')
        self.assertEqual(report.report_type, 'THREAT_INTEL')
        self.assertEqual(report.output_format, 'JSON')
