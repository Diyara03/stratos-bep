"""
Phase 1 Tests: All 15 Django Models + Migrations
26 tests covering imports, creation, defaults, constraints, __str__, admin, cascades, migrations.
"""
from io import StringIO

from django.contrib import admin
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from emails.models import (
    AnalysisResult,
    Email,
    EmailAttachment,
    ExtractedIOC,
    QuarantineEntry,
)
from reports.models import IOCExport, Report, ScheduledReport
from threat_intel.models import (
    BlacklistEntry,
    MaliciousDomain,
    MaliciousHash,
    MaliciousIP,
    WhitelistEntry,
    YaraRule,
)


class EmailModelHelper:
    """Helper to create Email instances for tests."""

    @staticmethod
    def create_email(**kwargs):
        defaults = {
            'message_id': f'test-{timezone.now().timestamp()}',
            'from_address': 'sender@example.com',
            'subject': 'Test Email',
            'received_at': timezone.now(),
        }
        defaults.update(kwargs)
        return Email.objects.create(**defaults)


# --- T-001, T-002, T-003: Model Import Tests ---

class TestModelImports(TestCase):
    def test_t001_import_emails_models(self):
        """T-001: Import all 5 emails models without error."""
        self.assertIsNotNone(Email)
        self.assertIsNotNone(EmailAttachment)
        self.assertIsNotNone(AnalysisResult)
        self.assertIsNotNone(QuarantineEntry)
        self.assertIsNotNone(ExtractedIOC)

    def test_t002_import_threat_intel_models(self):
        """T-002: Import all 6 threat_intel models without error."""
        self.assertIsNotNone(MaliciousHash)
        self.assertIsNotNone(MaliciousDomain)
        self.assertIsNotNone(MaliciousIP)
        self.assertIsNotNone(YaraRule)
        self.assertIsNotNone(WhitelistEntry)
        self.assertIsNotNone(BlacklistEntry)

    def test_t003_import_reports_models(self):
        """T-003: Import all 3 reports models without error."""
        self.assertIsNotNone(Report)
        self.assertIsNotNone(ScheduledReport)
        self.assertIsNotNone(IOCExport)


# --- T-004 through T-009: Model Creation Tests ---

class TestModelCreation(TestCase):
    def setUp(self):
        self.email = EmailModelHelper.create_email(message_id='creation-test-001')
        self.user = User.objects.create_user(
            username='testanalyst', password='testpass123', role='ANALYST'
        )

    def test_t004_create_email(self):
        """T-004: Create an Email with required fields; assert it saves and has auto-generated id."""
        email = EmailModelHelper.create_email(message_id='t004-email')
        self.assertIsNotNone(email.id)
        self.assertEqual(email.from_address, 'sender@example.com')

    def test_t005_create_email_attachment(self):
        """T-005: Create EmailAttachment linked to Email; verify FK and related_name."""
        att = EmailAttachment.objects.create(
            email=self.email,
            filename='malware.exe',
            content_type='application/octet-stream',
            size_bytes=1024,
            sha256_hash='a' * 64,
            md5_hash='b' * 32,
        )
        self.assertEqual(att.email, self.email)
        self.assertIn(att, self.email.attachments.all())

    def test_t006_create_analysis_result(self):
        """T-006: Create AnalysisResult linked to Email; verify OneToOne and related_name."""
        ar = AnalysisResult.objects.create(email=self.email)
        self.assertEqual(ar.email, self.email)
        self.assertEqual(self.email.analysis, ar)

    def test_t007_create_quarantine_entry(self):
        """T-007: Create QuarantineEntry with reviewer User; verify FK to User."""
        qe = QuarantineEntry.objects.create(
            email=self.email, reviewer=self.user
        )
        self.assertEqual(qe.reviewer, self.user)
        self.assertEqual(qe.email, self.email)

    def test_t008_create_extracted_ioc(self):
        """T-008: Create ExtractedIOC linked to Email; verify related_name='iocs'."""
        ioc = ExtractedIOC.objects.create(
            email=self.email,
            ioc_type='URL',
            value='http://malicious.example.com',
        )
        self.assertIn(ioc, self.email.iocs.all())

    def test_t009_create_threat_intel_models(self):
        """T-009: Create one instance of each threat_intel model."""
        mh = MaliciousHash.objects.create(sha256_hash='c' * 64)
        self.assertIsNotNone(mh.id)

        md = MaliciousDomain.objects.create(domain='evil.com')
        self.assertIsNotNone(md.id)

        mi = MaliciousIP.objects.create(ip_address='192.168.1.1')
        self.assertIsNotNone(mi.id)

        yr = YaraRule.objects.create(name='test_rule', rule_content='rule test { condition: true }')
        self.assertIsNotNone(yr.id)

        wl = WhitelistEntry.objects.create(entry_type='EMAIL', value='safe@example.com', added_by=self.user)
        self.assertIsNotNone(wl.id)

        bl = BlacklistEntry.objects.create(entry_type='DOMAIN', value='bad.com', added_by=self.user)
        self.assertIsNotNone(bl.id)


# --- T-010 through T-012: Default Value Tests ---

class TestDefaultValues(TestCase):
    def test_t010_email_default_status(self):
        """T-010: Email without specifying status defaults to PENDING."""
        email = EmailModelHelper.create_email(message_id='t010-email')
        self.assertEqual(email.status, 'PENDING')

    def test_t011_analysis_result_default_scores(self):
        """T-011: AnalysisResult score fields default to 0."""
        email = EmailModelHelper.create_email(message_id='t011-email')
        ar = AnalysisResult.objects.create(email=email)
        self.assertEqual(ar.preprocess_score, 0)
        self.assertEqual(ar.keyword_score, 0)
        self.assertEqual(ar.url_score, 0)
        self.assertEqual(ar.attachment_score, 0)
        self.assertEqual(ar.chain_score, 0)
        self.assertEqual(ar.total_score, 0)

    def test_t012_malicious_hash_default_severity(self):
        """T-012: MaliciousHash without specifying severity defaults to HIGH."""
        mh = MaliciousHash.objects.create(sha256_hash='d' * 64)
        self.assertEqual(mh.severity, 'HIGH')


# --- T-013 through T-016: Constraint Tests ---

class TestConstraints(TestCase):
    def test_t013_email_unique_message_id(self):
        """T-013: Duplicate message_id raises IntegrityError."""
        EmailModelHelper.create_email(message_id='unique-001')
        with self.assertRaises(IntegrityError):
            EmailModelHelper.create_email(message_id='unique-001')

    def test_t014_analysis_result_one_to_one(self):
        """T-014: Two AnalysisResult for same Email raises IntegrityError."""
        email = EmailModelHelper.create_email(message_id='t014-email')
        AnalysisResult.objects.create(email=email)
        with self.assertRaises(IntegrityError):
            AnalysisResult.objects.create(email=email)

    def test_t015_whitelist_unique_together(self):
        """T-015: Duplicate (entry_type, value) on WhitelistEntry raises IntegrityError."""
        WhitelistEntry.objects.create(entry_type='EMAIL', value='dup@example.com')
        with self.assertRaises(IntegrityError):
            WhitelistEntry.objects.create(entry_type='EMAIL', value='dup@example.com')

    def test_t016_email_invalid_status_validation(self):
        """T-016: full_clean() on Email with status='INVALID' raises ValidationError."""
        email = EmailModelHelper.create_email(message_id='t016-email')
        email.status = 'INVALID'
        with self.assertRaises(ValidationError):
            email.full_clean()


# --- T-017 through T-019: String Representation Tests ---

class TestStringRepresentations(TestCase):
    def test_t017_email_str(self):
        """T-017: str(email) returns '{subject} from {from_address}'."""
        email = EmailModelHelper.create_email(
            message_id='t017-email', subject='Hello', from_address='test@example.com'
        )
        self.assertEqual(str(email), 'Hello from test@example.com')

    def test_t018_malicious_hash_str(self):
        """T-018: str(malicious_hash) contains first 16 chars of sha256."""
        sha = 'abcdef0123456789' + 'f' * 48
        mh = MaliciousHash.objects.create(sha256_hash=sha, malware_family='TestMalware')
        self.assertIn('abcdef0123456789', str(mh))

    def test_t019_yara_rule_str(self):
        """T-019: str(yara_rule) contains 'active' or 'inactive'."""
        yr_active = YaraRule.objects.create(
            name='active_rule', rule_content='rule a { condition: true }', is_active=True
        )
        yr_inactive = YaraRule.objects.create(
            name='inactive_rule', rule_content='rule b { condition: true }', is_active=False
        )
        self.assertIn('active', str(yr_active))
        self.assertIn('inactive', str(yr_inactive))


# --- T-020 through T-022: Admin Registration Tests ---

class TestAdminRegistration(TestCase):
    def test_t020_emails_models_registered(self):
        """T-020: All 5 emails models are registered in admin."""
        for model in [Email, EmailAttachment, AnalysisResult, QuarantineEntry, ExtractedIOC]:
            self.assertIn(model, admin.site._registry, f'{model.__name__} not registered in admin')

    def test_t021_threat_intel_models_registered(self):
        """T-021: All 6 threat_intel models are registered in admin."""
        for model in [MaliciousHash, MaliciousDomain, MaliciousIP, YaraRule, WhitelistEntry, BlacklistEntry]:
            self.assertIn(model, admin.site._registry, f'{model.__name__} not registered in admin')

    def test_t022_reports_models_registered(self):
        """T-022: All 3 reports models are registered in admin."""
        for model in [Report, ScheduledReport, IOCExport]:
            self.assertIn(model, admin.site._registry, f'{model.__name__} not registered in admin')


# --- T-023, T-024: Relationship and Cascade Tests ---

class TestCascadeAndSetNull(TestCase):
    def test_t023_email_cascade_delete(self):
        """T-023: Deleting Email cascades to related objects."""
        email = EmailModelHelper.create_email(message_id='t023-email')
        att = EmailAttachment.objects.create(
            email=email, filename='file.txt', content_type='text/plain',
            size_bytes=100, sha256_hash='e' * 64, md5_hash='f' * 32,
        )
        ar = AnalysisResult.objects.create(email=email)
        qe = QuarantineEntry.objects.create(email=email)
        ioc = ExtractedIOC.objects.create(email=email, ioc_type='HASH', value='g' * 64)

        email_id = email.id
        email.delete()

        self.assertFalse(EmailAttachment.objects.filter(id=att.id).exists())
        self.assertFalse(AnalysisResult.objects.filter(id=ar.id).exists())
        self.assertFalse(QuarantineEntry.objects.filter(id=qe.id).exists())
        self.assertFalse(ExtractedIOC.objects.filter(id=ioc.id).exists())

    def test_t024_user_set_null_on_delete(self):
        """T-024: Deleting User sets QuarantineEntry.reviewer to None."""
        user = User.objects.create_user(username='deleteme', password='testpass123')
        email = EmailModelHelper.create_email(message_id='t024-email')
        qe = QuarantineEntry.objects.create(email=email, reviewer=user)

        user.delete()
        qe.refresh_from_db()
        self.assertIsNone(qe.reviewer)


# --- T-025: Migration Integrity Test ---

class TestMigrationIntegrity(TestCase):
    def test_t025_no_unapplied_migrations(self):
        """T-025: showmigrations has no unapplied migrations (no '[ ]')."""
        out = StringIO()
        call_command('showmigrations', stdout=out)
        output = out.getvalue()
        self.assertNotIn('[ ]', output)


# --- T-026: JSONField Default Tests ---

class TestJSONFieldDefaults(TestCase):
    def test_t026_email_json_field_defaults(self):
        """T-026: Email JSONField defaults are correct empty types."""
        email = EmailModelHelper.create_email(message_id='t026-email')
        self.assertEqual(email.to_addresses, [])
        self.assertEqual(email.headers_raw, {})
        self.assertEqual(email.received_chain, [])
        self.assertEqual(email.urls_extracted, [])
