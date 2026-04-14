"""
Phase 0 smoke tests for Stratos BEP.
Covers all acceptance criteria from docs/phase0/SPEC.md.
"""
import json
import os
from pathlib import Path

from django.conf import settings
from django.test import Client, TestCase

from accounts.models import User

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class HealthEndpointTests(TestCase):
    """AC-003: GET /health/ returns 200 with JSON body."""

    def setUp(self):
        self.client = Client()

    def test_ac_003_health_returns_200_with_json_keys(self):
        """Health endpoint returns HTTP 200 with status, version, db keys."""
        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("status", data)
        self.assertIn("version", data)
        self.assertIn("db", data)

    def test_ac_003_health_status_ok(self):
        """Health endpoint returns status=ok when DB is reachable."""
        response = self.client.get("/health/")
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["version"], "0.1.0")
        self.assertEqual(data["db"], "connected")

    def test_ac_003_health_content_type_is_json(self):
        """Health endpoint returns Content-Type: application/json."""
        response = self.client.get("/health/")
        self.assertEqual(response["Content-Type"], "application/json")


class CustomUserTests(TestCase):
    """AC-005, AC-006: Custom User model with role and department fields."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", password="testpass123"
        )

    def test_ac_006_user_default_role_is_viewer(self):
        """New user defaults to VIEWER role."""
        self.assertEqual(self.user.role, "VIEWER")

    def test_ac_006_user_default_department_is_blank(self):
        """New user defaults to blank department."""
        self.assertEqual(self.user.department, "")

    def test_ac_006_user_role_admin(self):
        """User can be created with ADMIN role."""
        admin = User.objects.create_user(
            username="adminuser", password="testpass123", role="ADMIN"
        )
        admin.refresh_from_db()
        self.assertEqual(admin.role, "ADMIN")

    def test_ac_006_user_role_analyst(self):
        """User can be created with ANALYST role."""
        analyst = User.objects.create_user(
            username="analystuser", password="testpass123", role="ANALYST"
        )
        analyst.refresh_from_db()
        self.assertEqual(analyst.role, "ANALYST")

    def test_ac_006_user_last_login_ip_nullable(self):
        """last_login_ip defaults to None."""
        self.assertIsNone(self.user.last_login_ip)

    def test_ac_006_user_db_table_name(self):
        """User model uses stratos_user table name."""
        self.assertEqual(User._meta.db_table, "stratos_user")

    def test_ac_006_user_str_representation(self):
        """User __str__ returns username (role) format."""
        self.assertEqual(str(self.user), "testuser (VIEWER)")


class SettingsTests(TestCase):
    """AC-005, AC-007, AC-010: Settings configuration."""

    def test_ac_005_auth_user_model(self):
        """AUTH_USER_MODEL is set to accounts.User."""
        self.assertEqual(settings.AUTH_USER_MODEL, "accounts.User")

    def test_ac_007_installed_apps_emails(self):
        """emails app is in INSTALLED_APPS."""
        self.assertIn("emails", settings.INSTALLED_APPS)

    def test_ac_007_installed_apps_accounts(self):
        """accounts app is in INSTALLED_APPS."""
        self.assertIn("accounts", settings.INSTALLED_APPS)

    def test_ac_007_installed_apps_threat_intel(self):
        """threat_intel app is in INSTALLED_APPS."""
        self.assertIn("threat_intel", settings.INSTALLED_APPS)

    def test_ac_007_installed_apps_reports(self):
        """reports app is in INSTALLED_APPS."""
        self.assertIn("reports", settings.INSTALLED_APPS)

    def test_ac_007_installed_apps_rest_framework(self):
        """rest_framework is in INSTALLED_APPS."""
        self.assertIn("rest_framework", settings.INSTALLED_APPS)

    def test_ac_010_dev_settings_importable(self):
        """stratos_server.settings.dev imports without error."""
        import stratos_server.settings.dev  # noqa: F401

    def test_ac_010_prod_settings_importable(self):
        """stratos_server.settings.prod imports without error."""
        import stratos_server.settings.prod  # noqa: F401

    def test_scoring_thresholds(self):
        """Scoring thresholds have correct default values."""
        self.assertEqual(settings.CLEAN_THRESHOLD, 25)
        self.assertEqual(settings.MALICIOUS_THRESHOLD, 70)

    def test_celery_settings_present(self):
        """Celery broker and result backend settings exist."""
        self.assertTrue(hasattr(settings, "CELERY_BROKER_URL"))
        self.assertTrue(hasattr(settings, "CELERY_RESULT_BACKEND"))


class FileExistenceTests(TestCase):
    """AC-001 through AC-010: Verify all required files exist on disk."""

    REQUIRED_FILES = [
        "manage.py",
        "Dockerfile",
        "docker-compose.yml",
        ".env.example",
        ".gitignore",
        "requirements.txt",
        "stratos_server/celery.py",
        "stratos_server/views.py",
        "stratos_server/__init__.py",
        "stratos_server/urls.py",
        "stratos_server/wsgi.py",
        "stratos_server/asgi.py",
        "stratos_server/settings/__init__.py",
        "stratos_server/settings/base.py",
        "stratos_server/settings/dev.py",
        "stratos_server/settings/prod.py",
        "accounts/models.py",
        "accounts/migrations/__init__.py",
        "emails/migrations/__init__.py",
        "threat_intel/migrations/__init__.py",
        "reports/migrations/__init__.py",
    ]

    def test_ac_008_required_files_exist(self):
        """All files from the Phase 0 file manifest exist."""
        missing = []
        for rel_path in self.REQUIRED_FILES:
            full_path = PROJECT_ROOT / rel_path
            if not full_path.exists():
                missing.append(rel_path)
        self.assertEqual(missing, [], f"Missing files: {missing}")

    def test_ac_008_env_example_has_required_vars(self):
        """`.env.example` contains all required environment variables."""
        env_path = PROJECT_ROOT / ".env.example"
        content = env_path.read_text()
        required_vars = [
            "SECRET_KEY",
            "DATABASE_URL",
            "REDIS_URL",
            # API keys and thresholds are now managed via Settings UI
            # but should still be referenced in .env.example
            "GMAIL_CREDENTIALS_PATH",
            "GMAIL_TOKEN_PATH",
        ]
        missing = [v for v in required_vars if v not in content]
        self.assertEqual(missing, [], f"Missing vars in .env.example: {missing}")


class SystemCheckTests(TestCase):
    """AC-001, AC-002: Django system checks and migrations."""

    def test_ac_002_system_check_no_issues(self):
        """python manage.py check reports no issues."""
        from django.core.management import call_command
        from io import StringIO

        out = StringIO()
        call_command("check", stdout=out)
        output = out.getvalue()
        self.assertIn("System check identified no issues", output)

    def test_ac_001_no_unapplied_migrations(self):
        """showmigrations shows no unapplied migrations (no [ ] entries)."""
        from django.core.management import call_command
        from io import StringIO

        out = StringIO()
        call_command("showmigrations", stdout=out)
        output = out.getvalue()
        # [ ] means unapplied, [X] means applied
        unapplied = [
            line.strip()
            for line in output.splitlines()
            if "[ ]" in line
        ]
        self.assertEqual(
            unapplied, [], f"Unapplied migrations found: {unapplied}"
        )


class CeleryConfigTests(TestCase):
    """AC-009 (partial): Celery configuration is valid (no broker connection test)."""

    def test_celery_app_importable(self):
        """Celery app can be imported from stratos_server."""
        from stratos_server.celery import app

        self.assertEqual(app.main, "stratos_server")

    def test_celery_app_in_init(self):
        """stratos_server.__init__ exports the celery app."""
        import stratos_server

        self.assertTrue(hasattr(stratos_server, "celery_app"))
