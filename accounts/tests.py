from django.conf import settings
from django.test import TestCase, Client

from accounts.models import User


class HealthEndpointTest(TestCase):
    """Test the /health/ endpoint."""

    def test_health_returns_200(self):
        client = Client()
        response = client.get('/health/')
        self.assertEqual(response.status_code, 200)

    def test_health_returns_json_keys(self):
        client = Client()
        response = client.get('/health/')
        data = response.json()
        self.assertIn('status', data)
        self.assertIn('version', data)
        self.assertIn('db', data)

    def test_health_status_ok(self):
        client = Client()
        response = client.get('/health/')
        data = response.json()
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['version'], '0.1.0')
        self.assertEqual(data['db'], 'connected')


class CustomUserTest(TestCase):
    """Test the custom User model."""

    def test_create_user_default_role(self):
        user = User.objects.create_user(username='testuser', password='testpass123')
        self.assertEqual(user.role, 'VIEWER')
        self.assertEqual(user.department, '')

    def test_create_user_admin_role(self):
        user = User.objects.create_user(
            username='adminuser', password='testpass123', role='ADMIN'
        )
        self.assertEqual(user.role, 'ADMIN')

    def test_create_user_analyst_role(self):
        user = User.objects.create_user(
            username='analystuser', password='testpass123', role='ANALYST'
        )
        self.assertEqual(user.role, 'ANALYST')

    def test_user_str(self):
        user = User.objects.create_user(username='testuser', password='testpass123')
        self.assertEqual(str(user), 'testuser (VIEWER)')

    def test_user_last_login_ip(self):
        user = User.objects.create_user(username='testuser', password='testpass123')
        self.assertIsNone(user.last_login_ip)
        user.last_login_ip = '192.168.1.1'
        user.save()
        user.refresh_from_db()
        self.assertEqual(user.last_login_ip, '192.168.1.1')

    def test_user_db_table(self):
        self.assertEqual(User._meta.db_table, 'stratos_user')


class SettingsTest(TestCase):
    """Test settings configuration."""

    def test_auth_user_model(self):
        self.assertEqual(settings.AUTH_USER_MODEL, 'accounts.User')

    def test_installed_apps_contains_all_apps(self):
        required_apps = ['emails', 'accounts', 'threat_intel', 'reports', 'rest_framework']
        for app in required_apps:
            self.assertIn(app, settings.INSTALLED_APPS)

    def test_settings_imports(self):
        """Both dev and prod settings should import without error."""
        import stratos_server.settings.dev  # noqa: F401
        # prod settings may fail on DB parse in test env, just test import
        import stratos_server.settings.prod  # noqa: F401

    def test_clean_threshold(self):
        self.assertEqual(settings.CLEAN_THRESHOLD, 25)

    def test_malicious_threshold(self):
        self.assertEqual(settings.MALICIOUS_THRESHOLD, 70)
