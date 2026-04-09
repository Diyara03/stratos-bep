"""
Phase 8 — API Authentication and Permission Tests.
Tests session auth, token auth, and role-based access to all API endpoints.
"""
import uuid

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from emails.models import AnalysisResult, Email, QuarantineEntry

User = get_user_model()


def _make_email(**kwargs):
    defaults = {
        'message_id': f'<api-{uuid.uuid4()}@test.com>',
        'from_address': 'sender@example.com',
        'from_display_name': 'Sender',
        'subject': 'Test email',
        'body_text': 'Hello world',
        'received_at': timezone.now(),
        'status': 'PENDING',
    }
    defaults.update(kwargs)
    return Email.objects.create(**defaults)


class APIAuthenticationTests(APITestCase):
    """Test authentication mechanisms for the API."""

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

    def test_ac_301_unauthenticated_emails_list(self):
        """AC-301: GET /api/emails/ without auth -> 401 or 403."""
        client = APIClient()
        response = client.get('/api/emails/')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_ac_302_session_auth_emails_list(self):
        """AC-302: force_login + GET /api/emails/ -> 200."""
        client = APIClient()
        client.force_authenticate(user=self.analyst)
        response = client.get('/api/emails/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_ac_303_token_auth_emails_list(self):
        """AC-303: Token authentication header -> 200."""
        token = Token.objects.create(user=self.analyst)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        response = client.get('/api/emails/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_ac_304_viewer_can_read_emails(self):
        """AC-304: VIEWER can GET /api/emails/ -> 200."""
        client = APIClient()
        client.force_authenticate(user=self.viewer)
        _make_email()
        response = client.get('/api/emails/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(response.data['count'], 1)

    def test_ac_305_viewer_cannot_quarantine_action(self):
        """AC-305: VIEWER POST /api/quarantine/<pk>/action/ -> 403."""
        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(email=email, status='PENDING', action='QUARANTINE')

        client = APIClient()
        client.force_authenticate(user=self.viewer)
        response = client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'release'},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_ac_306_analyst_can_release(self):
        """AC-306: ANALYST POST release action -> 200, status changed."""
        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(email=email, status='PENDING', action='QUARANTINE')

        client = APIClient()
        client.force_authenticate(user=self.analyst)
        response = client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'release', 'notes': 'FP confirmed'},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        entry.refresh_from_db()
        email.refresh_from_db()
        self.assertEqual(entry.status, 'RELEASED')
        self.assertEqual(email.status, 'DELIVERED')

    def test_ac_307_admin_dashboard_stats(self):
        """AC-307: ADMIN GET /api/dashboard/stats/ -> 200 with expected keys."""
        client = APIClient()
        client.force_authenticate(user=self.admin)
        response = client.get('/api/dashboard/stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        expected_keys = [
            'total_emails', 'clean_count', 'suspicious_count',
            'malicious_count', 'pending_count', 'quarantine_pending',
            'ti_hashes', 'ti_domains', 'last_sync',
        ]
        for key in expected_keys:
            self.assertIn(key, response.data, f'Missing key: {key}')

    def test_ac_308_email_detail_has_analysis(self):
        """AC-308: GET /api/emails/<pk>/ -> response has 'analysis' key."""
        email = _make_email(verdict='CLEAN', score=5, status='DELIVERED')
        AnalysisResult.objects.create(
            email=email, preprocess_score=0, total_score=5, pipeline_duration_ms=50,
        )

        client = APIClient()
        client.force_authenticate(user=self.analyst)
        response = client.get(f'/api/emails/{email.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('analysis', response.data)
        self.assertEqual(response.data['analysis']['total_score'], 5)

    def test_ac_309_quarantine_list_filters(self):
        """AC-309: GET /api/quarantine/ -> 200."""
        client = APIClient()
        client.force_authenticate(user=self.analyst)
        response = client.get('/api/quarantine/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_ac_310_invalid_token(self):
        """AC-310: Bogus Authorization header -> 401 or 403 (rejected)."""
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token invalidtoken12345')
        response = client.get('/api/emails/')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_ac_311_dashboard_stats_counts(self):
        """AC-311: Create known emails, check response counts match."""
        _make_email(verdict='CLEAN', score=5, status='DELIVERED')
        _make_email(verdict='MALICIOUS', score=90, status='BLOCKED')
        _make_email(verdict=None, score=None, status='PENDING')

        client = APIClient()
        client.force_authenticate(user=self.admin)
        response = client.get('/api/dashboard/stats/')
        self.assertEqual(response.data['total_emails'], 3)
        self.assertEqual(response.data['clean_count'], 1)
        self.assertEqual(response.data['malicious_count'], 1)
        self.assertEqual(response.data['pending_count'], 1)

    def test_ac_312_quarantine_action_block(self):
        """AC-312: ANALYST POST block -> QuarantineEntry.status=BLOCKED, email.status=BLOCKED."""
        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(email=email, status='PENDING', action='QUARANTINE')

        client = APIClient()
        client.force_authenticate(user=self.analyst)
        response = client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'block'},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        entry.refresh_from_db()
        email.refresh_from_db()
        self.assertEqual(entry.status, 'BLOCKED')
        self.assertEqual(email.status, 'BLOCKED')

    def test_ac_313_viewer_can_view_dashboard(self):
        """AC-313: VIEWER can GET /api/dashboard/stats/ -> 200 (IsAuthenticated only)."""
        client = APIClient()
        client.force_authenticate(user=self.viewer)
        response = client.get('/api/dashboard/stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_ac_314_admin_can_quarantine_action(self):
        """AC-314: ADMIN can perform quarantine actions (IsAnalystOrAbove)."""
        email = _make_email(verdict='SUSPICIOUS', score=45, status='QUARANTINED')
        entry = QuarantineEntry.objects.create(email=email, status='PENDING', action='QUARANTINE')

        client = APIClient()
        client.force_authenticate(user=self.admin)
        response = client.post(
            f'/api/quarantine/{entry.id}/action/',
            {'action': 'release'},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
