"""Settings views for Stratos BEP system configuration. ADMIN only."""
import json
import logging
import os

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from emails.models import SystemConfig

logger = logging.getLogger(__name__)


def admin_required(view_func):
    """Decorator: require ADMIN role."""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.role != 'ADMIN':
            return HttpResponseForbidden('Admin access required.')
        return view_func(request, *args, **kwargs)
    return wrapper


@login_required
@admin_required
def settings_view(request):
    """Main settings page."""
    config = SystemConfig.get_solo()

    # Check Gmail files status
    creds_path = os.environ.get('GMAIL_CREDENTIALS_PATH', 'credentials/gmail_credentials.json')
    token_path = os.environ.get('GMAIL_TOKEN_PATH', 'credentials/gmail_token.json')

    context = {
        'config': config,
        'vt_key_masked': config.mask_key(config.virustotal_api_key),
        'abuseipdb_key_masked': config.mask_key(config.abuseipdb_api_key),
        'gmail_creds_exist': os.path.exists(creds_path),
        'gmail_token_exists': os.path.exists(token_path),
        'active_page': 'settings',
    }
    return render(request, 'settings/index.html', context)


@login_required
@admin_required
@require_POST
def save_api_keys(request):
    """Save API keys (only non-empty values are updated)."""
    config = SystemConfig.get_solo()

    vt_key = request.POST.get('virustotal_api_key', '').strip()
    abuse_key = request.POST.get('abuseipdb_api_key', '').strip()

    if not vt_key and not abuse_key:
        messages.warning(request, 'No API keys entered. Nothing was changed.')
        return redirect('settings:index')

    updated = []
    if vt_key:
        config.virustotal_api_key = vt_key
        updated.append('VirusTotal')
    if abuse_key:
        config.abuseipdb_api_key = abuse_key
        updated.append('AbuseIPDB')

    config.updated_by = request.user
    config.save()
    messages.success(request, f'{", ".join(updated)} API key{"s" if len(updated) > 1 else ""} saved successfully.')
    return redirect('settings:index')


@login_required
@admin_required
@require_POST
def save_thresholds(request):
    """Save detection thresholds."""
    config = SystemConfig.get_solo()

    try:
        clean = int(request.POST.get('clean_threshold', 25))
        malicious = int(request.POST.get('malicious_threshold', 70))
        fetch_interval = int(request.POST.get('fetch_interval_seconds', 10))
    except (ValueError, TypeError):
        messages.error(request, 'Invalid threshold values.')
        return redirect('settings:index')

    if clean >= malicious:
        messages.error(request, 'Clean threshold must be less than malicious threshold.')
        return redirect('settings:index')

    if clean < 0 or malicious > 100:
        messages.error(request, 'Thresholds must be between 0 and 100.')
        return redirect('settings:index')

    if fetch_interval < 5:
        messages.error(request, 'Fetch interval must be at least 5 seconds.')
        return redirect('settings:index')

    config.clean_threshold = clean
    config.malicious_threshold = malicious
    config.fetch_interval_seconds = fetch_interval
    config.ti_sync_enabled = request.POST.get('ti_sync_enabled') == 'on'
    config.updated_by = request.user
    config.save()
    messages.success(request, 'Detection settings saved.')
    return redirect('settings:index')


@login_required
@admin_required
@require_POST
def upload_gmail_credentials(request):
    """Handle Gmail credentials.json file upload."""
    uploaded = request.FILES.get('gmail_credentials')
    if not uploaded:
        messages.error(request, 'No file selected.')
        return redirect('settings:index')

    if not uploaded.name.endswith('.json'):
        messages.error(request, 'File must be a JSON file.')
        return redirect('settings:index')

    try:
        content = uploaded.read().decode('utf-8')
        data = json.loads(content)

        # Validate it looks like Google OAuth credentials
        if 'installed' not in data and 'web' not in data:
            messages.error(request, 'Invalid credentials file. Must contain "installed" or "web" key.')
            return redirect('settings:index')

        creds_dir = os.environ.get('GMAIL_CREDENTIALS_DIR', 'credentials')
        os.makedirs(creds_dir, exist_ok=True)
        creds_path = os.path.join(creds_dir, 'gmail_credentials.json')

        with open(creds_path, 'w') as f:
            f.write(content)

        config = SystemConfig.get_solo()
        config.gmail_credentials_uploaded = True
        config.updated_by = request.user
        config.save()

        messages.success(request, 'Gmail credentials uploaded. Now click "Connect Gmail" to authorize.')
    except json.JSONDecodeError:
        messages.error(request, 'Invalid JSON file.')
    except Exception as e:
        logger.exception("Failed to save Gmail credentials")
        messages.error(request, f'Error saving credentials: {e}')

    return redirect('settings:index')


@login_required
@admin_required
def gmail_connect(request):
    """Initiate Gmail OAuth web flow."""
    creds_path = os.environ.get('GMAIL_CREDENTIALS_PATH', 'credentials/gmail_credentials.json')

    if not os.path.exists(creds_path):
        messages.error(request, 'Upload Gmail credentials first.')
        return redirect('settings:index')

    try:
        from google_auth_oauthlib.flow import Flow

        SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

        # Determine redirect URI
        scheme = 'https' if request.is_secure() else 'http'
        redirect_uri = f'{scheme}://{request.get_host()}/settings/gmail/callback/'

        flow = Flow.from_client_secrets_file(creds_path, scopes=SCOPES, redirect_uri=redirect_uri)
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
        )

        # Save state in session for CSRF protection
        request.session['gmail_oauth_state'] = state
        request.session['gmail_redirect_uri'] = redirect_uri

        return redirect(auth_url)

    except Exception as e:
        logger.exception("Failed to initiate Gmail OAuth")
        messages.error(request, f'OAuth error: {e}')
        return redirect('settings:index')


@login_required
@admin_required
def gmail_callback(request):
    """Handle OAuth callback from Google."""
    error = request.GET.get('error')
    if error:
        messages.error(request, f'Google authorization denied: {error}')
        return redirect('settings:index')

    code = request.GET.get('code')
    state = request.GET.get('state')

    saved_state = request.session.get('gmail_oauth_state')
    if not state or state != saved_state:
        messages.error(request, 'Invalid OAuth state. Please try again.')
        return redirect('settings:index')

    creds_path = os.environ.get('GMAIL_CREDENTIALS_PATH', 'credentials/gmail_credentials.json')
    redirect_uri = request.session.get('gmail_redirect_uri', '')

    try:
        from google_auth_oauthlib.flow import Flow

        SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
        flow = Flow.from_client_secrets_file(creds_path, scopes=SCOPES, redirect_uri=redirect_uri)
        flow.fetch_token(code=code)
        creds = flow.credentials

        # Save token
        token_path = os.environ.get('GMAIL_TOKEN_PATH', 'credentials/gmail_token.json')
        os.makedirs(os.path.dirname(token_path) or '.', exist_ok=True)
        with open(token_path, 'w') as f:
            f.write(creds.to_json())

        # Try to get the connected email address
        from googleapiclient.discovery import build
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        connected_email = profile.get('emailAddress', '')

        # Update config
        config = SystemConfig.get_solo()
        config.gmail_connection_status = 'CONNECTED'
        config.gmail_connected_email = connected_email
        config.gmail_credentials_uploaded = True
        config.updated_by = request.user
        config.save()

        # Clean up session
        request.session.pop('gmail_oauth_state', None)
        request.session.pop('gmail_redirect_uri', None)

        messages.success(request, f'Gmail connected successfully. Monitoring: {connected_email}')

    except Exception as e:
        logger.exception("Gmail OAuth callback failed")
        messages.error(request, f'Authorization failed: {e}')

    return redirect('settings:index')


@login_required
@admin_required
@require_POST
def gmail_disconnect(request):
    """Disconnect Gmail by removing the token file."""
    token_path = os.environ.get('GMAIL_TOKEN_PATH', 'credentials/gmail_token.json')

    try:
        if os.path.exists(token_path):
            os.remove(token_path)

        config = SystemConfig.get_solo()
        config.gmail_connection_status = 'DISCONNECTED'
        config.gmail_connected_email = ''
        config.updated_by = request.user
        config.save()

        messages.success(request, 'Gmail disconnected.')
    except Exception as e:
        logger.exception("Failed to disconnect Gmail")
        messages.error(request, f'Error: {e}')

    return redirect('settings:index')


@login_required
@admin_required
def gmail_status(request):
    """AJAX endpoint: check Gmail connection status."""
    config = SystemConfig.get_solo()
    token_path = os.environ.get('GMAIL_TOKEN_PATH', 'credentials/gmail_token.json')

    status = 'DISCONNECTED'
    email = ''

    if os.path.exists(token_path):
        try:
            from google.oauth2.credentials import Credentials
            SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)

            if creds.valid:
                status = 'CONNECTED'
            elif creds.expired and creds.refresh_token:
                from google.auth.transport.requests import Request
                creds.refresh(Request())
                status = 'CONNECTED'
                # Re-save refreshed token
                with open(token_path, 'w') as f:
                    f.write(creds.to_json())
            else:
                status = 'EXPIRED'
        except Exception:
            status = 'EXPIRED'

    if status != config.gmail_connection_status:
        config.gmail_connection_status = status
        config.save(update_fields=['gmail_connection_status', 'updated_at'])

    return JsonResponse({
        'status': status,
        'email': config.gmail_connected_email,
    })


@login_required
@admin_required
@require_POST
def test_virustotal(request):
    """Test VirusTotal API key."""
    config = SystemConfig.get_solo()
    key = config.virustotal_api_key
    if not key:
        return JsonResponse({'ok': False, 'error': 'No API key configured.'})

    try:
        import requests as req
        resp = req.get(
            'https://www.virustotal.com/api/v3/users/me',
            headers={'x-apikey': key},
            timeout=10,
        )
        if resp.status_code == 200:
            return JsonResponse({'ok': True, 'message': 'VirusTotal API key is valid.'})
        else:
            return JsonResponse({'ok': False, 'error': f'API returned status {resp.status_code}'})
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)})


@login_required
@admin_required
@require_POST
def test_abuseipdb(request):
    """Test AbuseIPDB API key."""
    config = SystemConfig.get_solo()
    key = config.abuseipdb_api_key
    if not key:
        return JsonResponse({'ok': False, 'error': 'No API key configured.'})

    try:
        import requests as req
        resp = req.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': key, 'Accept': 'application/json'},
            params={'ipAddress': '8.8.8.8', 'maxAgeInDays': '1'},
            timeout=10,
        )
        if resp.status_code == 200:
            return JsonResponse({'ok': True, 'message': 'AbuseIPDB API key is valid.'})
        else:
            return JsonResponse({'ok': False, 'error': f'API returned status {resp.status_code}'})
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)})
