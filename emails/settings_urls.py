from django.urls import path
from . import settings_views

app_name = 'settings'

urlpatterns = [
    path('', settings_views.settings_view, name='index'),
    path('api-keys/', settings_views.save_api_keys, name='save-api-keys'),
    path('thresholds/', settings_views.save_thresholds, name='save-thresholds'),
    path('gmail/upload/', settings_views.upload_gmail_credentials, name='gmail-upload'),
    path('gmail/connect/', settings_views.gmail_connect, name='gmail-connect'),
    path('gmail/callback/', settings_views.gmail_callback, name='gmail-callback'),
    path('gmail/disconnect/', settings_views.gmail_disconnect, name='gmail-disconnect'),
    path('gmail/status/', settings_views.gmail_status, name='gmail-status'),
    path('test/virustotal/', settings_views.test_virustotal, name='test-vt'),
    path('test/abuseipdb/', settings_views.test_abuseipdb, name='test-abuseipdb'),
]
