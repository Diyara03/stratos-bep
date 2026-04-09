"""
Celery tasks for threat intelligence feed synchronization.
"""
from celery import shared_task
from django.core.management import call_command


@shared_task
def sync_malwarebazaar_task():
    """Sync MalwareBazaar feed via management command."""
    call_command('sync_ti_feeds', feed='malwarebazaar')
    return {'status': 'completed', 'feed': 'malwarebazaar'}


@shared_task
def sync_urlhaus_task():
    """Sync URLhaus feed via management command."""
    call_command('sync_ti_feeds', feed='urlhaus')
    return {'status': 'completed', 'feed': 'urlhaus'}
