"""
Celery tasks for threat intelligence feed synchronization.
"""
import logging

from celery import shared_task
from django.core.management import call_command

logger = logging.getLogger(__name__)


@shared_task
def sync_malwarebazaar_task():
    """Sync MalwareBazaar feed via management command. Respects SystemConfig.ti_sync_enabled."""
    try:
        from emails.models import SystemConfig
        if not SystemConfig.get_solo().ti_sync_enabled:
            logger.info("TI sync disabled in settings, skipping MalwareBazaar.")
            return {'status': 'skipped', 'feed': 'malwarebazaar', 'reason': 'disabled'}
    except Exception:
        pass  # If config not available, proceed with sync
    call_command('sync_ti_feeds', feed='malwarebazaar')
    return {'status': 'completed', 'feed': 'malwarebazaar'}


@shared_task
def sync_urlhaus_task():
    """Sync URLhaus feed via management command. Respects SystemConfig.ti_sync_enabled."""
    try:
        from emails.models import SystemConfig
        if not SystemConfig.get_solo().ti_sync_enabled:
            logger.info("TI sync disabled in settings, skipping URLhaus.")
            return {'status': 'skipped', 'feed': 'urlhaus', 'reason': 'disabled'}
    except Exception:
        pass
    call_command('sync_ti_feeds', feed='urlhaus')
    return {'status': 'completed', 'feed': 'urlhaus'}
