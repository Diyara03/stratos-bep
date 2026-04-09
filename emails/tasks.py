"""
Celery tasks for email ingestion and analysis in Stratos BEP.
"""
import logging

from celery import shared_task
from django.db import IntegrityError

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def analyze_email_task(self, email_id: int) -> dict:
    """
    Analyze a single email through the pipeline.

    Args:
        email_id: Primary key of the Email to analyze.

    Returns:
        Dict with email_id and status.
    """
    from emails.services.analyzer import EmailAnalyzer

    try:
        EmailAnalyzer().analyze(email_id)
        return {'email_id': email_id, 'status': 'analyzed'}
    except Exception as exc:
        logger.error("Failed to analyze email %s: %s", email_id, exc)
        raise self.retry(exc=exc)


@shared_task
def fetch_gmail_task() -> dict:
    """
    Fetch new emails from Gmail, parse, save to DB, and dispatch analysis.

    Returns:
        Dict with fetched, skipped, and errors counts.
    """
    from emails.models import Email, EmailAttachment
    from emails.services.gmail_connector import GmailConnector
    from emails.services.parser import EmailParser

    fetched = 0
    skipped = 0
    errors = 0

    try:
        connector = GmailConnector()
    except FileNotFoundError as e:
        logger.warning("Gmail credentials not configured: %s", e)
        return {'fetched': 0, 'skipped': 0, 'errors': 0}

    try:
        raw_messages = connector.fetch_new_emails(max_results=10)
    except Exception as exc:
        logger.error("Failed to fetch emails from Gmail: %s", exc)
        return {'fetched': 0, 'skipped': 0, 'errors': 1}

    parser = EmailParser()

    for raw_message in raw_messages:
        try:
            email_instance, attachment_dicts = parser.parse_gmail_message(raw_message)
            email_instance.gmail_id = raw_message['id']
            email_instance.save()

            for att_dict in attachment_dicts:
                EmailAttachment.objects.create(
                    email=email_instance,
                    filename=att_dict['filename'],
                    content_type=att_dict['content_type'],
                    size_bytes=att_dict['size_bytes'],
                    sha256_hash=att_dict['sha256_hash'],
                    md5_hash=att_dict['md5_hash'],
                )

            analyze_email_task.delay(email_instance.id)
            connector.mark_as_read(raw_message['id'])
            fetched += 1

        except IntegrityError:
            logger.info(
                "Duplicate email skipped (race condition): %s",
                raw_message.get('id', 'unknown')
            )
            skipped += 1

        except Exception as exc:
            logger.error(
                "Error processing email %s: %s",
                raw_message.get('id', 'unknown'), exc
            )
            errors += 1

    return {'fetched': fetched, 'skipped': skipped, 'errors': errors}
