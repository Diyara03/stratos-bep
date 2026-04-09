# SPEC: Phase 2 -- Gmail API Ingestion + Email Parser

## Goal

Stratos can connect to Gmail via the Gmail API, fetch new emails, parse them into structured Email and EmailAttachment records saved to the database, with a management command for manual polling and Celery Beat for automatic polling every 10 seconds.

## In Scope

### S-01: emails/services/__init__.py -- Services package

Create an empty `__init__.py` to make `emails/services/` a Python package.

### S-02: emails/services/gmail_connector.py -- GmailConnector class

```
class GmailConnector:
    def __init__(self):
        self.service = self._authenticate()

    def _authenticate(self) -> Resource:
        """
        Load credentials from GMAIL_CREDENTIALS_PATH env var.
        Load/save token from GMAIL_TOKEN_PATH env var.
        Use google-auth-oauthlib InstalledAppFlow for initial auth.
        Build and return googleapiclient.discovery.build('gmail', 'v1', credentials=creds).

        Token refresh: if creds exist but are expired and have a refresh_token,
        use creds.refresh(google.auth.transport.requests.Request()).

        Raises FileNotFoundError with helpful message if credentials.json is missing.
        """

    def fetch_new_emails(self, max_results: int = 10) -> list[dict]:
        """
        1. Call service.users().messages().list(userId='me', labelIds=['INBOX'],
           maxResults=max_results) to get message ID list.
        2. For each message ID, check if Email.objects.filter(gmail_id=msg_id).exists().
           If yes, skip (count as skipped).
        3. For non-duplicate IDs, call self.get_message(msg_id) to get full message.
        4. Return list of raw Gmail API message dicts (full format).
        """

    def get_message(self, gmail_message_id: str) -> dict:
        """
        Call service.users().messages().get(userId='me', id=gmail_message_id, format='full').
        Return the raw Gmail API message dict.
        """

    def mark_as_read(self, gmail_message_id: str) -> None:
        """
        Call service.users().messages().modify(userId='me', id=gmail_message_id,
        body={'removeLabelIds': ['UNREAD']}).
        """
```

**Environment variables used:**
- `GMAIL_CREDENTIALS_PATH` -- path to OAuth credentials.json (default: `credentials/credentials.json`)
- `GMAIL_TOKEN_PATH` -- path to saved token.json (default: `credentials/token.json`)

**OAuth scopes:** `['https://www.googleapis.com/auth/gmail.modify']`

### S-03: emails/services/parser.py -- EmailParser class

```
class EmailParser:
    def parse_gmail_message(self, raw_message: dict) -> tuple[Email, list[dict]]:
        """
        Parse a raw Gmail API message dict into an unsaved Email instance
        and a list of attachment dicts.

        Returns:
            (email_instance, attachment_list)
            email_instance: unsaved Email model instance with all fields populated
            attachment_list: list of dicts, each with keys:
                {filename, content_type, size_bytes, content, sha256_hash, md5_hash}
                where content is raw bytes
        """

    def _extract_header_value(self, headers: list[dict], name: str) -> str:
        """Get a single header value by name from Gmail headers list.
        Gmail headers are [{name: str, value: str}, ...].
        Returns empty string if header not found."""

    def _extract_message_id(self, headers: list[dict]) -> str:
        """Get Message-ID header, strip angle brackets < >.
        Falls back to gmail_id if Message-ID header is missing."""

    def _extract_from(self, headers: list[dict]) -> tuple[str, str]:
        """Parse 'Display Name <email@domain.com>' format.
        Returns (display_name, email_address).
        If no display name, returns ('', email_address).
        Uses email.utils.parseaddr from stdlib."""

    def _extract_to(self, headers: list[dict]) -> list[str]:
        """Parse To and Cc headers into list of email addresses.
        Uses email.utils.getaddresses from stdlib.
        Returns deduplicated list of addresses."""

    def _extract_cc(self, headers: list[dict]) -> list[str]:
        """Parse Cc header into list of email addresses.
        Returns empty list if no Cc header."""

    def _extract_subject(self, headers: list[dict]) -> str:
        """Get Subject header. Decode RFC 2047 encoded words
        using email.header.decode_header from stdlib.
        Returns empty string if no Subject header."""

    def _extract_date(self, headers: list[dict]) -> datetime:
        """Parse Date header to timezone-aware datetime.
        Uses email.utils.parsedate_to_datetime from stdlib.
        Falls back to django.utils.timezone.now() if parsing fails.
        Result MUST be timezone-aware (USE_TZ=True)."""

    def _extract_reply_to(self, headers: list[dict]) -> str | None:
        """Extract Reply-To header email address.
        Returns None if not present."""

    def _extract_body(self, payload: dict) -> tuple[str, str]:
        """Extract email body from Gmail payload structure.
        Returns (body_text, body_html).

        Handles:
        - Simple messages with body.data directly on payload
        - multipart/alternative with text/plain and text/html parts
        - multipart/mixed with nested multipart/alternative
        - Recursive part traversal

        Gmail encodes body.data as URL-safe base64.
        Decode using base64.urlsafe_b64decode.
        Returns ('', '') if no body found."""

    def _extract_urls(self, body_text: str, body_html: str) -> list[str]:
        """Extract URLs from email body.
        1. Regex pattern on body_text: https?://[^\s<>"']+
        2. BeautifulSoup on body_html: find all <a> tags, extract href attributes
           that start with http:// or https://
        3. Deduplicate (preserve order).
        4. Return list of URL strings.
        Handles empty body_text or body_html gracefully."""

    def _extract_attachments(self, payload: dict, service=None, gmail_message_id: str = None) -> list[dict]:
        """Extract attachment metadata and content from Gmail payload.
        For each part where filename is non-empty:
            - filename: part['filename']
            - content_type: part['mimeType']
            - size_bytes: part['body'].get('size', 0)
            - content: base64-decoded part['body']['data'] if present,
              otherwise empty bytes (attachment data may need separate API call)
            - sha256_hash, md5_hash: computed via _compute_hashes()
        Returns list of attachment dicts.
        Handles emails with no attachments (returns empty list)."""

    def _compute_hashes(self, content: bytes) -> tuple[str, str]:
        """Compute SHA-256 and MD5 hex digests using hashlib.
        Returns (sha256_hex, md5_hex)."""

    def _extract_received_chain(self, headers: list[dict]) -> list[dict]:
        """Parse all Received headers into structured list.
        Each hop: {from_server: str, by_server: str, timestamp_str: str}.
        Parse 'from X by Y' pattern from each Received header value.
        Returns list ordered as they appear in headers (most recent first)."""

    def _extract_auth_results(self, headers: list[dict]) -> dict:
        """Parse Authentication-Results header.
        Returns dict with keys: spf, dkim, dmarc.
        Each value is one of: 'pass', 'fail', 'softfail', 'none'.
        If Authentication-Results header is missing, returns all 'none'.

        Parsing logic:
        - Search for 'spf=WORD' pattern in header value
        - Search for 'dkim=WORD' pattern in header value
        - Search for 'dmarc=WORD' pattern in header value
        """
```

**Dependencies:** `email.utils`, `email.header`, `base64`, `hashlib`, `re`, `beautifulsoup4`

### S-04: emails/services/analyzer.py -- Stub only

```
class EmailAnalyzer:
    def analyze(self, email_id: int) -> None:
        """
        Stub orchestrator for the analysis pipeline.
        Phase 2 behavior:
            1. Set Email.status = 'ANALYZING'
            2. Save
            3. Set Email.status = 'PENDING' (placeholder -- real logic in Phase 3+)
            4. Save
        Raises Email.DoesNotExist if email_id is invalid.
        """
```

### S-05: emails/tasks.py -- Celery tasks

```
from celery import shared_task
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def analyze_email_task(self, email_id: int) -> dict:
    """
    Calls EmailAnalyzer().analyze(email_id).
    Returns {'email_id': email_id, 'status': 'analyzed'}.
    On exception: retries up to 3 times, then logs error.
    """

@shared_task
def fetch_gmail_task() -> dict:
    """
    1. Instantiate GmailConnector().
       If FileNotFoundError: log warning, return {'fetched': 0, 'skipped': 0, 'errors': 0}.
    2. Call connector.fetch_new_emails(max_results=10).
    3. For each raw message:
       a. Parse with EmailParser().parse_gmail_message(raw_message)
       b. Save Email to DB (email.gmail_id = raw_message['id'])
       c. For each attachment dict, create EmailAttachment linked to saved Email
       d. Dispatch analyze_email_task.delay(email.id)
       e. Call connector.mark_as_read(raw_message['id'])
    4. Return {'fetched': N, 'skipped': M, 'errors': K}
       where N = successfully saved, M = skipped duplicates, K = parse/save errors.
    Errors on individual emails are caught and counted, not re-raised.
    """
```

**Duplicate handling:** `fetch_new_emails` filters out gmail_ids already in the database. If a race condition causes a duplicate `message_id` IntegrityError during save, catch it, increment error count, and continue.

### S-06: emails/management/commands/fetch_emails.py -- Management command

```
class Command(BaseCommand):
    help = 'Fetch new emails from Gmail and save to database'

    def add_arguments(self, parser):
        parser.add_argument('--max', type=int, default=10,
                            help='Maximum number of emails to fetch (default: 10)')
        parser.add_argument('--dry-run', action='store_true',
                            help='Print what would be fetched without saving')

    def handle(self, *args, **options):
        """
        Calls the same logic as fetch_gmail_task but directly (not via Celery).
        --dry-run: fetch and parse messages, print summary, but do NOT save to DB
                   and do NOT dispatch analyze_email_task.
        Normal mode: fetch, parse, save, dispatch, print summary.

        Output format:
            'Fetched N new emails, skipped M already processed'
            or in dry-run mode:
            '[DRY RUN] Would fetch N new emails, skipped M already processed'

        On FileNotFoundError: prints helpful error message about setting up
        Gmail credentials and exits with code 0 (not a crash).
        """
```

### S-07: Celery Beat schedule in settings/base.py

Add to `stratos_server/settings/base.py`:

```python
# Celery Beat schedule
CELERY_BEAT_SCHEDULE = {
    'fetch-gmail-every-10s': {
        'task': 'emails.tasks.fetch_gmail_task',
        'schedule': 10.0,
    },
}
```

### S-08: Test fixtures

**tests/fixtures/test_gmail_message.json**

A realistic Gmail API response dict containing:
- `id`: `'test_gmail_id_001'`
- `threadId`: `'thread_001'`
- `labelIds`: `['INBOX', 'UNREAD']`
- `payload.headers` including:
  - `From`: `'John Doe <john.doe@example.com>'`
  - `To`: `'analyst@stratos-bep.com'`
  - `Subject`: `'Quarterly Report Q4 2025'`
  - `Date`: `'Mon, 6 Jan 2026 10:30:00 +0000'`
  - `Message-ID`: `'<msg-001@example.com>'`
  - `Authentication-Results`: contains `spf=pass`, `dkim=pass`, `dmarc=pass`
  - Two `Received` headers with from/by/timestamp info
- `payload.mimeType`: `'multipart/mixed'`
- `payload.parts`:
  - Part 0: `multipart/alternative` with:
    - `text/plain` body (base64-encoded): contains `"Please find the quarterly report attached. Visit https://example.com/reports for more details."`
    - `text/html` body (base64-encoded): contains same text plus `<a href="https://example.com/dashboard">Dashboard</a>`
  - Part 1: attachment `test.pdf` with `mimeType: 'application/pdf'`, body data (base64-encoded small content), `size: 1024`

**tests/fixtures/phishing_gmail_message.json**

A phishing email Gmail API response containing:
- `id`: `'test_gmail_id_002'`
- `payload.headers` including:
  - `From`: `'Security Team <attacker@suspicious-domain.xyz>'`
  - `To`: `'victim@stratos-bep.com'`
  - `Subject`: `'Urgent: Verify your account immediately'`
  - `Date`: `'Tue, 7 Jan 2026 08:15:00 +0000'`
  - `Message-ID`: `'<phish-001@suspicious-domain.xyz>'`
  - `Reply-To`: `'different-reply@evil.com'`
  - `Authentication-Results`: contains `spf=fail`, `dkim=fail`, `dmarc=fail`
  - Three `Received` headers
- Body text (base64-encoded): contains at least 3 phishing keywords from the 24-keyword list:
  `"verify your account"`, `"urgent action required"`, `"click here immediately"`
  Plus a malicious URL: `https://evil-phishing.example.com/steal-creds`
- Attachment: `invoice.pdf.exe` with `mimeType: 'application/octet-stream'`, body data (base64-encoded), `size: 2048`

### S-09: requirements.txt update

Add `beautifulsoup4==4.12.3` to `requirements.txt`.

Current requirements.txt has 13 packages. After this change: 14 packages.

## Out of Scope

- SPF/DKIM/DMARC scoring logic (Phase 3) -- parser only extracts raw auth results
- URL analysis against URLhaus or VirusTotal (Phase 4)
- Attachment analysis against MalwareBazaar, YARA scanning, magic byte detection (Phase 4)
- Keyword scoring (Phase 4)
- Verdict assignment or score calculation (Phase 5)
- Real Gmail OAuth setup -- user must manually obtain credentials.json and run initial auth flow
- Any frontend or UI templates (Phase 6)
- Actual persistent file storage for attachment content -- attachments are saved as metadata only in EmailAttachment; raw bytes are not stored to disk or blob storage
- REST API endpoints for emails (Phase 5)
- WhitelistEntry/BlacklistEntry lookup during ingestion (Phase 3)
- AnalysisResult creation -- the stub analyzer does NOT create an AnalysisResult record; that is Phase 3
- Rate limiting or throttling of Gmail API calls
- Email sending or reply functionality

## Acceptance Criteria

| ID     | Criterion | Pass Condition |
|--------|-----------|----------------|
| AC-001 | EmailParser parses the test fixture into correct Email fields | `parse_gmail_message(test_fixture)` returns Email with `from_address='john.doe@example.com'`, `subject='Quarterly Report Q4 2025'`, `received_at` is timezone-aware datetime for `2026-01-06 10:30:00 UTC` |
| AC-002 | Parsed Email has urls_extracted populated | After parsing test fixture, `email.urls_extracted` contains `['https://example.com/reports', 'https://example.com/dashboard']` (at minimum these two, order may vary) |
| AC-003 | EmailAttachment saved with correct hashes and filename | After parsing test fixture, attachment list contains one dict with `filename='test.pdf'`, non-empty `sha256_hash` (64 hex chars), non-empty `md5_hash` (32 hex chars) |
| AC-004 | Auth results extraction works | `_extract_auth_results(test_fixture_headers)` returns `{'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}` for clean fixture and `{'spf': 'fail', 'dkim': 'fail', 'dmarc': 'fail'}` for phishing fixture |
| AC-005 | Duplicate gmail_id is skipped on second fetch | Insert Email with `gmail_id='test_gmail_id_001'`, call `fetch_new_emails` with a mocked API returning that same ID; result list is empty (skipped) |
| AC-006 | Management command is registered | `python manage.py fetch_emails --help` exits with code 0 and shows `--max` and `--dry-run` arguments |
| AC-007 | Dry-run mode saves nothing | Run management command with `--dry-run` (mocked Gmail API); assert Email.objects.count() is unchanged after command completes |
| AC-008 | Missing credentials handled gracefully | `GmailConnector()` with nonexistent credentials path raises `FileNotFoundError`; `fetch_gmail_task()` catches it, logs warning, returns `{'fetched': 0, 'skipped': 0, 'errors': 0}` |
| AC-009 | URL extraction finds URLs in both text and HTML | `_extract_urls('Visit https://text-url.com', '<a href="https://html-url.com">link</a>')` returns list containing both URLs |
| AC-010 | Attachment hashing is correct | `_compute_hashes(b'test content')` returns the correct SHA-256 and MD5 hex digests for that input |
| AC-011 | analyze_email_task can be dispatched | `analyze_email_task.delay(email_id)` with mocked Celery does not raise an exception |
| AC-012 | Phishing fixture parsed correctly | Parsing phishing fixture produces Email with `from_address='attacker@suspicious-domain.xyz'` and attachment list containing `filename='invoice.pdf.exe'` |
| AC-013 | Email with no attachments parses cleanly | A Gmail message dict with no attachment parts returns empty attachment list and valid Email instance |
| AC-014 | Email with no HTML body parses cleanly | A Gmail message with only text/plain part returns `body_html=''` or `None` and valid `body_text` |
| AC-015 | All datetimes are timezone-aware | Every `received_at` value produced by `_extract_date` has `tzinfo` that is not None |
| AC-016 | Celery Beat schedule is configured | `settings.CELERY_BEAT_SCHEDULE` contains `'fetch-gmail-every-10s'` with task `'emails.tasks.fetch_gmail_task'` and schedule `10.0` |
| AC-017 | beautifulsoup4 is in requirements.txt | `beautifulsoup4==4.12.3` appears in `requirements.txt` |
| AC-018 | Received chain extraction works | `_extract_received_chain` on test fixture headers returns a list with at least 2 entries, each containing `from_server` and `by_server` keys |
| AC-019 | fetch_gmail_task saves Email and EmailAttachment to DB | After mocked `fetch_gmail_task()` runs with test fixture, `Email.objects.count() >= 1` and the saved Email has related `attachments.count() >= 1` |
| AC-020 | Stub analyzer sets status correctly | After `EmailAnalyzer().analyze(email.id)`, email status is `'PENDING'` (round-tripped through ANALYZING) |

## API Contracts

### Management Command: fetch_emails

This phase introduces no HTTP API endpoints. The interface is a Django management command.

**Command:** `python manage.py fetch_emails`

**Arguments:**

| Argument    | Type   | Default | Description                                     |
|-------------|--------|---------|--------------------------------------------------|
| `--max`     | int    | 10      | Maximum number of emails to fetch from Gmail     |
| `--dry-run` | flag   | False   | Print what would be fetched, save nothing to DB  |

**Output (normal mode):**
```
Fetched 3 new emails, skipped 2 already processed
```

**Output (dry-run mode):**
```
[DRY RUN] Would fetch 3 new emails, skipped 2 already processed
```

**Output (missing credentials):**
```
Gmail credentials not found at credentials/credentials.json. 
Please set up OAuth credentials: https://console.cloud.google.com/apis/credentials
Set GMAIL_CREDENTIALS_PATH in .env to point to your credentials.json file.
```

**Exit codes:**
- 0: success (including dry-run and missing credentials)
- 1: unexpected error

### Celery Task: fetch_gmail_task

**Task name:** `emails.tasks.fetch_gmail_task`
**Arguments:** None
**Return value:**
```json
{
    "fetched": 3,
    "skipped": 2,
    "errors": 0
}
```

### Celery Task: analyze_email_task

**Task name:** `emails.tasks.analyze_email_task`
**Arguments:** `email_id` (int)
**Return value:**
```json
{
    "email_id": 42,
    "status": "analyzed"
}
```
**Retry policy:** max_retries=3, default_retry_delay=60 seconds

## Data Model Changes

No new models are created in this phase. All models were defined in Phase 1.

**Fields populated by Phase 2 parser (on existing Email model):**

| Field             | Populated by               | Value source                          |
|-------------------|----------------------------|---------------------------------------|
| gmail_id          | fetch_gmail_task           | Gmail API message `id`                |
| message_id        | _extract_message_id        | Message-ID header                     |
| from_address      | _extract_from              | From header (email part)              |
| from_display_name | _extract_from              | From header (display name part)       |
| to_addresses      | _extract_to                | To header                             |
| cc_addresses      | _extract_cc                | Cc header                             |
| reply_to          | _extract_reply_to          | Reply-To header                       |
| subject           | _extract_subject           | Subject header                        |
| body_text         | _extract_body              | text/plain part                       |
| body_html         | _extract_body              | text/html part                        |
| headers_raw       | parse_gmail_message        | Full headers list as JSON             |
| received_chain    | _extract_received_chain    | Parsed Received headers               |
| urls_extracted    | _extract_urls              | URLs from body_text + body_html       |
| status            | (default)                  | 'PENDING'                             |
| received_at       | _extract_date              | Date header                           |

**Fields populated on existing EmailAttachment model:**

| Field        | Populated by          | Value source                     |
|--------------|-----------------------|----------------------------------|
| email        | fetch_gmail_task      | FK to saved Email                |
| filename     | _extract_attachments  | Attachment part filename         |
| content_type | _extract_attachments  | Attachment part mimeType         |
| size_bytes   | _extract_attachments  | Attachment body size             |
| sha256_hash  | _compute_hashes       | SHA-256 of attachment content    |
| md5_hash     | _compute_hashes       | MD5 of attachment content        |

**Fields NOT populated in Phase 2** (remain at defaults):
- Email: verdict, score, confidence, analyzed_at
- EmailAttachment: file_magic, is_dangerous_ext, is_double_ext, is_mime_mismatch, yara_matches, ti_match
- AnalysisResult: not created at all in Phase 2

## File Manifest

Files to be created or modified in this phase:

```
emails/
  services/
    __init__.py                          # CREATE: empty package init
    gmail_connector.py                   # CREATE: GmailConnector class
    parser.py                            # CREATE: EmailParser class
    analyzer.py                          # CREATE: EmailAnalyzer stub
  tasks.py                               # CREATE: Celery tasks
  management/
    __init__.py                          # CREATE: empty package init
    commands/
      __init__.py                        # CREATE: empty package init
      fetch_emails.py                    # CREATE: management command

stratos_server/
  settings/
    base.py                              # MODIFY: add CELERY_BEAT_SCHEDULE

tests/
  fixtures/
    test_gmail_message.json              # CREATE: clean email fixture
    phishing_gmail_message.json          # CREATE: phishing email fixture
  test_phase2.py                         # CREATE: phase 2 test suite

requirements.txt                         # MODIFY: add beautifulsoup4==4.12.3
```

**Files NOT touched:**
- `emails/models.py` -- all models already defined in Phase 1
- `emails/admin.py` -- no changes needed
- `accounts/` -- no changes
- `threat_intel/` -- no changes
- `reports/` -- no changes
- `docker-compose.yml` -- no changes needed
- `Dockerfile` -- no changes needed (beautifulsoup4 is pure Python, no system deps)

## Dependencies

| Dependency | Source | Status |
|-----------|--------|--------|
| Django project scaffold | Phase 0 | COMPLETE |
| All 15 models defined and migrated | Phase 1 | COMPLETE |
| Email model with gmail_id, message_id, all content fields | Phase 1 | COMPLETE |
| EmailAttachment model with sha256_hash, md5_hash fields | Phase 1 | COMPLETE |
| Celery configuration (celery.py, autodiscover_tasks) | Phase 0 | COMPLETE |
| Redis broker configured | Phase 0 | COMPLETE |
| google-api-python-client in requirements.txt | Phase 0 | COMPLETE |
| google-auth-oauthlib in requirements.txt | Phase 0 | COMPLETE |

**External dependencies (not managed by Stratos):**
- Gmail API OAuth credentials (credentials.json) -- user must obtain from Google Cloud Console
- Active Gmail account with API access enabled

## Open Questions

| ID   | Question | Impact |
|------|----------|--------|
| OQ-1 | Should attachment raw content (bytes) be stored persistently (e.g., in a `BinaryField` or file on disk), or is metadata-only storage sufficient for Phase 2? The current spec stores only metadata in `EmailAttachment` and discards raw bytes after hashing. Phase 4 checker may need the raw bytes for YARA scanning. | If YARA needs raw bytes, Phase 4 will need to re-fetch from Gmail API or we need to add storage now. Recommend deferring storage to Phase 4 and re-fetching via `get_message()` at scan time. Human decision needed. |
| OQ-2 | The Gmail API `messages.list` returns messages matching a query. Should we use `q='is:unread'` to only fetch unread messages, or fetch all INBOX messages and rely on the gmail_id dedup check? | Using `is:unread` reduces API calls but means manually-read emails are never ingested. Current spec uses `labelIds=['INBOX']` without a query filter and relies on dedup. |
| OQ-3 | Should `mark_as_read` be called immediately after successful save, or should it be deferred until analysis is complete (Phase 3+)? Current spec calls it in `fetch_gmail_task` right after save. | Calling immediately means the email stays marked as read even if analysis later fails. Deferring means the same email could be re-fetched on next poll (but dedup prevents re-processing). |
| OQ-4 | The Gmail API may return attachment data inline (small attachments) or require a separate `messages.attachments.get()` call (large attachments with `attachmentId`). Should the parser handle both cases in Phase 2? | Large attachments with only `attachmentId` and no inline `data` would result in empty content and zeroed hashes. Recommend handling both cases for correctness. |

## Test Plan

The qa-agent should create `tests/test_phase2.py` with a minimum of 25 tests. All tests MUST mock the Gmail API -- never call the real Gmail service.

### Parser Extraction Tests (10 tests)

1. **T-001:** `_extract_message_id` strips angle brackets from `'<msg-001@example.com>'` and returns `'msg-001@example.com'`.
2. **T-002:** `_extract_from` parses `'John Doe <john.doe@example.com>'` into `('John Doe', 'john.doe@example.com')`.
3. **T-003:** `_extract_from` parses bare email `'user@example.com'` into `('', 'user@example.com')`.
4. **T-004:** `_extract_subject` decodes RFC 2047 encoded subject correctly.
5. **T-005:** `_extract_date` returns timezone-aware datetime; `tzinfo` is not None.
6. **T-006:** `_extract_date` with malformed date falls back to `timezone.now()` (still timezone-aware).
7. **T-007:** `_extract_body` handles multipart/alternative with text and HTML parts.
8. **T-008:** `_extract_body` handles plain text only (no HTML part) -- returns `body_html` as empty string.
9. **T-009:** `_extract_urls` finds URLs in both text and HTML bodies; deduplicates.
10. **T-010:** `_extract_urls` with empty strings returns empty list.

### Auth Results and Chain Tests (3 tests)

11. **T-011:** `_extract_auth_results` parses `'spf=pass dkim=pass dmarc=pass'` correctly.
12. **T-012:** `_extract_auth_results` with missing header returns `{'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}`.
13. **T-013:** `_extract_received_chain` returns list of dicts with `from_server` and `by_server` keys.

### Fixture Parsing Tests (4 tests)

14. **T-014:** Parse `test_gmail_message.json` -- Email has `from_address='john.doe@example.com'`, `subject='Quarterly Report Q4 2025'`.
15. **T-015:** Parse `test_gmail_message.json` -- attachment list has one entry with `filename='test.pdf'` and valid sha256_hash (64 chars).
16. **T-016:** Parse `phishing_gmail_message.json` -- Email has `from_address='attacker@suspicious-domain.xyz'`.
17. **T-017:** Parse `phishing_gmail_message.json` -- attachment has `filename='invoice.pdf.exe'`.

### Hashing Tests (2 tests)

18. **T-018:** `_compute_hashes(b'test content')` returns correct SHA-256 hex digest.
19. **T-019:** `_compute_hashes(b'test content')` returns correct MD5 hex digest.

### Database Persistence Tests (3 tests)

20. **T-020:** After running mocked `fetch_gmail_task`, `Email.objects.count()` increases by number of fetched messages.
21. **T-021:** Saved Email has `EmailAttachment` records accessible via `email.attachments.all()`.
22. **T-022:** Duplicate `gmail_id` on second `fetch_gmail_task` run does not create duplicate Email records.

### Task and Command Tests (4 tests)

23. **T-023:** `fetch_gmail_task` with missing credentials returns `{'fetched': 0, 'skipped': 0, 'errors': 0}` and does not raise.
24. **T-024:** Management command `fetch_emails` with `--dry-run` does not save any Email to DB (mock Gmail API).
25. **T-025:** Management command `fetch_emails --help` shows `--max` and `--dry-run` arguments.
26. **T-026:** `analyze_email_task` calls `EmailAnalyzer.analyze` with correct email_id (mock analyzer).

### Stub Analyzer Test (1 test)

27. **T-027:** `EmailAnalyzer().analyze(email.id)` sets email status to PENDING after execution (round-trip through ANALYZING).

### Configuration Tests (2 tests)

28. **T-028:** `CELERY_BEAT_SCHEDULE` in settings contains `'fetch-gmail-every-10s'` entry.
29. **T-029:** `beautifulsoup4` appears in `requirements.txt`.

**Total: 29 tests**

### Testing Notes

- ALL Gmail API calls must be mocked using `unittest.mock.patch` or `unittest.mock.MagicMock`.
- Use the JSON fixtures in `tests/fixtures/` for realistic test data.
- Use `django.test.TestCase` (with transaction rollback) for DB tests.
- Assert all datetime objects have non-None `tzinfo`.
- Test both the happy path and edge cases (no attachments, no HTML, missing headers).
