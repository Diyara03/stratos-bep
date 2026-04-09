# SPEC: Phase 5 -- Decider + TI Feed Sync + REST API

## Goal

Complete the full email-to-verdict pipeline end-to-end by adding the Decider stage, populating threat intelligence feeds from MalwareBazaar and URLhaus, and exposing a REST API for dashboard consumption.

## In Scope

### 1. Decider Service (`emails/services/decider.py`)

**DecisionResult dataclass:**

| Field             | Type       | Description                                      |
|-------------------|------------|--------------------------------------------------|
| verdict           | str        | CLEAN, SUSPICIOUS, or MALICIOUS                  |
| total_score       | int        | Combined score capped at 0-100                   |
| confidence        | str        | HIGH, MEDIUM, or LOW                             |
| action            | str        | DELIVER, QUARANTINE, or BLOCK                    |
| preprocess_score  | int        | Score from Preprocessor stage                    |
| check_score       | int        | Score from Checker stage                         |
| override_reason   | str or None| Reason for override (e.g., "known_malware_hash") |

**Decider class:**

- Class constants: `CLEAN_THRESHOLD = 25`, `MALICIOUS_THRESHOLD = 70`
- Single public method: `decide(preprocess_result: PreprocessResult, check_result: CheckResult) -> DecisionResult`

**Decision logic (exact rules):**

1. **Known malware override:** If `check_result.has_known_malware` is True, return verdict=MALICIOUS, total_score=100, confidence=HIGH, action=BLOCK, override_reason="known_malware_hash".
2. **Normal scoring:** `raw = preprocess_result.score + check_result.total_check_score`, `total = min(raw, 100)`.
3. **Verdict thresholds:**
   - `total >= 70`: verdict=MALICIOUS, action=BLOCK. Confidence is HIGH if total >= 90, else MEDIUM.
   - `total >= 25`: verdict=SUSPICIOUS, action=QUARANTINE, confidence=LOW.
   - `total < 25`: verdict=CLEAN, action=DELIVER. Confidence is HIGH if total < 10, else MEDIUM.

### 2. EmailAnalyzer Update (`emails/services/analyzer.py`)

The `analyze()` method becomes the final pipeline orchestrator:

```
Preprocessor.process(email)
  -> if whitelist: _finalize as CLEAN/DELIVERED (unchanged from Phase 3)
  -> else:
       _save_preprocess_result(email, preprocess_result)
       Checker.check_all(email)
       _save_check_result(email, check_result)
       Decider.decide(preprocess_result, check_result)
       _finalize_decision(email, preprocess_result, check_result, decision_result)
```

**New method `_finalize_decision(email, preprocess_result, check_result, decision)`:**

- Sets `email.verdict = decision.verdict`
- Sets `email.score = decision.total_score`
- Sets `email.confidence = decision.confidence`
- Sets `email.analyzed_at = timezone.now()`
- Sets `email.status` based on `decision.action`: DELIVER -> "DELIVERED", QUARANTINE -> "QUARANTINED", BLOCK -> "BLOCKED"
- Updates AnalysisResult: `total_score = decision.total_score`, `pipeline_duration_ms` (measured via `time.time()` at start and end of `analyze()`)
- Creates QuarantineEntry if action is QUARANTINE or BLOCK (status="PENDING", action=decision.action)
- Does NOT create QuarantineEntry for DELIVER action

**Pipeline timing:**
- Record `start_time = time.time()` at the beginning of `analyze()`
- Compute `pipeline_duration_ms = int((time.time() - start_time) * 1000)` before saving

### 3. TI Feed Sync Management Command (`threat_intel/management/commands/sync_ti_feeds.py`)

**Command: `python manage.py sync_ti_feeds`**

Arguments:
- `--feed`: choices are `malwarebazaar`, `urlhaus`, `all`. Default: `all`.
- `--limit`: max records to import per feed. Default: `5000`. Type: int.

**`_sync_malwarebazaar()` method:**
- GET `https://bazaar.abuse.ch/export/csv/recent/`
- Parse CSV response body (text, not file). Skip lines starting with `#` (comments).
- CSV columns of interest: `sha256_hash` (index varies -- find by header row), `md5_hash`, `signature` (maps to malware_family).
- Validation: skip rows where sha256_hash is not exactly 64 hex characters (`re.match(r'^[a-fA-F0-9]{64}$', hash)`).
- Upsert: `MaliciousHash.objects.update_or_create(sha256_hash=sha256, defaults={md5_hash, malware_family, source='MALWAREBAZAAR'})`.
- Stop after `--limit` successful upserts.
- Log count of imported and skipped records.

**`_sync_urlhaus()` method:**
- GET `https://urlhaus.abuse.ch/downloads/csv_recent/`
- Parse CSV response body. Skip lines starting with `#`.
- CSV columns of interest: `url`, `url_status`.
- Filter: only process rows where `url_status == 'online'`.
- Extract domain from URL using `urllib.parse.urlparse(url).hostname`.
- Skip rows where hostname extraction fails or is empty.
- Upsert: `MaliciousDomain.objects.update_or_create(domain=hostname, defaults={category='threat', source='URLHAUS'})`.
- Stop after `--limit` successful upserts.
- Log count of imported and skipped records.

**HTTP library:** `requests` (already in requirements.txt at version 2.31.0).

**Timeout:** 30 seconds for each HTTP request.

### 4. TI Feed Celery Tasks (`threat_intel/tasks.py`)

Two new Celery tasks:

```python
@shared_task
def sync_malwarebazaar_task() -> dict:
    # Calls: management.call_command('sync_ti_feeds', feed='malwarebazaar')
    # Returns: {'status': 'completed', 'feed': 'malwarebazaar'}

@shared_task
def sync_urlhaus_task() -> dict:
    # Calls: management.call_command('sync_ti_feeds', feed='urlhaus')
    # Returns: {'status': 'completed', 'feed': 'urlhaus'}
```

**CELERY_BEAT_SCHEDULE additions in `stratos_server/settings/base.py`:**

| Task Name                    | Schedule                               | Task Path                                  |
|------------------------------|----------------------------------------|--------------------------------------------|
| sync-malwarebazaar-daily     | crontab(hour=2, minute=0)              | threat_intel.tasks.sync_malwarebazaar_task |
| sync-urlhaus-daily           | crontab(hour=2, minute=30)             | threat_intel.tasks.sync_urlhaus_task       |

Import `crontab` from `celery.schedules` at the top of base.py.

### 5. REST API

#### 5a. Serializers (`emails/serializers.py`)

**EmailListSerializer:**

| Field              | Source                  |
|--------------------|-------------------------|
| id                 | Email.id                |
| message_id         | Email.message_id        |
| from_address       | Email.from_address      |
| from_display_name  | Email.from_display_name |
| subject            | Email.subject           |
| verdict            | Email.verdict           |
| score              | Email.score             |
| confidence         | Email.confidence        |
| status             | Email.status            |
| received_at        | Email.received_at       |

**EmailDetailSerializer (extends EmailListSerializer):**

Additional fields:
| Field              | Source                     |
|--------------------|----------------------------|
| to_addresses       | Email.to_addresses         |
| reply_to           | Email.reply_to             |
| body_text          | Email.body_text            |
| urls_extracted     | Email.urls_extracted       |
| analyzed_at        | Email.analyzed_at          |
| created_at         | Email.created_at           |
| analysis           | Nested AnalysisResultSerializer (read_only, source='analysis') |
| attachments        | Nested EmailAttachmentSerializer (read_only, many=True)        |

**EmailAttachmentSerializer:**

All fields from EmailAttachment: id, filename, content_type, size_bytes, sha256_hash, md5_hash, file_magic, is_dangerous_ext, is_double_ext, is_mime_mismatch, yara_matches, ti_match, created_at.

**AnalysisResultSerializer:**

All fields from AnalysisResult: id, preprocess_score, spf_result, dkim_result, dmarc_result, is_reply_to_mismatch, is_display_spoof, keyword_score, keywords_matched, url_score, url_findings, attachment_score, attachment_findings, chain_score, chain_findings, total_score, pipeline_duration_ms, created_at.

**QuarantineEntrySerializer:**

| Field       | Source                        |
|-------------|-------------------------------|
| id          | QuarantineEntry.id            |
| status      | QuarantineEntry.status        |
| action      | QuarantineEntry.action        |
| reviewed_at | QuarantineEntry.reviewed_at   |
| notes       | QuarantineEntry.notes         |
| created_at  | QuarantineEntry.created_at    |
| email       | Nested EmailListSerializer (read_only) |

**QuarantineActionSerializer (input):**

| Field  | Type   | Validation                                  |
|--------|--------|---------------------------------------------|
| action | str    | Required. choices: "release", "block", "delete" |
| notes  | str    | Optional, default empty string.             |

**DashboardStatsSerializer (output, not model-bound):**

| Field             | Type | Description                                        |
|-------------------|------|----------------------------------------------------|
| total_emails      | int  | Email.objects.count()                              |
| clean_count       | int  | Email.objects.filter(verdict='CLEAN').count()       |
| suspicious_count  | int  | Email.objects.filter(verdict='SUSPICIOUS').count()  |
| malicious_count   | int  | Email.objects.filter(verdict='MALICIOUS').count()   |
| pending_count     | int  | Email.objects.filter(verdict__isnull=True).count()  |
| quarantine_pending| int  | QuarantineEntry.objects.filter(status='PENDING').count() |
| ti_hashes         | int  | MaliciousHash.objects.count()                      |
| ti_domains        | int  | MaliciousDomain.objects.count()                    |
| last_sync         | datetime or None | Most recent MaliciousHash.added_at or MaliciousDomain.added_at |

#### 5b. API Views (`emails/api_views.py`)

**EmailListView**
- Method: GET
- URL: `/api/emails/`
- Auth: IsAuthenticated
- Serializer: EmailListSerializer
- Queryset: `Email.objects.all()` ordered by `-received_at`
- Pagination: PageNumberPagination, page_size=20
- Filters (query params):
  - `verdict` (exact match, e.g., `?verdict=MALICIOUS`)
  - `status` (exact match, e.g., `?status=QUARANTINED`)
  - `from_address` (case-insensitive contains, e.g., `?from_address=evil.com`)
  - `date_from` (received_at >= value, ISO format)
  - `date_to` (received_at <= value, ISO format)

**EmailDetailView**
- Method: GET
- URL: `/api/emails/<int:pk>/`
- Auth: IsAuthenticated
- Serializer: EmailDetailSerializer
- Queryset: `Email.objects.select_related('analysis').prefetch_related('attachments')`

**QuarantineListView**
- Method: GET
- URL: `/api/quarantine/`
- Auth: IsAuthenticated
- Serializer: QuarantineEntrySerializer
- Queryset: `QuarantineEntry.objects.select_related('email').filter(email__status__in=['QUARANTINED', 'BLOCKED'])` ordered by `-created_at`
- Filters (query params):
  - `status` (exact match, e.g., `?status=PENDING`)

**QuarantineActionView**
- Method: POST
- URL: `/api/quarantine/<int:pk>/action/`
- Auth: IsAuthenticated + custom permission (user.role in ['ADMIN', 'ANALYST'])
- Input serializer: QuarantineActionSerializer
- Logic:
  - `release`: QuarantineEntry.status = "RELEASED", Email.status = "DELIVERED", QuarantineEntry.reviewed_at = now(), reviewer = request.user
  - `block`: QuarantineEntry.status = "BLOCKED", Email.status = "BLOCKED", QuarantineEntry.reviewed_at = now(), reviewer = request.user
  - `delete`: Permanently delete the Email record (cascades to QuarantineEntry, AnalysisResult, etc.)
- Response on success: 200 with updated QuarantineEntrySerializer (or 204 for delete)
- Response on invalid action: 400

**DashboardStatsView**
- Method: GET
- URL: `/api/dashboard/stats/`
- Auth: IsAuthenticated
- Serializer: DashboardStatsSerializer
- Logic: Aggregate counts from Email, QuarantineEntry, MaliciousHash, MaliciousDomain. Compute `last_sync` as the max of `MaliciousHash.objects.aggregate(Max('added_at'))` and `MaliciousDomain.objects.aggregate(Max('added_at'))`.

#### 5c. Custom Permission (`emails/permissions.py`)

**IsAnalystOrAbove:**
- Returns True if `request.user.role in ('ADMIN', 'ANALYST')`
- Returns False for VIEWER role
- Used on QuarantineActionView

#### 5d. URL Configuration

**`emails/urls.py` (new file):**

| Method | URL Pattern                        | View                | Name                  |
|--------|------------------------------------|---------------------|-----------------------|
| GET    | `emails/`                          | EmailListView       | email-list            |
| GET    | `emails/<int:pk>/`                 | EmailDetailView     | email-detail          |
| GET    | `quarantine/`                      | QuarantineListView  | quarantine-list       |
| POST   | `quarantine/<int:pk>/action/`      | QuarantineActionView| quarantine-action     |
| GET    | `dashboard/stats/`                 | DashboardStatsView  | dashboard-stats       |

**`stratos_server/urls.py` update:**

Add: `path('api/', include('emails.urls'))`

The final URL paths will be:
- `/api/emails/`
- `/api/emails/<int:pk>/`
- `/api/quarantine/`
- `/api/quarantine/<int:pk>/action/`
- `/api/dashboard/stats/`

#### 5e. DRF Authentication Configuration

Update `REST_FRAMEWORK` in `base.py`:

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}
```

Add `'rest_framework.authtoken'` to `INSTALLED_APPS` (generates a migration for the Token model).

Update PAGE_SIZE from 25 to 20 to match API spec.

### 6. Files Created or Modified (Summary)

| File                                              | Action   |
|---------------------------------------------------|----------|
| `emails/services/decider.py`                      | CREATE   |
| `emails/services/analyzer.py`                     | MODIFY   |
| `emails/serializers.py`                           | CREATE   |
| `emails/api_views.py`                             | CREATE   |
| `emails/permissions.py`                           | CREATE   |
| `emails/urls.py`                                  | CREATE   |
| `threat_intel/tasks.py`                           | CREATE   |
| `threat_intel/management/__init__.py`             | CREATE   |
| `threat_intel/management/commands/__init__.py`    | CREATE   |
| `threat_intel/management/commands/sync_ti_feeds.py` | CREATE |
| `stratos_server/settings/base.py`                 | MODIFY   |
| `stratos_server/urls.py`                          | MODIFY   |

## Out of Scope

- Frontend templates and dashboard UI (Phase 6)
- VirusTotal API integration (future enhancement)
- AbuseIPDB API integration (future enhancement)
- Report generation and PDF export (Phase 7)
- MaliciousIP feed sync (no feed source defined yet)
- Email body_html in API responses (excluded to reduce payload size)
- Bulk quarantine actions (single-item only in this phase)
- API rate limiting / throttling (Phase 8 hardening)
- WebSocket / real-time push notifications
- Attachment file download endpoint (attachments are metadata-only)

## Acceptance Criteria

| ID     | Criterion                                                                                          | Pass Condition                                                                                       |
|--------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| AC-001 | Decider produces MALICIOUS verdict for high score                                                  | Given preprocess_score=30 + check_score=50 (total=80), decide() returns verdict=MALICIOUS, action=BLOCK. QuarantineEntry created. |
| AC-002 | Decider produces SUSPICIOUS verdict for medium score                                               | Given total_score=30, decide() returns verdict=SUSPICIOUS, action=QUARANTINE. QuarantineEntry created. |
| AC-003 | Decider produces CLEAN verdict for low score                                                       | Given total_score=10, decide() returns verdict=CLEAN, action=DELIVER. No QuarantineEntry created.    |
| AC-004 | Known malware override forces MALICIOUS                                                            | Given has_known_malware=True and total_score=20, decide() returns verdict=MALICIOUS, total_score=100, action=BLOCK, override_reason="known_malware_hash". |
| AC-005 | Total score never exceeds 100                                                                      | Given preprocess_score=60 + check_score=80 (raw=140), decide() returns total_score=100.              |
| AC-006 | sync_ti_feeds command completes without error                                                      | `call_command('sync_ti_feeds', feed='all')` with mocked HTTP responses completes without raising exceptions. stdout contains import counts. |
| AC-007 | MaliciousHash records created after MalwareBazaar sync                                             | After `sync_ti_feeds --feed=malwarebazaar` with mocked CSV containing 5 valid rows, MaliciousHash.objects.count() >= 5. |
| AC-008 | GET /api/emails/ returns paginated list with verdict                                               | Authenticated GET to `/api/emails/` returns HTTP 200. Response body contains `results` array. Each item has `id`, `verdict`, `score`. Response contains `count`, `next`, `previous`. |
| AC-009 | GET /api/emails/<id>/ returns full detail with nested analysis                                     | Authenticated GET to `/api/emails/<valid_id>/` returns HTTP 200. Response contains `analysis` object with `preprocess_score`, `total_score`. Response contains `attachments` array. |
| AC-010 | GET /api/quarantine/ returns only QUARANTINED/BLOCKED emails                                       | Authenticated GET to `/api/quarantine/` returns HTTP 200. Every item in `results` has its nested email.status in ["QUARANTINED", "BLOCKED"]. |
| AC-011 | POST quarantine action "release" changes status to DELIVERED                                       | Authenticated POST to `/api/quarantine/<id>/action/` with `{"action": "release"}` by ANALYST user returns 200. Email.status becomes "DELIVERED". QuarantineEntry.status becomes "RELEASED". |
| AC-012 | POST quarantine action by VIEWER returns 403                                                       | Authenticated POST to `/api/quarantine/<id>/action/` with `{"action": "release"}` by VIEWER user returns HTTP 403. |
| AC-013 | GET /api/dashboard/stats/ returns correct aggregate counts                                         | Given 3 CLEAN, 2 SUSPICIOUS, 1 MALICIOUS emails in DB, GET `/api/dashboard/stats/` returns `clean_count=3`, `suspicious_count=2`, `malicious_count=1`, `total_emails=6`. |
| AC-014 | Full pipeline produces verdict and QuarantineEntry                                                 | Call `EmailAnalyzer().analyze(email_id)` on an email with blacklisted sender (score >= 70). Email.verdict == "MALICIOUS", Email.status == "BLOCKED". QuarantineEntry exists for this email. AnalysisResult.pipeline_duration_ms > 0. |
| AC-015 | sync_ti_feeds skips invalid SHA-256 hashes                                                        | Mocked MalwareBazaar CSV contains a row with sha256 of 32 chars. After sync, that row is NOT in MaliciousHash. Valid rows ARE imported. |
| AC-016 | sync_ti_feeds only imports URLhaus rows where url_status is "online"                               | Mocked URLhaus CSV has 3 rows: 2 with url_status="online", 1 with url_status="offline". After sync, MaliciousDomain.objects.count() == 2. |

## API Contracts

### GET /api/emails/

**Auth:** Session or Token (IsAuthenticated)

**Query Parameters:**

| Param        | Type   | Required | Description                            |
|--------------|--------|----------|----------------------------------------|
| verdict      | string | No       | Filter by exact verdict (CLEAN, SUSPICIOUS, MALICIOUS) |
| status       | string | No       | Filter by exact status                 |
| from_address | string | No       | Case-insensitive contains filter       |
| date_from    | string | No       | ISO 8601 datetime, received_at >=      |
| date_to      | string | No       | ISO 8601 datetime, received_at <=      |
| page         | int    | No       | Page number, default 1                 |

**Response 200:**

```json
{
  "count": 42,
  "next": "http://localhost:8000/api/emails/?page=2",
  "previous": null,
  "results": [
    {
      "id": 1,
      "message_id": "<abc@example.com>",
      "from_address": "sender@example.com",
      "from_display_name": "Sender Name",
      "subject": "Test Email",
      "verdict": "CLEAN",
      "score": 5,
      "confidence": "HIGH",
      "status": "DELIVERED",
      "received_at": "2026-04-07T10:00:00Z"
    }
  ]
}
```

**Response 401:** `{"detail": "Authentication credentials were not provided."}`

---

### GET /api/emails/<int:pk>/

**Auth:** Session or Token (IsAuthenticated)

**Response 200:**

```json
{
  "id": 1,
  "message_id": "<abc@example.com>",
  "from_address": "sender@example.com",
  "from_display_name": "Sender Name",
  "subject": "Test Email",
  "verdict": "MALICIOUS",
  "score": 85,
  "confidence": "MEDIUM",
  "status": "BLOCKED",
  "received_at": "2026-04-07T10:00:00Z",
  "to_addresses": ["recipient@example.com"],
  "reply_to": null,
  "body_text": "Click here to verify your account...",
  "urls_extracted": ["http://evil.com/phish"],
  "analyzed_at": "2026-04-07T10:00:15Z",
  "created_at": "2026-04-07T10:00:01Z",
  "analysis": {
    "id": 1,
    "preprocess_score": 35,
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail",
    "is_reply_to_mismatch": false,
    "is_display_spoof": false,
    "keyword_score": 10,
    "keywords_matched": ["verify your account", "click here immediately"],
    "url_score": 30,
    "url_findings": [{"url": "http://evil.com/phish", "type": "malicious_domain", "domain": "evil.com"}],
    "attachment_score": 0,
    "attachment_findings": [],
    "chain_score": 0,
    "chain_findings": {},
    "total_score": 85,
    "pipeline_duration_ms": 145,
    "created_at": "2026-04-07T10:00:15Z"
  },
  "attachments": [
    {
      "id": 1,
      "filename": "invoice.pdf",
      "content_type": "application/pdf",
      "size_bytes": 12345,
      "sha256_hash": "a1b2c3...",
      "md5_hash": "d4e5f6...",
      "file_magic": "application/pdf",
      "is_dangerous_ext": false,
      "is_double_ext": false,
      "is_mime_mismatch": false,
      "yara_matches": null,
      "ti_match": null,
      "created_at": "2026-04-07T10:00:01Z"
    }
  ]
}
```

**Response 404:** `{"detail": "Not found."}`

---

### GET /api/quarantine/

**Auth:** Session or Token (IsAuthenticated)

**Query Parameters:**

| Param  | Type   | Required | Description                             |
|--------|--------|----------|-----------------------------------------|
| status | string | No       | Filter by quarantine status (PENDING, RELEASED, DELETED, BLOCKED) |
| page   | int    | No       | Page number, default 1                  |

**Response 200:**

```json
{
  "count": 5,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 1,
      "status": "PENDING",
      "action": "QUARANTINE",
      "reviewed_at": null,
      "notes": "",
      "created_at": "2026-04-07T10:00:15Z",
      "email": {
        "id": 3,
        "message_id": "<phish@evil.com>",
        "from_address": "phish@evil.com",
        "from_display_name": "PayPal Security",
        "subject": "Urgent: Verify your account",
        "verdict": "SUSPICIOUS",
        "score": 45,
        "confidence": "LOW",
        "status": "QUARANTINED",
        "received_at": "2026-04-07T09:55:00Z"
      }
    }
  ]
}
```

---

### POST /api/quarantine/<int:pk>/action/

**Auth:** Session or Token (IsAuthenticated + IsAnalystOrAbove)

**Request Body:**

```json
{
  "action": "release",
  "notes": "Reviewed by analyst, false positive"
}
```

Valid `action` values: `"release"`, `"block"`, `"delete"`

**Response 200 (release/block):**

```json
{
  "id": 1,
  "status": "RELEASED",
  "action": "QUARANTINE",
  "reviewed_at": "2026-04-07T11:00:00Z",
  "notes": "Reviewed by analyst, false positive",
  "created_at": "2026-04-07T10:00:15Z",
  "email": {
    "id": 3,
    "message_id": "<phish@evil.com>",
    "from_address": "phish@evil.com",
    "from_display_name": "PayPal Security",
    "subject": "Urgent: Verify your account",
    "verdict": "SUSPICIOUS",
    "score": 45,
    "confidence": "LOW",
    "status": "DELIVERED",
    "received_at": "2026-04-07T09:55:00Z"
  }
}
```

**Response 204 (delete):** No content. Email and all related records permanently deleted.

**Response 400:** `{"action": ["Invalid action. Choose from: release, block, delete."]}`

**Response 403:** `{"detail": "You do not have permission to perform this action."}`

**Response 404:** `{"detail": "Not found."}`

---

### GET /api/dashboard/stats/

**Auth:** Session or Token (IsAuthenticated)

**Response 200:**

```json
{
  "total_emails": 150,
  "clean_count": 120,
  "suspicious_count": 20,
  "malicious_count": 10,
  "pending_count": 0,
  "quarantine_pending": 8,
  "ti_hashes": 4500,
  "ti_domains": 1200,
  "last_sync": "2026-04-07T02:30:00Z"
}
```

## Data Model Changes

No new models or fields. All existing models (Email, AnalysisResult, QuarantineEntry, MaliciousHash, MaliciousDomain) already have the required fields from Phase 1.

One migration will be generated for the `rest_framework.authtoken` app (Token model) when it is added to INSTALLED_APPS.

## Dependencies

| Dependency                          | Status    | Notes                                                   |
|-------------------------------------|-----------|---------------------------------------------------------|
| Phase 1: All 15 Django models       | DONE      | Email, AnalysisResult, QuarantineEntry, MaliciousHash, MaliciousDomain |
| Phase 2: Gmail ingestion + parser   | DONE      | fetch_gmail_task, EmailParser, GmailConnector           |
| Phase 3: Preprocessor               | DONE      | PreprocessResult dataclass, Preprocessor.process()      |
| Phase 4: Checker engine             | DONE      | CheckResult dataclass, Checker.check_all()              |
| `requests` library                  | INSTALLED | Already in requirements.txt (2.31.0)                    |
| `djangorestframework`               | INSTALLED | Already in requirements.txt (3.14.0) and INSTALLED_APPS |

## Open Questions

| ID     | Question                                                                                     | Recommendation                                                |
|--------|----------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| OQ-001 | Should the API use DRF TokenAuthentication, SessionAuthentication, or both?                  | Both. SessionAuthentication for browser-based dashboard (Phase 6), TokenAuthentication for API clients and testing. This is standard DRF practice. |
| OQ-002 | Should sync_ti_feeds use `requests` or `urllib`?                                             | `requests` -- already in requirements.txt (v2.31.0), simpler API, better error handling. |
| OQ-003 | Should QuarantineActionView "delete" action permanently delete or soft-delete?               | Permanent delete (CASCADE). The brief specifies permanent deletion. Soft-delete adds complexity with no clear benefit for an academic project. |
| OQ-004 | Should the Decider read thresholds from Django settings or use hardcoded constants?          | Read from `settings.CLEAN_THRESHOLD` and `settings.MALICIOUS_THRESHOLD` (already defined in base.py) with class-level defaults as fallback. This makes thresholds configurable without code changes. |
| OQ-005 | Should unauthenticated API requests return 401 or redirect to login?                        | Return 401 JSON response. The API is consumed by JavaScript (Phase 6), not browsers directly. DRF default behavior with SessionAuthentication + TokenAuthentication handles this correctly. |

## Test Plan

The qa-agent should create `tests/test_phase5.py` covering:

### Decider Unit Tests (6 tests)
- Test MALICIOUS verdict for score >= 70 (AC-001)
- Test SUSPICIOUS verdict for score 25-69 (AC-002)
- Test CLEAN verdict for score < 25 (AC-003)
- Test known malware override to MALICIOUS (AC-004)
- Test score capping at 100 (AC-005)
- Test confidence levels: HIGH (score >= 90), MEDIUM (score 70-89), LOW (suspicious), HIGH (score < 10), MEDIUM (score 10-24)

### EmailAnalyzer Integration Tests (3 tests)
- Test full pipeline: PENDING -> ANALYZING -> verdict set, AnalysisResult.total_score populated, pipeline_duration_ms > 0 (AC-014)
- Test QuarantineEntry created for MALICIOUS verdict
- Test QuarantineEntry NOT created for CLEAN verdict

### TI Feed Sync Tests (4 tests, all with mocked HTTP)
- Test sync_ti_feeds command runs without error (AC-006)
- Test MalwareBazaar sync creates MaliciousHash records (AC-007)
- Test invalid SHA-256 hashes are skipped (AC-015)
- Test URLhaus sync only imports online rows (AC-016)

### API Tests (8 tests)
- Test GET /api/emails/ returns 200 with paginated results (AC-008)
- Test GET /api/emails/<id>/ returns 200 with nested analysis and attachments (AC-009)
- Test GET /api/quarantine/ returns only QUARANTINED/BLOCKED entries (AC-010)
- Test POST /api/quarantine/<id>/action/ release changes status (AC-011)
- Test POST /api/quarantine/<id>/action/ by VIEWER returns 403 (AC-012)
- Test GET /api/dashboard/stats/ returns correct counts (AC-013)
- Test unauthenticated request returns 401
- Test email list filtering by verdict query param

### Celery Task Tests (2 tests)
- Test sync_malwarebazaar_task calls management command
- Test sync_urlhaus_task calls management command

**Total estimated tests: 23**

All TI feed tests MUST mock HTTP requests (use `unittest.mock.patch` on `requests.get`) to avoid external network calls. API tests should use DRF's `APITestCase` and `APIClient` with `force_authenticate()`.
