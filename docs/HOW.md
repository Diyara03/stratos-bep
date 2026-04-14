# Stratos -- Technical Implementation Reference

## Status: Phase 8 COMPLETE + System Settings + Production Deployment (473 tests)
(updated automatically after each phase by documenter subagent)

---

## Running Locally (without Docker) -- Phase 0
Location: `manage.py` (project root)
Purpose: Start the Django development server with SQLite database for rapid iteration.

```
# Prerequisites: Python 3.10+, pip
cd Stratos
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

When `DATABASE_URL` is not set, `dev.py` falls back to SQLite at `db.sqlite3`.
Redis/Celery are not required for basic web development -- tasks will fail silently.

---

## Running with Docker -- Phase 0
Location: `docker-compose.yml`, `Dockerfile` (project root)
Purpose: Full 5-service stack matching production architecture.

```
cp .env.example .env
docker compose up --build
```

Services start in order: postgres -> redis -> django (runs migrate, then runserver) -> celery + celery-beat.
All health checks must pass before dependent services start.

Django accessible at: `http://localhost:8000`
Health check at: `http://localhost:8000/health/`

---

## Health Endpoint -- Phase 0
Location: `stratos_server/views.py`
Purpose: Liveness and readiness probe for Docker healthcheck and monitoring.
Key method: `health(request)` -> `JsonResponse`
Input: HTTP GET request (no parameters, no authentication)
Output: JSON with keys `status`, `version`, `db`; HTTP 200 or 503
Called by: Docker healthcheck (every 10s), manual testing
Calls: `django.db.connection.ensure_connection()`
Performance: O(1) -- single lightweight DB connection check

Response on success (200):
```json
{"status": "ok", "version": "0.1.0", "db": "connected"}
```

Response on DB failure (503):
```json
{"status": "degraded", "version": "0.1.0", "db": "unavailable"}
```

---

## Celery Configuration -- Phase 0
Location: `stratos_server/celery.py`
Purpose: Configure Celery app for async task processing.
Key method: `app = Celery('stratos_server')` with `autodiscover_tasks()`
Input: Settings from `django.conf:settings` with `CELERY` namespace prefix
Output: Celery app instance available as `stratos_server.celery_app`
Called by: Celery worker process (`celery -A stratos_server worker`)
Calls: Redis broker at `CELERY_BROKER_URL`

Settings in `base.py`:
- `CELERY_BROKER_URL`: from `REDIS_URL` env var, default `redis://localhost:6379/0`
- `CELERY_RESULT_BACKEND`: same as broker URL
- Serialization: JSON only (`CELERY_ACCEPT_CONTENT`, `CELERY_TASK_SERIALIZER`, `CELERY_RESULT_SERIALIZER`)
- Timezone: UTC

The `stratos_server/__init__.py` imports the Celery app so Django loads it on startup:
```python
from .celery import app as celery_app
__all__ = ['celery_app']
```

---

## Custom User Model -- Phase 0
Location: `accounts/models.py`
Purpose: Role-based user model extending Django's AbstractUser.
Key method: Inherits all AbstractUser methods (create_user, authenticate, etc.)
Input: Standard Django user fields + `role`, `department`, `last_login_ip`
Output: User instances stored in `stratos_user` table
Called by: Django auth system, admin panel, future API views
Calls: Nothing (data model only)

Fields added beyond AbstractUser:
| Field          | Type                     | Default  | Purpose                    |
|----------------|--------------------------|----------|----------------------------|
| role           | CharField(max_length=10) | 'VIEWER' | RBAC: ADMIN/ANALYST/VIEWER |
| department     | CharField(max_length=100)| ''       | Organizational grouping    |
| last_login_ip  | GenericIPAddressField    | null     | Audit trail                |

`AUTH_USER_MODEL = 'accounts.User'` is set in `base.py` before any migrations.

---

## Settings Split -- Phase 0
Location: `stratos_server/settings/` (package with `__init__.py`, `base.py`, `dev.py`, `prod.py`)
Purpose: Separate shared, development, and production configuration.

### base.py
- INSTALLED_APPS: 4 project apps + rest_framework + Django defaults
- AUTH_USER_MODEL: `accounts.User`
- REST_FRAMEWORK: IsAuthenticated default, PageNumberPagination (25/page)
- CELERY_*: broker and backend from REDIS_URL
- CLEAN_THRESHOLD: 25 (from env)
- MALICIOUS_THRESHOLD: 70 (from env)

### dev.py
- DEBUG: True
- ALLOWED_HOSTS: `['*']`
- DATABASE: SQLite if no DATABASE_URL; PostgreSQL if DATABASE_URL is set

### prod.py
- DEBUG: False
- ALLOWED_HOSTS: from env (comma-separated)
- DATABASE: PostgreSQL required (parsed from DATABASE_URL)

---

## Dockerfile -- Phase 0
Location: `Dockerfile` (project root)
Purpose: Build image for django, celery, and celery-beat services.
Base: `python:3.10-slim`
System deps: `libssl-dev`, `libjansson-dev`, `libmagic1`, `build-essential`, `curl`, `automake`, `libtool`, `pkg-config`
Python deps: 13 packages from `requirements.txt`

---

## Test Suite -- Phase 0
Location: `tests/test_phase0.py`
Purpose: Verify all Phase 0 acceptance criteria (AC-001 through AC-010).
Test count: 26 test methods across 6 test classes.
Run with: `python manage.py test tests`

| Test Class            | Count | Covers                                     |
|-----------------------|-------|---------------------------------------------|
| HealthEndpointTests   | 3     | AC-003: /health/ returns 200 with JSON      |
| CustomUserTests       | 7     | AC-005, AC-006: User model fields and roles |
| SettingsTests         | 9     | AC-005, AC-007, AC-010: config validation   |
| FileExistenceTests    | 2     | AC-008: all required files + .env.example   |
| SystemCheckTests      | 2     | AC-001, AC-002: migrations + system check   |
| CeleryConfigTests     | 2     | AC-009: Celery app configuration            |

---

## Model Organization -- Phase 1
Location: `emails/models.py`, `threat_intel/models.py`, `reports/models.py`
Purpose: 15 Django models across 4 apps, separated by domain responsibility.

The four apps follow separation of concerns:
- **emails** holds all pipeline data: the email itself, its attachments, per-stage analysis scores, quarantine state, and extracted IOCs. Everything here is created or mutated by the analysis pipeline.
- **threat_intel** holds reference data consumed by the pipeline: known-bad indicators (hashes, domains, IPs), YARA rules, and whitelist/blacklist entries. These are populated by TI feed syncs and manual admin entry.
- **reports** holds export artifacts: on-demand reports, scheduled reports, and IOC exports. These read from emails and threat_intel but never write back.
- **accounts** holds the User model with role-based access. It is referenced by FK from quarantine (reviewer), whitelist/blacklist (added_by), and reports (generated_by/created_by).

---

## Email Model -- Pipeline Flow -- Phase 1
Location: `emails/models.py`
Purpose: Central entity representing a single incoming email. Tracks its lifecycle from ingestion to verdict.

Key lifecycle (status field transitions):
```
PENDING --> ANALYZING --> DELIVERED (if CLEAN)
                     --> QUARANTINED (if SUSPICIOUS/MALICIOUS)
                     --> BLOCKED (if explicitly blocked)
```

The `verdict` field (CLEAN/SUSPICIOUS/MALICIOUS) and `score` (0-100) are null until the Decider completes. The `analyzed_at` timestamp records when analysis finished. `received_at` records when the email was received by Gmail.

JSONField usage on Email:
- `to_addresses`: list of recipient emails (variable length)
- `cc_addresses`: list of CC recipients (optional)
- `headers_raw`: dict of all raw email headers (arbitrary key-value pairs)
- `received_chain`: list of Received header hops (variable length)
- `urls_extracted`: list of URLs found in body (variable length)

These use JSONField because email structure varies per message. A relational table for each would add unnecessary joins for data that is always read/written as a unit.

---

## AnalysisResult Model -- Per-Stage Scores -- Phase 1
Location: `emails/models.py`
Purpose: Stores the breakdown of scores from each analysis stage, linked 1:1 to an Email.

The OneToOne relationship to Email ensures exactly one analysis result per email. Scores are broken down by stage:

| Field              | Stage        | Range    | Purpose                          |
|--------------------|--------------|----------|----------------------------------|
| preprocess_score   | Preprocessor | 0-75     | SPF/DKIM/DMARC + blacklist hits  |
| keyword_score      | Checker      | 0-20     | Phishing keyword matches         |
| url_score          | Checker      | 0-40     | Malicious URL detections         |
| attachment_score   | Checker      | 0-50     | File hash/YARA/magic findings    |
| chain_score        | Checker      | 0-15     | Received chain anomalies         |
| total_score        | Decider      | 0-100+   | Sum of all stage scores          |

Auth check results (spf_result, dkim_result, dmarc_result) and boolean flags (is_reply_to_mismatch, is_display_spoof) store the detail behind the preprocess_score.

JSONField usage: `keywords_matched` (list), `url_findings` (list), `attachment_findings` (list), `chain_findings` (dict) store detailed evidence for each detection.

`pipeline_duration_ms` records total analysis time (target: <30000ms).

---

## Threat Intel Models -- Checker Feed -- Phase 1
Location: `threat_intel/models.py`
Purpose: Reference tables of known-bad indicators that the Checker stage queries during analysis.

How they feed into checking (Phase 4):
- **MaliciousHash**: Checker compares `EmailAttachment.sha256_hash` against `MaliciousHash.sha256_hash`. A match triggers override to MALICIOUS regardless of score.
- **MaliciousDomain**: Checker compares extracted URLs' domains against `MaliciousDomain.domain`. Matches contribute to `url_score`.
- **MaliciousIP**: Checker compares received chain IPs against `MaliciousIP.ip_address`. Matches contribute to `chain_score`.
- **YaraRule**: Checker loads active rules (`is_active=True`) and scans attachment content. Matches recorded in `EmailAttachment.yara_matches`.
- **WhitelistEntry**: Preprocessor checks sender email/domain against whitelist. Match triggers `verdict_override=CLEAN`, skipping all further analysis.
- **BlacklistEntry**: Preprocessor checks sender against blacklist. Match adds +40 (email) or +30 (domain) to `preprocess_score`.

All TI models have `source` fields tracking provenance (MALWAREBAZAAR, URLHAUS, VIRUSTOTAL, ABUSEIPDB, MANUAL).

---

## Reports Models -- Phase 1
Location: `reports/models.py`
Purpose: Track generated report artifacts and scheduled report jobs.

- **Report**: Represents a single generated report file. `output_format` (renamed from `format` to avoid shadowing Python builtin) stores CSV/JSON/PDF. `filters_applied` (JSONField) records the query parameters used.
- **ScheduledReport**: Defines recurring report generation. `schedule` (DAILY/WEEKLY/MONTHLY) + `next_run` datetime drive Celery Beat scheduling.
- **IOCExport**: Specialized export of IOC data in CSV/JSON/STIX formats. Separate from Report because IOC exports have different fields (ioc_types filter, STIX format option).

---

## Django Admin Registration -- Phase 1
Location: `emails/admin.py`, `threat_intel/admin.py`, `reports/admin.py`
Purpose: All 15 models registered with list_display, list_filter, and search_fields for admin usability.
Each ModelAdmin class provides useful column display and filtering. The admin interface serves as the primary data inspection tool until the dashboard UI is built in Phase 6.

---

## Test Suite -- Phase 1
Location: `tests/test_phase1.py`
Purpose: Verify all Phase 1 acceptance criteria (AC-001 through AC-010).
Test count: 26 test methods.
Run with: `python manage.py test tests.test_phase1`

| Category                    | Count | Covers                                          |
|-----------------------------|-------|--------------------------------------------------|
| Model Import Tests          | 3     | AC-003, AC-004, AC-005: all models importable   |
| Model Creation Tests        | 6     | AC-006: CRUD for all model types                |
| Default Value Tests         | 3     | Field defaults (PENDING, score=0, severity=HIGH)|
| Constraint Tests            | 4     | AC-007, AC-008, AC-009: unique, OneToOne, choice|
| String Representation Tests | 3     | __str__ methods return expected formats          |
| Admin Registration Tests    | 3     | AC-010: all 15 models in admin registry         |
| Cascade/SET_NULL Tests      | 2     | FK cascade and SET_NULL behavior                |
| Migration Integrity Tests   | 1     | No unapplied migrations                         |
| JSONField Default Tests     | 1     | Empty list/dict defaults on Email               |

---

## GmailConnector -- Phase 2
Location: `emails/services/gmail_connector.py`
Purpose: OAuth-authenticated Gmail API client for email ingestion.
Key method: `fetch_new_emails(max_results=10)` -> `list[dict]`
Called by: `fetch_gmail_task` (Celery), `fetch_emails` management command
Calls: Gmail API (messages.list, messages.get, messages.modify), `Email.objects.filter` for dedup

| Method                 | Purpose                                   | Returns          |
|------------------------|-------------------------------------------|------------------|
| `__init__()`           | Authenticate via OAuth, build service      | None             |
| `_authenticate()`      | Load/refresh JSON token, InstalledAppFlow  | Gmail service    |
| `fetch_new_emails()`   | List INBOX, skip known gmail_ids, get full | list[dict]       |
| `get_message(id)`      | Get single message in full format          | dict             |
| `mark_as_read(id)`     | Remove UNREAD label                        | None             |
| `_fetch_attachment_data(msg_id, att_id)` | Fetch large attachment | bytes |

Environment variables: `GMAIL_CREDENTIALS_PATH`, `GMAIL_TOKEN_PATH`
OAuth scope: `https://www.googleapis.com/auth/gmail.modify`

## EmailParser -- Phase 2
Location: `emails/services/parser.py`
Purpose: Parse raw Gmail API message dicts into Email model instances and attachment metadata.
Key method: `parse_gmail_message(raw_message)` -> `tuple[Email, list[dict]]`
Called by: `fetch_gmail_task`, `fetch_emails` management command

| Method                      | Extracts                                           |
|-----------------------------|-----------------------------------------------------|
| `_extract_header_value()`   | Single header value by name (case-insensitive)      |
| `_extract_message_id()`     | Message-ID without angle brackets                   |
| `_extract_from()`           | Display name + email address (parseaddr)            |
| `_extract_to()`             | List of To: email addresses                         |
| `_extract_cc()`             | List of Cc: email addresses                         |
| `_extract_subject()`        | Subject with RFC 2047 decoding                      |
| `_extract_date()`           | Timezone-aware datetime (fallback: now())           |
| `_extract_reply_to()`       | Reply-To email address or None                      |
| `_extract_body()`           | body_text + body_html from multipart traversal      |
| `_extract_urls()`           | Deduplicated URLs from text (regex) + HTML (BS4)    |
| `_extract_attachments()`    | Attachment metadata + SHA-256/MD5 hashes            |
| `_extract_received_chain()` | List of {from_server, by_server, timestamp_str}     |
| `_extract_auth_results()`   | {spf, dkim, dmarc} from Authentication-Results      |
| `_compute_hashes()`         | (sha256_hex, md5_hex) from raw bytes                |

## EmailAnalyzer (Stub) -- Phase 2
Location: `emails/services/analyzer.py`
Purpose: Pipeline orchestrator stub. Real logic added in Phase 3+.
Key method: `analyze(email_id)` -> None (updates Email.status in-place)
Phase 2 behavior: Sets status ANALYZING -> PENDING (placeholder).
**NOTE: Upgraded in Phase 3 -- see EmailAnalyzer (Phase 3) section below.**

## Celery Tasks -- Phase 2
Location: `emails/tasks.py`

| Task                  | Trigger          | Retries | Returns                              |
|-----------------------|------------------|---------|--------------------------------------|
| `fetch_gmail_task`    | Beat (every 10s) | None    | {fetched, skipped, errors}           |
| `analyze_email_task`  | .delay(email_id) | 3 @ 60s | {email_id, status}                   |

## Management Command -- Phase 2
Location: `emails/management/commands/fetch_emails.py`
Usage: `python manage.py fetch_emails --max N --dry-run`
Dry-run mode prints subjects/senders without saving to DB.

## Test Suite -- Phase 2
Location: `tests/test_phase2.py` (29 tests, 105 total)
Fixtures: `tests/fixtures/test_gmail_message.json`, `tests/fixtures/phishing_gmail_message.json`
All Gmail API calls mocked -- no network access in tests.

---

## Preprocessor -- Phase 3
Location: `emails/services/preprocessor.py`
Purpose: First pipeline stage. Performs fast triage checks on email authentication headers, whitelist/blacklist status, and BEC signals (Reply-To mismatch, display name spoof). Returns a PreprocessResult dataclass with score and findings.
Key method: `process(email)` -> `PreprocessResult`
Input: Email model instance (requires from_address, reply_to, from_display_name, headers_raw)
Output: PreprocessResult dataclass (score: int, findings: dict, verdict_override: str|None, spf_result, dkim_result, dmarc_result, is_reply_to_mismatch, is_display_spoof)
Called by: EmailAnalyzer.analyze()
Calls: WhitelistEntry.objects.filter(), BlacklistEntry.objects.filter()
Performance: O(1) whitelist/blacklist lookups (indexed by entry_type + value). No external API calls. Regex-based header parsing is O(n) on header length (typically <1KB).

### Sub-methods

| Method                       | Purpose                                  | Returns                          |
|------------------------------|------------------------------------------|----------------------------------|
| `_check_whitelist(addr)`     | EMAIL then DOMAIN lookup in WhitelistEntry | `(bool, PreprocessResult\|None)` |
| `_check_blacklist(addr)`     | EMAIL (+40) then DOMAIN (+30) in BlacklistEntry | `(dict, int)`              |
| `_check_email_auth(headers)` | Regex parse Authentication-Results header | `(dict, int, str, str, str)`    |
| `_check_reply_to_mismatch(email)` | Compare From domain vs Reply-To domain | `(bool, int, dict)`          |
| `_check_display_spoof(email)` | Detect foreign domain in display name   | `(bool, int, dict)`             |

### Scoring Table

| Check   | Condition        | Score |
|---------|------------------|-------|
| SPF     | fail             | +15   |
| SPF     | softfail         | +5    |
| SPF     | none/missing     | +10   |
| SPF     | pass             | +0    |
| DKIM    | fail             | +15   |
| DKIM    | none/missing     | +5    |
| DKIM    | pass             | +0    |
| DMARC   | fail             | +15   |
| DMARC   | none/missing     | +5    |
| DMARC   | pass             | +0    |
| Blacklist | email match    | +40   |
| Blacklist | domain match   | +30   |
| Reply-To  | domain mismatch| +10   |
| Display   | spoof detected | +10   |
| Whitelist | match          | verdict_override=CLEAN (score=0, skip all) |

Maximum preprocess_score (no whitelist): 15 + 15 + 15 + 40 + 30 + 10 + 10 = 135 (theoretical; capped by thresholds at Decider stage)

### Auth Header Parsing

The `_check_email_auth()` method parses the `Authentication-Results` header from `headers_raw` (a list of `{name, value}` dicts from Gmail API). It uses three regex patterns:
- `spf=(\w+)` -- extracts pass/fail/softfail/none
- `dkim=(\w+)` -- extracts pass/fail/none
- `dmarc=(\w+)` -- extracts pass/fail/none

Unknown or unparseable values default to 'none' (scored as missing).

### Display Name Spoof Detection

Two detection methods:
1. Email-like pattern: If display name contains `@`, extract domain after `@` and compare to From domain
2. Domain-like pattern: Regex matches common TLDs (.com, .org, .net, .edu, .gov, .io, .co, .uk, .ru, .info, .biz) in display name and compares to From domain

Both trigger +10 if the embedded domain differs from the actual From domain.

---

## EmailAnalyzer (Upgraded) -- Phase 3
Location: `emails/services/analyzer.py`
Purpose: Pipeline orchestrator. Calls Preprocessor as Stage 1. Manages Email status transitions and AnalysisResult persistence.
Key method: `analyze(email_id)` -> `None`
Input: email_id (int, primary key)
Output: Updates Email and AnalysisResult in database
Called by: analyze_email_task (Celery)
Calls: Preprocessor.process(), AnalysisResult.objects.update_or_create(), Email.save()
Performance: One SELECT (email), one Preprocessor.process() call (see above), one INSERT/UPDATE (AnalysisResult), one UPDATE (Email). Total: 3-4 DB queries.

### Pipeline Flow (Phase 3)

1. Fetch Email with `select_related('analysis')` (single query)
2. Set `status='ANALYZING'`
3. Call `Preprocessor().process(email)` -> PreprocessResult
4. If `verdict_override == 'CLEAN'`: call `_finalize()` (sets DELIVERED, score=0, confidence=HIGH)
5. Else: call `_save_preprocess_result()` (saves scores, leaves status=ANALYZING for Phase 4 Checker)

### Helper Methods

| Method                          | Purpose                                    |
|---------------------------------|--------------------------------------------|
| `_finalize(email, result, ...)` | Set final verdict/status, create AnalysisResult, timestamp analyzed_at |
| `_save_preprocess_result(email, result)` | Write preprocess scores to AnalysisResult without finalizing |

---

## Test Suite -- Phase 3
Location: `tests/test_phase3.py` (32 tests, 137 total across 4 test files)
Tests cover: whitelist short-circuit, blacklist scoring (+40 email, +30 domain), SPF/DKIM/DMARC scoring (all combinations), Reply-To mismatch detection, display name spoof detection, error resilience (process() never raises), EmailAnalyzer integration with Preprocessor.
No new fixtures required -- tests create Email instances and WhitelistEntry/BlacklistEntry records inline.

---

## Checker -- Phase 4
Location: `emails/services/checker.py`
Purpose: Stage 2 of the analysis pipeline. Performs content-level threat detection across 4 sub-checkers: keywords, URLs, attachments, and received chain. Returns a CheckResult dataclass with per-sub-checker scores and findings.
Key method: `check_all(email)` -> `CheckResult`
Input: Email model instance (requires subject, body_text, urls_extracted, received_chain, attachments relation)
Output: CheckResult dataclass (keyword_score, keywords_matched, url_score, url_findings, attachment_score, attachment_findings, chain_score, chain_findings, total_check_score, has_known_malware)
Called by: EmailAnalyzer.analyze()
Calls: MaliciousDomain.objects.filter(), MaliciousHash.objects.filter(), ExtractedIOC.objects.create(), EmailAttachment.save()
Performance: O(K) keyword scan where K=24 keywords x text length. O(U) URL checks where U=number of URLs, each with one DB query. O(A) attachment checks where A=number of attachments, each with one DB query. O(H) chain checks where H=hop count. All DB lookups hit indexed fields.

### Sub-methods

| Method                        | Purpose                                         | Returns                              |
|-------------------------------|--------------------------------------------------|--------------------------------------|
| `_check_keywords(email)`      | Scan subject+body for 24 phishing keywords       | `(int, list[str])`                   |
| `_check_urls(email)`          | Check URLs against MaliciousDomain, IP, shortener| `(int, list[dict])`                  |
| `_check_attachments(email)`   | Check hashes, extensions, MIME, YARA             | `(int, list[dict], bool)`            |
| `_check_received_chain(email)`| Detect hop count, private IPs, timestamp disorder| `(int, dict)`                        |

### Keyword Checker Scoring

| Condition                        | Score |
|----------------------------------|-------|
| Each unique keyword match        | +2    |
| Cap                              | 20    |

24 keywords defined as class constant. Case-insensitive substring match on `(subject + ' ' + body_text).lower()`. Duplicate keywords counted once.

### URL Checker Scoring

| Condition                        | Score |
|----------------------------------|-------|
| MaliciousDomain DB match         | +30   |
| IP-based URL (regex)             | +10   |
| URL shortener (8 services)       | +5    |
| Cap                              | 40    |

URL shorteners detected: bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, buff.ly, short.io, rebrand.ly.
MaliciousDomain lookup uses `domain__iexact` for case-insensitive matching.
On malicious domain match, creates `ExtractedIOC(ioc_type='DOMAIN', severity='HIGH', source_checker='url_checker')`.

### Attachment Checker Scoring

| Condition                        | Score |
|----------------------------------|-------|
| MaliciousHash DB match           | +50   |
| Dangerous extension (13 types)   | +15   |
| Double extension                 | +20   |
| MIME mismatch (type vs magic)    | +10   |
| YARA match (pre-populated)       | +25/rule |
| Cap                              | 50    |

Dangerous extensions: .exe .scr .vbs .js .bat .cmd .ps1 .hta .com .dll .msi .pif .wsf
Double extension detected when filename has 3+ dot-separated parts and the last extension is dangerous.
MIME mismatch only checked when both `content_type` and `file_magic` are non-null (graceful skip otherwise).
On malicious hash match, creates `ExtractedIOC(ioc_type='HASH', source_checker='attachment_checker')` and sets `has_known_malware=True`.
EmailAttachment flags updated in-place: `ti_match`, `is_dangerous_ext`, `is_double_ext`, `is_mime_mismatch`.

### Received Chain Checker Scoring

| Condition                        | Score |
|----------------------------------|-------|
| Hop count > 7                    | +5    |
| Private IP in chain              | +5    |
| Timestamp disorder               | +5    |
| Cap                              | 15    |

Private IP detection uses `ipaddress.ip_address(ip).is_private` from Python stdlib.
Timestamp disorder: string comparison of consecutive hop timestamps; first out-of-order pair triggers the flag.
Chain entries handled as both dict (`{from, by, timestamp}`) and plain string formats.

### Error Resilience

Same pattern as Preprocessor (Phase 3): `check_all()` wraps all logic in try/except and returns a safe default `CheckResult()` (all zeros) on any unhandled exception. Each sub-checker also has its own try/except. Individual URL and attachment iterations catch exceptions per-item and continue to the next.

---

## EmailAnalyzer (Upgraded) -- Phase 4
Location: `emails/services/analyzer.py`
Purpose: Pipeline orchestrator. Now calls Preprocessor (Stage 1) then Checker (Stage 2). Manages Email status transitions and AnalysisResult persistence.
Key method: `analyze(email_id)` -> `None`
Input: email_id (int, primary key)
Output: Updates Email and AnalysisResult in database
Called by: analyze_email_task (Celery)
Calls: Preprocessor.process(), Checker.check_all(), AnalysisResult.objects.update_or_create(), AnalysisResult.objects.filter().update(), Email.save()
Performance: Phase 3 queries + Checker queries (see above) + one UPDATE for check results. Total: 5-10 DB queries depending on URL and attachment count.

### New Method: _save_check_result

| Method                             | Purpose                                             |
|------------------------------------|------------------------------------------------------|
| `_save_check_result(email, result)` | Write checker scores and findings to existing AnalysisResult via filter().update() |

Uses `AnalysisResult.objects.filter(email=email).update(...)` instead of `update_or_create()` because the AnalysisResult record already exists from `_save_preprocess_result()`.

### Pipeline Flow (Phase 4)

1. Fetch Email with `select_related('analysis')` (single query)
2. Set `status='ANALYZING'`
3. Call `Preprocessor().process(email)` -> PreprocessResult
4. If `verdict_override == 'CLEAN'`: call `_finalize()` (DELIVERED, score=0) -- Checker skipped
5. Else: call `_save_preprocess_result()`, then `Checker().check_all(email)`, then `_save_check_result()`
6. Email remains in 'ANALYZING' status (Phase 5 Decider will finalize)

---

## Test Suite -- Phase 4
Location: `tests/test_phase4.py` (35 tests, 172 total across 5 test files)
Tests cover: keyword scoring (single match, case-insensitive, cap at 20, zero on no match), URL scoring (IP-based, shortener, malicious domain, IOC creation, cap at 40, cumulative scoring), attachment scoring (malicious hash, dangerous extension, double extension, MIME mismatch, YARA matches, cap at 50, null file_magic graceful skip), received chain scoring (excessive hops, boundary 7 hops, private IP, timestamp disorder, empty chain), integration (check_all sums sub-scores, analyzer calls preprocessor then checker, whitelisted skips checker, results saved to DB), error resilience (check_all catches exceptions, sub-checker failures isolated), performance (checker completes under 200ms).
No new fixtures required -- tests create Email, EmailAttachment, MaliciousDomain, and MaliciousHash records inline.

---

## Decider -- Phase 5
Location: `emails/services/decider.py`
Purpose: Stage 3 of the analysis pipeline. Combines preprocess and check scores into a final verdict, confidence level, and recommended action. Implements known malware hash override and configurable thresholds.
Key method: `decide(preprocess_result, check_result)` -> `DecisionResult`
Input: PreprocessResult (from Preprocessor), CheckResult (from Checker)
Output: DecisionResult dataclass (verdict, total_score, confidence, action, preprocess_score, check_score, override_reason)
Called by: EmailAnalyzer.analyze()
Calls: Nothing (pure decision logic, no DB access)
Performance: O(1) -- arithmetic comparison, no loops or queries

### Decision Logic

1. **Known malware override**: If `check_result.has_known_malware` is True, immediately return MALICIOUS / score=100 / confidence=HIGH / action=BLOCK / override_reason='known_malware_hash'. No score calculation needed.

2. **Normal scoring**: `raw = preprocess_score + check_score`, then `total = min(raw, 100)` to cap the score.

3. **Verdict thresholds** (configurable via Django settings):

| Score Range | Verdict     | Action     | Confidence                                |
|-------------|-------------|------------|-------------------------------------------|
| >= 90       | MALICIOUS   | BLOCK      | HIGH                                      |
| 70-89       | MALICIOUS   | BLOCK      | MEDIUM                                    |
| 25-69       | SUSPICIOUS  | QUARANTINE | LOW                                       |
| 10-24       | CLEAN       | DELIVER    | MEDIUM                                    |
| 0-9         | CLEAN       | DELIVER    | HIGH                                      |

Thresholds read from `settings.CLEAN_THRESHOLD` (default 25) and `settings.MALICIOUS_THRESHOLD` (default 70).

---

## EmailAnalyzer (Full Pipeline) -- Phase 5
Location: `emails/services/analyzer.py`
Purpose: Complete pipeline orchestrator. Calls Preprocessor (Stage 1) -> Checker (Stage 2) -> Decider (Stage 3) -> _finalize. Measures pipeline duration and creates QuarantineEntry for non-DELIVER actions.
Key method: `analyze(email_id)` -> `None`
Input: email_id (int, primary key)
Output: Updates Email, AnalysisResult, and optionally creates QuarantineEntry in database
Called by: analyze_email_task (Celery)
Calls: Preprocessor.process(), Checker.check_all(), Decider.decide(), AnalysisResult.objects.update_or_create(), QuarantineEntry.objects.get_or_create(), Email.save()
Performance: Phase 4 queries + one Decider call (O(1)) + one AnalysisResult upsert + one QuarantineEntry get_or_create. Total: 6-12 DB queries depending on URL/attachment count.

### Pipeline Flow (Phase 5 -- Final)

1. Start timer (`time.time()`)
2. Fetch Email with `select_related('analysis')`
3. Set `status='ANALYZING'`
4. Call `Preprocessor().process(email)` -> PreprocessResult
5. If `verdict_override == 'CLEAN'`: call `_finalize()` (DELIVERED, score=0) -- Checker and Decider skipped
6. Else: `_save_preprocess_result()`, then `Checker().check_all()`, then `_save_check_result()`
7. Call `Decider().decide(preprocess_result, check_result)` -> DecisionResult
8. Call `_finalize()` with verdict, score, confidence, action, and duration_ms

### _finalize Method (Phase 5 upgrade)

| Step | Action |
|------|--------|
| 1    | AnalysisResult.objects.update_or_create() with all scores + pipeline_duration_ms |
| 2    | Email: set verdict, score, confidence, analyzed_at, status (via ACTION_STATUS_MAP) |
| 3    | If action in (QUARANTINE, BLOCK): QuarantineEntry.objects.get_or_create(status=PENDING, action=action) |

### ACTION_STATUS_MAP

| Decider Action | Email Status |
|----------------|-------------|
| DELIVER        | DELIVERED   |
| QUARANTINE     | QUARANTINED |
| BLOCK          | BLOCKED     |

---

## TI Feed Sync Command -- Phase 5
Location: `threat_intel/management/commands/sync_ti_feeds.py`
Purpose: Import threat intelligence data from external feeds into the local database.
Key method: `handle(*args, **options)` (Django management command)
Input: `--feed=all|malwarebazaar|urlhaus` `--limit=5000`
Output: Creates/updates MaliciousHash and MaliciousDomain records. Prints summary to stdout.
Called by: Celery tasks (sync_malwarebazaar_task, sync_urlhaus_task), manual CLI
Calls: requests.get() to external URLs, MaliciousHash.objects.update_or_create(), MaliciousDomain.objects.update_or_create()
Performance: O(N) where N = min(records_in_feed, limit). One HTTP request per feed. One DB upsert per record.

### MalwareBazaar Sync (`_sync_malwarebazaar`)

| Step | Action |
|------|--------|
| 1    | GET https://bazaar.abuse.ch/export/csv/recent/ (timeout 30s) |
| 2    | Strip comment lines (starting with #) |
| 3    | Parse CSV, locate sha256_hash, md5_hash, signature columns |
| 4    | Validate SHA-256 with regex `^[a-fA-F0-9]{64}$` |
| 5    | `MaliciousHash.objects.update_or_create(sha256_hash=sha256, defaults={md5, malware_family, source='MALWAREBAZAAR'})` |
| 6    | Stop after `limit` successful upserts |

### URLhaus Sync (`_sync_urlhaus`)

| Step | Action |
|------|--------|
| 1    | GET https://urlhaus.abuse.ch/downloads/csv_recent/ (timeout 30s) |
| 2    | Strip comment lines, parse CSV, locate url and url_status columns |
| 3    | Filter: only `url_status='online'` records |
| 4    | Extract hostname via `urllib.parse.urlparse(url).hostname` |
| 5    | `MaliciousDomain.objects.update_or_create(domain=hostname, defaults={category, source='URLHAUS'})` |
| 6    | Stop after `limit` successful upserts |

---

## TI Sync Celery Tasks -- Phase 5
Location: `threat_intel/tasks.py`
Purpose: Thin Celery task wrappers that delegate to the sync_ti_feeds management command.

| Task                        | Trigger                     | Returns                              |
|-----------------------------|-----------------------------|--------------------------------------|
| `sync_malwarebazaar_task`   | Beat (crontab 02:00 UTC)   | {status: completed, feed: malwarebazaar} |
| `sync_urlhaus_task`         | Beat (crontab 02:30 UTC)   | {status: completed, feed: urlhaus}   |

Both tasks use `django.core.management.call_command()` to invoke the management command, keeping the task layer thin and the sync logic independently testable via CLI.

---

## REST API Views -- Phase 5
Location: `emails/api_views.py`
Purpose: DRF views for email browsing, quarantine management, and dashboard statistics.

### EmailListView
Key method: `get_queryset()` -> filtered, ordered `Email.objects` queryset
Input: Query params: verdict, status, from_address, date_from, date_to
Output: Paginated JSON via EmailListSerializer (25/page default)
Auth: IsAuthenticated (DRF default)

### EmailDetailView
Key method: Inherits `RetrieveAPIView.retrieve()`
Input: URL pk parameter
Output: JSON with nested AnalysisResultSerializer and EmailAttachmentSerializer
Auth: IsAuthenticated
Performance: `select_related('analysis').prefetch_related('attachments')` -- 2 queries regardless of attachment count

### QuarantineListView
Key method: `get_queryset()` -> QuarantineEntry filtered to QUARANTINED/BLOCKED emails
Input: Optional query param: status
Output: Paginated JSON via QuarantineEntrySerializer (nested EmailListSerializer)
Auth: IsAuthenticated

### QuarantineActionView
Key method: `post(request, pk)` -> handles release/block/delete actions
Input: JSON body `{action: "release"|"block"|"delete", notes: "optional"}`
Output: Updated QuarantineEntrySerializer (200) or 204 No Content (delete)
Auth: IsAnalystOrAbove (ADMIN/ANALYST only)
Side effects:
- release: QuarantineEntry.status=RELEASED, Email.status=DELIVERED, reviewer set, reviewed_at set
- block: QuarantineEntry.status=BLOCKED, Email.status=BLOCKED, reviewer set, reviewed_at set
- delete: Email.delete() -- cascades to all related records (QuarantineEntry, AnalysisResult, etc.)

### DashboardStatsView
Key method: `get(request)` -> aggregate counts
Input: None
Output: JSON via DashboardStatsSerializer: total_emails, clean_count, suspicious_count, malicious_count, pending_count, quarantine_pending, ti_hashes, ti_domains, last_sync
Auth: IsAuthenticated
Performance: 7 COUNT queries + 2 MAX aggregates. No joins.

---

## REST API Serializers -- Phase 5
Location: `emails/serializers.py`
Purpose: 7 DRF serializers for API request/response transformation.

| Serializer                  | Model/Type       | Fields | Nesting              |
|-----------------------------|------------------|--------|----------------------|
| EmailListSerializer         | Email            | 10     | None                 |
| EmailAttachmentSerializer   | EmailAttachment  | 13     | None                 |
| AnalysisResultSerializer    | AnalysisResult   | 17     | None                 |
| EmailDetailSerializer       | Email            | 16+    | analysis, attachments|
| QuarantineEntrySerializer   | QuarantineEntry  | 7      | email (EmailList)    |
| QuarantineActionSerializer  | Serializer       | 2      | None (input only)    |
| DashboardStatsSerializer    | Serializer       | 9      | None (output only)   |

---

## IsAnalystOrAbove Permission -- Phase 5
Location: `emails/permissions.py`
Purpose: Custom DRF permission that restricts access to users with ADMIN or ANALYST role.
Key method: `has_permission(request, view)` -> `bool`
Input: DRF request object
Output: True if request.user.is_authenticated and request.user.role in ('ADMIN', 'ANALYST')
Called by: QuarantineActionView.permission_classes
Calls: request.user.role (reads accounts.User model)
Performance: O(1) -- single attribute check, no DB query (user already loaded by auth middleware)

---

## Test Suite -- Phase 5
Location: `tests/test_phase5.py` (39 tests, 211 total across 6 test files)
Tests cover:
- **Decider logic**: MALICIOUS verdict for high score, SUSPICIOUS for medium, CLEAN for low, known malware override, score cap at 100, confidence level mapping (HIGH/MEDIUM/LOW)
- **Boundary testing**: score=70 is MALICIOUS, score=69 is SUSPICIOUS, score=25 is SUSPICIOUS, score=24 is CLEAN, score=0 is CLEAN/HIGH confidence
- **Override**: known malware forces MALICIOUS even with low raw score
- **Full pipeline integration**: analyze() produces verdict, QuarantineEntry created for MALICIOUS, no QuarantineEntry for CLEAN
- **TI feed sync**: sync command runs without error, MalwareBazaar creates hashes, invalid SHA-256 skipped, URLhaus imports only online URLs, --limit caps imports, --feed=all syncs both feeds
- **API endpoints**: email list returns 200 paginated, filter by verdict works, unauthenticated returns 401, email detail returns nested data, quarantine list returns only QUARANTINED/BLOCKED, release changes status, VIEWER returns 403, delete permanently removes, block changes status, ADMIN can perform actions, 404 for nonexistent, filter by status and from_address
- **Dashboard stats**: returns correct counts, pending count, TI counts
- **Celery tasks**: sync_malwarebazaar_task and sync_urlhaus_task call management command

---

## Dashboard View -- Phase 6
Location: `emails/views.py`
Purpose: Landing page showing aggregate email stats cards and a recent alerts table.
Key method: `dashboard_view(request)` -> `HttpResponse`
Input: HTTP GET (authenticated, @login_required)
Output: Rendered dashboard/index.html with stats dict and recent_alerts queryset
Called by: Browser at `/` (via emails/template_urls.py)
Calls: Email.objects.count(), Email.objects.filter().count() (4 verdict/status queries), QuarantineEntry.objects.filter().count(), MaliciousHash.objects.count(), MaliciousDomain.objects.count(), MaliciousHash.objects.aggregate(Max('added_at'))
Performance: 8 COUNT queries + 1 aggregate + 1 ORDER BY LIMIT 10. No joins. Same query pattern as DashboardStatsView API (Phase 5).

---

## Email List View -- Phase 6
Location: `emails/views.py`
Purpose: Filterable, paginated table of all emails with verdict badges and score indicators.
Key method: `email_list_view(request)` -> `HttpResponse`
Input: HTTP GET with optional query params: verdict, status, from_address, date_from, date_to
Output: Rendered emails/list.html with page_obj (Paginator, 20 per page) and active filters
Called by: Browser at `/emails/`
Calls: Email.objects.all().order_by('-received_at'), Django Paginator
Performance: O(1) paginated query. Filters applied via .filter() chain before pagination.

---

## Email Detail View -- Phase 6
Location: `emails/views.py`
Purpose: Multi-tab email detail page showing overview, headers, URLs, attachments, and raw analysis JSON.
Key method: `email_detail_view(request, pk)` -> `HttpResponse`
Input: HTTP GET with pk URL parameter (authenticated)
Output: Rendered emails/detail.html with email object, can_view_raw flag, analysis_json
Called by: Browser at `/emails/<pk>/`
Calls: Email.objects.select_related('analysis').prefetch_related('attachments', 'iocs'), json.dumps() for raw analysis tab
Performance: 2 queries (1 for email+analysis via select_related, 1 for attachments+iocs via prefetch_related). Raw analysis JSON only serialized for ADMIN/ANALYST roles.

### Tab Structure

| Tab         | Content                                        | Access        |
|-------------|------------------------------------------------|---------------|
| Overview    | Verdict badge, score bar, sender/recipient, subject, timestamps | All roles |
| Headers     | SPF/DKIM/DMARC results, auth header details    | All roles     |
| URLs        | Extracted URLs with findings and IOC indicators | All roles     |
| Attachments | File names, hashes, extension/MIME flags        | All roles     |
| Raw Analysis| Full AnalysisResult as formatted JSON           | ANALYST/ADMIN |

---

## Quarantine List View -- Phase 6
Location: `emails/views.py`
Purpose: Quarantine management page listing emails pending analyst review with action buttons.
Key method: `quarantine_list_view(request)` -> `HttpResponse`
Input: HTTP GET with optional status filter (authenticated)
Output: Rendered quarantine/list.html with page_obj and can_act flag
Called by: Browser at `/quarantine/`
Calls: QuarantineEntry.objects.select_related('email', 'reviewer').filter(email__status__in=['QUARANTINED', 'BLOCKED'])
Performance: 1 query with select_related to fetch entry + email + reviewer in a single query. Paginated at 20.

---

## Quarantine Action View -- Phase 6
Location: `emails/views.py`
Purpose: Server-side handler for quarantine release/block/delete actions submitted via POST form.
Key method: `quarantine_action_view(request, pk)` -> `HttpResponseRedirect`
Input: POST with action (release|block|delete) and optional notes
Output: Redirect to quarantine list with flash message
Called by: Quarantine list form submission at `/quarantine/<pk>/action/`
Calls: QuarantineEntry.objects.select_related('email'), entry.save(), email.save(), BlacklistEntry.objects.get_or_create() (on block), email.delete() (on delete)
Performance: O(1) -- single entry lookup, 1-2 saves. Block action additionally creates a BlacklistEntry for the sender.

### Action Behaviors

| Action  | Entry Status | Email Status | Side Effect                            |
|---------|-------------|-------------|----------------------------------------|
| release | RELEASED    | DELIVERED   | reviewer and reviewed_at set           |
| block   | BLOCKED     | BLOCKED     | reviewer set, BlacklistEntry created for sender |
| delete  | (deleted)   | (deleted)   | CASCADE deletes all related records    |

---

## Template URL Configuration -- Phase 6
Location: `emails/template_urls.py`
Purpose: URL patterns for template views, separate from API URLs to avoid namespace collisions.

| Path                          | View                    | Name               |
|-------------------------------|-------------------------|--------------------|
| /                             | dashboard_view          | ui:dashboard       |
| /emails/                      | email_list_view         | ui:email-list      |
| /emails/<int:pk>/             | email_detail_view       | ui:email-detail    |
| /quarantine/                  | quarantine_list_view    | ui:quarantine-list |
| /quarantine/<int:pk>/action/  | quarantine_action_view  | ui:quarantine-action|

Namespace: `app_name = 'ui'` (distinct from `emails` namespace used by API)

---

## CSS Design System -- Phase 6
Location: `static/css/stratos.css`
Purpose: Complete CSS design system implementing the Stratos light theme with CSS custom properties, layout grid, component styles, and responsive considerations.

### CSS Custom Properties

| Variable              | Value      | Purpose                   |
|-----------------------|------------|---------------------------|
| --bg-page             | #F8FAFC    | Page background           |
| --bg-card             | #FFFFFF    | Card/panel surfaces       |
| --bg-sidebar          | #1E3A5F    | Navy sidebar              |
| --bg-nav              | #1E293B    | Top navigation bar        |
| --border              | #E2E8F0    | Subtle borders            |
| --text-primary        | #1E293B    | Headings, body text       |
| --text-secondary      | #64748B    | Secondary text            |
| --text-muted          | #94A3B8    | Muted text                |
| --accent              | #2563EB    | Links, active states      |
| --clean-text/bg/border| Green      | CLEAN verdict indicators  |
| --suspicious-text/bg  | Amber      | SUSPICIOUS indicators     |
| --malicious-text/bg   | Red        | MALICIOUS indicators      |

### Key CSS Components

- **Sidebar layout**: Fixed 240px navy sidebar with white navigation links, logo area, role-conditional admin link
- **Stats cards**: Grid of metric cards with large number display, label, and subtle border
- **Verdict badges**: Inline pill elements with verdict-specific background/text/border colors
- **Score bars**: Horizontal progress bars with width proportional to score, colored by threshold
- **Data tables**: Striped rows, hover highlight, column alignment
- **Tab navigation**: Underline-style tabs with active state indicator
- **Flash messages**: Auto-dismissing notification bars (success=green, error=red, info=blue)

---

## JavaScript Module -- Phase 6
Location: `static/js/stratos.js`
Purpose: Client-side interactivity for the Stratos dashboard without external JavaScript dependencies.

### Functions

| Function/Feature       | Purpose                                              |
|------------------------|------------------------------------------------------|
| Tab switching          | Read/write URL hash, toggle .active class on tabs and panels |
| Flash auto-dismiss     | setTimeout to remove flash message elements after 5s |
| Confirm dialogs        | window.confirm() on destructive quarantine actions   |
| Score bar coloring     | Read data-score attribute, apply green/amber/red class based on threshold |

No external JS libraries. All interactivity is vanilla JavaScript using standard DOM APIs.

---

## seed_demo_data Management Command -- Phase 6
Location: `emails/management/commands/seed_demo_data.py`
Purpose: Populate the database with realistic demo data for viva demonstration and screenshot capture.
Key method: `handle(*args, **options)` (Django management command)
Input: None (no arguments)
Output: Creates demo Email, EmailAttachment, AnalysisResult, QuarantineEntry, MaliciousHash, and MaliciousDomain records. Prints summary to stdout.
Called by: Manual CLI: `python manage.py seed_demo_data`
Calls: Various model .objects.create() and .objects.get_or_create() methods.

---

## Authentication Flow -- Phase 6
Location: `stratos_server/urls.py` (auth URL config)
Purpose: Login/logout using Django's built-in auth views with the Stratos light theme.

| Path               | View                        | Template                    |
|--------------------|-----------------------------|-----------------------------|
| /accounts/login/   | django.contrib.auth.LoginView | registration/login.html   |
| /accounts/logout/  | django.contrib.auth.LogoutView | redirect to /accounts/login/ |

All template views use @login_required decorator. Unauthenticated requests redirect to /accounts/login/ with a next parameter for post-login redirect.
LOGIN_REDIRECT_URL defaults to `/` (dashboard).

---

## Screenshots -- Phase 6
Location: `docs/screenshots/`
Purpose: 9 screenshots captured from the live UI with seed demo data, ready for inclusion in the BISP report.

| File                             | Content                                    |
|----------------------------------|--------------------------------------------|
| 01-login.png                     | Login page with Stratos branding           |
| 02-dashboard.png                 | Dashboard with stats cards and alerts      |
| 03-email-list.png                | Email list with verdict badges             |
| 04-email-detail-overview.png     | Email detail Overview tab                  |
| 05-email-detail-headers.png      | Email detail Headers tab (SPF/DKIM/DMARC)  |
| 06-email-detail-urls.png         | Email detail URLs tab                      |
| 07-email-detail-attachments.png  | Email detail Attachments tab               |
| 08-quarantine.png                | Quarantine list with action buttons        |
| 09-dashboard-wide.png            | Dashboard wide viewport                    |
| 10-threat-intel.png              | Threat Intel page (Phase 7)                |
| 11-reports.png                   | Reports page (Phase 7)                     |
| 12-iocs.png                      | IOC list page (Phase 7)                    |
| 13-users.png                     | User management page (Phase 7)             |

---

## Threat Intel View -- Phase 7
Location: `threat_intel/views.py`
Purpose: TI dashboard showing stat cards, feed status, whitelist/blacklist management, and recent IOC detections.
Key method: `threat_intel_view(request)` -> `HttpResponse`
Input: HTTP GET (authenticated, @login_required)
Output: Rendered threat_intel/stats.html with TI counts, feed metadata, whitelist/blacklist entries, recent IOCs
Called by: Browser at `/threat-intel/` (via threat_intel/template_urls.py)
Calls: MaliciousHash.objects.count(), MaliciousDomain.objects.count(), MaliciousIP.objects.count(), YaraRule.objects.filter(is_active=True).count(), WhitelistEntry.objects.select_related('added_by'), BlacklistEntry.objects.select_related('added_by'), ExtractedIOC.objects.select_related('email')
Performance: 6 COUNT/aggregate queries + 3 SELECT queries (whitelist, blacklist, IOCs all limited with [:50] or [:20]).

### Sub-views (all ADMIN-only, POST-only)

| Method                     | Path                                | Purpose                               |
|----------------------------|-------------------------------------|---------------------------------------|
| `threat_intel_sync_view`   | /threat-intel/sync/                 | Queue async TI sync via .delay()      |
| `whitelist_add_view`       | /threat-intel/whitelist/add/        | Add WhitelistEntry (get_or_create)    |
| `whitelist_remove_view`    | /threat-intel/whitelist/<pk>/remove/| Delete WhitelistEntry                 |
| `blacklist_add_view`       | /threat-intel/blacklist/add/        | Add BlacklistEntry (get_or_create)    |
| `blacklist_remove_view`    | /threat-intel/blacklist/<pk>/remove/| Delete BlacklistEntry                 |

---

## Report List View -- Phase 7
Location: `reports/views.py`
Purpose: Reports page showing export buttons, report audit history, and scheduled report management.
Key method: `report_list_view(request)` -> `HttpResponse`
Input: HTTP GET (authenticated, @login_required)
Output: Rendered reports/list.html with reports history, scheduled reports, role flags
Called by: Browser at `/reports/` (via reports/template_urls.py)
Calls: Report.objects.select_related('generated_by'), ScheduledReport.objects.select_related('created_by')
Performance: 2 queries (reports + scheduled). Reports limited to [:50].

---

## Email Summary Export -- Phase 7
Location: `reports/views.py`
Purpose: Streaming CSV export of email summary data with optional filters.
Key method: `email_summary_export(request)` -> `HttpResponse`
Input: HTTP GET with optional query params: verdict, status, date_from, date_to (ANALYST+ only)
Output: CSV file download (streamed via HttpResponse, no disk write)
Called by: Browser at `/reports/export/emails/`
Calls: Email.objects.filter().iterator(), csv.writer, Report.objects.create() (audit record)
Performance: O(N) where N = matching emails. qs.iterator() prevents full queryset materialization.

---

## IOC Export -- Phase 7
Location: `reports/views.py`
Purpose: Streaming CSV export of all extracted IOCs.
Key method: `ioc_export_view(request)` -> `HttpResponse`
Input: HTTP GET (ANALYST+ only)
Output: CSV file download with columns: IOC Type, Value, Severity, Source Checker, Email Subject, Email From, First Seen
Called by: Browser at `/reports/export/iocs/`
Calls: ExtractedIOC.objects.select_related('email').iterator(), csv.writer, IOCExport.objects.create() (audit record)
Performance: O(N) where N = total IOCs. select_related avoids N+1 on email FK.

---

## TI Stats Export -- Phase 7
Location: `reports/views.py`
Purpose: JSON export of TI database statistics (counts, sources, samples).
Key method: `ti_stats_export(request)` -> `HttpResponse`
Input: HTTP GET (ADMIN only)
Output: JSON file download with hash/domain/IP/YARA statistics
Called by: Browser at `/reports/export/ti-stats/`
Calls: MaliciousHash/Domain/IP.objects.count(), YaraRule.objects.count(), Count aggregation by source, Report.objects.create() (audit record)
Performance: ~10 aggregate queries. No full table scans.

---

## IOC List View -- Phase 7
Location: `emails/views.py`
Purpose: Filterable, paginated list of all extracted IOCs.
Key method: `ioc_list_view(request)` -> `HttpResponse`
Input: HTTP GET with optional query params: ioc_type, severity
Output: Rendered emails/iocs.html with paginated IOC queryset (20 per page)
Called by: Browser at `/iocs/` (via emails/template_urls.py)
Calls: ExtractedIOC.objects.select_related('email'), Django Paginator
Performance: O(1) paginated query. Filters applied via .filter() chain.

---

## User List View -- Phase 7
Location: `accounts/views.py`
Purpose: User management page listing all users with role editing and activation controls.
Key method: `user_list_view(request)` -> `HttpResponse`
Input: HTTP GET (ADMIN only)
Output: Rendered accounts/users.html with all users ordered by username
Called by: Browser at `/users/` (via accounts/template_urls.py)
Calls: User.objects.all().order_by('username')
Performance: O(1) -- single query, typically <50 users.

### User Management Sub-views (all ADMIN-only, POST-only)

| Method                     | Path                            | Purpose                                    |
|----------------------------|---------------------------------|--------------------------------------------|
| `user_edit_role_view`      | /users/<pk>/edit-role/          | Change role (self-protection: cannot change own) |
| `user_toggle_active_view`  | /users/<pk>/toggle-active/      | Toggle is_active (self-protection: cannot deactivate own) |
| `user_add_view`            | /users/add/                     | Create user via create_user() with role     |

Self-protection pattern: All mutating views compare `target == request.user` and reject with error flash message if matched.

---

## Threat Intel URL Configuration -- Phase 7
Location: `threat_intel/template_urls.py`
Purpose: URL patterns for TI management views.

| Path                                | View                    | Name               |
|-------------------------------------|-------------------------|--------------------|
| /threat-intel/                      | threat_intel_view       | ti:stats           |
| /threat-intel/sync/                 | threat_intel_sync_view  | ti:sync            |
| /threat-intel/whitelist/add/        | whitelist_add_view      | ti:whitelist-add   |
| /threat-intel/whitelist/<pk>/remove/| whitelist_remove_view   | ti:whitelist-remove|
| /threat-intel/blacklist/add/        | blacklist_add_view      | ti:blacklist-add   |
| /threat-intel/blacklist/<pk>/remove/| blacklist_remove_view   | ti:blacklist-remove|

Namespace: `app_name = 'ti'`

---

## Reports URL Configuration -- Phase 7
Location: `reports/template_urls.py`
Purpose: URL patterns for report views and exports.

| Path                                  | View                      | Name                    |
|---------------------------------------|---------------------------|-------------------------|
| /reports/                             | report_list_view          | reports:list            |
| /reports/export/emails/               | email_summary_export      | reports:email-summary-export |
| /reports/export/iocs/                 | ioc_export_view           | reports:ioc-export      |
| /reports/export/ti-stats/             | ti_stats_export           | reports:ti-stats-export |
| /reports/scheduled/<pk>/toggle/       | scheduled_report_toggle   | reports:scheduled-toggle|

Namespace: `app_name = 'reports'`

---

## Accounts URL Configuration -- Phase 7
Location: `accounts/template_urls.py`
Purpose: URL patterns for user management views.

| Path                            | View                     | Name                     |
|---------------------------------|--------------------------|--------------------------|
| /users/                         | user_list_view           | accounts:user-list       |
| /users/<pk>/edit-role/          | user_edit_role_view      | accounts:user-edit-role  |
| /users/<pk>/toggle-active/      | user_toggle_active_view  | accounts:user-toggle-active |
| /users/add/                     | user_add_view            | accounts:user-add        |

Namespace: `app_name = 'accounts'`

---

## Testing Strategy -- Phase 8
Location: `tests/` (14 test files)
Purpose: Comprehensive test suite validating all pipeline stages, scoring logic, API access control, export correctness, and boundary conditions. Phase 8 added 91 new tests (6 files) to the existing 260 tests from Phases 0-7, bringing the total to 351.

### Test Infrastructure
- Framework: Django TestCase with DRF APIClient for API tests
- Database: in-memory SQLite (Django TestCase default) for speed
- Mocking: Gmail API calls mocked via unittest.mock; no external network access in any test
- Coverage: measured via coverage.py (95%)
- Execution time: all 351 tests complete in under 30 seconds

### Phase 8 Test Files

#### test_full_pipeline.py
Location: `tests/test_full_pipeline.py`
Purpose: End-to-end pipeline integration tests verifying the complete flow from email creation through verdict assignment.
Key scenarios: CLEAN email (low score, DELIVERED status), MALICIOUS email (high score, BLOCKED status, QuarantineEntry created), SUSPICIOUS email (mid score, QUARANTINED), whitelist bypass (skips CHECK and DECIDE stages), known malware hash override (forces MALICIOUS regardless of score).
Called by: `python manage.py test tests.test_full_pipeline`
Performance: Each test creates a complete email with headers and attachments, runs full pipeline -- completes in <1 second per test.

#### test_decider_boundaries.py
Location: `tests/test_decider_boundaries.py`
Purpose: Exhaustive boundary testing of Decider verdict thresholds to ensure exact threshold behavior.
Key scenarios: score=0 -> CLEAN/HIGH, score=24 -> CLEAN, score=25 -> SUSPICIOUS, score=69 -> SUSPICIOUS, score=70 -> MALICIOUS/MEDIUM, score=89 -> MALICIOUS/MEDIUM, score=90 -> MALICIOUS/HIGH, score=100 -> MALICIOUS/HIGH (cap), score=150 (raw) -> capped at 100.
Called by: `python manage.py test tests.test_decider_boundaries`
Performance: O(1) per test -- Decider is pure logic with no DB access.

#### test_api_auth.py
Location: `tests/test_api_auth.py`
Purpose: API authentication and role-based access control enforcement across all 5 API endpoints.
Key scenarios: unauthenticated requests return 401, VIEWER role returns 403 on quarantine actions, ANALYST can perform quarantine actions, ADMIN can perform all actions, token authentication works alongside session auth.
Called by: `python manage.py test tests.test_api_auth`
Performance: Uses DRF APIClient with force_authenticate() for fast auth setup.

#### test_export.py
Location: `tests/test_export.py`
Purpose: Validate CSV and JSON export output format, content correctness, and audit record creation.
Key scenarios: email summary CSV has correct headers (Subject, From, Verdict, Score, Date), IOC export CSV includes IOC type/value/severity columns, TI stats JSON has expected keys (hashes, domains, IPs, yara_rules), audit records (Report/IOCExport) created on each export, VIEWER role cannot trigger exports (403).
Called by: `python manage.py test tests.test_export`
Performance: Uses HttpResponse content parsing -- no disk I/O.

#### test_preprocessor_scoring.py
Location: `tests/test_preprocessor_scoring.py`
Purpose: Comprehensive edge case testing for Preprocessor scoring across all sub-checks.
Key scenarios: all 27 SPF/DKIM/DMARC combinations (3x3x3) produce expected scores, blacklist email+domain stacking (+40+30=70), whitelist email match bypasses all checks, whitelist domain match bypasses all checks, Reply-To mismatch with edge cases (no Reply-To, same domain), display name spoof with edge cases (no display name, matching domain).
Called by: `python manage.py test tests.test_preprocessor_scoring`
Performance: O(1) per test -- Preprocessor uses only DB lookups on indexed fields.

#### test_checker_scoring.py
Location: `tests/test_checker_scoring.py`
Purpose: Comprehensive edge case testing for Checker scoring across all 4 sub-checkers.
Key scenarios: keyword cap verified at exactly 20 (10+ unique keywords), URL cumulative scoring (malicious+IP+shortener), URL cap at 40, attachment scoring with multiple flags active simultaneously, attachment cap at 50, chain scoring with all 3 anomalies present, empty inputs produce zero scores, has_known_malware flag set correctly on MaliciousHash match.
Called by: `python manage.py test tests.test_checker_scoring`
Performance: O(K+U+A+H) where K=keywords, U=URLs, A=attachments, H=hops -- all in-memory.

---

## demo_setup Management Command -- Phase 8
Location: `emails/management/commands/demo_setup.py`
Purpose: Create a complete demo environment for the 8-minute viva presentation. Idempotent -- safe to run multiple times.
Key method: `handle(*args, **options)` (Django management command)
Input: None (no arguments)
Output: Creates 3 demo users (admin/analyst/viewer), sample TI data (MaliciousHash, MaliciousDomain, WhitelistEntry, BlacklistEntry), sample emails at all verdict levels (CLEAN, SUSPICIOUS, MALICIOUS), and corresponding QuarantineEntries.
Called by: Manual CLI: `python manage.py demo_setup`
Calls: User.objects.get_or_create(), Email.objects.get_or_create(), AnalysisResult.objects.get_or_create(), QuarantineEntry.objects.get_or_create(), various TI model .get_or_create() methods.

---

## demo_teardown Management Command -- Phase 8
Location: `emails/management/commands/demo_teardown.py`
Purpose: Cleanly remove all demo data without affecting any production records. Reverses demo_setup.
Key method: `handle(*args, **options)` (Django management command)
Input: None (no arguments)
Output: Deletes demo users, demo emails (CASCADE removes AnalysisResult, QuarantineEntry, etc.), and demo TI records.
Called by: Manual CLI: `python manage.py demo_teardown`
Calls: User.objects.filter().delete(), Email.objects.filter().delete(), various TI model .filter().delete().

---

## Screenshots -- Phase 8 (Final Demo State)
Location: `docs/screenshots/`
Purpose: 7 new screenshots (14-20) captured with demo_setup data showing the final production-ready state.

| File                                   | Content                                    |
|----------------------------------------|--------------------------------------------|
| 14-dashboard-with-data.png             | Dashboard populated with demo emails       |
| 15-email-detail-malicious.png          | Detail view of a MALICIOUS verdict email   |
| 16-email-detail-score-breakdown.png    | Score breakdown across all pipeline stages |
| 17-quarantine-pending.png              | Quarantine page with pending review items  |
| 18-threat-intel-stats.png              | TI page showing populated feed statistics  |
| 19-reports-page.png                    | Reports page with export buttons           |
| 20-users-page.png                      | User management with ADMIN/ANALYST/VIEWER  |

Total screenshots: 20 (Phase 6: 9, Phase 7: 4, Phase 8: 7)

---

## System Configuration -- Post-Phase 8
Location: `emails/models.py` (SystemConfig model), `emails/settings_views.py`, `templates/settings/index.html`
Purpose: UI-driven configuration for API keys, Gmail OAuth, and detection thresholds.

### SystemConfig Model (Singleton Pattern)
Location: `emails/models.py`
Key method: `get_solo()` -- returns the single SystemConfig row (pk=1), creating it if absent.

API Key Encryption:
- Uses `cryptography.fernet.Fernet` with a key derived from `hashlib.sha256(SECRET_KEY)`
- `set_api_key(field, value)` encrypts and stores
- `get_api_key(field)` decrypts and returns
- `mask_key(value)` returns display-safe version (e.g., `sk-1****7f3a`)

### Gmail Web OAuth Flow
Location: `emails/settings_views.py` (gmail_connect, gmail_callback)
Purpose: Replace the CLI-based `generate_gmail_token.py` with a browser-based OAuth flow.

Key method: `gmail_connect(request)` -- builds a `google_auth_oauthlib.flow.Flow` with redirect URI pointing to the server's `/settings/gmail/callback/`. Saves state in `request.session` for CSRF protection.

Key method: `gmail_callback(request)` -- receives Google's auth code, verifies the state parameter, exchanges the code for credentials, saves the token file, fetches the connected email via Gmail API `users().getProfile()`, and updates SystemConfig.

### Services Integration
The Decider reads `clean_threshold` and `malicious_threshold` from SystemConfig on each instantiation, falling back to `settings.CLEAN_THRESHOLD` / `settings.MALICIOUS_THRESHOLD` if the DB is unavailable.

TI sync tasks (`sync_malwarebazaar_task`, `sync_urlhaus_task`) check `SystemConfig.ti_sync_enabled` before running.

---

## Production Deployment -- Post-Phase 8
Location: `docker-compose.prod.yml`, `Caddyfile`, `Dockerfile`, `stratos_server/settings/prod.py`
Purpose: Deploy to Hetzner Cloud with Caddy reverse proxy, gunicorn, and WhiteNoise static serving.

Key changes from development:
- `gunicorn` replaces `runserver` (3 workers, 120s timeout)
- `whitenoise` serves static files (no nginx needed)
- `Caddy` provides reverse proxy and automatic HTTPS
- Production settings add security headers (X-Frame-Options, XSS filter, Content-Type sniff)
- `CSRF_TRUSTED_ORIGINS` required for cross-origin form submissions

See `docs/DEPLOYMENT.md` for step-by-step instructions.
See `docs/ADMIN_GUIDE.md` for admin usage guide.
