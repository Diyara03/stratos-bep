# Stratos -- System Architecture

## Status: Phase 8 COMPLETE + System Settings + Production Deployment (473 tests)

## System Map

```
+-------------------------------------------------------------------+
|                     Docker Compose Network                         |
|                                                                    |
|  +--------------+    +-------------+    +---------------------+    |
|  |  postgres     |    |   redis     |    |    django           |    |
|  |  :15-alpine   |    |  :7-alpine  |    |  python:3.10-slim   |    |
|  |  port 5432    |    |  port 6379  |    |  port 8000          |    |
|  |               |    |             |    |                     |    |
|  |  stratos DB   |    |  broker +   |    |  manage.py          |    |
|  |  stratos_user |    |  result     |    |  runserver          |    |
|  |  table        |    |  backend    |    |  /health/ endpoint  |    |
|  +---------+-----+    +------+------+    +---+--------+--------+    |
|            |                 |                |        |            |
|            |    depends_on   |   depends_on   |        |            |
|            +--------+--------+--------+-------+        |            |
|                     |                                  |            |
|          +----------+-----------+    +-----------------+-------+    |
|          |      celery          |    |    celery-beat          |    |
|          |  worker --loglevel   |    |  beat --loglevel        |    |
|          |  (no port exposed)   |    |  (no port exposed)      |    |
|          +----------------------+    +-------------------------+    |
|                                                                    |
+-------------------------------------------------------------------+
          |
          v
  +-------------------+
  |  Volume:           |
  |  postgres_data     |
  +-------------------+
```

### Dependency Chain
1. postgres + redis start first (healthchecked)
2. django waits for both, runs migrate, then starts dev server
3. celery + celery-beat wait for django healthy

## Project Structure

```
Stratos/
  manage.py
  requirements.txt        (13 packages, pinned)
  Dockerfile              (python:3.10-slim + system deps)
  docker-compose.yml      (5 services)
  .env.example            (all env vars with defaults)
  .gitignore
  stratos_server/         --- Django project package
    __init__.py           (imports celery_app)
    celery.py             (Celery app, autodiscover_tasks)
    urls.py               (/admin/, /health/)
    views.py              (health endpoint)
    wsgi.py
    asgi.py
    settings/
      __init__.py
      base.py             (shared: apps, auth, celery, DRF, thresholds)
      dev.py              (DEBUG=True, SQLite fallback)
      prod.py             (DEBUG=False, PostgreSQL required)
  accounts/               --- Custom User model (Phase 0)
    models.py             (User: AbstractUser + role/department/last_login_ip)
    admin.py
    migrations/0001_initial.py
  emails/                 --- Pipeline data models (Phase 1)
    models.py             (Email, EmailAttachment, AnalysisResult, QuarantineEntry, ExtractedIOC)
    admin.py              (5 ModelAdmin registrations)
    migrations/0001_initial.py
  threat_intel/           --- TI feed models (Phase 1)
    models.py             (MaliciousHash, MaliciousDomain, MaliciousIP, YaraRule, WhitelistEntry, BlacklistEntry)
    admin.py              (6 ModelAdmin registrations)
    migrations/0001_initial.py
  reports/                --- Export/scheduling models (Phase 1)
    models.py             (Report, ScheduledReport, IOCExport)
    admin.py              (3 ModelAdmin registrations)
    migrations/0001_initial.py
  tests/
    test_phase0.py        (26 test methods)
    test_phase1.py        (26 test methods)
    test_phase2.py        (29 test methods)
    test_phase3.py        (32 test methods)
    test_phase4.py        (35 test methods)
    test_phase5.py        (39 test methods)
```

## Settings Architecture

```
base.py  (all shared config)
  |
  +---> dev.py   (DEBUG=True, SQLite if no DATABASE_URL, ALLOWED_HOSTS=*)
  |
  +---> prod.py  (DEBUG=False, PostgreSQL required, ALLOWED_HOSTS from env)
```

Selected via `DJANGO_SETTINGS_MODULE` environment variable.
Default: `stratos_server.settings.dev`

## Endpoints

| Method | Path                          | View                              | Auth              | Description                     |
|--------|-------------------------------|-----------------------------------|-------------------|---------------------------------|
| GET    | /health/                      | stratos_server.views.health       | None              | Liveness probe                  |
| GET    | /admin/                       | Django admin                      | Staff             | Admin interface                 |
| GET    | /api/emails/                  | emails.api_views.EmailListView    | IsAuthenticated   | Paginated, filterable emails    |
| GET    | /api/emails/<id>/             | emails.api_views.EmailDetailView  | IsAuthenticated   | Email detail + analysis         |
| GET    | /api/quarantine/              | emails.api_views.QuarantineListView| IsAuthenticated  | Quarantine entries              |
| POST   | /api/quarantine/<id>/action/  | emails.api_views.QuarantineActionView| IsAnalystOrAbove| Release/block/delete            |
| GET    | /api/dashboard/stats/         | emails.api_views.DashboardStatsView| IsAuthenticated  | Aggregate stats                 |

## Models (Phase 0 + Phase 1)

### Model Inventory: 15 models across 4 apps, 117 fields

| App          | Model             | Fields | Key Constraints                           |
|--------------|-------------------|--------|-------------------------------------------|
| accounts     | User              | 3+     | AbstractUser, AUTH_USER_MODEL             |
| emails       | Email             | 21     | message_id UNIQUE, status/verdict indexed |
| emails       | EmailAttachment   | 13     | FK->Email CASCADE, sha256 indexed         |
| emails       | AnalysisResult    | 17     | OneToOne->Email CASCADE                   |
| emails       | QuarantineEntry   | 7      | OneToOne->Email CASCADE, FK->User SET_NULL|
| emails       | ExtractedIOC      | 6      | FK->Email CASCADE, ioc_type indexed       |
| threat_intel | MaliciousHash     | 6      | sha256_hash UNIQUE                        |
| threat_intel | MaliciousDomain   | 4      | domain UNIQUE                             |
| threat_intel | MaliciousIP       | 5      | ip_address UNIQUE                         |
| threat_intel | YaraRule          | 6      | name UNIQUE                               |
| threat_intel | WhitelistEntry    | 5      | unique_together (entry_type, value)       |
| threat_intel | BlacklistEntry    | 5      | unique_together (entry_type, value)       |
| reports      | Report            | 8      | FK->User SET_NULL                         |
| reports      | ScheduledReport   | 8      | FK->User SET_NULL, next_run indexed       |
| reports      | IOCExport         | 6      | FK->User SET_NULL                         |

### Entity Relationship Summary

Email is the central entity. 10 FK relationships total:

```
                            +---> EmailAttachment (1:N, CASCADE)
                            |
  User <--SET_NULL-- QuarantineEntry <--1:1-- Email --1:1--> AnalysisResult
    |                                          |
    |                                          +---> ExtractedIOC (1:N, CASCADE)
    |
    +--SET_NULL--> WhitelistEntry
    +--SET_NULL--> BlacklistEntry
    +--SET_NULL--> Report
    +--SET_NULL--> ScheduledReport
    +--SET_NULL--> IOCExport
```

### App Responsibilities

| App          | Responsibility                                              |
|--------------|-------------------------------------------------------------|
| emails       | Pipeline data: incoming emails, attachments, analysis scores, quarantine, IOCs |
| threat_intel | TI feeds: known-bad hashes/domains/IPs, YARA rules, whitelist/blacklist |
| reports      | Export and scheduling: on-demand reports, scheduled reports, IOC exports |
| accounts     | Auth and roles: ADMIN/ANALYST/VIEWER RBAC                   |

## Data Flows

### Health Check Flow
```
Client --> GET /health/ --> views.health()
  --> connection.ensure_connection()
  --> 200 {"status":"ok","version":"0.1.0","db":"connected"}
  OR  503 {"status":"degraded","version":"0.1.0","db":"unavailable"}
```

### Celery Configuration Flow
```
stratos_server/__init__.py imports celery_app
  --> celery.py creates Celery('stratos_server')
  --> config_from_object('django.conf:settings', namespace='CELERY')
  --> autodiscover_tasks() scans all INSTALLED_APPS
  --> broker + result backend: REDIS_URL env var
```

### Email Pipeline Data Flow (ALL 3 STAGES COMPLETE)

```
Gmail API --> Email (status=PENDING)
               |
               +--> EmailAttachment (metadata only, fetched on-demand)
               |
         Preprocessor (Phase 3) [DONE]
               |
               +--> AnalysisResult.preprocess_score
               +--> AnalysisResult.spf/dkim/dmarc_result
               |
         Checker (Phase 4) [DONE]
               |
               +--> AnalysisResult.keyword_score / url_score / attachment_score / chain_score
               +--> AnalysisResult.keywords_matched / url_findings / attachment_findings / chain_findings
               +--> ExtractedIOC (DOMAIN from URL checker, HASH from attachment checker)
               +--> EmailAttachment flags (ti_match, is_dangerous_ext, is_double_ext, is_mime_mismatch)
               |
         Decider (Phase 5) [DONE]
               |
               +--> DecisionResult (verdict, total_score, confidence, action, override_reason)
               +--> Email.verdict (CLEAN/SUSPICIOUS/MALICIOUS)
               +--> Email.score (0-100, capped)
               +--> Email.confidence (HIGH/MEDIUM/LOW)
               +--> Email.status (DELIVERED/QUARANTINED/BLOCKED)
               +--> AnalysisResult.total_score + pipeline_duration_ms
               +--> QuarantineEntry (if QUARANTINE/BLOCK action)
```

### Threat Intel Lookup Flow (All stages implemented)

```
  MaliciousHash ----+--> Checker._check_attachments() [Phase 4, DONE]
                    +--> Decider: has_known_malware override [Phase 5, DONE]
  MaliciousDomain --+--> Checker._check_urls() [Phase 4, DONE]
  MaliciousIP ------+--> (reserved for future enhancement)
  YaraRule ---------+--> Checker reads yara_matches field if pre-populated [Phase 4, DONE]
  
  WhitelistEntry ---+--> Preprocessor._check_whitelist() [Phase 3, DONE]
  BlacklistEntry ---+--> Preprocessor._check_blacklist() [Phase 3, DONE]
```

### TI Feed Sync Flow (Phase 5)

```
Celery Beat (crontab)
  |
  +--> sync-malwarebazaar-daily (02:00 UTC)
  |      |
  |      +--> sync_malwarebazaar_task()
  |             +--> call_command('sync_ti_feeds', feed='malwarebazaar')
  |                    +--> GET https://bazaar.abuse.ch/export/csv/recent/
  |                    +--> Parse CSV, validate SHA-256 (64 hex chars)
  |                    +--> MaliciousHash.objects.update_or_create()
  |
  +--> sync-urlhaus-daily (02:30 UTC)
         |
         +--> sync_urlhaus_task()
                +--> call_command('sync_ti_feeds', feed='urlhaus')
                       +--> GET https://urlhaus.abuse.ch/downloads/csv_recent/
                       +--> Filter: url_status='online' only
                       +--> Extract hostname via urllib.parse.urlparse()
                       +--> MaliciousDomain.objects.update_or_create()
```

## Phase 2: Gmail Ingestion + Email Parser

### Email Ingestion Data Flow

```
Gmail API
  |
  v
GmailConnector.fetch_new_emails(max_results=10)
  | (skips emails where gmail_id already in DB)
  v
Gmail API .messages().get(format='full')
  |
  v
EmailParser.parse_gmail_message(raw_message)
  | Extracts: message_id, from, to, cc, reply_to, subject (RFC 2047),
  |   body_text, body_html, urls (regex + BeautifulSoup), attachments
  |   (SHA-256 + MD5), received_chain, auth_results (SPF/DKIM/DMARC)
  v
Email.save() + EmailAttachment.objects.create() (per attachment)
  |
  v
analyze_email_task.delay(email.id)  --> Celery worker
  |
  v
EmailAnalyzer.analyze(email_id)     --> Preprocessor --> (Phase 4: Checker) --> (Phase 5: Decider)
  |
  v
GmailConnector.mark_as_read(gmail_id)
```

### Project Structure (Phase 2 additions)

```
emails/
  services/
    __init__.py
    gmail_connector.py    (GmailConnector: OAuth, fetch, mark_as_read, dedup)
    parser.py             (EmailParser: 11 header methods, URL/attachment extraction)
    analyzer.py           (EmailAnalyzer: stub orchestrator, sets PENDING)
  tasks.py                (fetch_gmail_task, analyze_email_task)
  management/
    commands/
      fetch_emails.py     (--max N --dry-run)
tests/
  test_phase2.py          (29 tests)
  fixtures/
    test_gmail_message.json         (clean email fixture)
    phishing_gmail_message.json     (phishing email with .pdf.exe attachment)
```

### Celery Beat Schedule

| Task Name              | Schedule  | Task Path                      |
|------------------------|-----------|--------------------------------|
| fetch-gmail-every-10s  | 10.0s     | emails.tasks.fetch_gmail_task  |

### Management Command

```
python manage.py fetch_emails --max N --dry-run
```

## Phase 3: Preprocessor + SPF/DKIM/DMARC Analysis

### Preprocessor Pipeline Flow

```
EmailAnalyzer.analyze(email_id)
  |
  +--> Email.status = 'ANALYZING'
  |
  +--> Preprocessor.process(email) --> PreprocessResult
  |      |
  |      +--> 1. _check_whitelist(from_address)
  |      |       WhitelistEntry lookup (EMAIL then DOMAIN)
  |      |       Match? --> verdict_override=CLEAN, score=0, RETURN EARLY
  |      |
  |      +--> 2. _check_blacklist(from_address)
  |      |       BlacklistEntry lookup (EMAIL: +40, DOMAIN: +30)
  |      |
  |      +--> 3. _check_email_auth(headers_raw)
  |      |       Parse Authentication-Results header via regex
  |      |       SPF fail:+15 softfail:+5 none:+10 pass:0
  |      |       DKIM fail:+15 none:+5 pass:0
  |      |       DMARC fail:+15 none:+5 pass:0
  |      |
  |      +--> 4. _check_reply_to_mismatch(email)
  |      |       Compare From domain vs Reply-To domain: +10 if mismatch
  |      |
  |      +--> 5. _check_display_spoof(email)
  |              Detect foreign domain in display name: +10 if spoof
  |
  +--> If verdict_override == 'CLEAN':
  |      _finalize(CLEAN, DELIVERED, HIGH)
  |      Email.status = 'DELIVERED', verdict = 'CLEAN', score = 0
  |
  +--> Else:
         _save_preprocess_result(email, result)
         AnalysisResult.preprocess_score = result.score
         Email.status remains 'ANALYZING' (waiting for Checker + Decider)
```

### Preprocessor Data Flow (DB interactions)

```
  WhitelistEntry -----> Preprocessor._check_whitelist() --+
  BlacklistEntry -----> Preprocessor._check_blacklist() --+--> PreprocessResult
  headers_raw --------> Preprocessor._check_email_auth() -+       |
  Email.reply_to -----> Preprocessor._check_reply_to()  --+       |
  Email.from_display -> Preprocessor._check_display()   --+       v
                                                          EmailAnalyzer
                                                              |
                                                              +--> AnalysisResult (update_or_create)
                                                              +--> Email (status, verdict, score)
```

### Project Structure (Phase 3 additions)

```
emails/
  services/
    preprocessor.py       (Preprocessor + PreprocessResult dataclass)
    analyzer.py           (EmailAnalyzer: now calls Preprocessor, no longer a stub)
tests/
  test_phase3.py          (32 tests)
```

## Phase 4: Checker Engine -- Content-Level Threat Detection

### Checker Pipeline Flow

```
EmailAnalyzer.analyze(email_id)
  |
  +--> Preprocessor.process(email) --> PreprocessResult   [Phase 3]
  |
  +--> Checker.check_all(email) --> CheckResult           [Phase 4]
  |      |
  |      +--> 1. _check_keywords(email)
  |      |       Subject + body_text scanned for 24 keywords (case-insensitive)
  |      |       +2 per unique match, cap at 20
  |      |
  |      +--> 2. _check_urls(email)
  |      |       urls_extracted list checked against:
  |      |         MaliciousDomain DB: +30
  |      |         IP-based URL: +10
  |      |         URL shortener (8 services): +5
  |      |       Cap at 40. Creates ExtractedIOC(DOMAIN) on malicious match.
  |      |
  |      +--> 3. _check_attachments(email)
  |      |       email.attachments.all() checked for:
  |      |         MaliciousHash DB: +50, sets has_known_malware=True
  |      |         Dangerous extension (13 types): +15
  |      |         Double extension: +20
  |      |         MIME mismatch (content_type vs file_magic): +10
  |      |         YARA matches (pre-populated): +25 per rule
  |      |       Cap at 50. Creates ExtractedIOC(HASH) on malicious match.
  |      |
  |      +--> 4. _check_received_chain(email)
  |              received_chain list checked for:
  |                Hop count > 7: +5
  |                Private IP: +5
  |                Timestamp disorder: +5
  |              Cap at 15
  |
  +--> _save_check_result(email, check_result)
         AnalysisResult.filter(email).update(keyword_score, url_score, ...)
         Email.status remains 'ANALYZING' (waiting for Decider in Phase 5)
```

### Checker Data Flow (DB interactions)

```
  Email.subject       --+
  Email.body_text     --+--> Checker._check_keywords() --> keywords_matched
                         
  Email.urls_extracted --> Checker._check_urls()
                              |
                              +--> MaliciousDomain.objects.filter()
                              +--> ExtractedIOC.objects.create()    [on match]
                              --> url_findings

  EmailAttachment.all() --> Checker._check_attachments()
                              |
                              +--> MaliciousHash.objects.filter()
                              +--> ExtractedIOC.objects.create()    [on match]
                              +--> EmailAttachment.save()           [flags updated]
                              --> attachment_findings

  Email.received_chain --> Checker._check_received_chain() --> chain_findings

  All results --> EmailAnalyzer._save_check_result()
                    --> AnalysisResult.filter(email).update(...)
```

### Project Structure (Phase 4 additions)

```
emails/
  services/
    checker.py            (Checker + CheckResult dataclass, 357 lines)
    analyzer.py           (EmailAnalyzer: now calls Checker after Preprocessor)
tests/
  test_phase4.py          (35 tests)
```

## Phase 5: Decider + TI Feed Sync + REST API -- 50% MILESTONE

### Decider Pipeline Flow

```
EmailAnalyzer.analyze(email_id)
  |
  +--> Preprocessor.process(email) --> PreprocessResult   [Phase 3]
  |
  +--> Checker.check_all(email) --> CheckResult           [Phase 4]
  |
  +--> Decider().decide(preprocess_result, check_result) --> DecisionResult  [Phase 5]
  |      |
  |      +--> 1. Known malware override check
  |      |       has_known_malware=True? --> MALICIOUS/100/HIGH/BLOCK
  |      |
  |      +--> 2. Normal scoring
  |      |       raw = preprocess_score + check_score
  |      |       total = min(raw, 100)
  |      |
  |      +--> 3. Verdict thresholds
  |              total >= 70 --> MALICIOUS (BLOCK)
  |              total >= 25 --> SUSPICIOUS (QUARANTINE)
  |              total < 25  --> CLEAN (DELIVER)
  |
  +--> _finalize(email, decision)
         +--> AnalysisResult: total_score, pipeline_duration_ms
         +--> Email: verdict, score, confidence, status, analyzed_at
         +--> QuarantineEntry (if action=QUARANTINE or BLOCK)
```

### REST API Endpoints

| Method | Path                          | View                  | Auth                 | Description                     |
|--------|-------------------------------|-----------------------|----------------------|---------------------------------|
| GET    | /api/emails/                  | EmailListView         | IsAuthenticated      | Paginated, filterable email list|
| GET    | /api/emails/<id>/             | EmailDetailView       | IsAuthenticated      | Nested analysis + attachments   |
| GET    | /api/quarantine/              | QuarantineListView    | IsAuthenticated      | QUARANTINED/BLOCKED entries     |
| POST   | /api/quarantine/<id>/action/  | QuarantineActionView  | IsAnalystOrAbove     | Release/block/delete            |
| GET    | /api/dashboard/stats/         | DashboardStatsView    | IsAuthenticated      | Aggregate verdict counts + TI   |

### REST API Data Flow

```
Browser/Client
  |
  +--> GET /api/emails/?verdict=MALICIOUS&status=QUARANTINED
  |      --> EmailListView.get_queryset() filters Email.objects
  |      --> EmailListSerializer --> paginated JSON response
  |
  +--> GET /api/emails/42/
  |      --> EmailDetailView with select_related('analysis').prefetch_related('attachments')
  |      --> EmailDetailSerializer (nested AnalysisResultSerializer + EmailAttachmentSerializer)
  |
  +--> GET /api/quarantine/
  |      --> QuarantineListView filters email__status__in=[QUARANTINED, BLOCKED]
  |      --> QuarantineEntrySerializer (nested EmailListSerializer)
  |
  +--> POST /api/quarantine/42/action/ {"action": "release", "notes": "false positive"}
  |      --> IsAnalystOrAbove permission check (ADMIN/ANALYST only)
  |      --> release: QuarantineEntry.status=RELEASED, Email.status=DELIVERED
  |      --> block: QuarantineEntry.status=BLOCKED, Email.status=BLOCKED
  |      --> delete: Email.delete() (cascades to all related records)
  |
  +--> GET /api/dashboard/stats/
         --> Aggregate counts: total, clean, suspicious, malicious, pending
         --> QuarantineEntry.filter(status=PENDING).count()
         --> MaliciousHash.count(), MaliciousDomain.count(), last_sync timestamp
```

### Project Structure (Phase 5 additions)

```
emails/
  services/
    decider.py            (Decider + DecisionResult dataclass)
    analyzer.py           (EmailAnalyzer: full 3-stage pipeline, _finalize creates QuarantineEntry)
  api_views.py            (5 DRF views: EmailList, EmailDetail, QuarantineList, QuarantineAction, DashboardStats)
  serializers.py          (7 serializers: EmailList, EmailDetail, EmailAttachment, AnalysisResult, QuarantineEntry, QuarantineAction, DashboardStats)
  permissions.py          (IsAnalystOrAbove permission class)
  urls.py                 (5 URL patterns under /api/)
threat_intel/
  tasks.py                (sync_malwarebazaar_task, sync_urlhaus_task)
  management/
    commands/
      sync_ti_feeds.py    (--feed=all/malwarebazaar/urlhaus --limit=5000)
tests/
  test_phase5.py          (39 tests)
```

### Celery Beat Schedule (Phase 5 update)

| Task Name                  | Schedule           | Task Path                                   |
|----------------------------|--------------------|---------------------------------------------|
| fetch-gmail-every-10s      | 10.0s              | emails.tasks.fetch_gmail_task               |
| sync-malwarebazaar-daily   | crontab(2:00 UTC)  | threat_intel.tasks.sync_malwarebazaar_task  |
| sync-urlhaus-daily         | crontab(2:30 UTC)  | threat_intel.tasks.sync_urlhaus_task        |

## Phase 6: Dashboard UI (Light Theme)

### UI Layer Architecture

```
Browser (authenticated user)
  |
  +--> / (dashboard)           --> dashboard_view    --> dashboard/index.html
  +--> /emails/                --> email_list_view   --> emails/list.html
  +--> /emails/<pk>/           --> email_detail_view --> emails/detail.html
  +--> /quarantine/            --> quarantine_list_view --> quarantine/list.html
  +--> /quarantine/<pk>/action/ --> quarantine_action_view --> redirect
  +--> /accounts/login/        --> Django LoginView  --> registration/login.html
  +--> /accounts/logout/       --> Django LogoutView --> redirect to login
  |
  +--> /api/*                  --> DRF API views (Phase 5, unchanged)
```

### Template Hierarchy

```
templates/
  base.html                     Master layout: sidebar, nav, flash messages, font loading
  registration/
    login.html                  Login page (light theme, centered card)
  dashboard/
    index.html                  Stats cards, recent alerts table
  emails/
    list.html                   Filterable, paginated email table with verdict badges
    detail.html                 5-tab detail: Overview, Headers, URLs, Attachments, Raw Analysis
  quarantine/
    list.html                   Quarantine entries with release/block/delete actions

static/
  css/stratos.css               Design system: CSS variables, layout, components, verdict badges
  js/stratos.js                 Tab switching, flash messages, confirmations, score bars
```

### URL Routing Strategy

```
stratos_server/urls.py
  |
  +--> /admin/                        Django admin
  +--> /health/                       Health probe
  +--> /api/                          include('emails.urls')        -- DRF API (Phase 5)
  +--> /accounts/login/               Django LoginView
  +--> /accounts/logout/              Django LogoutView
  +--> /                              include('emails.template_urls') -- Template views (Phase 6)
```

Template views and API views coexist via separate URL files:
- `emails/urls.py` (app_name='emails') serves `/api/*` endpoints
- `emails/template_urls.py` (app_name='ui') serves `/` root template views

### Role-Based UI Visibility

| UI Element                | ADMIN | ANALYST | VIEWER |
|---------------------------|-------|---------|--------|
| Dashboard                 | Yes   | Yes     | Yes    |
| Email list/detail         | Yes   | Yes     | Yes    |
| Raw analysis tab          | Yes   | Yes     | No     |
| Quarantine list           | Yes   | Yes     | Yes    |
| Quarantine actions        | Yes   | Yes     | No     |
| Admin sidebar link        | Yes   | No      | No     |

### CSS Design System (stratos.css)

```
Light theme CSS variables:
  --bg-page:       #F8FAFC    (page background)
  --bg-card:       #FFFFFF    (card/panel surfaces)
  --bg-sidebar:    #1E3A5F    (navy sidebar -- only dark element)
  --bg-nav:        #1E293B    (top nav bar)
  --border:        #E2E8F0    (subtle borders)
  --text-primary:  #1E293B    (headings, body)
  --text-secondary:#64748B    (secondary text)
  --accent:        #2563EB    (links, active states)

Verdict badges (color-coded pills):
  CLEAN:       bg #DCFCE7, text #16A34A, border #BBF7D0
  SUSPICIOUS:  bg #FEF3C7, text #D97706, border #FDE68A
  MALICIOUS:   bg #FEE2E2, text #DC2626, border #FECACA

Score bars: colored by threshold (green <25, amber 25-69, red >=70)
Font stack: Inter (body), JetBrains Mono (hashes/code)
```

### JavaScript Functionality (stratos.js)

- Tab switching: URL hash-based (#headers, #urls, #attachments, #raw) with active state management
- Flash messages: auto-dismiss after 5 seconds
- Confirmations: confirm() dialog on destructive quarantine actions
- Score bars: dynamically colored based on score threshold

### Data Flow: Template Views

```
Browser --> GET / (authenticated)
  --> dashboard_view (login_required)
  --> DB queries: Email counts, QuarantineEntry.filter(PENDING), MaliciousHash/Domain counts
  --> render('dashboard/index.html', {stats, recent_alerts})

Browser --> GET /emails/<pk>/
  --> email_detail_view (login_required)
  --> Email.objects.select_related('analysis').prefetch_related('attachments', 'iocs')
  --> if ADMIN/ANALYST: serialize analysis as JSON for raw tab
  --> render('emails/detail.html', {email, can_view_raw, analysis_json})

Browser --> POST /quarantine/<pk>/action/
  --> quarantine_action_view (login_required, ADMIN/ANALYST check)
  --> release: entry.status=RELEASED, email.status=DELIVERED
  --> block: entry.status=BLOCKED, email.status=BLOCKED, BlacklistEntry created
  --> delete: email.delete() (CASCADE)
  --> messages.success() flash message
  --> redirect to quarantine list
```

### Project Structure (Phase 6 additions)

```
templates/                        --- 6 HTML templates (new directory)
  base.html                       (master layout with sidebar, nav, font loading)
  registration/login.html         (login form)
  dashboard/index.html            (stats cards + recent alerts)
  emails/list.html                (filterable email table)
  emails/detail.html              (5-tab detail view)
  quarantine/list.html            (quarantine management)
static/                           --- 2 static assets (new directory)
  css/stratos.css                 (design system, ~400 lines)
  js/stratos.js                   (UI interactions, ~100 lines)
emails/
  views.py                        (5 template views: dashboard, email_list, email_detail, quarantine_list, quarantine_action)
  template_urls.py                (5 URL patterns under / root, app_name='ui')
  management/
    commands/
      seed_demo_data.py           (populates demo data for screenshots/viva)
stratos_server/
  urls.py                         (updated: added auth views + template_urls include)
docs/
  screenshots/                    (9 PNG screenshots for BISP report)
    01-login.png
    02-dashboard.png
    03-email-list.png
    04-email-detail-overview.png
    05-email-detail-headers.png
    06-email-detail-urls.png
    07-email-detail-attachments.png
    08-quarantine.png
    09-dashboard-wide.png
```

## Phase 7: TI Management + Reports + IOCs + User Management

### UI Layer Architecture (Phase 7 additions)

```
Browser (authenticated user)
  |
  +--> /threat-intel/              --> threat_intel_view        --> threat_intel/stats.html
  +--> /threat-intel/sync/         --> threat_intel_sync_view   --> redirect (ADMIN, POST)
  +--> /threat-intel/whitelist/add/    --> whitelist_add_view   --> redirect (ADMIN, POST)
  +--> /threat-intel/whitelist/<pk>/remove/ --> whitelist_remove_view --> redirect (ADMIN, POST)
  +--> /threat-intel/blacklist/add/    --> blacklist_add_view   --> redirect (ADMIN, POST)
  +--> /threat-intel/blacklist/<pk>/remove/ --> blacklist_remove_view --> redirect (ADMIN, POST)
  |
  +--> /reports/                   --> report_list_view         --> reports/list.html
  +--> /reports/export/emails/     --> email_summary_export     --> CSV download (ANALYST+)
  +--> /reports/export/iocs/       --> ioc_export_view          --> CSV download (ANALYST+)
  +--> /reports/export/ti-stats/   --> ti_stats_export          --> JSON download (ADMIN)
  +--> /reports/scheduled/<pk>/toggle/ --> scheduled_report_toggle --> redirect (ADMIN, POST)
  |
  +--> /iocs/                      --> ioc_list_view            --> emails/iocs.html
  |
  +--> /users/                     --> user_list_view           --> accounts/users.html (ADMIN)
  +--> /users/<pk>/edit-role/      --> user_edit_role_view      --> redirect (ADMIN, POST)
  +--> /users/<pk>/toggle-active/  --> user_toggle_active_view  --> redirect (ADMIN, POST)
  +--> /users/add/                 --> user_add_view            --> redirect (ADMIN, POST)
  |
  +--> (all Phase 6 routes unchanged)
  +--> /api/*                      --> DRF API views (Phase 5, unchanged)
```

### URL Routing Strategy (Phase 7 update)

```
stratos_server/urls.py
  |
  +--> /admin/                        Django admin
  +--> /health/                       Health probe
  +--> /api/                          include('emails.urls')            -- DRF API (Phase 5)
  +--> /accounts/login/               Django LoginView
  +--> /accounts/logout/              Django LogoutView
  +--> /threat-intel/                 include('threat_intel.template_urls')  -- TI views (Phase 7, app_name='ti')
  +--> /reports/                      include('reports.template_urls')       -- Reports views (Phase 7, app_name='reports')
  +--> /users/, /users/*              include('accounts.template_urls')      -- User mgmt (Phase 7, app_name='accounts')
  +--> /                              include('emails.template_urls')        -- Template views (Phase 6, app_name='ui')
```

4 URL namespaces: `ui`, `emails`, `ti`, `reports`, `accounts`

### Template Hierarchy (Phase 7 additions)

```
templates/
  (all Phase 6 templates unchanged)
  threat_intel/
    stats.html                  TI dashboard: stat cards, feed status, whitelist/blacklist, recent IOCs
  reports/
    list.html                   Export buttons, report history, scheduled reports
  emails/
    iocs.html                   Filterable, paginated IOC list
  accounts/
    users.html                  User management table (ADMIN only)
```

### Sidebar Navigation (Phase 7 update)

```
MONITOR section (all roles):
  Dashboard (/)
  Emails (/emails/)
  Quarantine (/quarantine/)

SECURITY section (all roles):
  Threat Intel (/threat-intel/)
  IOCs (/iocs/)

REPORTS section (all roles):
  Reports (/reports/)

ADMIN section (ADMIN only):
  Users (/users/)
  Django Admin (/admin/)
```

### Role-Based UI Visibility (Phase 7 update)

| UI Element                | ADMIN | ANALYST | VIEWER |
|---------------------------|-------|---------|--------|
| Dashboard                 | Yes   | Yes     | Yes    |
| Email list/detail         | Yes   | Yes     | Yes    |
| Raw analysis tab          | Yes   | Yes     | No     |
| Quarantine list           | Yes   | Yes     | Yes    |
| Quarantine actions        | Yes   | Yes     | No     |
| Threat Intel page         | Yes   | Yes     | Yes    |
| TI sync / list management | Yes   | No      | No     |
| IOC list                  | Yes   | Yes     | Yes    |
| Reports page              | Yes   | Yes     | Yes    |
| Export buttons             | Yes   | Yes     | No     |
| TI stats export (JSON)    | Yes   | No      | No     |
| User management           | Yes   | No      | No     |
| Admin sidebar link        | Yes   | No      | No     |

### Data Flow: Export (Streaming)

```
Browser --> GET /reports/export/emails/?verdict=MALICIOUS
  --> email_summary_export (login_required, ANALYST+ check)
  --> Email.objects.filter() with optional verdict/status/date filters
  --> HttpResponse(content_type='text/csv')
  --> csv.writer streams rows via qs.iterator() (no full materialization)
  --> Report.objects.create() audit record (type, format, filters, count)
  --> Browser downloads CSV file

Browser --> GET /reports/export/iocs/
  --> ioc_export_view (login_required, ANALYST+ check)
  --> ExtractedIOC.objects.select_related('email').iterator()
  --> HttpResponse streams CSV
  --> IOCExport.objects.create() audit record

Browser --> GET /reports/export/ti-stats/
  --> ti_stats_export (login_required, ADMIN check)
  --> Aggregate COUNT queries on MaliciousHash, MaliciousDomain, MaliciousIP, YaraRule
  --> json.dumps() into HttpResponse
  --> Report.objects.create() audit record
```

### Data Flow: TI Sync (Async)

```
Browser --> POST /threat-intel/sync/  (ADMIN only)
  --> threat_intel_sync_view
  --> sync_malwarebazaar_task.delay()
  --> sync_urlhaus_task.delay()
  --> Flash message "sync tasks queued"
  --> Redirect to /threat-intel/

Celery worker picks up tasks asynchronously
  --> sync_ti_feeds management command
  --> MaliciousHash / MaliciousDomain updated
```

### Data Flow: User Management

```
Browser --> GET /users/  (ADMIN only)
  --> user_list_view
  --> User.objects.all().order_by('username')
  --> render accounts/users.html

Browser --> POST /users/<pk>/edit-role/  (ADMIN only)
  --> user_edit_role_view
  --> Self-protection: cannot change own role
  --> target.role = new_role, target.save()
  --> redirect to user list

Browser --> POST /users/<pk>/toggle-active/  (ADMIN only)
  --> user_toggle_active_view
  --> Self-protection: cannot deactivate own account
  --> target.is_active toggled, target.save()
  --> redirect to user list

Browser --> POST /users/add/  (ADMIN only)
  --> user_add_view
  --> Username uniqueness check
  --> User.objects.create_user()
  --> redirect to user list
```

### Project Structure (Phase 7 additions)

```
threat_intel/
  views.py                        (6 views: stats, sync, whitelist add/remove, blacklist add/remove)
  template_urls.py                (6 URL patterns, app_name='ti')
reports/
  views.py                        (5 views: list, email_summary_export, ioc_export, ti_stats_export, scheduled_toggle)
  template_urls.py                (5 URL patterns, app_name='reports')
accounts/
  views.py                        (4 views: user_list, user_edit_role, user_toggle_active, user_add)
  template_urls.py                (4 URL patterns, app_name='accounts')
emails/
  views.py                        (added ioc_list_view)
  template_urls.py                (added /iocs/ pattern)
templates/
  threat_intel/stats.html         (TI dashboard with stat cards, feed status, whitelist/blacklist management)
  reports/list.html               (export buttons, report audit log, scheduled reports)
  emails/iocs.html                (filterable IOC list)
  accounts/users.html             (user management table, add/edit/toggle forms)
  base.html                       (updated sidebar: 4 sections — MONITOR, SECURITY, REPORTS, ADMIN)
stratos_server/
  urls.py                         (updated: added threat_intel, reports, accounts URL includes)
docs/
  screenshots/                    (4 new PNGs: 10-13)
    10-threat-intel.png
    11-reports.png
    12-iocs.png
    13-users.png
```

## Phase 8: Testing + Demo Prep -- ALL PHASES COMPLETE

### Test Architecture

```
tests/
  test_phase0.py                 (26 tests -- infra, health, settings)
  test_phase1.py                 (49 tests -- all 15 models)
  test_phase2.py                 (29 tests -- Gmail connector, parser)
  test_phase3.py                 (32 tests -- Preprocessor, SPF/DKIM/DMARC)
  test_phase4.py                 (35 tests -- Checker sub-checkers)
  test_phase5.py                 (39 tests -- Decider, TI sync, API)
  test_phase6_ui.py              (UI template view tests)
  test_phase7_ui.py              (TI/reports/users view tests)
  test_full_pipeline.py          (end-to-end pipeline integration)    [Phase 8 NEW]
  test_decider_boundaries.py     (verdict boundary edge cases)        [Phase 8 NEW]
  test_api_auth.py               (API auth and RBAC enforcement)      [Phase 8 NEW]
  test_export.py                 (CSV/JSON export validation)         [Phase 8 NEW]
  test_preprocessor_scoring.py   (preprocessor scoring edge cases)    [Phase 8 NEW]
  test_checker_scoring.py        (checker scoring edge cases)         [Phase 8 NEW]
```

Total: 351 tests | Coverage: 95% | All passing

### Demo Infrastructure

```
emails/management/commands/
  demo_setup.py                  (create demo users, emails, TI data for viva)
  demo_teardown.py               (cleanly remove all demo data)

docs/
  DEMO_SCRIPT.md                 (8-minute viva walkthrough script)
  QUICK_REFERENCE.md             (single-page reference card for examiner)
  screenshots/                   (20 screenshots: Figs 1-9 Phase 6, 10-13 Phase 7, 14-20 Phase 8)
```

### Management Commands (4 total)

| Command          | Location                                           | Purpose                    |
|------------------|----------------------------------------------------|----------------------------|
| seed_demo_data   | emails/management/commands/seed_demo_data.py       | Dev data seeding           |
| demo_setup       | emails/management/commands/demo_setup.py           | Viva demo data (idempotent)|
| demo_teardown    | emails/management/commands/demo_teardown.py        | Clean demo data removal    |
| sync_ti_feeds    | threat_intel/management/commands/sync_ti_feeds.py  | TI feed import from APIs   |

## System Configuration (Post-Phase 8)

### SystemConfig Model (Singleton)

```
SystemConfig (pk=1, always one row)
  _virustotal_api_key     (Fernet-encrypted TextField)
  _abuseipdb_api_key      (Fernet-encrypted TextField)
  gmail_credentials_uploaded  (Boolean)
  gmail_connection_status     (DISCONNECTED / CONNECTED / EXPIRED)
  gmail_connected_email       (EmailField)
  clean_threshold             (Integer, default 25)
  malicious_threshold         (Integer, default 70)
  fetch_interval_seconds      (Integer, default 10)
  ti_sync_enabled             (Boolean, default True)
  updated_at                  (auto)
  updated_by                  (FK User)
```

API keys are encrypted using Fernet (AES-128-CBC) derived from Django SECRET_KEY.

### Settings URL Patterns

| Method | Path                          | View                          | Description                |
|--------|-------------------------------|-------------------------------|----------------------------|
| GET    | /settings/                    | settings_view                 | Settings page (ADMIN only) |
| POST   | /settings/api-keys/           | save_api_keys                 | Save TI API keys           |
| POST   | /settings/thresholds/         | save_thresholds               | Save detection thresholds  |
| POST   | /settings/gmail/upload/       | upload_gmail_credentials      | Upload OAuth JSON file     |
| GET    | /settings/gmail/connect/      | gmail_connect                 | Start OAuth web flow       |
| GET    | /settings/gmail/callback/     | gmail_callback                | Google OAuth callback      |
| POST   | /settings/gmail/disconnect/   | gmail_disconnect              | Remove token + disconnect  |
| GET    | /settings/gmail/status/       | gmail_status                  | AJAX connection check      |
| POST   | /settings/test/virustotal/    | test_virustotal               | Test VT API key            |
| POST   | /settings/test/abuseipdb/     | test_abuseipdb                | Test AbuseIPDB key         |

### Gmail OAuth Web Flow

```
Admin Browser                    Stratos Server                Google OAuth
    |                                |                             |
    |  Click "Connect Gmail"         |                             |
    |------------------------------->|                             |
    |                                |  Generate auth URL + state  |
    |                                |  Save state in session      |
    |  Redirect to Google            |                             |
    |------------------------------------------------------->     |
    |                                |                    Login    |
    |                                |                    Grant    |
    |  Redirect to /callback/?code=  |                             |
    |<-------------------------------------------------------|     |
    |------------------------------->|                             |
    |                                |  Verify state (CSRF)       |
    |                                |  Exchange code for token   |
    |                                |  Save token to file        |
    |                                |  Get email from Gmail API  |
    |                                |  Update SystemConfig       |
    |  Settings page: CONNECTED      |                             |
    |<-------------------------------|                             |
```

### Production Deployment Architecture

```
+-------------------------------------------------------------------+
|                     Docker Compose Network                         |
|                                                                    |
|  +---------+  +-------+  +-----------+  +--------+  +-----------+ |
|  | postgres |  | redis |  |  django   |  | celery |  | celery-   | |
|  | :15      |  | :7    |  |  gunicorn |  | worker |  | beat      | |
|  | 5432     |  | 6379  |  |  :8000    |  |        |  |           | |
|  +---------+  +-------+  +-----------+  +--------+  +-----------+ |
|                                |                                   |
|  +-----------------------------+---+                               |
|  |        caddy (reverse proxy)    |                               |
|  |   :80 (HTTP) / :443 (HTTPS)    |                               |
|  +---------------------------------+                               |
+-------------------------------------------------------------------+
```

### Key Files Added

| File                         | Purpose                                    |
|------------------------------|--------------------------------------------|
| emails/models.py (SystemConfig) | Singleton config with encrypted API keys |
| emails/settings_views.py     | 10 views for settings management           |
| emails/settings_urls.py      | URL routing for /settings/                 |
| templates/settings/index.html| Settings page template (ADMIN only)        |
| docker-compose.prod.yml      | Production compose with Caddy + gunicorn   |
| Caddyfile                    | Reverse proxy config (HTTP/HTTPS)          |
| docs/DEPLOYMENT.md           | Step-by-step Hetzner deployment guide       |
| docs/ADMIN_GUIDE.md          | Admin usage instructions                   |
