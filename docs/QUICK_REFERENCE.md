# Stratos BEP -- Quick Reference Card

## Project

| Field | Value |
|-------|-------|
| Product | Stratos BEP (Business Email Protection) |
| Tagline | "Threats burn up before they land" |
| Framework | Django 4.2, Python 3.10+ |
| Database | PostgreSQL 15+ |
| Task Queue | Redis + Celery |
| API | Django REST Framework |
| Models | 15 total across 4 apps |
| Tests | 351 (15 test files) |
| Coverage (full project) | 82% (1,863 statements) |
| Coverage (core pipeline) | 95%+ (analyzer 100%, decider 100%, checker 92%, preprocessor 90%) |

## Analysis Pipeline

```
Email -> PARSE -> PREPROCESS -> CHECK -> DECIDE -> ACT
                                                    |
Target: <30 seconds per email          CLEAN / SUSPICIOUS / MALICIOUS
```

### Scoring Thresholds

| Verdict | Score Range | Action |
|---------|------------|--------|
| CLEAN | 0 - 24 | Delivered |
| SUSPICIOUS | 25 - 69 | Quarantined for review |
| MALICIOUS | 70 - 100 | Blocked |

### Preprocessor Scoring

| Check | Points |
|-------|--------|
| SPF fail | +15 |
| SPF softfail | +5 |
| SPF none | +10 |
| DKIM fail | +15 |
| DKIM none | +5 |
| DMARC fail | +15 |
| DMARC none | +5 |
| Blacklist email | +40 |
| Blacklist domain | +30 |
| Reply-To mismatch | +10 |
| Display name spoof | +10 |
| Whitelist match | verdict_override=CLEAN (skip all) |

### Checker Scoring

| Check | Max Points |
|-------|-----------|
| Keywords (24 total) | +2 each, max +20 |
| URLs (URLhaus + VirusTotal) | max +40 |
| Attachments (MalwareBazaar + YARA + magic) | max +50 |
| Received chain anomalies | max +15 |

## Page URLs

| URL | Page | Description |
|-----|------|-------------|
| `/` | Dashboard | Overview with verdict distribution and statistics |
| `/emails/` | Email List | All analyzed emails with verdict filters |
| `/emails/<pk>/` | Email Detail | Full analysis breakdown for single email |
| `/quarantine/` | Quarantine | Emails awaiting analyst review with actions |
| `/iocs/` | IOC List | Extracted indicators of compromise |
| `/threat-intel/` | Threat Intelligence | TI feeds, hashes, domains, YARA rules |
| `/reports/` | Reports | Export and scheduled report management |
| `/users/` | User Management | User accounts and role assignment |
| `/accounts/login/` | Login | Authentication page |

## API Endpoints (prefix: `/api/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/emails/` | List emails (filterable by verdict, status) |
| GET | `/api/emails/<pk>/` | Email detail with full analysis |
| GET | `/api/quarantine/` | List quarantine entries |
| POST | `/api/quarantine/<pk>/action/` | Take action (release/delete/block) |
| GET | `/api/dashboard/stats/` | Dashboard statistics JSON |

## User Credentials (Demo)

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| admin | admin123 | ADMIN | Full access, user management, TI config |
| analyst | analyst123 | ANALYST | Review quarantine, take actions |
| viewer | viewer123 | VIEWER | Read-only access to all pages |

## Management Commands

| Command | Description |
|---------|-------------|
| `python manage.py demo_setup` | Create complete demo scenario (10 emails, TI data, users) |
| `python manage.py demo_setup --flush` | Clear existing demo data then recreate |
| `python manage.py demo_teardown` | Remove demo emails (preserves users) |
| `python manage.py seed_demo_data` | Seed basic demo data (Phase 2 legacy) |
| `python manage.py fetch_emails` | Fetch emails from Gmail API |

## Threat Intelligence Feeds

| Feed | Data Type | Rate Limit |
|------|-----------|------------|
| MalwareBazaar | Malicious file hashes | Unlimited |
| URLhaus | Malicious URLs and domains | Unlimited |
| VirusTotal | Hash and URL cross-reference | 4 req/min |
| AbuseIPDB | Malicious IP addresses | 1000/day |

## Phishing Keywords (24)

```
verify your account          urgent action required       confirm your identity
unusual activity             suspended account            click here immediately
update your payment          security alert               unauthorized access
reset your password          limited time offer           act now
your account will be closed  verify your information      important security update
confirm your email           invoice attached             wire transfer
bank account details         confidential request         gift card
bitcoin payment              do not share with anyone     reply urgently
```

## YARA Rules (6)

| ID | Name | Severity |
|----|------|----------|
| yara_001 | VBA_macro_suspicious | HIGH |
| yara_002 | PE_executable_in_email | CRITICAL |
| yara_003 | JS_obfuscation_pattern | HIGH |
| yara_004 | Double_extension_exe | HIGH |
| yara_005 | OLE_suspicious_stream | HIGH |
| yara_006 | Ransomware_file_patterns | CRITICAL |

## Dangerous Extensions (13)

```
.exe .scr .vbs .js .bat .cmd .ps1 .hta .com .dll .msi .pif .wsf
```

## Django Apps and Models

### emails (5 models)
- **Email** -- Core email record with verdict, score, status
- **EmailAttachment** -- File attachments with hash, YARA, TI match info
- **AnalysisResult** -- Full score breakdown per pipeline stage (OneToOne with Email)
- **QuarantineEntry** -- Quarantine queue with review actions
- **ExtractedIOC** -- Indicators of compromise extracted during analysis

### accounts (1 model)
- **User** -- AbstractUser with role field (ADMIN / ANALYST / VIEWER)

### threat_intel (6 models)
- **MaliciousHash** -- SHA256 hashes from MalwareBazaar/VirusTotal
- **MaliciousDomain** -- Domains from URLhaus/VirusTotal
- **MaliciousIP** -- IPs from AbuseIPDB
- **YaraRule** -- YARA rule definitions for attachment scanning
- **WhitelistEntry** -- Trusted senders (bypass all checks)
- **BlacklistEntry** -- Known bad senders (automatic scoring)

### reports (3 models)
- **Report** -- Generated report records
- **ScheduledReport** -- Recurring report configuration
- **IOCExport** -- IOC export records

## Services (emails/services/)

| Service | Method | Purpose |
|---------|--------|---------|
| GmailConnector | `fetch_new_emails()` | Pull emails via Gmail API |
| EmailParser | `parse_raw_email()` | Parse raw email into model fields |
| Preprocessor | `process()` | SPF/DKIM/DMARC + whitelist/blacklist |
| Checker | `check_all()` | Keywords, URLs, attachments, YARA |
| Decider | `decide()` | Score aggregation and verdict |
| EmailAnalyzer | `analyze(email_id)` | Orchestrate full pipeline |

## Celery Tasks

| Task | Schedule |
|------|----------|
| `analyze_email_task(email_id)` | On demand (per email) |
| `fetch_gmail_task()` | Periodic (Celery Beat) |
| `sync_malwarebazaar_task()` | Daily |
| `sync_urlhaus_task()` | Daily |
