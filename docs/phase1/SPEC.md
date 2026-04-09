# SPEC: Phase 1 -- All 15 Django Models + Migrations

## Goal

Define all 14 remaining Django models (User already exists), generate migrations, and register every model in Django admin with useful `list_display` so that `python manage.py migrate` produces zero unapplied migrations and `/admin/` shows all 15 models.

## In Scope

### S-01: emails app -- 5 models

All models in `emails/models.py`. Each model includes complete field definitions, choices, constraints, Meta options, and `__str__` methods.

**Email**
| Field | Type | Constraints |
|-------|------|-------------|
| message_id | CharField(255) | unique=True, db_index=True |
| gmail_id | CharField(100) | null=True, blank=True |
| from_address | EmailField | db_index=True |
| from_display_name | CharField(255) | blank=True |
| to_addresses | JSONField | default=list |
| cc_addresses | JSONField | null=True, blank=True |
| reply_to | EmailField | null=True, blank=True |
| subject | CharField(500) | |
| body_text | TextField | blank=True |
| body_html | TextField | null=True, blank=True |
| headers_raw | JSONField | default=dict |
| received_chain | JSONField | default=list |
| urls_extracted | JSONField | default=list |
| status | CharField(20) | choices: PENDING/ANALYZING/DELIVERED/QUARANTINED/BLOCKED, default='PENDING', db_index=True |
| verdict | CharField(15) | choices: CLEAN/SUSPICIOUS/MALICIOUS, null=True, blank=True, db_index=True |
| score | IntegerField | null=True, blank=True |
| confidence | CharField(10) | choices: LOW/MEDIUM/HIGH, null=True, blank=True |
| analyzed_at | DateTimeField | null=True, blank=True |
| received_at | DateTimeField | db_index=True |
| created_at | DateTimeField | auto_now_add=True |
| updated_at | DateTimeField | auto_now=True |

- Meta: `ordering = ['-received_at']`
- `__str__`: `f"{self.subject} from {self.from_address}"`

**EmailAttachment**
| Field | Type | Constraints |
|-------|------|-------------|
| email | ForeignKey(Email) | on_delete=CASCADE, related_name='attachments' |
| filename | CharField(255) | |
| content_type | CharField(100) | |
| size_bytes | IntegerField | |
| sha256_hash | CharField(64) | db_index=True |
| md5_hash | CharField(32) | |
| file_magic | CharField(100) | null=True, blank=True |
| is_dangerous_ext | BooleanField | default=False |
| is_double_ext | BooleanField | default=False |
| is_mime_mismatch | BooleanField | default=False |
| yara_matches | JSONField | null=True, blank=True |
| ti_match | CharField(50) | null=True, blank=True |
| created_at | DateTimeField | auto_now_add=True |

- `__str__`: `f"{self.filename} ({self.sha256_hash[:8]})"`

**AnalysisResult**
| Field | Type | Constraints |
|-------|------|-------------|
| email | OneToOneField(Email) | on_delete=CASCADE, related_name='analysis' |
| preprocess_score | IntegerField | default=0 |
| spf_result | CharField(20) | choices: pass/fail/softfail/none, default='none' |
| dkim_result | CharField(20) | choices: pass/fail/none, default='none' |
| dmarc_result | CharField(20) | choices: pass/fail/none, default='none' |
| is_reply_to_mismatch | BooleanField | default=False |
| is_display_spoof | BooleanField | default=False |
| keyword_score | IntegerField | default=0 |
| keywords_matched | JSONField | default=list |
| url_score | IntegerField | default=0 |
| url_findings | JSONField | default=list |
| attachment_score | IntegerField | default=0 |
| attachment_findings | JSONField | default=list |
| chain_score | IntegerField | default=0 |
| chain_findings | JSONField | default=dict |
| total_score | IntegerField | default=0 |
| pipeline_duration_ms | IntegerField | null=True, blank=True |
| created_at | DateTimeField | auto_now_add=True |

- `__str__`: `f"Analysis for {self.email.message_id} -- {self.email.verdict}"`

**QuarantineEntry**
| Field | Type | Constraints |
|-------|------|-------------|
| email | OneToOneField(Email) | on_delete=CASCADE, related_name='quarantine' |
| status | CharField(20) | choices: PENDING/RELEASED/DELETED/BLOCKED, default='PENDING', db_index=True |
| action | CharField(20) | null=True, blank=True |
| reviewer | ForeignKey(User) | null=True, blank=True, on_delete=SET_NULL |
| reviewed_at | DateTimeField | null=True, blank=True |
| notes | TextField | blank=True |
| created_at | DateTimeField | auto_now_add=True |

- `__str__`: `f"Quarantine: {self.email.subject} [{self.status}]"`

**ExtractedIOC**
| Field | Type | Constraints |
|-------|------|-------------|
| email | ForeignKey(Email) | on_delete=CASCADE, related_name='iocs' |
| ioc_type | CharField(20) | choices: HASH/URL/IP/DOMAIN, db_index=True |
| value | CharField(500) | db_index=True |
| severity | CharField(10) | choices: CRITICAL/HIGH/MEDIUM/LOW, default='HIGH' |
| source_checker | CharField(50) | blank=True |
| first_seen | DateTimeField | auto_now_add=True |

- `__str__`: `f"{self.ioc_type}: {self.value[:50]}"`

### S-02: threat_intel app -- 6 models

All models in `threat_intel/models.py`.

**MaliciousHash**
| Field | Type | Constraints |
|-------|------|-------------|
| sha256_hash | CharField(64) | unique=True, db_index=True |
| md5_hash | CharField(32) | blank=True |
| malware_family | CharField(100) | blank=True |
| source | CharField(30) | choices: MALWAREBAZAAR/VIRUSTOTAL/MANUAL, default='MALWAREBAZAAR' |
| severity | CharField(10) | choices: CRITICAL/HIGH/MEDIUM, default='HIGH' |
| added_at | DateTimeField | auto_now_add=True |

- `__str__`: `f"{self.sha256_hash[:16]}... ({self.malware_family})"`

**MaliciousDomain**
| Field | Type | Constraints |
|-------|------|-------------|
| domain | CharField(255) | unique=True, db_index=True |
| category | CharField(50) | blank=True |
| source | CharField(30) | choices: URLHAUS/VIRUSTOTAL/ABUSEIPDB/MANUAL, default='URLHAUS' |
| added_at | DateTimeField | auto_now_add=True |

- `__str__`: `return self.domain`

**MaliciousIP**
| Field | Type | Constraints |
|-------|------|-------------|
| ip_address | GenericIPAddressField | unique=True, db_index=True |
| category | CharField(50) | blank=True |
| source | CharField(30) | choices: ABUSEIPDB/VIRUSTOTAL/MANUAL, default='ABUSEIPDB' |
| abuse_score | IntegerField | default=0 |
| added_at | DateTimeField | auto_now_add=True |

- `__str__`: `return self.ip_address`

**YaraRule**
| Field | Type | Constraints |
|-------|------|-------------|
| name | CharField(100) | unique=True |
| rule_content | TextField | |
| severity | CharField(10) | choices: CRITICAL/HIGH/MEDIUM, default='HIGH' |
| description | TextField | blank=True |
| is_active | BooleanField | default=True |
| added_at | DateTimeField | auto_now_add=True |

- `__str__`: `f"{self.name} ({'active' if self.is_active else 'inactive'})"`

**WhitelistEntry**
| Field | Type | Constraints |
|-------|------|-------------|
| entry_type | CharField(10) | choices: EMAIL/DOMAIN/IP |
| value | CharField(255) | db_index=True |
| reason | TextField | blank=True |
| added_by | ForeignKey(User) | null=True, on_delete=SET_NULL |
| added_at | DateTimeField | auto_now_add=True |

- Meta: `unique_together = [('entry_type', 'value')]`
- `__str__`: `f"Whitelist {self.entry_type}: {self.value}"`

**BlacklistEntry**
| Field | Type | Constraints |
|-------|------|-------------|
| entry_type | CharField(10) | choices: EMAIL/DOMAIN/IP |
| value | CharField(255) | db_index=True |
| reason | TextField | blank=True |
| added_by | ForeignKey(User) | null=True, on_delete=SET_NULL |
| added_at | DateTimeField | auto_now_add=True |

- Meta: `unique_together = [('entry_type', 'value')]`
- `__str__`: `f"Blacklist {self.entry_type}: {self.value}"`

### S-03: reports app -- 3 models

All models in `reports/models.py`.

**Report**
| Field | Type | Constraints |
|-------|------|-------------|
| report_type | CharField(30) | choices: EMAIL_SUMMARY/THREAT_INTEL/IOC_EXPORT/CUSTOM |
| generated_by | ForeignKey(User) | null=True, on_delete=SET_NULL |
| file_path | CharField(500) | blank=True |
| format | CharField(10) | choices: CSV/JSON/PDF, default='CSV' |
| filters_applied | JSONField | default=dict |
| record_count | IntegerField | default=0 |
| file_size_bytes | IntegerField | default=0 |
| created_at | DateTimeField | auto_now_add=True, db_index=True |

- `__str__`: `f"{self.report_type} report -- {self.created_at.date()}"`

**ScheduledReport**
| Field | Type | Constraints |
|-------|------|-------------|
| report_type | CharField(30) | choices: EMAIL_SUMMARY/THREAT_INTEL/IOC_EXPORT/CUSTOM (same as Report) |
| schedule | CharField(10) | choices: DAILY/WEEKLY/MONTHLY |
| last_run | DateTimeField | null=True, blank=True |
| next_run | DateTimeField | null=True, blank=True, db_index=True |
| is_active | BooleanField | default=True |
| recipients | JSONField | default=list |
| created_by | ForeignKey(User) | null=True, on_delete=SET_NULL |
| created_at | DateTimeField | auto_now_add=True |

- `__str__`: `f"{self.schedule} {self.report_type}"`

**IOCExport**
| Field | Type | Constraints |
|-------|------|-------------|
| export_format | CharField(10) | choices: CSV/JSON/STIX, default='CSV' |
| ioc_types | JSONField | default=list |
| record_count | IntegerField | default=0 |
| file_path | CharField(500) | blank=True |
| created_by | ForeignKey(User) | null=True, on_delete=SET_NULL |
| created_at | DateTimeField | auto_now_add=True |

- `__str__`: `f"IOC Export {self.export_format} -- {self.record_count} records"`

### S-04: Django admin registration

**emails/admin.py:**
| Model | list_display | list_filter | search_fields |
|-------|-------------|-------------|---------------|
| Email | id, from_address, subject, verdict, score, status, received_at | verdict, status | from_address, subject |
| EmailAttachment | email, filename, sha256_hash, is_dangerous_ext, ti_match | is_dangerous_ext | filename, sha256_hash |
| AnalysisResult | email, total_score, spf_result, keyword_score | spf_result | -- |
| QuarantineEntry | email, status, reviewer, reviewed_at | status | -- |
| ExtractedIOC | email, ioc_type, value, severity | ioc_type, severity | value |

**threat_intel/admin.py:**
| Model | list_display | list_filter | search_fields |
|-------|-------------|-------------|---------------|
| MaliciousHash | sha256_hash, malware_family, source, severity, added_at | source, severity | sha256_hash, malware_family |
| MaliciousDomain | domain, category, source, added_at | source | domain |
| MaliciousIP | ip_address, category, abuse_score, added_at | source | ip_address |
| YaraRule | name, severity, is_active, added_at | severity, is_active | name |
| WhitelistEntry | entry_type, value, reason, added_by | entry_type | value |
| BlacklistEntry | entry_type, value, reason, added_by | entry_type | value |

**reports/admin.py:**
| Model | list_display | list_filter | search_fields |
|-------|-------------|-------------|---------------|
| Report | report_type, generated_by, format, record_count, created_at | report_type, format | -- |
| ScheduledReport | report_type, schedule, is_active, next_run | schedule, is_active | -- |
| IOCExport | export_format, record_count, created_by, created_at | export_format | -- |

### S-05: Migrations

- Run `python manage.py makemigrations emails threat_intel reports` to generate initial migration files for the three apps.
- The `accounts` app already has `0001_initial.py` from Phase 0; do NOT regenerate it.
- Verify with `python manage.py migrate` that all migrations apply cleanly.

## Out of Scope

- Service/business logic (preprocessor, checker, decider) -- Phase 3-5
- Views, URL routes, serializers -- Phase 2+
- Celery tasks -- Phase 2+
- Fixtures, seed data, or management commands -- Phase 8
- Any changes to `accounts.User` model (already complete from Phase 0)
- REST API endpoints -- Phase 5
- Frontend templates or static files -- Phase 6
- YARA rule file content (the `YaraRule` model stores rules; actual `.yar` files are Phase 4)
- Model methods beyond `__str__` (e.g., scoring helpers, verdict logic)

## Acceptance Criteria

| ID | Criterion | Pass Condition |
|----|-----------|----------------|
| AC-001 | `python manage.py migrate` completes with zero errors and zero unapplied migrations | Exit code 0; `showmigrations` shows no `[ ]` entries |
| AC-002 | `python manage.py check` reports no issues | Output contains `System check identified no issues` |
| AC-003 | All 5 emails models importable | `from emails.models import Email, EmailAttachment, AnalysisResult, QuarantineEntry, ExtractedIOC` succeeds |
| AC-004 | All 6 threat_intel models importable | `from threat_intel.models import MaliciousHash, MaliciousDomain, MaliciousIP, YaraRule, WhitelistEntry, BlacklistEntry` succeeds |
| AC-005 | All 3 reports models importable | `from reports.models import Report, ScheduledReport, IOCExport` succeeds |
| AC-006 | Email creation works with required fields | `Email.objects.create(message_id='test-001', from_address='a@b.com', subject='Test', received_at=now())` succeeds without error |
| AC-007 | Email status field rejects invalid choice | `Email(status='INVALID')` followed by `full_clean()` raises `ValidationError` |
| AC-008 | AnalysisResult OneToOne constraint enforced | Creating two AnalysisResult rows for the same Email raises `IntegrityError` |
| AC-009 | WhitelistEntry unique_together enforced | Creating duplicate `(entry_type, value)` pair raises `IntegrityError` |
| AC-010 | Django admin `/admin/` shows all 15 models without errors | Navigate to admin; all 15 models appear in their respective app sections; each model's changelist page loads without 500 |

## API Contracts

No new API endpoints are introduced in Phase 1. The only existing endpoint is `GET /health/` from Phase 0, which remains unchanged.

## Data Model Changes

14 new models are added across 3 apps. See S-01, S-02, and S-03 above for complete field definitions.

**Summary by app:**

| App | New Models | Total Fields (excluding id) |
|-----|-----------|---------------------------|
| emails | Email (21), EmailAttachment (13), AnalysisResult (17), QuarantineEntry (7), ExtractedIOC (6) | 64 |
| threat_intel | MaliciousHash (6), MaliciousDomain (4), MaliciousIP (5), YaraRule (6), WhitelistEntry (5), BlacklistEntry (5) | 31 |
| reports | Report (8), ScheduledReport (8), IOCExport (6) | 22 |
| **Total** | **14 new models** | **117 fields** |

**Foreign key relationships:**
- `EmailAttachment.email` -> `Email` (CASCADE)
- `AnalysisResult.email` -> `Email` (CASCADE, OneToOne)
- `QuarantineEntry.email` -> `Email` (CASCADE, OneToOne)
- `QuarantineEntry.reviewer` -> `User` (SET_NULL)
- `ExtractedIOC.email` -> `Email` (CASCADE)
- `WhitelistEntry.added_by` -> `User` (SET_NULL)
- `BlacklistEntry.added_by` -> `User` (SET_NULL)
- `Report.generated_by` -> `User` (SET_NULL)
- `ScheduledReport.created_by` -> `User` (SET_NULL)
- `IOCExport.created_by` -> `User` (SET_NULL)

## File Manifest

Files to be created or modified in this phase:

```
emails/
  models.py              # MODIFY: add 5 models (currently empty)
  admin.py               # MODIFY: register 5 models with ModelAdmin classes
  migrations/
    0001_initial.py      # CREATE: auto-generated by makemigrations

threat_intel/
  models.py              # MODIFY: add 6 models (currently empty)
  admin.py               # MODIFY: register 6 models with ModelAdmin classes
  migrations/
    0001_initial.py      # CREATE: auto-generated by makemigrations

reports/
  models.py              # MODIFY: add 3 models (currently empty)
  admin.py               # MODIFY: register 3 models with ModelAdmin classes
  migrations/
    0001_initial.py      # CREATE: auto-generated by makemigrations

tests/
  test_phase1.py         # CREATE: phase 1 test suite
```

**Files NOT touched:**
- `accounts/models.py` -- already complete
- `accounts/admin.py` -- already registers User
- `accounts/migrations/0001_initial.py` -- already exists
- `stratos_server/settings/*` -- no changes needed
- `stratos_server/urls.py` -- no new endpoints

## Dependencies

| Dependency | Source | Status |
|-----------|--------|--------|
| Django project scaffold | Phase 0 | COMPLETE |
| Custom User model (`accounts.User`) | Phase 0 | COMPLETE |
| `accounts/migrations/0001_initial.py` | Phase 0 | COMPLETE |
| 4 apps registered in INSTALLED_APPS | Phase 0 | COMPLETE |
| PostgreSQL + Django ORM configured | Phase 0 | COMPLETE |

All Phase 0 deliverables must be in place. The implementer should verify `python manage.py check` passes before starting model work.

## Open Questions

| ID | Question | Impact |
|----|----------|--------|
| OQ-1 | Should `EmailAttachment` store the actual file content (as `FileField` or `BinaryField`), or only metadata? The current spec stores only metadata fields (filename, hashes, size). The actual file bytes would need to come from Gmail API at analysis time. | If file storage is needed, a `FileField` or blob storage path should be added. Current spec assumes metadata-only since attachments are fetched on-demand from Gmail. |
| OQ-2 | The `Report.format` field name shadows Python's built-in `format()`. Should it be renamed to `output_format`? | Minor code smell. Django handles it fine but could cause confusion. Human decision needed. |
| OQ-3 | Should `BlacklistEntry` and `WhitelistEntry` share an abstract base model to reduce code duplication, or remain as separate concrete models? | No functional impact. Abstract base would reduce ~10 lines of duplication. Current spec defines them as separate models matching the CLAUDE.md model count of 15. |
| OQ-4 | The `AnalysisResult.__str__` references `self.email.verdict` which triggers an extra DB query. Should it use `self.total_score` instead for efficiency? | Minor performance concern in admin list views. `select_related` in admin can mitigate this. |

## Test Plan

The qa-agent should create `tests/test_phase1.py` with a minimum of 20 tests covering the following categories.

### Model Import Tests (3 tests)
1. **T-001:** Import all 5 emails models without error.
2. **T-002:** Import all 6 threat_intel models without error.
3. **T-003:** Import all 3 reports models without error.

### Model Creation Tests (6 tests)
4. **T-004:** Create an `Email` with all required fields; assert it saves and has an auto-generated `id`.
5. **T-005:** Create an `EmailAttachment` linked to an Email; assert FK relationship works and `related_name='attachments'` returns it.
6. **T-006:** Create an `AnalysisResult` linked to an Email; assert OneToOne relationship works and `email.analysis` returns it.
7. **T-007:** Create a `QuarantineEntry` linked to an Email with a reviewer User; assert FK to User works.
8. **T-008:** Create an `ExtractedIOC` linked to an Email; assert `related_name='iocs'` returns it.
9. **T-009:** Create one instance of each threat_intel model (`MaliciousHash`, `MaliciousDomain`, `MaliciousIP`, `YaraRule`, `WhitelistEntry`, `BlacklistEntry`); assert all save without error.

### Default Value Tests (3 tests)
10. **T-010:** Create an `Email` without specifying `status`; assert `status == 'PENDING'`.
11. **T-011:** Create an `AnalysisResult`; assert all score fields default to 0.
12. **T-012:** Create a `MaliciousHash` without specifying `severity`; assert `severity == 'HIGH'`.

### Constraint Tests (4 tests)
13. **T-013:** Create two Emails with the same `message_id`; assert `IntegrityError` on the second.
14. **T-014:** Create two `AnalysisResult` rows for the same Email; assert `IntegrityError`.
15. **T-015:** Create two `WhitelistEntry` rows with the same `(entry_type, value)`; assert `IntegrityError`.
16. **T-016:** Call `full_clean()` on an Email with `status='INVALID'`; assert `ValidationError`.

### String Representation Tests (3 tests)
17. **T-017:** Assert `str(email)` returns `f"{subject} from {from_address}"`.
18. **T-018:** Assert `str(malicious_hash)` contains the first 16 chars of the sha256 hash.
19. **T-019:** Assert `str(yara_rule)` contains 'active' when `is_active=True` and 'inactive' when `is_active=False`.

### Admin Registration Tests (3 tests)
20. **T-020:** Assert all 5 emails models are registered in `django.contrib.admin.site._registry`.
21. **T-021:** Assert all 6 threat_intel models are registered in `django.contrib.admin.site._registry`.
22. **T-022:** Assert all 3 reports models are registered in `django.contrib.admin.site._registry`.

### Relationship and Cascade Tests (2 tests)
23. **T-023:** Delete an Email; assert its related `EmailAttachment`, `AnalysisResult`, `QuarantineEntry`, and `ExtractedIOC` are also deleted (CASCADE).
24. **T-024:** Delete a User who is `reviewer` on a `QuarantineEntry`; assert the QuarantineEntry still exists with `reviewer=None` (SET_NULL).

### Migration Integrity Tests (1 test)
25. **T-025:** Run `call_command('showmigrations')` and assert no unapplied migrations exist (no `[ ]` in output).

### JSONField Default Tests (1 test)
26. **T-026:** Create an Email without specifying `to_addresses`, `headers_raw`, `received_chain`, `urls_extracted`; assert each defaults to its expected empty type (`[]` or `{}`).

**Total: 26 tests**
