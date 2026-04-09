# SPEC: Phase 4 -- Checker Engine

## Goal

Implement the Checker service with four sub-checkers (keywords, URLs, attachments, received chain) that perform content-level threat detection on emails not whitelisted by the Preprocessor, producing scored findings that feed into the Decider in Phase 5.

## In Scope

### 1. New file: `emails/services/checker.py`

#### CheckResult dataclass

```python
@dataclass
class CheckResult:
    keyword_score: int = 0
    keywords_matched: list = field(default_factory=list)
    url_score: int = 0
    url_findings: list = field(default_factory=list)
    attachment_score: int = 0
    attachment_findings: list = field(default_factory=list)
    chain_score: int = 0
    chain_findings: dict = field(default_factory=dict)
    total_check_score: int = 0
    has_known_malware: bool = False
```

`total_check_score` = `keyword_score + url_score + attachment_score + chain_score`. This is the Checker's contribution only; it does NOT include the Preprocessor's score. The combined total is computed by the Decider in Phase 5.

#### Checker class

**Class-level constants:**

```python
KEYWORDS: list[str] = [
    'verify your account', 'urgent action required', 'confirm your identity',
    'unusual activity', 'suspended account', 'click here immediately',
    'update your payment', 'security alert', 'unauthorized access',
    'reset your password', 'limited time offer', 'act now',
    'your account will be closed', 'verify your information',
    'important security update', 'confirm your email',
    'invoice attached', 'wire transfer', 'bank account details',
    'confidential request', 'gift card', 'bitcoin payment',
    'do not share with anyone', 'reply urgently',
]  # 24 keywords

DANGEROUS_EXTENSIONS: set[str] = {
    '.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1',
    '.hta', '.com', '.dll', '.msi', '.pif', '.wsf',
}

URL_SHORTENERS: set[str] = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
    'ow.ly', 'buff.ly', 'short.io', 'rebrand.ly',
}
```

**Public method:**

```python
def check_all(self, email: Email) -> CheckResult
```

Calls the four private methods below, sums their scores into `total_check_score`, and returns `CheckResult`. Like the Preprocessor, `check_all()` must never raise exceptions to the caller. Wrap the entire body in try/except, log errors, and return a safe default `CheckResult()` on failure.

---

#### Method 1: `_check_keywords(email: Email) -> tuple[int, list[str]]`

**Logic:**
1. Combine `email.subject` and `email.body_text` into a single search string (lowercase).
2. For each of the 24 `KEYWORDS`, check if it appears as a case-insensitive substring in the combined text.
3. Each match: +2 points. Multiple occurrences of the same keyword count only once.
4. Cap the keyword_score at 20 (max 10 unique keywords count toward score).
5. Return `(score, list_of_matched_keywords)`.

**Scoring:** +2 per unique keyword match, max 20.

---

#### Method 2: `_check_urls(email: Email) -> tuple[int, list[dict]]`

**Logic:**
1. Read `email.urls_extracted` (a JSON list of URL strings populated by EmailParser in Phase 2).
2. If the list is empty, return `(0, [])`.
3. For each URL:
   a. Parse the URL to extract the hostname.
   b. **MaliciousDomain match:** Query `MaliciousDomain.objects.filter(domain__iexact=hostname)`. If found: +30, add finding `{'url': url, 'type': 'malicious_domain', 'domain': hostname}`.
   c. **IP-based URL:** If hostname is an IP address (detect using regex `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`): +10, add finding `{'url': url, 'type': 'ip_url', 'ip': hostname}`.
   d. **URL shortener:** If hostname (lowercase) is in `URL_SHORTENERS`: +5, add finding `{'url': url, 'type': 'shortener', 'service': hostname}`.
   e. A single URL can trigger multiple rules (e.g., an IP-based shortener). Score contributions are cumulative per URL.
4. Cap the total url_score at 40.
5. Return `(capped_score, findings_list)`.

**DB queries:** `MaliciousDomain` lookup per unique hostname (deduplicate hostnames before querying).

**NOT in scope:** VirusTotal URL lookup (deferred to Phase 5 or later).

---

#### Method 3: `_check_attachments(email: Email) -> tuple[int, list[dict], bool]`

**Logic:**
1. Fetch `email.attachments.all()` (related `EmailAttachment` queryset).
2. If no attachments, return `(0, [], False)`.
3. For each attachment, apply these checks in order:

   a. **MaliciousHash match:** Query `MaliciousHash.objects.filter(sha256_hash=attachment.sha256_hash)`. If found: +50, set `has_known_malware = True`, set `attachment.ti_match = 'MALWAREBAZAAR'` (or the source from the MaliciousHash record), add finding `{'filename': filename, 'type': 'known_malware', 'sha256': hash, 'malware_family': family}`.

   b. **Dangerous extension:** Check if the file extension (lowercase, including the dot) is in `DANGEROUS_EXTENSIONS`. If yes: +15, set `attachment.is_dangerous_ext = True`, add finding `{'filename': filename, 'type': 'dangerous_ext', 'extension': ext}`.

   c. **Double extension:** Check if the filename has two or more extensions where the last extension is in `DANGEROUS_EXTENSIONS` (e.g., `report.pdf.exe`, `document.docx.scr`). Detection: split filename by `.`, if there are 3+ parts and the last part (with dot prepended) is in `DANGEROUS_EXTENSIONS`, it is a double extension. If yes: +20, set `attachment.is_double_ext = True`, add finding `{'filename': filename, 'type': 'double_ext', 'extensions': ext_chain}`.

   d. **MIME mismatch:** Compare `attachment.content_type` against `attachment.file_magic`. If `file_magic` is populated and does not match `content_type` (using a reasonable mapping -- e.g., `content_type` says `application/pdf` but `file_magic` says `application/x-executable`): +10, set `attachment.is_mime_mismatch = True`, add finding `{'filename': filename, 'type': 'mime_mismatch', 'declared': content_type, 'actual': file_magic}`.

   e. **YARA match:** Query `YaraRule.objects.filter(is_active=True)`. Since `EmailAttachment` does not store file content (only metadata and hashes), YARA scanning against attachment bytes is NOT possible in this phase without re-fetching from Gmail. Instead, YARA matching is deferred -- the `yara_matches` field on `EmailAttachment` remains null unless populated by a future enhancement. If `attachment.yara_matches` is already populated (e.g., by a future fetch-and-scan step), score +25 per match. Add finding `{'filename': filename, 'type': 'yara_match', 'rules': rule_names}`.

4. After all checks, call `attachment.save()` to persist the boolean flags (`is_dangerous_ext`, `is_double_ext`, `is_mime_mismatch`, `ti_match`, `yara_matches`).
5. Cap the total attachment_score at 50.
6. Return `(capped_score, findings_list, has_known_malware)`.

**DB queries:** `MaliciousHash` lookup per attachment SHA-256. `YaraRule` lookup (single query for active rules). `attachment.save()` per attachment with updated flags.

---

#### Method 4: `_check_received_chain(email: Email) -> tuple[int, dict]`

**Logic:**
1. Read `email.received_chain` (a JSON list of dicts populated by EmailParser, each representing one hop with fields like `from`, `by`, `timestamp`, etc.).
2. If the chain is empty, return `(0, {})`.
3. **Hop count check:** If `len(received_chain) > 7`: +5, finding `{'excessive_hops': True, 'hop_count': N}`.
4. **Private IP check:** For each hop, extract IP addresses from the `from` and `by` fields using regex. Check if any IP is in a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8). If found: +5 (once, not per occurrence), finding `{'private_ip_in_chain': True, 'ips': [list]}`.
5. **Timestamp disorder check:** Parse timestamps from each hop. If any hop has a timestamp earlier than a subsequent hop (i.e., time goes backward in the chain), this indicates header forgery: +5, finding `{'timestamp_disorder': True}`.
6. Cap the total chain_score at 15.
7. Return `(capped_score, findings_dict)`.

**Note:** Private IP detection uses Python's `ipaddress` module (`ipaddress.ip_address(ip).is_private`). Timestamp parsing uses `email.utils.parsedate_to_datetime()` or a regex fallback for common formats.

---

#### Error handling (all methods)

Each private method must be wrapped in try/except. On failure, log the error, return a zero-score safe default, and continue to the next check. The public `check_all()` method must also have an outer try/except returning a default `CheckResult()`.

---

### 2. Updated file: `emails/services/analyzer.py`

Replace the Phase 3 "else" branch with Checker integration:

```python
class EmailAnalyzer:
    def analyze(self, email_id: int) -> None:
        email = Email.objects.select_related('analysis').get(id=email_id)
        email.status = 'ANALYZING'
        email.save(update_fields=['status', 'updated_at'])

        preprocess_result = Preprocessor().process(email)

        if preprocess_result.verdict_override == 'CLEAN':
            self._finalize(email, preprocess_result,
                           verdict='CLEAN', status='DELIVERED', confidence='HIGH')
        else:
            self._save_preprocess_result(email, preprocess_result)

            # Phase 4: Run Checker
            check_result = Checker().check_all(email)
            self._save_check_result(email, check_result)
            # Phase 5 will add Decider call here
```

**New method: `_save_check_result(email, check_result)`**

Update the existing `AnalysisResult` for this email with Checker fields:

```python
def _save_check_result(self, email: Email, check_result: CheckResult) -> None:
    AnalysisResult.objects.filter(email=email).update(
        keyword_score=check_result.keyword_score,
        keywords_matched=check_result.keywords_matched,
        url_score=check_result.url_score,
        url_findings=check_result.url_findings,
        attachment_score=check_result.attachment_score,
        attachment_findings=check_result.attachment_findings,
        chain_score=check_result.chain_score,
        chain_findings=check_result.chain_findings,
    )
```

Does NOT set `total_score` or `verdict` -- that is the Decider's job in Phase 5. Email remains in `status='ANALYZING'`.

### 3. No new models or migrations

All fields needed on `AnalysisResult` (`keyword_score`, `keywords_matched`, `url_score`, `url_findings`, `attachment_score`, `attachment_findings`, `chain_score`, `chain_findings`) and on `EmailAttachment` (`is_dangerous_ext`, `is_double_ext`, `is_mime_mismatch`, `yara_matches`, `ti_match`) already exist from Phase 1.

## Out of Scope

- VirusTotal API integration for URL or hash lookups (Phase 5+)
- AbuseIPDB integration (Phase 5+)
- Decider / final verdict calculation (Phase 5)
- REST API endpoints (Phase 5)
- TI feed sync tasks (Phase 5)
- Frontend / dashboard UI (Phase 6)
- Quarantine actions (Phase 7)
- New Django models or migrations
- Re-fetching attachment binary content from Gmail for YARA scanning (see OQ-001)
- Real `file_magic` detection via python-magic (requires binary content; see OQ-002)

## Acceptance Criteria

| ID     | Criterion                          | Pass Condition                                                                                                |
|--------|------------------------------------|---------------------------------------------------------------------------------------------------------------|
| AC-001 | Single keyword match               | Email with "verify your account" in subject returns `keyword_score=2`, `keywords_matched=['verify your account']` |
| AC-002 | Keyword score capped at 20         | Email containing 10+ distinct keywords returns `keyword_score=20`, not higher                                  |
| AC-003 | Zero keywords                      | Email with no keyword matches returns `keyword_score=0`, `keywords_matched=[]`                                 |
| AC-004 | IP-based URL detected              | Email with `http://192.168.1.1/login` in `urls_extracted` returns url_score including +10, finding type `ip_url` |
| AC-005 | URL shortener detected             | Email with `https://bit.ly/abc123` in `urls_extracted` returns url_score including +5, finding type `shortener` |
| AC-006 | MaliciousDomain match              | Email with URL whose hostname matches a `MaliciousDomain` record returns url_score including +30               |
| AC-007 | MaliciousHash match                | Attachment with SHA-256 matching a `MaliciousHash` record returns `attachment_score=50`, `has_known_malware=True`, `ti_match` set on attachment |
| AC-008 | Dangerous extension flagged        | Attachment with `.exe` extension returns `is_dangerous_ext=True` on the attachment record, attachment_score includes +15 |
| AC-009 | Double extension flagged           | Attachment named `report.pdf.exe` returns `is_double_ext=True` on the attachment record, attachment_score includes +20 |
| AC-010 | MIME mismatch flagged              | Attachment where `content_type` differs from `file_magic` returns `is_mime_mismatch=True` on the attachment record |
| AC-011 | Excessive hops detected            | Email with 8 hops in `received_chain` returns chain_score including +5                                         |
| AC-012 | Private IP in chain detected       | Email with a private IP (e.g., 10.0.0.1) in received_chain returns chain_score including +5                    |
| AC-013 | total_check_score capped at 125    | `total_check_score` = `min(keyword_score,20) + min(url_score,40) + min(attachment_score,50) + min(chain_score,15)` never exceeds 125 |
| AC-014 | No attachments yields zero         | Email with no attachments returns `attachment_score=0`, `attachment_findings=[]`                                |
| AC-015 | No URLs yields zero                | Email with empty `urls_extracted` returns `url_score=0`, `url_findings=[]`                                     |
| AC-016 | Analyzer integrates Checker        | `EmailAnalyzer().analyze(email_id)` for a non-whitelisted email calls both Preprocessor and Checker; `AnalysisResult` has both `preprocess_score` and `keyword_score`/`url_score`/`attachment_score`/`chain_score` populated |

## API Contracts

### Internal Python APIs (no HTTP endpoints in this phase)

**Checker.check_all()**

```
Input:  email: Email  (Django model instance with subject, body_text,
                       urls_extracted, received_chain populated;
                       attachments accessible via email.attachments.all())
Output: CheckResult (dataclass)
        {
            keyword_score: 20,
            keywords_matched: ['verify your account', 'urgent action required', ...],
            url_score: 35,
            url_findings: [
                {'url': 'http://evil.com/login', 'type': 'malicious_domain', 'domain': 'evil.com'},
                {'url': 'https://bit.ly/abc', 'type': 'shortener', 'service': 'bit.ly'}
            ],
            attachment_score: 50,
            attachment_findings: [
                {'filename': 'trojan.exe', 'type': 'known_malware', 'sha256': '...', 'malware_family': 'Emotet'}
            ],
            chain_score: 10,
            chain_findings: {
                'excessive_hops': True,
                'hop_count': 9,
                'private_ip_in_chain': True,
                'ips': ['10.0.0.1']
            },
            total_check_score: 115,
            has_known_malware: True
        }
Raises: Never. All exceptions caught internally.
```

**EmailAnalyzer.analyze() (updated for Phase 4)**

```
Input:  email_id: int
Output: None
Side effects:
  - Email.status set to 'ANALYZING'
  - If whitelist match: finalize as CLEAN/DELIVERED (unchanged from Phase 3)
  - If not whitelisted:
    - AnalysisResult.preprocess_score populated (Phase 3 behavior)
    - AnalysisResult.keyword_score, keywords_matched populated
    - AnalysisResult.url_score, url_findings populated
    - AnalysisResult.attachment_score, attachment_findings populated
    - AnalysisResult.chain_score, chain_findings populated
    - EmailAttachment flags (is_dangerous_ext, is_double_ext, is_mime_mismatch, ti_match) updated
    - Email.status remains 'ANALYZING' (Decider in Phase 5 will finalize)
Raises: Email.DoesNotExist if email_id is invalid
```

**Checker._check_keywords()**

```
Input:  email: Email
Output: tuple[int, list[str]]  -- (capped_score, matched_keyword_strings)
```

**Checker._check_urls()**

```
Input:  email: Email
Output: tuple[int, list[dict]]  -- (capped_score, findings_list)
```

**Checker._check_attachments()**

```
Input:  email: Email
Output: tuple[int, list[dict], bool]  -- (capped_score, findings_list, has_known_malware)
```

**Checker._check_received_chain()**

```
Input:  email: Email
Output: tuple[int, dict]  -- (capped_score, findings_dict)
```

## Data Model Changes

None. All required fields exist from Phase 1 migrations.

**Fields written by Checker on AnalysisResult:**
- `keyword_score` (IntegerField, default=0)
- `keywords_matched` (JSONField, default=list)
- `url_score` (IntegerField, default=0)
- `url_findings` (JSONField, default=list)
- `attachment_score` (IntegerField, default=0)
- `attachment_findings` (JSONField, default=list)
- `chain_score` (IntegerField, default=0)
- `chain_findings` (JSONField, default=dict)

**Fields written by Checker on EmailAttachment:**
- `is_dangerous_ext` (BooleanField, default=False)
- `is_double_ext` (BooleanField, default=False)
- `is_mime_mismatch` (BooleanField, default=False)
- `ti_match` (CharField, null=True)
- `yara_matches` (JSONField, null=True)

## Dependencies

| Dependency | Status |
|-----------|--------|
| Phase 1: All 15 Django models (Email, EmailAttachment, AnalysisResult, MaliciousHash, MaliciousDomain, YaraRule) | DONE |
| Phase 2: EmailParser populating `urls_extracted`, `received_chain`, attachment metadata (sha256_hash, content_type, filename) | DONE |
| Phase 3: Preprocessor + EmailAnalyzer with whitelist short-circuit and `_save_preprocess_result` | DONE |
| Phase 3: AnalysisResult created by `_save_preprocess_result` before Checker runs | DONE |

## Open Questions

| ID     | Question | Recommendation | Impact |
|--------|----------|----------------|--------|
| OQ-001 | YARA scanning requires file content bytes, but `EmailAttachment` stores only metadata (filename, hashes, content_type). The parser produces `content` bytes but `fetch_gmail_task` discards them. Should we (a) store attachment content in the DB/filesystem, (b) re-fetch from Gmail during Checker, or (c) defer real YARA scanning? | Recommend (c): defer real YARA scanning. In Phase 4, the Checker checks the `yara_matches` field but does not populate it. A future enhancement can add a fetch-and-scan step. For testing and demo, YARA matches can be seeded manually on EmailAttachment records. | Medium -- YARA is 1 of 6 detection types. Deferring it does not block the pipeline. |
| OQ-002 | `file_magic` on `EmailAttachment` is nullable and not currently populated by the parser or task (it requires binary content + python-magic). Should MIME mismatch detection compare `content_type` vs `file_magic` only when `file_magic` is populated, or should we add magic detection? | Recommend: only check when `file_magic` is not null. If null, skip MIME mismatch for that attachment. This allows manual/future population without blocking Phase 4. | Low -- graceful skip when data unavailable. |
| OQ-003 | Should the Checker create `ExtractedIOC` records for malicious domains, hashes, and IPs found during checking? This would populate the IOC table for later reporting. | Recommend: yes, create ExtractedIOC records in Phase 4 for any TI match found (malicious domain, malicious hash). This adds ~10 lines of code and makes Phase 7 reporting richer. However, if scope must stay minimal, defer to Phase 5. | Low -- additive, not blocking. Awaiting human decision. |

## Test Plan

qa-agent writes tests in `tests/test_phase4.py`. Minimum 25 tests covering all 16 ACs plus edge cases.

All tests use `django.test.TestCase` with in-memory SQLite. TI records (`MaliciousHash`, `MaliciousDomain`, `YaraRule`) created in `setUp()`. Email and EmailAttachment records created programmatically.

### Keyword Checker Tests (5 tests)

| Test | Covers | Description |
|------|--------|-------------|
| test_single_keyword_in_subject_scores_2 | AC-001 | Subject = "Please verify your account", body empty. keyword_score=2, keywords_matched=['verify your account'] |
| test_single_keyword_in_body_scores_2 | AC-001 | Subject empty, body contains "urgent action required". keyword_score=2 |
| test_keyword_case_insensitive | AC-001 | "VERIFY YOUR ACCOUNT" matches. keyword_score=2 |
| test_ten_keywords_capped_at_20 | AC-002 | Body contains 12 distinct keywords. keyword_score=20 |
| test_no_keywords_scores_zero | AC-003 | Clean email with no keywords. keyword_score=0, keywords_matched=[] |

### URL Checker Tests (6 tests)

| Test | Covers | Description |
|------|--------|-------------|
| test_ip_url_scores_10 | AC-004 | urls_extracted=['http://192.168.1.1/login']. url_score=10, finding type='ip_url' |
| test_shortener_scores_5 | AC-005 | urls_extracted=['https://bit.ly/abc123']. url_score=5, finding type='shortener' |
| test_malicious_domain_scores_30 | AC-006 | MaliciousDomain('evil.com') in DB, urls_extracted=['http://evil.com/phish']. url_score=30 |
| test_url_score_capped_at_40 | AC-006 | Two malicious domain URLs (+30+30=60). url_score=40 |
| test_no_urls_scores_zero | AC-015 | urls_extracted=[]. url_score=0, url_findings=[] |
| test_multiple_url_types_cumulative | AC-004,005 | One IP URL (+10) and one shortener (+5). url_score=15 |

### Attachment Checker Tests (8 tests)

| Test | Covers | Description |
|------|--------|-------------|
| test_malicious_hash_scores_50 | AC-007 | Attachment sha256 matches MaliciousHash record. attachment_score=50, has_known_malware=True, ti_match set |
| test_dangerous_ext_scores_15 | AC-008 | Attachment filename='malware.exe'. is_dangerous_ext=True on attachment, score includes +15 |
| test_double_ext_scores_20 | AC-009 | Attachment filename='report.pdf.exe'. is_double_ext=True on attachment, score includes +20 |
| test_mime_mismatch_flagged | AC-010 | Attachment content_type='application/pdf', file_magic='application/x-executable'. is_mime_mismatch=True |
| test_mime_mismatch_skipped_when_no_magic | OQ-002 | Attachment file_magic=None. is_mime_mismatch remains False |
| test_no_attachments_scores_zero | AC-014 | Email with no attachments. attachment_score=0, attachment_findings=[] |
| test_attachment_score_capped_at_50 | AC-007 | Known malware hash (+50) plus dangerous ext (+15) = 65, capped at 50 |
| test_double_ext_detection_three_parts | AC-009 | Filename='archive.tar.gz.exe'. is_double_ext=True |

### Received Chain Tests (5 tests)

| Test | Covers | Description |
|------|--------|-------------|
| test_excessive_hops_scores_5 | AC-011 | received_chain with 8 entries. chain_score includes +5 |
| test_seven_hops_no_score | AC-011 neg | received_chain with 7 entries. No hop penalty |
| test_private_ip_scores_5 | AC-012 | Hop with '10.0.0.1' in from field. chain_score includes +5 |
| test_timestamp_disorder_scores_5 | Edge | Hop timestamps go backward. chain_score includes +5 |
| test_empty_chain_scores_zero | Edge | received_chain=[]. chain_score=0, chain_findings={} |

### Integration Tests (4 tests)

| Test | Covers | Description |
|------|--------|-------------|
| test_check_all_sums_subscores | AC-013 | total_check_score = keyword + url + attachment + chain |
| test_analyzer_calls_preprocessor_and_checker | AC-016 | Non-whitelisted email: AnalysisResult has preprocess_score AND keyword_score populated |
| test_analyzer_whitelisted_skips_checker | AC-016 neg | Whitelisted email: AnalysisResult has preprocess_score=0, keyword_score=0 (Checker not called) |
| test_analyzer_saves_check_result_to_db | AC-016 | After analyze(), AnalysisResult.keyword_score, url_score, attachment_score, chain_score are non-default for a flagged email |

### Error Resilience Tests (3 tests)

| Test | Covers | Description |
|------|--------|-------------|
| test_checker_catches_exception_returns_default | Robustness | Mock DB to raise, check_all returns CheckResult with all zeros |
| test_keyword_check_exception_isolated | Robustness | Mock _check_keywords to raise; url/attachment/chain checks still run |
| test_checker_with_none_urls_extracted | Edge | email.urls_extracted=None (not list). Does not crash, url_score=0 |

### Performance Test (1 test)

| Test | Covers | Description |
|------|--------|-------------|
| test_checker_under_200ms | Perf | check_all() completes within 200ms for an email with 5 URLs, 3 attachments, 10-hop chain, and 24 keyword matches (using pre-seeded TI data) |

**Total: 32 tests.**
