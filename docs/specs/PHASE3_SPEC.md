# SPEC: Phase 3 -- Preprocessor + SPF/DKIM/DMARC Analysis

## Goal

Implement Stage 1 of the analysis pipeline: the Preprocessor runs fast checks on every new email (whitelist/blacklist lookup, SPF/DKIM/DMARC header parsing, BEC signal detection), returns a PreprocessResult dataclass with score and findings, and is called by EmailAnalyzer.analyze() as the first real pipeline step.

## In Scope

### 1. New file: `emails/services/preprocessor.py`

#### PreprocessResult dataclass

```
@dataclass
class PreprocessResult:
    score: int                        # cumulative preprocess score
    findings: dict                    # detailed findings per check
    verdict_override: str | None      # None or 'CLEAN' (whitelist match)
    spf_result: str                   # 'pass' | 'fail' | 'softfail' | 'none'
    dkim_result: str                  # 'pass' | 'fail' | 'none'
    dmarc_result: str                 # 'pass' | 'fail' | 'none'
    is_reply_to_mismatch: bool        # True if Reply-To domain differs from From domain
    is_display_spoof: bool            # True if display name contains foreign domain
```

#### Preprocessor class

`class Preprocessor` with a single public method:

```
def process(self, email: Email) -> PreprocessResult
```

Internally calls these private methods in order. Each method receives the email (or relevant field) and returns a contribution to score + findings. If any method raises an exception, catch it, log a warning, and continue with zero contribution from that method.

**Method 1: `_check_whitelist(email_address: str) -> tuple[bool, int]`**

- Extract domain from email_address (split on `@`).
- Query `WhitelistEntry.objects.filter(entry_type='EMAIL', value__iexact=email_address)`. If match found, return immediately with `(True, 0)`.
- Query `WhitelistEntry.objects.filter(entry_type='DOMAIN', value__iexact=domain)`. If match found, return immediately with `(True, 0)`.
- If whitelisted: set `verdict_override='CLEAN'`, `score=0`, all auth results to `'none'`, both flags to `False`, findings to `{'whitelist': {'matched': True, 'value': <matched_value>, 'type': <entry_type>}}`. Return the PreprocessResult immediately -- skip all subsequent checks.
- If not whitelisted: return `(False, 0)` and continue to next checks.

**Method 2: `_check_blacklist(email_address: str) -> tuple[dict, int]`**

- Extract domain from email_address.
- Query `BlacklistEntry.objects.filter(entry_type='EMAIL', value__iexact=email_address)`. If match: `score += 40`, `findings['blacklist_email'] = True`.
- Query `BlacklistEntry.objects.filter(entry_type='DOMAIN', value__iexact=domain)`. If match: `score += 30`, `findings['blacklist_domain'] = True`.
- Both can match (email + domain), yielding `score += 70` total from blacklist alone.
- Return `(findings_dict, total_blacklist_score)`.

**Method 3: `_check_email_auth(headers_raw) -> tuple[dict, int, str, str, str]`**

- `headers_raw` is the Email.headers_raw field (list of `{name, value}` dicts from Gmail API).
- Find the `Authentication-Results` header value. If multiple exist, use the first one.
- Parse SPF result using regex `spf=(\w+)`: map to `'pass'`, `'fail'`, `'softfail'`, or `'none'`.
- Parse DKIM result using regex `dkim=(\w+)`: map to `'pass'`, `'fail'`, or `'none'`.
- Parse DMARC result using regex `dmarc=(\w+)`: map to `'pass'`, `'fail'`, or `'none'`.
- Scoring (from CLAUDE.md, exact values):
  - SPF: pass=+0, softfail=+5, fail=+15, none/missing=+10
  - DKIM: pass=+0, fail=+15, none/missing=+5
  - DMARC: pass=+0, fail=+15, none/missing=+5
- Return `(findings_dict, auth_score, spf_result, dkim_result, dmarc_result)`.
- `findings['auth'] = {'spf': spf_result, 'dkim': dkim_result, 'dmarc': dmarc_result, 'score_contribution': auth_score}`.

**Method 4: `_check_reply_to_mismatch(email: Email) -> tuple[bool, int, dict]`**

- If `email.reply_to` is None or empty string: return `(False, 0, {})`.
- Extract domain from `email.from_address` and domain from `email.reply_to`.
- If domains differ (case-insensitive): `score += 10`, `is_reply_to_mismatch = True`.
- `findings['reply_to_mismatch'] = {'from_domain': from_domain, 'reply_to_domain': reply_to_domain}`.
- Return `(is_mismatch, score_contribution, findings_dict)`.

**Method 5: `_check_display_spoof(email: Email) -> tuple[bool, int, dict]`**

- If `email.from_display_name` is blank/empty: return `(False, 0, {})`.
- Check if display name contains `@` sign OR matches a domain-like pattern `\b[\w.-]+\.(com|org|net|edu|gov|io|co|uk|ru|info|biz)\b` that differs from the actual `from_address` domain.
- If spoof detected: `score += 10`, `is_display_spoof = True`.
- `findings['display_spoof'] = {'display_name': display_name, 'actual_domain': from_domain, 'spoofed_domain': detected_domain}`.
- Return `(is_spoof, score_contribution, findings_dict)`.

#### Error handling

The `process()` method must never raise exceptions to the caller. Wrap the entire method body in try/except. On any exception, log the error and return a safe default PreprocessResult with `score=0`, all auth results `'none'`, both flags `False`, empty findings.

### 2. Updated file: `emails/services/analyzer.py`

Replace the Phase 2 stub with real Phase 3 logic:

```python
class EmailAnalyzer:
    def analyze(self, email_id: int) -> None:
        email = Email.objects.select_related('analysis').get(id=email_id)
        email.status = 'ANALYZING'
        email.save(update_fields=['status', 'updated_at'])

        result = Preprocessor().process(email)

        if result.verdict_override == 'CLEAN':
            self._finalize(email, result, verdict='CLEAN', status='DELIVERED', confidence='HIGH')
        else:
            self._save_preprocess_result(email, result)
            # Phase 4+ will add Checker and Decider calls here
```

**`_save_preprocess_result(email, result)`**:
- Create or update AnalysisResult for this email.
- Set fields: `preprocess_score`, `spf_result`, `dkim_result`, `dmarc_result`, `is_reply_to_mismatch`, `is_display_spoof`.
- Do NOT set `total_score` yet (Decider does that in Phase 5).
- Leave `email.status = 'ANALYZING'` (Phase 4+ will advance it).

**`_finalize(email, result, verdict, status, confidence)`**:
- Create or update AnalysisResult with preprocess fields.
- Set `email.verdict = verdict`, `email.status = status`, `email.confidence = confidence`, `email.score = result.score`.
- Set `email.analyzed_at = timezone.now()`.
- Save email.

### 3. No new models or migrations

All fields needed (`preprocess_score`, `spf_result`, `dkim_result`, `dmarc_result`, `is_reply_to_mismatch`, `is_display_spoof` on AnalysisResult; `verdict`, `status`, `score`, `confidence`, `analyzed_at` on Email) already exist from Phase 1.

## Out of Scope

- Keyword scoring (Phase 4)
- URL checking against URLhaus/VirusTotal (Phase 4)
- Attachment checking against MalwareBazaar/YARA (Phase 4)
- Received chain anomaly detection (Phase 4)
- Final verdict calculation combining all scores (Phase 5)
- TI feed sync tasks (Phase 5)
- REST API endpoints (Phase 5)
- Any frontend/template changes (Phase 6)
- New Django models or migrations
- IP-based whitelist/blacklist lookup (WhitelistEntry/BlacklistEntry support IP type, but the Preprocessor only checks EMAIL and DOMAIN types against from_address in this phase)

## Acceptance Criteria

| ID | Criterion | Pass condition |
|----|-----------|---------------|
| AC-001 | SPF fail detection | `Preprocessor().process(email_with_spf_fail)` returns `spf_result='fail'` and `score >= 15` |
| AC-002 | SPF softfail detection | `Preprocessor().process(email_with_spf_softfail)` returns `spf_result='softfail'` and `score >= 5` |
| AC-003 | Whitelist short-circuit | `Preprocessor().process(whitelisted_email)` returns `verdict_override='CLEAN'`, `score=0`, completes without running blacklist/auth/BEC checks |
| AC-004 | Blacklist email match | `Preprocessor().process(blacklisted_email)` returns `score >= 40` with `findings['blacklist_email'] == True` |
| AC-005 | Blacklist domain match | `Preprocessor().process(email_from_blacklisted_domain)` returns `score >= 30` with `findings['blacklist_domain'] == True` |
| AC-006 | Reply-To mismatch | Email with `from_address` domain != `reply_to` domain returns `is_reply_to_mismatch=True` and score includes +10 |
| AC-007 | Display name spoof | Email with `from_display_name` containing a foreign domain returns `is_display_spoof=True` and score includes +10 |
| AC-008 | All auth fail | SPF fail + DKIM fail + DMARC fail returns `score >= 45` (15+15+15) |
| AC-009 | All auth pass | SPF pass + DKIM pass + DMARC pass returns auth score contribution = 0 |
| AC-010 | Analyzer whitelist flow | `EmailAnalyzer().analyze(whitelisted_email_id)` sets `email.verdict='CLEAN'`, `email.status='DELIVERED'`, `email.confidence='HIGH'`, creates AnalysisResult |
| AC-011 | Analyzer normal flow | `EmailAnalyzer().analyze(normal_email_id)` creates AnalysisResult with `preprocess_score` populated, email stays `status='ANALYZING'` |
| AC-012 | Missing auth header | Email with no Authentication-Results header returns `spf_result='none'`, `dkim_result='none'`, `dmarc_result='none'`, score includes +20 (10+5+5) |
| AC-013 | Error resilience | Preprocessor never raises exceptions to caller; DB errors during whitelist lookup result in safe default (score=0) |
| AC-014 | Performance | Preprocessor.process() completes in <100ms for a single email (measured without DB latency, i.e., with pre-fetched related objects) |

## API Contracts

### Internal Python APIs (no HTTP endpoints in this phase)

**Preprocessor.process()**

```
Input:  email: Email  (Django model instance, must have from_address, reply_to, 
                       from_display_name, headers_raw populated)
Output: PreprocessResult (dataclass)
        {
            score: int,              # e.g., 45
            findings: {              # e.g.,
                "blacklist_email": true,
                "auth": {"spf": "fail", "dkim": "none", "dmarc": "pass", "score_contribution": 20},
                "reply_to_mismatch": {"from_domain": "company.com", "reply_to_domain": "evil.com"}
            },
            verdict_override: None,  # or "CLEAN"
            spf_result: "fail",
            dkim_result: "none",
            dmarc_result: "pass",
            is_reply_to_mismatch: true,
            is_display_spoof: false
        }
Raises: Never. All exceptions caught internally.
```

**EmailAnalyzer.analyze()**

```
Input:  email_id: int  (primary key of Email record)
Output: None
Side effects:
  - Email.status set to 'ANALYZING' then either 'DELIVERED' (whitelist) or stays 'ANALYZING' (normal)
  - Email.verdict set to 'CLEAN' (whitelist) or left None (normal)
  - Email.score set to preprocess score (whitelist) or left None (normal)
  - Email.confidence set to 'HIGH' (whitelist) or left None (normal)
  - Email.analyzed_at set (whitelist) or left None (normal)
  - AnalysisResult created/updated with preprocess fields
Raises: Email.DoesNotExist if email_id is invalid
```

## Data Model Changes

None. All required fields exist from Phase 1 migrations.

## Dependencies

| Dependency | Status |
|-----------|--------|
| Phase 1: All 15 Django models (Email, AnalysisResult, WhitelistEntry, BlacklistEntry) | DONE |
| Phase 2: Gmail ingestion + EmailParser populating headers_raw, from_address, reply_to, from_display_name | DONE |
| Phase 2: EmailAnalyzer stub in emails/services/analyzer.py | DONE (will be replaced) |
| Phase 2: analyze_email_task calling EmailAnalyzer.analyze() | DONE |

## Open Questions

| ID | Question | Impact |
|----|----------|--------|
| OQ-001 | The EmailParser._extract_auth_results() method exists but is never called during parse_gmail_message(). Auth results are not stored as a separate field -- they live in headers_raw. Should the Preprocessor parse auth from headers_raw directly (as specified above), or should we first fix the parser to store auth_results as a dedicated Email field? | Low -- parsing from headers_raw works fine; a dedicated field would be a migration + model change, which is out of scope. Recommend: parse from headers_raw. |
| OQ-002 | BlacklistEntry supports entry_type='IP' but the Preprocessor only checks EMAIL and DOMAIN against from_address. Should IP-based blacklist checks (e.g., checking received_chain IPs against BlacklistEntry IP entries) be added here or deferred to Phase 4 chain analysis? | Low -- recommend defer to Phase 4 where received chain analysis already lives. |

## Test Plan

qa-agent writes tests in `tests/test_phase3.py`. Minimum 18 tests covering all 14 ACs plus edge cases.

### Unit tests for Preprocessor (12+ tests)

| Test | Covers |
|------|--------|
| test_spf_fail_scores_15 | AC-001 |
| test_spf_softfail_scores_5 | AC-002 |
| test_spf_pass_scores_0 | AC-009 (partial) |
| test_spf_none_scores_10 | AC-012 (partial) |
| test_dkim_fail_scores_15 | AC-008 (partial) |
| test_dkim_none_scores_5 | AC-012 (partial) |
| test_dmarc_fail_scores_15 | AC-008 (partial) |
| test_dmarc_none_scores_5 | AC-012 (partial) |
| test_all_auth_fail_scores_45 | AC-008 |
| test_all_auth_pass_scores_0 | AC-009 |
| test_no_auth_header_defaults_none | AC-012 |
| test_whitelist_email_match_short_circuits | AC-003 |
| test_whitelist_domain_match_short_circuits | AC-003 |
| test_blacklist_email_match_scores_40 | AC-004 |
| test_blacklist_domain_match_scores_30 | AC-005 |
| test_blacklist_both_match_scores_70 | Edge case: cumulative blacklist |
| test_reply_to_mismatch_scores_10 | AC-006 |
| test_reply_to_none_no_score | AC-006 (negative) |
| test_reply_to_same_domain_no_score | AC-006 (negative) |
| test_display_spoof_with_at_sign | AC-007 |
| test_display_spoof_with_domain_pattern | AC-007 |
| test_display_name_blank_no_score | AC-007 (negative) |
| test_preprocessor_catches_exceptions | AC-013 |

### Integration tests for EmailAnalyzer (3+ tests)

| Test | Covers |
|------|--------|
| test_analyze_whitelisted_email_delivers | AC-010 |
| test_analyze_normal_email_creates_analysis_result | AC-011 |
| test_analyze_sets_analyzing_status | AC-011 |

### Edge case tests (2+ tests)

| Test | Covers |
|------|--------|
| test_empty_headers_raw_dict | AC-012 edge |
| test_malformed_auth_header_graceful | AC-013 edge |
| test_case_insensitive_whitelist_match | Correctness |

### Performance test (1 test)

| Test | Covers |
|------|--------|
| test_preprocessor_under_100ms | AC-014 |

**Total minimum: 18 tests. Target: 25+.**

All tests use Django TestCase with in-memory SQLite. WhitelistEntry/BlacklistEntry records created in setUp(). Email fixtures created programmatically with controlled headers_raw values.
