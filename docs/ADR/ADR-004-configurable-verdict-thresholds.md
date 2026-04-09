# ADR-004: Configurable Verdict Thresholds via Django Settings

## Status: Accepted

## Date: 2026-04-08

## Context

The Decider (Phase 5) must translate a numerical risk score (0-100) into a categorical verdict (CLEAN, SUSPICIOUS, MALICIOUS). The threshold values determine the boundary between each verdict category. During development and testing, fixed thresholds (25 and 70) were used. However, different deployment environments may require different sensitivity levels: a high-security organization might lower the MALICIOUS threshold to catch more threats, while a noisy environment might raise CLEAN threshold to reduce false positives.

Additionally, the known malware hash override must always force a MALICIOUS verdict regardless of the score, providing a guaranteed zero-false-negative path for confirmed threats.

## Decision

1. Verdict thresholds are read from Django settings (`CLEAN_THRESHOLD` and `MALICIOUS_THRESHOLD`), which are populated from environment variables with sensible defaults (25 and 70 respectively).

2. The Decider reads thresholds as class attributes at import time via `getattr(settings, ...)`.

3. Known malware hash override is the first check in `decide()`, before any score calculation. When triggered, it returns a fixed DecisionResult with score=100, confidence=HIGH, action=BLOCK, and override_reason='known_malware_hash'.

4. The raw score (preprocess + check) is capped at 100 via `min(raw, 100)` to provide a normalized 0-100 scale.

## Consequences

**Positive:**
- Operators can tune sensitivity without code changes (environment variable only)
- Known malware is never under-classified regardless of scoring gaps
- Normalized 0-100 scale is clean for dashboard display and reporting
- Decider has zero DB access, making it trivially unit-testable

**Negative:**
- Thresholds are read at import time, not per-request -- changing env vars requires a process restart
- No per-tenant threshold support (acceptable for single-tenant academic project)

## Alternatives Considered

1. **Hardcoded thresholds**: Simpler but not tunable. Rejected because configurability is needed for testing different sensitivity levels during the viva demo.

2. **Database-stored thresholds**: More flexible (per-tenant, no restart needed) but adds a DB query per decision. Rejected as over-engineering for a single-tenant academic project.

3. **Machine learning classification**: Replacing fixed thresholds with a trained model. Rejected as out of scope for BISP timeline and requires labeled training data not available.
