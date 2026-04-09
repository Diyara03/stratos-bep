# Stratos -- Component Business Justification

## Status: Phase 8 COMPLETE -- ALL PHASES DONE (351 tests, 95% coverage, demo-ready)
(updated automatically after each phase by documenter subagent)

---

## Django Monolith -- Phase 0
WHAT: Single Django project (`stratos_server`) containing all four apps in one deployable unit.
WHY: BISP is a single-developer academic project with a 6-month timeline. A monolith eliminates inter-service communication complexity, simplifies deployment for the viva demo, and allows rapid prototyping. Django provides ORM, admin panel, auth, and templating out of the box -- reducing boilerplate for a security-focused project where the analysis pipeline is the core value, not the web framework.
HOW IT CONNECTS: The `stratos_server` project package hosts settings, URL routing, Celery config, and the health endpoint. All four apps (emails, accounts, threat_intel, reports) register in INSTALLED_APPS and share the same database.
REPORT CHAPTER: Chapter 4, Section 4.1 (Architecture Overview); Chapter 5, Section 5.1 (Technology Selection)

## PostgreSQL -- Phase 0
WHAT: PostgreSQL 15 as the primary relational database, running in a Docker container with a named volume.
WHY: Relational integrity is essential for linking emails to attachments, analysis results, and quarantine entries via foreign keys. PostgreSQL's JSONB support will be used in later phases for storing variable-length IOC data and raw email headers. It is the standard production database for Django projects and is well-documented in academic literature.
HOW IT CONNECTS: The `django` service connects via `DATABASE_URL`. The `dev.py` settings fall back to SQLite for local development without Docker. The `prod.py` settings require PostgreSQL.
REPORT CHAPTER: Chapter 4, Section 4.2 (Data Layer); Chapter 5, Section 5.1

## Redis + Celery -- Phase 0
WHAT: Redis 7 as message broker and result backend; Celery 5.3 for asynchronous task execution with a separate beat scheduler.
WHY: Email analysis must not block the web request/response cycle. Incoming emails will be queued as Celery tasks, processed asynchronously, and results written back to the database. The beat scheduler will poll Gmail and sync TI feeds on configurable intervals. Redis is lightweight, fast, and sufficient for a single-node deployment.
HOW IT CONNECTS: `celery.py` creates the app, autodiscovers tasks from all apps. The `celery` Docker service runs the worker; `celery-beat` runs the scheduler. Both depend on the `django` service being healthy. Broker URL comes from `REDIS_URL` environment variable.
REPORT CHAPTER: Chapter 4, Section 4.3 (Async Processing); Chapter 5, Section 5.2

## Custom User Model (accounts.User) -- Phase 0
WHAT: Extended Django `AbstractUser` with `role` (ADMIN/ANALYST/VIEWER), `department`, and `last_login_ip` fields.
WHY: Role-based access control is a core requirement (FR-001 in the project proposal). Analysts need full pipeline access; viewers need read-only dashboards; admins manage TI feeds and system config. Setting `AUTH_USER_MODEL` before the first migration is a Django best practice -- changing it later requires a full database rebuild.
HOW IT CONNECTS: `AUTH_USER_MODEL = 'accounts.User'` in `base.py`. All Django auth (login, permissions, admin) uses this model. Future phases will check `request.user.role` for access control.
REPORT CHAPTER: Chapter 4, Section 4.4 (Authentication and Authorization); Chapter 7, Section 7.1 (FR-001)

## Settings Split (base/dev/prod) -- Phase 0
WHAT: Three-file settings package: `base.py` (shared), `dev.py` (local development), `prod.py` (Docker/production).
WHY: Local development uses SQLite and DEBUG=True for fast iteration without Docker. Docker and production use PostgreSQL and stricter security settings. This separation follows the Twelve-Factor App methodology and prevents accidental exposure of debug mode in production.
HOW IT CONNECTS: `DJANGO_SETTINGS_MODULE` env var selects the active profile. Default is `dev`. Docker `.env` can set `prod`. Both `dev.py` and `prod.py` import everything from `base.py`.
REPORT CHAPTER: Chapter 5, Section 5.1 (Configuration Management)

## Docker Compose (5 Services) -- Phase 0
WHAT: Multi-container deployment with postgres, redis, django, celery, and celery-beat services.
WHY: The viva demo requires a reproducible, one-command setup (`docker compose up --build`). Docker Compose ensures all services start in the correct order with health checks, matching the architecture described in the report. It also provides isolation from the host OS, solving cross-platform dependency issues (libmagic, yara).
HOW IT CONNECTS: Services communicate over Docker's internal network. The `django` service depends on healthy postgres and redis. Workers depend on healthy django. A named volume (`postgres_data`) persists the database across restarts.
REPORT CHAPTER: Chapter 4, Section 4.5 (Deployment Architecture); Chapter 5, Section 5.3

## Health Endpoint (/health/) -- Phase 0
WHAT: Public JSON endpoint that checks database connectivity and returns service status.
WHY: Docker healthchecks need an HTTP endpoint to determine if the django service is ready to accept traffic. The celery and celery-beat services depend on this health state. It also serves as a smoke test during development and demo.
HOW IT CONNECTS: Registered in `stratos_server/urls.py`. Called by Docker healthcheck every 10 seconds. Returns 200 (ok) or 503 (degraded) based on `connection.ensure_connection()`.
REPORT CHAPTER: Chapter 5, Section 5.3 (Deployment); Chapter 6, Section 6.1 (Smoke Tests)

## python-magic-bin (over python-magic) -- Phase 0
WHAT: Using `python-magic-bin==0.4.14` instead of `python-magic==0.4.27` in requirements.
WHY: `python-magic` requires the `libmagic` system library, which is Linux-native. `python-magic-bin` bundles the library as a wheel, enabling cross-platform development on Windows without WSL. The Dockerfile still installs `libmagic1` for the Linux container.
HOW IT CONNECTS: Used in future phases (Phase 4) for attachment MIME type detection via magic bytes. The package provides the same API as `python-magic`.
REPORT CHAPTER: Chapter 5, Section 5.1 (Dependency Decisions)

## Deferred weasyprint -- Phase 0
WHAT: `weasyprint` removed from Phase 0 requirements; deferred to Phase 7.
WHY: weasyprint requires heavy system dependencies (Pango, GDK-Pixbuf, Cairo) that bloat the Docker image and complicate builds. PDF report generation is a Phase 7 feature. Installing it now adds build time and potential failure points with no benefit.
HOW IT CONNECTS: Will be added to `requirements.txt` and Dockerfile system deps in Phase 7 when the reports app needs PDF export.
REPORT CHAPTER: Chapter 5, Section 5.1 (Dependency Decisions)

---

## Email as Central Entity -- Phase 1
WHAT: The `Email` model is the single source of truth for every incoming message, with 21 fields covering identity, content, extracted data, and pipeline state.
WHY: Every pipeline stage (Preprocessor, Checker, Decider) needs to read from and write results about the same email. A single central model avoids data duplication and ensures consistent state. The `status` field tracks lifecycle (PENDING -> ANALYZING -> DELIVERED/QUARANTINED/BLOCKED) and the `verdict` field stores the final decision. This design mirrors Group-IB BEP's architecture where each email has a unified record.
HOW IT CONNECTS: EmailAttachment (1:N), AnalysisResult (1:1), QuarantineEntry (1:1), and ExtractedIOC (1:N) all reference Email via FK/OneToOne. Gmail ingestion (Phase 2) creates Email records. Preprocessor, Checker, and Decider update the related AnalysisResult and Email fields.
REPORT CHAPTER: Chapter 4, Section 4.2 (Data Model Design); Chapter 5, Section 5.2

## OneToOne for AnalysisResult and QuarantineEntry -- Phase 1
WHAT: `AnalysisResult` and `QuarantineEntry` use `OneToOneField` to Email instead of ForeignKey.
WHY: Each email is analyzed exactly once and can have at most one quarantine record. OneToOne enforces this at the database level with a UNIQUE constraint, preventing duplicate analysis results from bugs or race conditions. It also provides a clean reverse accessor (`email.analysis`, `email.quarantine`) without needing `.first()` or `.get()`. This is conceptually different from EmailAttachment and ExtractedIOC, where one email can have many.
HOW IT CONNECTS: AnalysisResult is created by the Preprocessor (Phase 3), populated by the Checker (Phase 4), and finalized by the Decider (Phase 5). QuarantineEntry is created by the Decider when verdict is SUSPICIOUS or MALICIOUS. Both cascade-delete with their Email.
REPORT CHAPTER: Chapter 4, Section 4.2 (Data Model Design)

## JSONField for Variable-Structure Data -- Phase 1
WHAT: `urls_extracted`, `headers_raw`, `received_chain`, `to_addresses`, `keywords_matched`, `url_findings`, `attachment_findings`, `chain_findings`, `filters_applied`, `recipients`, `ioc_types` all use Django's JSONField.
WHY: Email structure varies per message: one email may have zero URLs and two recipients; another may have 50 URLs and 20 CC recipients. Creating separate relational tables for each would add 5+ join tables, increasing query complexity with no benefit -- this data is always read and written as a unit, never queried individually by value. PostgreSQL's JSONB storage provides efficient indexing if needed later. This is a pragmatic choice for an academic project where the analysis pipeline benefits from reading complete data in one query.
HOW IT CONNECTS: The parser (Phase 2) populates `urls_extracted`, `headers_raw`, `received_chain`. The Checker (Phase 4) populates `keywords_matched`, `url_findings`, `attachment_findings`. Reports (Phase 7) read `filters_applied` to reconstruct query parameters.
REPORT CHAPTER: Chapter 4, Section 4.2 (Data Model Design); Chapter 5, Section 5.2 (Implementation Decisions)

## output_format Instead of format -- Phase 1
WHAT: The `IOCExport` model uses `output_format` instead of `format` for the field name; `Report` uses `output_format` as well.
WHY: `format` is a Python builtin function. Shadowing it as a model field name causes subtle bugs when `format()` is called inside model methods or string formatting within the same scope. Django does not prevent this, but it is a well-known code smell. Renaming to `output_format` is explicit, avoids the shadow, and is more descriptive.
HOW IT CONNECTS: The Report and IOCExport admin panels display `output_format` in list_display. Report generation (Phase 7) will use this field to select CSV/JSON/PDF/STIX export paths.
REPORT CHAPTER: Chapter 5, Section 5.2 (Implementation Decisions)

## Separate WhitelistEntry and BlacklistEntry -- Phase 1
WHAT: Whitelist and blacklist are two separate concrete models rather than a single model with a `list_type` discriminator or an abstract base class.
WHY: The spec defines 15 models across 4 apps, and keeping them separate makes each model's purpose immediately clear in the admin, in imports, and in code. An abstract base would save roughly 10 lines of field duplication but adds conceptual overhead (developers must check which concrete class they are working with). The Preprocessor logic for whitelist (skip all analysis) is fundamentally different from blacklist (add score penalty), so separate models make the distinct behaviors explicit in code.
HOW IT CONNECTS: Preprocessor (Phase 3) queries WhitelistEntry first for early exit, then queries BlacklistEntry for score penalties. Admin users manage them independently. Both have `unique_together` on `(entry_type, value)` to prevent duplicates.
REPORT CHAPTER: Chapter 4, Section 4.2 (Data Model Design); Chapter 5, Section 5.2

---

## GmailConnector -- Phase 2
WHAT: OAuth-authenticated service that connects to the Gmail API, fetches new INBOX messages, and marks them as read after processing.
WHY: Email ingestion is the entry point of the entire analysis pipeline. The Gmail API was chosen because WIUT students use Google Workspace, providing a realistic data source for the BISP demo. OAuth 2.0 (InstalledAppFlow) provides secure, revocable access without storing user passwords. The connector handles deduplication by checking gmail_id against the database before fetching full message payloads, preventing reprocessing and wasted API quota.
HOW IT CONNECTS: Called by fetch_gmail_task (Celery Beat, every 10 seconds) and the fetch_emails management command. Returns raw Gmail API message dicts to EmailParser. After successful parsing and DB save, mark_as_read removes the UNREAD label.
REPORT CHAPTER: Chapter 4, Section 4.3 (Email Ingestion Pipeline); Chapter 5, Section 5.4 (Gmail Integration)

## EmailParser -- Phase 2
WHAT: Stateless service that transforms raw Gmail API message dicts into unsaved Email model instances and attachment metadata dicts, extracting 11 header fields, URLs, attachments with hashes, authentication results, and received chain.
WHY: The Gmail API returns nested JSON with base64-encoded bodies and multipart structures. A dedicated parser encapsulates all the complexity of RFC 2047 subject decoding, MIME traversal, URL extraction (regex for plain text, BeautifulSoup for HTML href attributes), and cryptographic hashing (SHA-256 + MD5 for every attachment). This separation keeps the task layer thin and the parsing logic independently testable with fixture files.
HOW IT CONNECTS: Called by fetch_gmail_task and fetch_emails management command. Produces unsaved Email instances and attachment dicts. The extracted urls_extracted, received_chain, and auth_results fields feed into Checker (Phase 4) and Preprocessor (Phase 3).
REPORT CHAPTER: Chapter 4, Section 4.3; Chapter 5, Section 5.4

## EmailAnalyzer (Stub) -- Phase 2
WHAT: Orchestrator class that will run the full analysis pipeline (Preprocess -> Check -> Decide). In Phase 2, it is a stub that sets status to ANALYZING then back to PENDING.
WHY: The task layer (analyze_email_task) needs a stable interface to call even before the analysis stages exist. Defining the orchestrator now establishes the contract: receive email_id, run pipeline stages, update Email status and verdict. The stub ensures the Celery task chain works end-to-end without errors while the real logic is built in Phases 3-5.
HOW IT CONNECTS: Called by analyze_email_task (Celery). Reads Email from DB by primary key. In Phase 3+ it will instantiate Preprocessor, Checker, and Decider in sequence.
REPORT CHAPTER: Chapter 4, Section 4.3; Chapter 5, Section 5.4

## Celery Beat Polling (10-second interval) -- Phase 2
WHAT: CELERY_BEAT_SCHEDULE entry that runs fetch_gmail_task every 10 seconds.
WHY: Continuous polling simulates near-real-time email protection. 10 seconds balances responsiveness against API quota consumption. Gmail API list calls are lightweight (returns message IDs only), and the connector skips known gmail_ids before making expensive full-message fetches.
HOW IT CONNECTS: Celery Beat triggers fetch_gmail_task. The task instantiates GmailConnector, fetches new emails, parses with EmailParser, saves to DB, and dispatches analyze_email_task per email.
REPORT CHAPTER: Chapter 4, Section 4.3; Chapter 5, Section 5.2 (Async Processing)

## beautifulsoup4 Dependency -- Phase 2
WHAT: BeautifulSoup 4.12.3 added to requirements.txt for HTML parsing in the email parser.
WHY: Emails contain URLs in both plain text and HTML bodies. Regex alone misses URLs embedded in anchor tag href attributes that may not appear in the visible text. BeautifulSoup reliably extracts href values from malformed HTML (common in phishing emails) without a full browser engine.
HOW IT CONNECTS: Used by EmailParser._extract_urls() to parse body_html and find all <a href="..."> tags. URLs extracted here feed into the Checker's URL analysis (Phase 4).
REPORT CHAPTER: Chapter 5, Section 5.1 (Dependency Decisions)

## gmail_id Dedup over message_id -- Phase 2
WHAT: Deduplication uses gmail_id (Google's internal identifier) rather than message_id (RFC 5322 Message-ID header).
WHY: gmail_id is guaranteed unique by Google. Message-ID headers can be spoofed, missing, or duplicated across different messages (especially in phishing emails). Using gmail_id eliminates false dedup matches and avoids an expensive full-message fetch for already-known emails.
HOW IT CONNECTS: GmailConnector.fetch_new_emails() checks Email.objects.filter(gmail_id=msg_id).exists() before fetching full payload. The gmail_id field has unique=True + db_index=True constraints.
REPORT CHAPTER: Chapter 5, Section 5.4

---

## Preprocessor -- Phase 3
WHAT: First stage of the analysis pipeline that performs fast triage checks: whitelist/blacklist lookup, SPF/DKIM/DMARC header validation, Reply-To mismatch detection, and display name spoof detection.
WHY: Email authentication (SPF, DKIM, DMARC) is the industry-standard first line of defense against spoofed emails. RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC) define these protocols. Checking them first allows the system to assign a baseline trust score before expensive content analysis (URL lookups, YARA scans) runs. The whitelist short-circuit saves processing time and API quota for known-safe senders -- a common pattern in commercial email security products like Group-IB BEP.
HOW IT CONNECTS: Called by EmailAnalyzer.analyze() as the first pipeline stage. Reads WhitelistEntry and BlacklistEntry from the threat_intel app. Reads headers_raw, from_address, reply_to, and from_display_name from the Email model. Produces a PreprocessResult dataclass that EmailAnalyzer writes to AnalysisResult (preprocess_score, spf_result, dkim_result, dmarc_result, is_reply_to_mismatch, is_display_spoof).
REPORT CHAPTER: Chapter 4, Section 4.4 (Preprocessor Design); Chapter 5, Section 5.5 (Preprocessor Implementation)

## PreprocessResult Dataclass -- Phase 3
WHAT: Python dataclass that encapsulates all outputs from the Preprocessor stage: score, findings dict, verdict_override, auth results, and BEC signal flags.
WHY: Using a dataclass instead of a plain dict provides type safety, IDE autocompletion, and self-documenting field names. It separates the Preprocessor's internal representation from the ORM model (AnalysisResult), allowing the Preprocessor to be tested independently without database access. The verdict_override field enables the whitelist short-circuit pattern without coupling the Preprocessor to Email model state management.
HOW IT CONNECTS: Returned by Preprocessor.process(). Consumed by EmailAnalyzer._finalize() and EmailAnalyzer._save_preprocess_result(). Fields map directly to AnalysisResult columns.
REPORT CHAPTER: Chapter 5, Section 5.5

## Whitelist Short-Circuit -- Phase 3
WHAT: When a sender's email or domain matches a WhitelistEntry, the Preprocessor immediately returns score=0 with verdict_override=CLEAN, skipping all remaining checks.
WHY: Whitelisted senders (internal domains, known partners) should not consume processing resources. Skipping blacklist, auth, and BEC checks for whitelisted senders reduces pipeline latency and prevents false positives on internal mail that may lack proper SPF/DKIM configuration. This is a standard optimization in commercial email gateways.
HOW IT CONNECTS: Preprocessor._check_whitelist() queries WhitelistEntry (EMAIL first, then DOMAIN). If matched, EmailAnalyzer._finalize() sets Email.status=DELIVERED, verdict=CLEAN, confidence=HIGH. No Checker or Decider stages run.
REPORT CHAPTER: Chapter 4, Section 4.4; Chapter 7, Section 7.2 (Performance)

## Error Resilience in Preprocessor -- Phase 3
WHAT: Preprocessor.process() wraps all logic in try/except and returns a safe default PreprocessResult(score=0) on any unhandled exception. Each sub-check also has its own try/except.
WHY: The analysis pipeline must not crash on unexpected input. A malformed email header or database timeout should degrade gracefully (score the email conservatively at 0) rather than leaving it in ANALYZING state permanently. This defensive pattern ensures the pipeline always produces a result, even if partial.
HOW IT CONNECTS: If process() fails, EmailAnalyzer receives a zero-score result and continues to Checker (Phase 4). The error is logged for debugging. No email is ever stuck in an unrecoverable state due to Preprocessor failure.
REPORT CHAPTER: Chapter 5, Section 5.5; Chapter 7, Section 7.3 (Reliability)

## EmailAnalyzer Upgrade (Stub to Stage 1) -- Phase 3
WHAT: EmailAnalyzer.analyze() upgraded from a stub (Phase 2: ANALYZING then back to PENDING) to a real pipeline orchestrator that calls Preprocessor and handles whitelist finalization vs. partial results.
WHY: The orchestrator pattern separates pipeline sequencing from stage logic. EmailAnalyzer manages state transitions (ANALYZING -> DELIVERED or ANALYZING -> wait for Checker) while Preprocessor focuses purely on scoring. This separation makes each stage independently testable and replaceable.
HOW IT CONNECTS: Called by analyze_email_task (Celery). Instantiates Preprocessor, calls process(), then either _finalize() (whitelist) or _save_preprocess_result() (non-whitelist) followed by Checker.check_all(). Phase 5 will add Decider call after Checker.
REPORT CHAPTER: Chapter 4, Section 4.3 (Pipeline Orchestration); Chapter 5, Section 5.5

---

## Checker -- Phase 4
WHAT: Second stage of the analysis pipeline that performs content-level threat detection: keyword scanning, URL analysis, attachment inspection, and received chain anomaly detection.
WHY: While the Preprocessor (Stage 1) evaluates email authentication and sender reputation, the Checker evaluates the actual email content for indicators of phishing or malware. This mirrors commercial email security products (Group-IB BEP, Proofpoint) that layer authentication checks with content analysis. Four sub-checkers provide defense in depth: even if an attacker passes SPF/DKIM/DMARC, phishing keywords, malicious URLs, or weaponized attachments will still be detected. The sub-checker architecture isolates each detection type so that a failure in one does not prevent others from running.
HOW IT CONNECTS: Called by EmailAnalyzer.analyze() after Preprocessor. Reads Email fields (subject, body_text, urls_extracted, received_chain) and EmailAttachment records. Queries MaliciousDomain and MaliciousHash from threat_intel app. Creates ExtractedIOC records for discovered indicators. Returns CheckResult dataclass consumed by EmailAnalyzer._save_check_result() which updates AnalysisResult.
REPORT CHAPTER: Chapter 4, Section 4.5 (Checker Design); Chapter 5, Section 5.6 (Checker Implementation)

## CheckResult Dataclass -- Phase 4
WHAT: Python dataclass that encapsulates all outputs from the Checker stage: per-sub-checker scores, matched keywords, URL/attachment/chain findings, total check score, and a known-malware flag.
WHY: Mirrors the PreprocessResult pattern from Phase 3 for consistency. Separates the Checker's internal data from the ORM model, enabling unit testing without database access. The has_known_malware flag enables the Decider (Phase 5) to override the score-based verdict to MALICIOUS when a known malware hash is found.
HOW IT CONNECTS: Returned by Checker.check_all(). Consumed by EmailAnalyzer._save_check_result() which writes scores and findings to AnalysisResult columns.
REPORT CHAPTER: Chapter 5, Section 5.6

## Keyword Checker -- Phase 4
WHAT: Sub-checker that scans email subject and body text for 24 phishing keywords using case-insensitive substring matching, scoring +2 per unique match up to a cap of 20.
WHY: Phishing emails consistently use urgency and fear language to trick recipients. Academic research (Almomani et al., 2013) and industry reports (APWG) confirm that keyword-based detection catches a significant portion of phishing attempts. The 24-keyword list covers urgency ("urgent action required"), credential harvesting ("verify your account"), financial fraud ("wire transfer", "bitcoin payment"), and social engineering ("do not share with anyone"). The +2 per keyword / max 20 scoring means a single keyword is low-signal but 10+ matches strongly indicate phishing.
HOW IT CONNECTS: Called by Checker.check_all() as sub-check 1. Reads Email.subject and Email.body_text. Produces keyword_score and keywords_matched list stored in AnalysisResult.
REPORT CHAPTER: Chapter 4, Section 4.5; Chapter 5, Section 5.6

## URL Checker -- Phase 4
WHAT: Sub-checker that analyzes extracted URLs for malicious domains (DB lookup), IP-based URLs, and URL shortener usage, scoring up to a cap of 40.
WHY: Phishing emails almost always contain malicious URLs that redirect to credential harvesting pages. Three detection strategies provide layered coverage: (1) MaliciousDomain DB lookup catches known-bad domains from TI feeds (URLhaus, VirusTotal), (2) IP-based URLs are suspicious because legitimate services use domain names, and (3) URL shorteners (bit.ly, tinyurl.com, etc.) are commonly used to hide the true destination. The +30 for a known malicious domain is high because TI feed data is high-confidence.
HOW IT CONNECTS: Called by Checker.check_all() as sub-check 2. Reads Email.urls_extracted (populated by EmailParser in Phase 2). Queries MaliciousDomain from threat_intel app. Creates ExtractedIOC(ioc_type=DOMAIN) on malicious matches. Produces url_score and url_findings stored in AnalysisResult.
REPORT CHAPTER: Chapter 4, Section 4.5; Chapter 5, Section 5.6

## Attachment Checker -- Phase 4
WHAT: Sub-checker that inspects email attachments for known malware hashes (DB lookup), dangerous file extensions (13 types), double extensions, MIME type mismatches, and pre-populated YARA rule matches, scoring up to a cap of 50.
WHY: Malicious attachments are the primary vector for malware delivery via email. The checker implements five detection layers: (1) MaliciousHash lookup provides certainty -- a matching SHA-256 is a confirmed malware sample, triggering has_known_malware=True for Decider override. (2) Dangerous extensions (.exe, .scr, .vbs, etc.) are rarely sent in legitimate business email. (3) Double extensions (report.pdf.exe) are a classic social engineering trick. (4) MIME mismatch (declared content_type differs from file_magic) indicates deliberate content disguise. (5) YARA rule matches detect patterns like VBA macros, obfuscated JavaScript, and ransomware signatures.
HOW IT CONNECTS: Called by Checker.check_all() as sub-check 3. Reads EmailAttachment records via email.attachments.all(). Queries MaliciousHash from threat_intel app. Creates ExtractedIOC(ioc_type=HASH) on malicious matches. Updates EmailAttachment flags (ti_match, is_dangerous_ext, is_double_ext, is_mime_mismatch). Produces attachment_score and attachment_findings stored in AnalysisResult.
REPORT CHAPTER: Chapter 4, Section 4.5; Chapter 5, Section 5.6

## Received Chain Checker -- Phase 4
WHAT: Sub-checker that analyzes the email received chain (hop headers) for anomalies: excessive hops (>7), private IP addresses, and timestamp disorder, scoring up to a cap of 15.
WHY: The Received headers record each mail server an email passes through. Legitimate business emails typically traverse 3-5 hops. Excessive hops (>7) may indicate relay abuse or header injection. Private IP addresses in the chain suggest the email originated from or passed through an internal network unexpectedly. Timestamp disorder (later hop has earlier timestamp) indicates forged Received headers, a technique used in header spoofing attacks.
HOW IT CONNECTS: Called by Checker.check_all() as sub-check 4. Reads Email.received_chain (populated by EmailParser in Phase 2). Uses Python ipaddress module for private IP detection. Produces chain_score and chain_findings dict stored in AnalysisResult.
REPORT CHAPTER: Chapter 4, Section 4.5; Chapter 5, Section 5.6

## YARA Scanning Deferred -- Phase 4
WHAT: The attachment checker reads the yara_matches field from EmailAttachment if pre-populated but does not run yara-python scanning itself.
WHY: Running YARA rules against attachment content requires fetching the full attachment bytes from Gmail API (an expensive, rate-limited operation). In Phase 4, the checker infrastructure is built to score YARA matches when present, but the actual scanning is deferred to a future enhancement. This keeps Phase 4 focused on the scoring and DB lookup logic while avoiding Gmail API complexity.
HOW IT CONNECTS: If yara_matches is populated (e.g., by a future YARA scanning service), the attachment checker scores +25 per rule match. The YaraRule model in threat_intel already stores rule definitions with is_active flags.
REPORT CHAPTER: Chapter 5, Section 5.6 (Implementation Decisions)

## EmailAnalyzer Upgrade (Stage 1+2) -- Phase 4
WHAT: EmailAnalyzer.analyze() upgraded to call Checker.check_all() after Preprocessor.process() for non-whitelisted emails, with a new _save_check_result() method that persists checker scores to AnalysisResult.
WHY: The orchestrator pattern continues from Phase 3: EmailAnalyzer manages the pipeline sequence while each stage focuses on its detection logic. The new _save_check_result() uses AnalysisResult.filter(email).update() rather than update_or_create() because the record already exists from _save_preprocess_result(). Whitelisted emails still skip the Checker entirely, preserving the short-circuit optimization.
HOW IT CONNECTS: Called by analyze_email_task (Celery). After Preprocessor, calls Checker().check_all(email), then _save_check_result(). Phase 5 will add Decider call after _save_check_result().
REPORT CHAPTER: Chapter 4, Section 4.3 (Pipeline Orchestration); Chapter 5, Section 5.6

---

## Decider -- Phase 5
WHAT: Third and final stage of the analysis pipeline that combines Preprocessor and Checker scores to produce a verdict (CLEAN/SUSPICIOUS/MALICIOUS), confidence level, and recommended action (DELIVER/QUARANTINE/BLOCK).
WHY: The Decider implements the core decision logic that translates numerical risk scores into actionable verdicts. Configurable thresholds (CLEAN < 25, SUSPICIOUS 25-69, MALICIOUS >= 70) allow tuning without code changes, addressing the operational need for adjustable sensitivity. The known malware hash override (force MALICIOUS/100/HIGH/BLOCK) ensures that confirmed threats are never under-classified regardless of the raw score, which is a compliance requirement in enterprise email security (zero false negatives on known malware). The score cap at 100 provides a normalized 0-100 scale for dashboard display and reporting.
HOW IT CONNECTS: Called by EmailAnalyzer.analyze() after Preprocessor and Checker. Receives PreprocessResult and CheckResult dataclasses. Returns DecisionResult dataclass consumed by EmailAnalyzer._finalize() which updates Email (verdict, score, confidence, status), AnalysisResult (total_score, pipeline_duration_ms), and creates QuarantineEntry for QUARANTINE/BLOCK actions.
REPORT CHAPTER: Chapter 4, Section 4.6 (Decider Design); Chapter 5, Section 5.7 (Decider Implementation); Chapter 7, Section 7.1 (Verdict Accuracy)

## DecisionResult Dataclass -- Phase 5
WHAT: Python dataclass that encapsulates all outputs from the Decider stage: verdict, total_score, confidence, action, preprocess_score, check_score, and optional override_reason.
WHY: Continues the dataclass pattern established by PreprocessResult (Phase 3) and CheckResult (Phase 4) for consistency across all pipeline stages. Separates decision logic from ORM persistence, enabling unit testing of verdict logic without database access. The override_reason field provides audit trail transparency when a known malware hash forces a MALICIOUS verdict, which is important for compliance reporting and analyst review.
HOW IT CONNECTS: Returned by Decider.decide(). Consumed by EmailAnalyzer._finalize() which maps the action to Email.status via ACTION_STATUS_MAP.
REPORT CHAPTER: Chapter 5, Section 5.7

## EmailAnalyzer Upgrade (Full Pipeline) -- Phase 5
WHAT: EmailAnalyzer.analyze() upgraded to the complete 3-stage pipeline: Preprocessor -> Checker -> Decider -> _finalize. The _finalize method now creates QuarantineEntry for QUARANTINE/BLOCK actions and measures pipeline_duration_ms.
WHY: The orchestrator pattern reaches its final form. Pipeline timing is critical for the <30 second target (measured via time.time() delta, stored in AnalysisResult.pipeline_duration_ms). QuarantineEntry creation completes the email lifecycle: suspicious/malicious emails are quarantined with a PENDING status for analyst review, while clean emails are delivered immediately. The ACTION_STATUS_MAP dict cleanly translates Decider actions (DELIVER/QUARANTINE/BLOCK) to Email statuses (DELIVERED/QUARANTINED/BLOCKED).
HOW IT CONNECTS: Called by analyze_email_task (Celery). Instantiates all three services in sequence. Whitelist short-circuit from Phase 3 is preserved (skips Checker and Decider). _finalize uses AnalysisResult.objects.update_or_create() for the complete result and QuarantineEntry.objects.get_or_create() for idempotent quarantine creation.
REPORT CHAPTER: Chapter 4, Section 4.3 (Pipeline Orchestration); Chapter 5, Section 5.7

## TI Feed Sync (Management Command) -- Phase 5
WHAT: Django management command `sync_ti_feeds` that imports threat intelligence data from MalwareBazaar (MaliciousHash records from CSV) and URLhaus (MaliciousDomain records from CSV).
WHY: The Checker's effectiveness depends on up-to-date threat intelligence. MalwareBazaar provides confirmed malware hashes (SHA-256) that enable the known malware override in the Decider. URLhaus provides actively malicious domains for URL scoring. Both are free, high-quality, community-maintained feeds from abuse.ch -- a trusted source in the security industry. The --limit parameter prevents runaway imports, and SHA-256 validation (64 hex chars regex) rejects malformed data. URLhaus filtering to url_status='online' only imports actively threatening domains, reducing false positives from already-taken-down infrastructure.
HOW IT CONNECTS: Called by Celery tasks (sync_malwarebazaar_task at 02:00 UTC, sync_urlhaus_task at 02:30 UTC) and manually via `python manage.py sync_ti_feeds`. Creates/updates MaliciousHash and MaliciousDomain records that the Checker queries during email analysis.
REPORT CHAPTER: Chapter 4, Section 4.7 (TI Feed Integration); Chapter 5, Section 5.8 (TI Sync Implementation)

## Celery Beat TI Sync Schedule -- Phase 5
WHAT: Two new Celery Beat entries: sync-malwarebazaar-daily at 02:00 UTC and sync-urlhaus-daily at 02:30 UTC.
WHY: Automated daily synchronization ensures threat intelligence stays current without manual intervention. The 02:00/02:30 UTC schedule runs during off-peak hours to minimize impact on analysis pipeline performance. Staggering by 30 minutes avoids concurrent external API requests.
HOW IT CONNECTS: Celery Beat triggers tasks in threat_intel/tasks.py which call the sync_ti_feeds management command. The tasks use Django's call_command() to delegate to the management command, keeping task definitions thin and the sync logic testable independently.
REPORT CHAPTER: Chapter 4, Section 4.7; Chapter 5, Section 5.8

## REST API (5 Endpoints) -- Phase 5
WHAT: DRF-based REST API with 5 endpoints: email list (paginated, filterable), email detail (nested analysis + attachments), quarantine list, quarantine action (release/block/delete), and dashboard statistics.
WHY: The dashboard UI (Phase 6) needs a data source. Building the API before the frontend follows the API-first design pattern, ensuring the backend contract is stable and testable before UI work begins. The quarantine action endpoint is the critical analyst workflow: analysts review quarantined emails and decide to release (false positive), confirm block, or permanently delete. Role-based access (IsAnalystOrAbove) on the action endpoint ensures only ADMIN and ANALYST users can modify quarantine state, satisfying FR-001 (RBAC). The dashboard stats endpoint provides aggregate counts needed for the landing page without requiring multiple API calls.
HOW IT CONNECTS: URLs registered under /api/ prefix in stratos_server/urls.py via include('emails.urls'). Views use DRF generics (ListAPIView, RetrieveAPIView, GenericAPIView) and APIView. Serializers handle Email, AnalysisResult, EmailAttachment, QuarantineEntry, and dashboard statistics. Auth: Session + Token authentication (DRF default). IsAnalystOrAbove permission checks request.user.role.
REPORT CHAPTER: Chapter 4, Section 4.8 (API Design); Chapter 5, Section 5.9 (API Implementation); Chapter 7, Section 7.1 (FR-002 API Access)

## IsAnalystOrAbove Permission -- Phase 5
WHAT: Custom DRF permission class that allows access only to users with ADMIN or ANALYST role.
WHY: Quarantine actions (release, block, delete) are security-sensitive operations that must not be available to VIEWER-role users. This permission class implements the RBAC requirement (FR-001) at the API layer, complementing the model-level role field defined in Phase 0. Using a dedicated permission class (rather than inline checks) follows DRF best practices and is reusable across multiple views.
HOW IT CONNECTS: Applied to QuarantineActionView via permission_classes = [IsAnalystOrAbove]. Reads request.user.role from the accounts.User model. Returns 403 Forbidden for unauthenticated users or VIEWER role.
REPORT CHAPTER: Chapter 4, Section 4.4 (Authorization); Chapter 5, Section 5.9; Chapter 7, Section 7.1 (FR-001)

---

## Django Templates (not SPA) -- Phase 6
WHAT: Server-side rendered HTML templates using Django's built-in template engine, with vanilla JS for interactivity, instead of a single-page application framework (React, Vue, etc.).
WHY: A SPA would require a separate build toolchain (Node.js, webpack/vite), add a dependency on a frontend framework, and double the testing surface (frontend unit tests + integration tests). For a BISP academic project with 5 pages and one developer, Django templates provide faster development, zero additional dependencies, SEO-irrelevant (internal tool), and natural integration with Django's auth system (@login_required decorator), CSRF protection, and flash messages. The Phase 5 REST API remains available for any future SPA migration or external integrations, so no capability is lost. This decision aligns with the locked tech stack ("Django templates + vanilla JS").
HOW IT CONNECTS: Template views in emails/views.py read the same Django ORM models that the API views use. Templates in the templates/ directory extend base.html for consistent layout. Static assets (CSS, JS) are served by Django's staticfiles app. URL routing in emails/template_urls.py coexists with API routes in emails/urls.py via separate URL include paths.
REPORT CHAPTER: Chapter 4, Section 4.9 (UI Architecture); Chapter 5, Section 5.10 (UI Implementation)

## Light Theme Design System -- Phase 6
WHAT: CSS custom property-based design system enforcing a light (white/slate) theme with the navy sidebar as the only dark element, using Inter font for body text and JetBrains Mono for code/hashes.
WHY: Light themes are the standard for enterprise security dashboards (Group-IB, CrowdStrike Falcon, Microsoft Defender) because analysts spend hours reviewing email data and light backgrounds reduce eye strain in well-lit office environments. The color-coded verdict badges (green/amber/red) are universally understood severity indicators in the cybersecurity industry. CSS custom properties enable consistent theming across all 6 templates from a single source of truth. The Inter font was chosen for its high readability at small sizes (email addresses, timestamps), while JetBrains Mono provides clear distinction for SHA-256 hashes and code snippets.
HOW IT CONNECTS: Defined in static/css/stratos.css, loaded by base.html via Google Fonts CDN (Inter, JetBrains Mono). All 6 templates inherit the theme through base.html. Verdict badges use the --clean/--suspicious/--malicious CSS variable groups. Score bars use JavaScript to apply threshold-based colors dynamically.
REPORT CHAPTER: Chapter 4, Section 4.9 (UI Design System); Chapter 5, Section 5.10; Chapter 7, Section 7.1 (FR-005 Dashboard)

## Role-Based UI Visibility -- Phase 6
WHAT: Template-level conditional rendering that shows/hides UI elements based on the authenticated user's role (ADMIN/ANALYST/VIEWER).
WHY: RBAC must be enforced at both the API layer (Phase 5 IsAnalystOrAbove permission) and the UI layer to prevent confusion and accidental actions. VIEWER users should not see quarantine action buttons they cannot use. ADMIN users need a link to the Django admin for system configuration. The raw analysis tab (full JSON score breakdown) is restricted to ANALYST+ because it exposes internal scoring details that could confuse VIEWER users. This dual enforcement (UI + API) satisfies defense-in-depth for FR-001.
HOW IT CONNECTS: Template views pass role-derived flags (can_view_raw, can_act) to templates. Templates use Django's {% if %} blocks to conditionally render elements. The quarantine_action_view also enforces role checks server-side as a security backstop.
REPORT CHAPTER: Chapter 4, Section 4.4 (Authorization); Chapter 5, Section 5.10; Chapter 7, Section 7.1 (FR-001)

## Separate template_urls.py -- Phase 6
WHAT: A dedicated URL configuration file (emails/template_urls.py, app_name='ui') for template views, separate from the existing emails/urls.py (app_name='emails') that serves the REST API.
WHY: Phase 5 established the API URL patterns at /api/ with their own namespace. Adding template view URLs to the same file would create naming collisions (both have 'email-list', 'email-detail', etc.) and require renaming Phase 5 patterns, which would break existing API consumers and tests. A separate file with a distinct namespace ('ui') allows both URL sets to coexist with identical human-readable names (ui:email-list vs emails:email-list).
HOW IT CONNECTS: stratos_server/urls.py includes emails/template_urls.py at the root path ('') and emails/urls.py at the '/api/' prefix. Template views use {% url 'ui:...' %} for internal links.
REPORT CHAPTER: Chapter 5, Section 5.10 (Implementation Decisions)

## seed_demo_data Management Command -- Phase 6
WHAT: Management command that populates the database with realistic demo data including emails with various verdicts, attachments, analysis results, quarantine entries, and TI records.
WHY: The BISP viva requires a live demonstration of the system with realistic data. Creating demo data manually through the admin panel is time-consuming and error-prone. A repeatable management command ensures the same demo scenario can be reconstructed at any time, including before the viva. It also enables capturing consistent screenshots for the report.
HOW IT CONNECTS: Called via `python manage.py seed_demo_data`. Creates Email, EmailAttachment, AnalysisResult, QuarantineEntry, MaliciousHash, and MaliciousDomain records. Does not affect existing data (creates new records only). Screenshots in docs/screenshots/ were captured from this seed data.
REPORT CHAPTER: Chapter 5, Section 5.10 (Demo Preparation); Chapter 6, Section 6.3 (Demo Scenario)

## Tab-Based Email Detail View -- Phase 6
WHAT: Email detail page with 5 tabs (Overview, Headers, URLs, Attachments, Raw Analysis) using URL hash-based tab switching in vanilla JavaScript.
WHY: Email analysis produces data across multiple dimensions (metadata, authentication headers, URL analysis, attachment analysis, raw scoring). Displaying all data at once overwhelms the analyst. Tabs organize related information into focused views, matching the UX pattern used in Group-IB BEP's email detail page. URL hash-based switching (#headers, #urls) preserves the active tab when the page is refreshed or shared with a colleague, without requiring additional HTTP requests.
HOW IT CONNECTS: emails/detail.html renders all 5 tab panels in the HTML. stratos.js reads window.location.hash to activate the correct tab on page load and updates the hash when tabs are clicked. The email_detail_view passes the email object with select_related('analysis') and prefetch_related('attachments', 'iocs') for efficient single-query data loading.
REPORT CHAPTER: Chapter 4, Section 4.9; Chapter 5, Section 5.10

---

## Threat Intel Management Page -- Phase 7
WHAT: Server-side rendered page at /threat-intel/ that displays TI stat cards (hashes, domains, IPs, YARA rules), feed sync status with last-sync timestamps, whitelist/blacklist management forms, and recent IOC detections.
WHY: Analysts need visibility into the threat intelligence data that drives the analysis pipeline. Without a TI dashboard, the only way to inspect TI records is via Django admin, which lacks context (e.g., feed sync timestamps, IOC detection links). Admin users need to manage whitelist/blacklist entries without dropping to the admin panel. The sync button enables on-demand TI refresh when a new threat campaign is detected, rather than waiting for the daily cron schedule.
HOW IT CONNECTS: threat_intel/views.py reads MaliciousHash, MaliciousDomain, MaliciousIP, YaraRule counts and last-sync timestamps. Whitelist/blacklist add/remove views use get_or_create and delete on WhitelistEntry/BlacklistEntry. The sync view triggers sync_malwarebazaar_task.delay() and sync_urlhaus_task.delay() for async execution. Recent IOCs come from ExtractedIOC (emails app) via cross-app query. URL routing uses threat_intel/template_urls.py with app_name='ti'.
REPORT CHAPTER: Chapter 4, Section 4.10 (TI Management UI); Chapter 5, Section 5.11 (TI Views)

## Streaming CSV/JSON Export (No Disk Write) -- Phase 7
WHAT: Report exports (email summary CSV, IOC list CSV, TI stats JSON) stream directly to the browser via Django HttpResponse without writing temporary files to disk.
WHY: Writing export files to disk introduces cleanup complexity, disk space management, and potential security issues (temporary files containing sensitive email data). Streaming via HttpResponse is the Django-recommended pattern for file downloads: the response object acts as a file-like object for csv.writer, and the iterator pattern (qs.iterator()) prevents loading the entire queryset into memory. This approach works for datasets up to tens of thousands of records, which is sufficient for the BISP scope. The Report/IOCExport model records serve as an audit log of what was exported, by whom, and with which filters -- satisfying the audit trail requirement without storing the actual file content.
HOW IT CONNECTS: reports/views.py creates HttpResponse with content_type='text/csv' or 'application/json', sets Content-Disposition header for download filename. csv.writer writes rows directly to the response. After streaming, a Report or IOCExport audit record is created with record_count and filters_applied. The reports/list.html page shows the audit history.
REPORT CHAPTER: Chapter 4, Section 4.11 (Export Architecture); Chapter 5, Section 5.11 (Export Implementation)

## IOC List Page -- Phase 7
WHAT: Filterable, paginated page at /iocs/ showing all extracted IOCs with type and severity filters.
WHY: IOC data is a key output of the analysis pipeline -- analysts need a centralized view of all indicators discovered across all analyzed emails. The IOC list enables threat hunting (searching for specific IOC types), incident response (tracking which emails contained specific indicators), and export (the IOC export button links to the CSV export). Placing the IOC list view in the emails app (rather than threat_intel) is correct because ExtractedIOC belongs to the emails app -- it represents IOCs extracted from emails, not reference TI data.
HOW IT CONNECTS: emails/views.py ioc_list_view queries ExtractedIOC.objects.select_related('email') with optional ioc_type and severity filters. Paginated at 20 per page. URL pattern at /iocs/ registered in emails/template_urls.py under the 'ui' namespace. Sidebar links to this page under the SECURITY section.
REPORT CHAPTER: Chapter 4, Section 4.10; Chapter 5, Section 5.11

## User Management Page -- Phase 7
WHAT: Admin-only page at /users/ for creating new users, changing user roles, and activating/deactivating accounts.
WHY: FR-001 (RBAC) requires that administrators can manage user access. Without a dedicated user management page, the only way to manage users is through Django admin, which is an unrestricted superuser tool -- not appropriate for a production security platform where admin actions should be scoped. The self-protection checks (cannot demote or deactivate your own account) prevent accidental lockout, which is a standard pattern in enterprise identity management systems.
HOW IT CONNECTS: accounts/views.py provides 4 views (list, edit-role, toggle-active, add). All views enforce ADMIN role check. Self-protection compares target user pk against request.user. User creation uses Django's create_user() for proper password hashing. URL routing uses accounts/template_urls.py with app_name='accounts'. The sidebar shows the Users link only for ADMIN role (template conditional).
REPORT CHAPTER: Chapter 4, Section 4.4 (Authorization); Chapter 5, Section 5.11; Chapter 7, Section 7.1 (FR-001)

## Async TI Sync via Celery .delay() -- Phase 7
WHAT: The TI sync button on the Threat Intel page dispatches sync tasks asynchronously using .delay() rather than running the sync synchronously in the request.
WHY: TI feed sync involves HTTP requests to external APIs (MalwareBazaar, URLhaus) that may take 10-30 seconds. Running this synchronously would block the HTTP response and risk a timeout. The .delay() pattern queues the tasks on Celery, immediately redirects the user with a flash message, and the sync completes in the background. This is the same pattern used by Celery Beat for the scheduled daily sync, maintaining architectural consistency.
HOW IT CONNECTS: threat_intel/views.py imports sync_malwarebazaar_task and sync_urlhaus_task from threat_intel/tasks.py. Both are called with .delay() (no arguments). The user sees a success flash message and is redirected to ti:stats. When the tasks complete, the TI stat cards will reflect updated counts on the next page refresh.
REPORT CHAPTER: Chapter 5, Section 5.11 (Implementation Decisions)

## Three Separate URL Namespaces -- Phase 7
WHAT: Three new URL configuration files with separate Django app_name namespaces: 'ti' (threat_intel/template_urls.py), 'reports' (reports/template_urls.py), 'accounts' (accounts/template_urls.py).
WHY: Each Django app now has its own view layer with its own URL namespace, following the separation of concerns established by the 4-app architecture in Phase 0. Separate namespaces prevent naming collisions (e.g., both reports and TI could have a 'list' view) and enable clean reverse URL resolution in templates ({% url 'ti:stats' %}, {% url 'reports:list' %}, {% url 'accounts:user-list' %}). This matches the Phase 6 pattern where emails has 'ui' and 'emails' namespaces.
HOW IT CONNECTS: stratos_server/urls.py includes all three new URL files with their respective path prefixes (/threat-intel/, /reports/, /users/). The accounts URLs are mounted at root ('') because the paths already include /users/ prefix. Phase 6 template_urls.py remains as a catch-all at the end of the URL list.
REPORT CHAPTER: Chapter 5, Section 5.11 (URL Routing)

---

## Test Suite (351 Tests) -- Phase 8
WHAT: Comprehensive test suite across 14 files and 6 test categories: pipeline integration, boundary testing, API authentication, export validation, preprocessor scoring, and checker scoring.
WHY: A BISP project requires demonstrable quality assurance to satisfy Chapter 6 (Testing) of the report. The 95% coverage metric provides quantitative evidence that the codebase is well-tested. The 6 test category organization maps directly to the evaluation criteria in Chapter 7: each functional requirement (FR-001 through FR-006) has corresponding test coverage. Boundary testing is particularly important for a scoring system because off-by-one errors in threshold comparisons would cause incorrect verdicts -- the boundary tests catch exactly these errors.
HOW IT CONNECTS: All 14 test files in tests/ are discovered by Django's test runner. Tests use Django TestCase (in-memory SQLite, transaction rollback) for isolation. API tests use DRF APIClient. No tests require external network access -- all Gmail API calls are mocked.
REPORT CHAPTER: Chapter 6, Section 6.1 (Test Strategy); Chapter 6, Section 6.2 (Test Results); Chapter 7, Section 7.2 (Quality Assurance)

## demo_setup / demo_teardown Commands -- Phase 8
WHAT: Two management commands that create and destroy a complete demo dataset for the 8-minute viva presentation, including 3 users (admin/analyst/viewer), sample emails at all verdict levels, TI records, and QuarantineEntries.
WHY: The viva requires a live demonstration of the working system. A repeatable, scripted demo setup ensures the presentation is consistent regardless of when or where it is run. The teardown command allows resetting the database between practice runs or after the viva. Separating demo_setup from the existing seed_demo_data command keeps concerns clean: seed_demo_data is for development screenshots, demo_setup is specifically tailored for the 8-minute viva script (docs/DEMO_SCRIPT.md).
HOW IT CONNECTS: demo_setup creates users, calls various model .get_or_create() methods for idempotency. demo_teardown uses .filter().delete() with CASCADE. Both are run via `python manage.py demo_setup` and `python manage.py demo_teardown`. The DEMO_SCRIPT.md references demo_setup as the first step before the viva.
REPORT CHAPTER: Chapter 6, Section 6.3 (Demo Preparation); Chapter 8, Section 8.2 (Viva Preparation)

## DEMO_SCRIPT.md -- Phase 8
WHAT: Structured 8-minute viva walkthrough script covering login, dashboard tour, email analysis demo, quarantine workflow, TI management, reports/exports, and architecture Q&A preparation.
WHY: The viva has a strict time constraint (18-30 April 2026, approximately 10 minutes per student). A scripted walkthrough ensures all key features are demonstrated within the time limit, no features are accidentally skipped, and the presentation has a logical flow from high-level overview to detailed feature demonstration. The Q&A preparation section anticipates common examiner questions about technology choices, security considerations, and scalability.
HOW IT CONNECTS: References demo_setup as prerequisite. The script flows through the same UI pages documented in screenshots (Figs 1-20) and demonstrates the pipeline stages documented in ARCHITECTURE.md.
REPORT CHAPTER: Chapter 8, Section 8.2 (Viva)

## QUICK_REFERENCE.md -- Phase 8
WHAT: Single-page reference card containing all key numbers, scoring tables, management commands, API endpoints, and URLs for the Stratos BEP project.
WHY: During the viva Q&A, the examiner may ask specific questions about scoring thresholds, test counts, or architectural decisions. A single-page reference card allows the presenter to quickly look up exact numbers without searching through multiple documentation files. It also serves as a handout if the examiner requests a summary document.
HOW IT CONNECTS: Consolidates key facts from CLAUDE.md, ARCHITECTURE.md, HOW.md, and REPORT_FEED.md into a single quick-reference format. Does not replace any existing documentation -- it is a summary view.
REPORT CHAPTER: Chapter 8, Section 8.2 (Viva Preparation)
