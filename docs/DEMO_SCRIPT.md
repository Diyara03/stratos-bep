# Stratos BEP -- Viva Demo Script (8 minutes)

## SETUP (Before examiner arrives)

```bash
# 1. Start all services
docker compose up -d

# 2. Load demo data (idempotent -- safe to run multiple times)
python manage.py demo_setup --flush

# 3. Verify in browser
#    Open http://localhost:8000/ and log in as admin/admin123
#    Confirm dashboard shows 10 emails, 3 verdicts in pie chart

# 4. Keep two browser tabs ready:
#    Tab 1: Dashboard        http://localhost:8000/
#    Tab 2: Email detail     http://localhost:8000/emails/<ID of demo-mal-001>/
```

Credentials for demo:
- **admin / admin123** (ADMIN role -- full access)
- **analyst / analyst123** (ANALYST role -- can review quarantine)
- **viewer / viewer123** (VIEWER role -- read-only)

---

## MINUTE 0-1: Dashboard Overview

**Navigate to:** `http://localhost:8000/`

**Talk track:**

> "This is Stratos, a Business Email Protection platform I built as my BISP project.
> It is inspired by Group-IB's commercial BEP product but implemented as a Django monolith.
>
> The dashboard gives a real-time overview of email security posture.
> You can see:
> - **Total emails analyzed** (10 in this demo)
> - **Verdict distribution**: 3 CLEAN (green), 4 SUSPICIOUS (amber), 3 MALICIOUS (red)
> - **Recent email activity** with timestamps
> - **Quarantine count** showing emails awaiting analyst review
>
> Every email passes through a three-stage pipeline: Preprocessor, Checker, Decider --
> all within 30 seconds."

**Key points to highlight:**
- Light theme with navy sidebar (design system compliance)
- Verdict badges with color coding: green/amber/red
- Real-time statistics from the database

---

## MINUTE 1-2: Email List with Filters

**Navigate to:** `http://localhost:8000/emails/`

**Talk track:**

> "The email list shows every email that has been ingested and analyzed.
> Each row shows the sender, subject, verdict badge, score, and timestamp.
>
> I can filter by verdict -- let me show MALICIOUS emails only."

**Actions:**
1. Click the **MALICIOUS** filter (or use `?verdict=MALICIOUS`)
2. Show 3 malicious emails appear
3. Click **SUSPICIOUS** filter -- show 4 suspicious emails
4. Click **ALL** to reset

> "Scores range from 0 to 100. CLEAN is below 25, SUSPICIOUS is 25-69,
> and MALICIOUS is 70 or above. These thresholds are based on the cumulative
> scoring from all pipeline stages."

---

## MINUTE 2-4: Email Detail (Key Demo -- demo-mal-001, score=88)

**Navigate to:** Click on "Urgent: Verify your identity -- account suspended" (demo-mal-001)

**URL:** `http://localhost:8000/emails/<pk>/` (the Ministry of Justice phishing email)

**Talk track:**

> "Let me drill into this MALICIOUS email with a score of 88.
> This simulates a government impersonation phishing attack targeting Uzbekistan.
>
> **Header Analysis (Preprocessor stage):**
> - SPF: FAIL -- the sender's IP is not authorized for this domain
> - DKIM: FAIL -- the digital signature does not verify
> - DMARC: FAIL -- the domain's DMARC policy was violated
> - Reply-To mismatch detected -- the reply address differs from the From address
> - Display name spoofing detected -- claims to be 'Ministry of Justice'
>
> The preprocessor alone contributed 42 points to the score.
>
> **Keyword Analysis (Checker stage):**
> - 8 phishing keywords detected: 'verify your identity', 'urgent action required',
>   'suspended account', 'click here immediately', 'unusual activity',
>   'your account will be closed', 'act now', 'verify your information'
> - Keyword score: 16 points (2 points each, capped at 20)
>
> **URL Analysis:**
> - Extracted URL matched against URLhaus threat intelligence feed
> - URL score: 30 points
>
> **Decider:**
> - Total: 42 (preprocess) + 16 (keywords) + 30 (URLs) = 88
> - Verdict: MALICIOUS (threshold is 70)
> - Status: BLOCKED -- this email was automatically blocked from delivery"

**Key points to highlight:**
- Score breakdown showing exactly how each pipeline stage contributed
- SPF/DKIM/DMARC results with color indicators
- Matched keywords list
- URL findings from threat intelligence
- Pipeline duration (typically 1-3 seconds)

---

## MINUTE 4-5: Quarantine Actions

**Navigate to:** `http://localhost:8000/quarantine/`

**Talk track:**

> "The quarantine queue holds emails that were flagged as SUSPICIOUS or MALICIOUS.
> Analysts can review each email and take action.
>
> We have 7 emails in quarantine -- 4 suspicious and 3 blocked.
> Let me demonstrate the review workflow."

**Actions:**
1. Point out the quarantine list with status badges
2. Show a SUSPICIOUS email (demo-susp-001, PayPal phishing, score=48)
3. Demonstrate the action options: Release / Delete / Block

> "An analyst reviews the evidence -- the score breakdown, keywords matched,
> authentication failures -- and decides whether to release or permanently block.
> This human-in-the-loop step is critical for the SUSPICIOUS category where
> automated decisions are not confident enough."

---

## MINUTE 5-6: Threat Intelligence

**Navigate to:** `http://localhost:8000/threat-intel/`

**Talk track:**

> "The Threat Intelligence page shows what feeds power our detection engine.
>
> We integrate with four external feeds:
> - **MalwareBazaar** -- malicious file hashes (currently 5 in demo)
> - **URLhaus** -- malicious URLs and domains (5 domains loaded)
> - **AbuseIPDB** -- malicious IP addresses (2 IPs loaded)
> - **VirusTotal** -- cross-reference for hashes and URLs
>
> Plus our local intelligence:
> - **6 YARA rules** for attachment scanning (VBA macros, PE executables, JS obfuscation, etc.)
> - **Whitelist**: 2 entries (trusted corporate domain and CEO address)
> - **Blacklist**: 2 entries (known phishing and C2 domains)
>
> The sync button triggers an on-demand pull from all feeds.
> In production, Celery Beat runs these syncs on a daily schedule."

**Actions:**
1. Show the hash table, domain table, YARA rules
2. Point out whitelist/blacklist entries
3. Mention the sync mechanism

---

## MINUTE 6-7: Technical Q&A Buffer

**Prepared answers for common questions:**

**Q: How does the scoring system work?**
> "Each pipeline stage contributes points. Preprocessor checks authentication (SPF/DKIM/DMARC)
> and blacklists. Checker scans keywords (max 20 pts), URLs (max 40 pts), attachments (max 50 pts),
> and received chain (max 15 pts). The Decider sums all scores and applies thresholds:
> CLEAN < 25, SUSPICIOUS 25-69, MALICIOUS >= 70."

**Q: What is the technology stack?**
> "Django 4.2 monolith with PostgreSQL, Redis for caching, Celery for async tasks.
> Gmail API for email ingestion. YARA for attachment scanning. DRF for the REST API.
> Docker Compose orchestrates 5 containers."

**Q: How do you handle rate limits for external APIs?**
> "VirusTotal is rate-limited to 4 requests per minute -- we use a token bucket pattern.
> URLhaus and MalwareBazaar are unlimited. AbuseIPDB allows 1000 requests per day.
> All TI syncs run as Celery tasks with built-in retry logic."

**Q: What about false positives?**
> "The SUSPICIOUS category (25-69) exists specifically for uncertain cases.
> Analysts review these in the quarantine queue. Whitelist entries let administrators
> mark trusted senders who bypass all checks. The confidence field (LOW/MEDIUM/HIGH)
> indicates how certain the system is about its verdict."

**Q: How would this scale in production?**
> "Celery workers can scale horizontally. The pipeline targets under 30 seconds per email.
> PostgreSQL handles the persistence layer with proper indexing on message_id, verdict,
> and received_at. Redis provides the message broker and result backend."

---

## MINUTE 7-8: Closing

**Navigate back to:** `http://localhost:8000/` (Dashboard)

**Talk track:**

> "To summarize, Stratos BEP demonstrates a complete email security pipeline:
>
> 1. **Ingestion** -- Gmail API pulls emails into the system
> 2. **Preprocessing** -- SPF, DKIM, DMARC authentication checks plus whitelist/blacklist
> 3. **Checking** -- Keyword analysis, URL scanning, attachment inspection, YARA rules
> 4. **Decision** -- Score aggregation with clear thresholds
> 5. **Action** -- Automatic blocking, quarantine, or delivery with analyst review
>
> The project has 15 models across 4 Django apps, 340+ tests with 97% coverage,
> and integrates with 4 external threat intelligence feeds.
>
> Thank you. I am happy to answer any additional questions."

---

## Emergency Recovery

If something breaks during the demo:

```bash
# Reset demo data
python manage.py demo_teardown
python manage.py demo_setup

# Restart services
docker compose restart

# Check logs
docker compose logs django --tail=50
```

If the database is corrupted:
```bash
docker compose down -v
docker compose up -d
python manage.py migrate
python manage.py demo_setup
```
