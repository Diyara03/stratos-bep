# Stratos -- Business Email Protection System

> **"Threats burn up before they land"**

Stratos is a multi-layered Business Email Protection (BEP) platform that analyses every incoming email through a three-stage detection pipeline and assigns a verdict of **Clean**, **Suspicious**, or **Malicious**. Built as a BSc BIS final-year project at Westminster International University in Tashkent (WIUT), Stratos is inspired by Group-IB's production BEP architecture and adapted to student scale.

---

## Features

| Feature | Detail |
|---|---|
| **Email ingestion** | Gmail API connector, polls every 10 seconds |
| **Preprocessing** | SPF / DKIM / DMARC scoring, whitelist/blacklist |
| **Keyword detection** | 24 phishing keywords, +2 points each, max +20 |
| **URL analysis** | URLhaus feed lookup, IP-based URL detection, shortener detection |
| **Attachment scanning** | SHA-256 vs MalwareBazaar, 13 dangerous extensions, double-extension, MIME mismatch |
| **YARA scanning** | 6 custom rules: VBA macro, PE executable, JS obfuscation, double extension, OLE, ransomware |
| **Received chain** | Hop count anomaly, private IP in public chain, timestamp disorder |
| **Threat intelligence** | MalwareBazaar + URLhaus daily sync via Celery Beat |
| **Verdict engine** | Score 0-100, CLEAN <25, SUSPICIOUS 25-69, MALICIOUS >=70 |
| **Dashboard** | 9 pages, light theme, role-based access (Admin / Analyst / Viewer) |
| **REST API** | 5 endpoints, DRF, Session + Token authentication |
| **Export** | CSV email summary, IOC export, JSON TI stats |
| **Testing** | 351 tests, 82% full coverage, 95%+ on core pipeline |

---

## Architecture

```
Email --> PARSE --> PREPROCESS --> CHECK --> DECIDE --> ACT
                                                       |
         Target: <30 seconds              CLEAN / SUSPICIOUS / MALICIOUS
```

### Three-Stage Pipeline

| Stage | Component | Max Score | Key Checks |
|-------|-----------|-----------|------------|
| 1 | **Preprocessor** | ~65 | SPF/DKIM/DMARC auth, blacklist (+40/+30), Reply-To mismatch (+10), display spoof (+10) |
| 2 | **Checker** | +125 | Keywords (max +20), URLs (max +40), Attachments (max +50), Chain (max +15) |
| 3 | **Decider** | - | Aggregates scores, applies thresholds, known malware override |

### Verdict Thresholds

| Score | Verdict | Action |
|-------|---------|--------|
| 0-24 | CLEAN | Delivered to inbox |
| 25-69 | SUSPICIOUS | Quarantined for analyst review |
| 70-100 | MALICIOUS | Blocked automatically |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Django 4.2, Django REST Framework |
| Database | PostgreSQL 15 |
| Task Queue | Redis 7 + Celery 5.3 |
| Email Source | Gmail API (OAuth2) |
| TI Feeds | MalwareBazaar, URLhaus (abuse.ch) |
| Detection | yara-python, python-magic |
| Frontend | Django templates, vanilla JS, Inter font |
| Deployment | Docker Compose (5 containers) |

---

## Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL 15+ (or use Docker)
- Redis 7+ (or use Docker)
- Google Cloud project with Gmail API enabled

### Setup

```bash
# Clone
git clone https://github.com/Stratos/stratos-bep.git
cd stratos-bep

# Environment
cp .env.example .env
# Edit .env with your values

# Option A: Docker (recommended)
docker compose up -d

# Option B: Local
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python manage.py migrate
python manage.py demo_setup
python manage.py runserver
```

### Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin (full access) |
| analyst | analyst123 | Analyst (review + export) |
| viewer | viewer123 | Viewer (read only) |

---

## Project Structure

```
stratos-bep/
  accounts/          # User model with RBAC (Admin/Analyst/Viewer)
  emails/            # Core app: models, services, views
    services/
      preprocessor.py  # SPF/DKIM/DMARC + whitelist/blacklist
      checker.py       # Keywords, URLs, attachments, chain
      decider.py       # Score aggregation + verdict
      analyzer.py      # Pipeline orchestrator
      parser.py        # Gmail message parser
      gmail_connector.py
    management/commands/
      demo_setup.py    # Create demo scenario
      demo_teardown.py # Clean demo data
  threat_intel/      # TI models + sync tasks
  reports/           # Export + report models
  stratos_server/    # Django project settings
  templates/         # 10 HTML templates (light theme)
  static/            # CSS + JS
  tests/             # 351 tests across 15 files
  docs/              # Architecture, diagrams, screenshots
  docker-compose.yml
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Django models | 15 across 4 apps |
| Migrations | 26 |
| Tests | 351 (all passing) |
| Coverage (full) | 82% (1,863 statements) |
| Coverage (core) | 95%+ (analyzer 100%, decider 100%) |
| UI pages | 9 |
| API endpoints | 5 |
| Phishing keywords | 24 |
| YARA rules | 6 |
| Dangerous extensions | 13 |
| UML diagrams | 13 |
| Screenshots | 20 |

---

## Screenshots

| Page | Screenshot |
|------|-----------|
| Dashboard | ![Dashboard](docs/screenshots/14-dashboard-with-data.png) |
| Email Detail | ![Email Detail](docs/screenshots/15-email-detail-malicious.png) |
| Quarantine | ![Quarantine](docs/screenshots/17-quarantine-pending.png) |
| Threat Intel | ![Threat Intel](docs/screenshots/18-threat-intel-stats.png) |

---

## Management Commands

```bash
python manage.py demo_setup          # Full demo scenario (10 emails, TI data, users)
python manage.py demo_setup --flush  # Clear and recreate
python manage.py demo_teardown       # Remove demo data, keep users
python manage.py sync_ti_feeds       # Manual TI feed sync
python manage.py fetch_emails        # Manual Gmail fetch
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/emails/` | Paginated email list (filterable) |
| GET | `/api/emails/<pk>/` | Email detail with full analysis |
| GET | `/api/quarantine/` | Quarantine entries |
| POST | `/api/quarantine/<pk>/action/` | Release / block / delete |
| GET | `/api/dashboard/stats/` | Dashboard statistics JSON |

All endpoints require authentication (Session or Token).

---

## Academic Context

- **University:** Westminster International University in Tashkent (WIUT)
- **Degree:** BSc (Hons) Business Information Systems
- **Module:** 6BUIS007C-n (Business Information Systems Project)
- **Inspired by:** Group-IB Business Email Protection

---

## License

This project was developed as an academic submission. Copyright belongs to the University of Westminster per BISP handbook Section 4, Appendix 3.
