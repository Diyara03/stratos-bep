# SPEC: Phase 0 — Django Project Scaffold + Docker Compose

## Goal

Stand up a working Django project with four apps, a custom User model, Docker Compose orchestration of five services, and a health endpoint so that `docker compose up --build` yields all containers healthy and `GET /health/` returns 200.

## In Scope

### S-01: Django project scaffold
- Project name: `stratos_server`
- Four apps created and registered: `emails`, `accounts`, `threat_intel`, `reports`
- Each app gets `__init__.py`, `admin.py`, `apps.py`, `models.py`, `views.py`, `urls.py`, `tests.py`, and a `migrations/` directory with `__init__.py`

### S-02: Requirements file
`requirements.txt` at project root with pinned versions:
```
django==4.2.13
djangorestframework==3.14.0
psycopg2-binary==2.9.9
redis==5.0.1
celery==5.3.6
google-api-python-client==2.111.0
google-auth-oauthlib==1.2.0
python-magic==0.4.27
yara-python==4.3.1
requests==2.31.0
Pillow==10.2.0
weasyprint==60.2
coverage==7.4.0
python-dotenv==1.0.0
```

### S-03: Settings split
- `stratos_server/settings/` package with `__init__.py`, `base.py`, `dev.py`, `prod.py`
- `base.py`: all shared config (INSTALLED_APPS, AUTH_USER_MODEL, middleware, REST_FRAMEWORK, CELERY settings, TEMPLATES, static files, CLEAN_THRESHOLD/MALICIOUS_THRESHOLD from env)
- `dev.py`: imports base, DEBUG=True, SQLite fallback when DATABASE_URL is unset, ALLOWED_HOSTS=['*']
- `prod.py`: imports base, DEBUG=False, PostgreSQL via DATABASE_URL, ALLOWED_HOSTS from env
- Default `DJANGO_SETTINGS_MODULE=stratos_server.settings.dev` in `.env.example`

### S-04: Custom User model
In `accounts/models.py`:
```
class User(AbstractUser):
    ROLE_CHOICES = [('ADMIN','Admin'),('ANALYST','Analyst'),('VIEWER','Viewer')]
    role = CharField(max_length=10, choices=ROLE_CHOICES, default='VIEWER')
    department = CharField(max_length=100, blank=True)
    last_login_ip = GenericIPAddressField(null=True, blank=True)
    class Meta:
        db_table = 'stratos_user'
```
`AUTH_USER_MODEL = 'accounts.User'` must be set in `base.py` BEFORE any migration is created.

### S-05: Health endpoint
- URL: `GET /health/`
- View: a simple function view in `stratos_server/views.py` (project-level, not inside any app)
- Response: `{"status": "ok", "version": "0.1.0", "db": "connected"}` with status 200
- The view must actually test the database connection and return `"db": "unavailable"` with status 503 if the database is unreachable
- Wired in `stratos_server/urls.py`

### S-06: Docker Compose
`docker-compose.yml` at project root with five services:

| Service      | Image                  | Ports        | Healthcheck                                        |
|------------- |------------------------|------------- |----------------------------------------------------|
| postgres     | postgres:15-alpine     | 5432:5432    | `pg_isready -U stratos`                            |
| redis        | redis:7-alpine         | 6379:6379    | `redis-cli ping`                                   |
| django       | build from Dockerfile  | 8000:8000    | `curl -f http://localhost:8000/health/ \|\| exit 1` |
| celery       | build from Dockerfile  | none         | `celery -A stratos_server inspect ping`            |
| celery-beat  | build from Dockerfile  | none         | `celery -A stratos_server inspect ping`            |

- `django` depends on `postgres` (healthy) and `redis` (healthy)
- `celery` and `celery-beat` depend on `django` (healthy)
- All services share a `.env` file
- Named volume `postgres_data` for PostgreSQL persistence

### S-07: Dockerfile
- Base: `python:3.10-slim`
- System deps: `libmagic1`, `build-essential`, `curl` (for healthcheck), any packages needed for `yara-python` compilation (`automake`, `libtool`, `libssl-dev`, `pkg-config`)
- `pip install --no-cache-dir -r requirements.txt`
- Copy project into `/app`
- Working directory: `/app`
- Expose port 8000
- CMD: `python manage.py runserver 0.0.0.0:8000` (dev; prod would use gunicorn but that is out of scope)

### S-08: Environment file
`.env.example` at project root with every variable and sane defaults:
```
DJANGO_SETTINGS_MODULE=stratos_server.settings.dev
SECRET_KEY=change-me-in-production
DEBUG=True
ALLOWED_HOSTS=*

# PostgreSQL
POSTGRES_DB=stratos
POSTGRES_USER=stratos
POSTGRES_PASSWORD=stratos_dev_pw
DATABASE_URL=postgresql://stratos:stratos_dev_pw@postgres:5432/stratos

# Redis
REDIS_URL=redis://redis:6379/0

# Gmail API (Phase 2)
GMAIL_CREDENTIALS_PATH=credentials/credentials.json
GMAIL_TOKEN_PATH=credentials/token.json

# Threat Intel API keys (Phase 5)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# Scoring thresholds
CLEAN_THRESHOLD=25
MALICIOUS_THRESHOLD=70
```

### S-09: .gitignore
At project root. Must include at minimum:
```
.env
credentials/
*.pyc
__pycache__/
venv/
db.sqlite3
*.egg-info/
dist/
build/
.pytest_cache/
htmlcov/
postgres_data/
```

### S-10: Celery configuration
`stratos_server/celery.py`:
- Celery app named `stratos_server`
- Autodiscover tasks from all registered apps
- Broker: `REDIS_URL` from env
- Result backend: `REDIS_URL` from env
- `stratos_server/__init__.py` must import the Celery app so Django loads it

## Out of Scope

- Email, EmailAttachment, AnalysisResult, QuarantineEntry, ExtractedIOC models (Phase 1)
- Any threat_intel or reports models (Phase 1)
- Gmail API credentials or ingestion logic (Phase 2)
- Analysis pipeline: preprocessor, checker, decider (Phases 3-5)
- Frontend templates, static files, or any HTML (Phase 6)
- Gunicorn or production web server configuration
- CI/CD pipeline
- SSL/TLS or HTTPS configuration
- Nginx reverse proxy
- Any YARA rule files (Phase 4)
- Management commands beyond Django defaults
- API authentication or permissions (Phase 5)
- Any model beyond the custom User model

## Acceptance Criteria

| ID     | Criterion                                                                                              | Pass Condition                                                                                 |
|--------|--------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| AC-001 | `python manage.py migrate` completes without errors and leaves zero unapplied migrations               | Exit code 0 and `python manage.py showmigrations` shows no `[ ]` entries                      |
| AC-002 | `python manage.py check` reports no issues                                                             | Output contains `System check identified no issues`                                            |
| AC-003 | `GET /health/` returns HTTP 200 with JSON body containing `"status": "ok"`                             | `curl -s http://localhost:8000/health/` returns 200 and body matches                           |
| AC-004 | `docker compose up --build` brings all 5 containers to healthy state                                   | `docker compose ps` shows all 5 services with status `healthy` or `running`                    |
| AC-005 | `AUTH_USER_MODEL` is set to `'accounts.User'` in `base.py`                                             | `grep AUTH_USER_MODEL stratos_server/settings/base.py` returns `accounts.User`                 |
| AC-006 | `python manage.py createsuperuser` works with the custom User model and the `role` field is accessible | Superuser created, `User.objects.get(username=...).role` returns `'VIEWER'` (the default)      |
| AC-007 | All 4 Django apps are registered in INSTALLED_APPS                                                     | `python -c "from django.apps import apps; print([a.name for a in apps.get_app_configs()])"` includes emails, accounts, threat_intel, reports |
| AC-008 | `.env.example` exists and contains all required variables                                              | File exists and contains SECRET_KEY, DATABASE_URL, REDIS_URL, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, CLEAN_THRESHOLD, MALICIOUS_THRESHOLD |
| AC-009 | Celery worker can connect to Redis broker                                                              | `celery -A stratos_server inspect ping` returns a pong response inside Docker                  |
| AC-010 | Settings split is functional: `dev.py` and `prod.py` both importable without error                     | `python -c "import stratos_server.settings.dev"` and `python -c "import stratos_server.settings.prod"` both exit 0 |

## API Contracts

### GET /health/

**Purpose:** Liveness and readiness probe for Docker healthcheck and monitoring.

**Authentication:** None (public endpoint).

**Request:**
```
GET /health/ HTTP/1.1
Host: localhost:8000
Accept: application/json
```
No query parameters. No request body.

**Response — 200 OK (database reachable):**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "db": "connected"
}
```
Headers: `Content-Type: application/json`

**Response — 503 Service Unavailable (database unreachable):**
```json
{
  "status": "degraded",
  "version": "0.1.0",
  "db": "unavailable"
}
```
Headers: `Content-Type: application/json`

**Implementation notes:**
- The view must execute a lightweight DB query (e.g., `connection.ensure_connection()`) to verify connectivity.
- This is a plain Django view using `JsonResponse`, NOT a DRF view. DRF is installed but not used in this phase.

## Data Model Changes

### New model: `accounts.User`

| Field           | Type                    | Constraints                                                    |
|-----------------|-------------------------|----------------------------------------------------------------|
| (inherited)     | AbstractUser fields     | username, email, first_name, last_name, password, is_staff, etc.|
| role            | CharField(max_length=10)| choices=[ADMIN, ANALYST, VIEWER], default='VIEWER'             |
| department      | CharField(max_length=100)| blank=True                                                    |
| last_login_ip   | GenericIPAddressField   | null=True, blank=True                                          |

Table name: `stratos_user`

This is the ONLY model created in Phase 0. All other models are Phase 1.

## File Manifest

Every file to be created in this phase, listed by path relative to project root:

```
Stratos/
  .env.example
  .gitignore
  requirements.txt
  Dockerfile
  docker-compose.yml
  manage.py
  stratos_server/
    __init__.py              # imports Celery app
    celery.py                # Celery configuration
    urls.py                  # project URL conf, includes /health/
    views.py                 # health endpoint view
    wsgi.py
    asgi.py
    settings/
      __init__.py
      base.py                # shared settings, AUTH_USER_MODEL, INSTALLED_APPS
      dev.py                 # DEBUG=True, SQLite fallback
      prod.py                # DEBUG=False, PostgreSQL
  accounts/
    __init__.py
    admin.py                 # register User with default ModelAdmin
    apps.py                  # AccountsConfig
    models.py                # Custom User model
    urls.py                  # empty, placeholder
    views.py                 # empty, placeholder
    tests.py                 # empty, placeholder
    migrations/
      __init__.py
      0001_initial.py        # generated by makemigrations
  emails/
    __init__.py
    admin.py
    apps.py                  # EmailsConfig
    models.py                # empty (Phase 1)
    urls.py
    views.py
    tests.py
    migrations/
      __init__.py
  threat_intel/
    __init__.py
    admin.py
    apps.py                  # ThreatIntelConfig
    models.py                # empty (Phase 1)
    urls.py
    views.py
    tests.py
    migrations/
      __init__.py
  reports/
    __init__.py
    admin.py
    apps.py                  # ReportsConfig
    models.py                # empty (Phase 1)
    urls.py
    views.py
    tests.py
    migrations/
      __init__.py
```

Total new files: ~38

## Dependencies

This is Phase 0. There are no prior-phase dependencies.

**External dependencies required on host machine for local (non-Docker) development:**
- Python 3.10+
- PostgreSQL 15+ (or SQLite for dev.py fallback)
- Redis 7+ (or skip Celery in local dev)
- Docker and Docker Compose v2

## Open Questions

| ID   | Question                                                                                              | Impact                                                        |
|------|-------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| OQ-1 | Should `python-magic` use `python-magic-bin` on Windows instead of `python-magic`? The latter requires `libmagic` system library which is Linux-native. | Dockerfile handles Linux; local Windows dev may need `python-magic-bin` or WSL. Implementer should document this. |
| OQ-2 | Should `yara-python==4.3.1` be installed via pip or built from source in Docker? Pip wheel availability varies by platform. | May need to add `yara` system package or build from source in Dockerfile. Implementer must verify the Dockerfile builds cleanly. |
| OQ-3 | Should the Django dev server (`runserver`) be used as the Docker CMD, or should we include `gunicorn` in requirements now? | Spec says `runserver` for Phase 0. Gunicorn can be added in a later phase if needed for production. |
| OQ-4 | Is `weasyprint==60.2` needed in Phase 0 requirements, given it has heavy system dependencies (Pango, GDK-Pixbuf, etc.) and reports are Phase 7? | Including it now means the Dockerfile must install those system deps. Could defer to Phase 7 to keep the image smaller. Human decision needed. |

## Test Plan

The qa-agent should verify the following after implementation:

### Unit tests (run locally or in Docker)
1. **Health endpoint test:** `django.test.Client().get('/health/')` returns status 200 and JSON with keys `status`, `version`, `db`.
2. **Custom User creation test:** Create a User via `User.objects.create_user(username='test', password='test')`, assert `role == 'VIEWER'` and `department == ''`.
3. **Custom User role test:** Create a User with `role='ADMIN'`, assert stored value is `'ADMIN'`.
4. **Settings import test:** Both `stratos_server.settings.dev` and `stratos_server.settings.prod` import without raising exceptions.
5. **INSTALLED_APPS test:** Assert all four apps (`emails`, `accounts`, `threat_intel`, `reports`) and `rest_framework` are in `INSTALLED_APPS`.
6. **AUTH_USER_MODEL test:** Assert `settings.AUTH_USER_MODEL == 'accounts.User'`.

### Integration tests (require Docker)
7. **Docker build test:** `docker compose build` exits with code 0.
8. **Docker up test:** `docker compose up -d` followed by polling until all 5 services report healthy (timeout: 120 seconds).
9. **Health endpoint via Docker:** `curl http://localhost:8000/health/` from host returns 200.
10. **Celery ping test:** `docker compose exec celery celery -A stratos_server inspect ping` returns a pong.
11. **Superuser creation test:** `docker compose exec django python manage.py createsuperuser --noinput` with `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_PASSWORD`, `DJANGO_SUPERUSER_EMAIL` env vars succeeds.

### Static checks
12. **System check:** `python manage.py check` outputs `System check identified no issues`.
13. **Migration check:** `python manage.py showmigrations` shows no unapplied migrations (all marked `[X]`).
14. **File existence check:** All files in the File Manifest above exist on disk.
