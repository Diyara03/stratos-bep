# ADR-006: Django Templates Over Single-Page Application

## Status: Accepted

## Date: 2026-04-09

## Context

Phase 6 requires a dashboard UI for the Stratos BEP platform. The UI needs 5 pages: dashboard, email list, email detail (with tabs), quarantine management, and login. Two main approaches were considered:

1. **Single-Page Application (SPA)**: React, Vue, or similar framework consuming the Phase 5 REST API
2. **Django server-side templates**: Django's built-in template engine with vanilla JavaScript for interactivity

The project has one developer, a 6-month timeline, and the locked tech stack specifies "Django templates + vanilla JS + Inter font". The Phase 5 REST API already exists at /api/ and remains available for any future frontend migration.

## Decision

Use Django server-side rendered templates with vanilla JavaScript for all UI interactivity.

Separate the template view URL patterns into `emails/template_urls.py` (app_name='ui') to coexist with the existing API routes in `emails/urls.py` (app_name='emails') without namespace collisions.

## Consequences

### Positive
- Zero additional dependencies (no Node.js, no webpack/vite, no npm packages)
- Native integration with Django's auth system (@login_required, CSRF tokens, flash messages)
- Single language/framework for the entire stack (Python/Django) simplifies debugging and testing
- No separate build step -- templates are served directly by Django
- Faster development for 5 pages than scaffolding a full SPA project
- The REST API (Phase 5) remains functional and unchanged for external integrations or future SPA migration

### Negative
- Limited client-side interactivity compared to a reactive framework
- Full page reloads on navigation (mitigated by fast Django response times)
- Tab switching implemented via vanilla JS rather than component state management
- No client-side routing -- each page requires a server round trip

### Neutral
- Two URL configuration files (template_urls.py and urls.py) add slight structural complexity but clearly separate concerns
- Screenshots captured from server-rendered pages are identical to what users will see (no hydration/loading states)

## Alternatives Considered

1. **React SPA**: Would require Node.js toolchain, webpack config, npm dependencies, and separate deployment. Overkill for 5 pages. Would double the testing surface.
2. **HTMX**: Lighter than SPA but adds a dependency and a different interaction paradigm. The UI's interactivity needs (tabs, flash messages) are simple enough for vanilla JS.
3. **Alpine.js**: Minimal reactive framework. Considered but rejected because the JS requirements are so simple (4 features) that a 10KB library adds complexity without meaningful benefit.
