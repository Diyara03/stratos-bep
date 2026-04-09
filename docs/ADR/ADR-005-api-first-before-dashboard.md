# ADR-005: Build REST API Before Dashboard UI (API-First)

## Status: Accepted

## Date: 2026-04-08

## Context

Phase 5 implements the REST API (5 endpoints) and Phase 6 will build the dashboard UI. The question is whether to build the API independently of the UI or to build them together. The API serves as the data layer for the dashboard and potentially for external integrations.

## Decision

Build the complete REST API in Phase 5 (with the Decider and TI sync), before any dashboard UI work in Phase 6. The API endpoints are fully functional and tested with DRF's built-in browsable API and automated tests using APIClient.

Key design choices:
- Session + Token authentication (DRF defaults) -- Session for browser-based dashboard, Token for CLI/automation
- IsAnalystOrAbove custom permission for quarantine actions (ADMIN/ANALYST only, VIEWER rejected with 403)
- Nested serializers for email detail (analysis result + attachments in one request)
- DashboardStatsView aggregates all counts in a single endpoint (7 COUNT + 2 MAX queries)
- Pagination at 25 items/page via PageNumberPagination

## Consequences

**Positive:**
- API contract is stable and tested before UI depends on it
- Frontend (Phase 6) can develop against a known, working API
- API is independently useful for automation, scripting, external tools
- Browsable API serves as interim data inspection tool before dashboard

**Negative:**
- No visual interface until Phase 6 (admin panel and browsable API are the interim tools)

## Alternatives Considered

1. **Build API and UI simultaneously**: Faster to see results but risks unstable API contract as UI requirements emerge. Rejected because spec-first workflow requires stable contracts.

2. **Skip API, render directly in Django templates**: Simpler but couples data access to HTML rendering, making future API consumers (CLI tools, mobile) impossible without refactoring. Rejected for extensibility reasons.
