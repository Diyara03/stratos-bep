# ADR-002: Defer weasyprint to Phase 7

## Status
Accepted

## Date
2026-04-08

## Phase
Phase 0 -- Environment + Infrastructure

## Context
The Phase 0 spec (OQ-4) originally listed `weasyprint==60.2` in `requirements.txt`. WeasyPrint is a PDF generation library needed for the reports app (Phase 7 -- Quarantine + Reports). However, it requires heavy system dependencies: Pango, GDK-Pixbuf, Cairo, and their development headers. These add significant build time and image size to the Docker container.

PDF report generation is not needed until Phase 7. Including weasyprint in Phase 0 would:
- Increase Docker image build time by several minutes
- Add ~200MB of system dependencies to the image
- Introduce potential build failures on platforms where these libraries are harder to install
- Provide zero functionality until Phase 7

## Decision
Remove `weasyprint==60.2` from `requirements.txt` in Phase 0. Add it back in Phase 7 along with the required system dependencies in the Dockerfile.

## Consequences

### Positive
- Docker image is smaller and faster to build in Phases 0-6
- Fewer potential build failures during early development
- Requirements file only contains packages that are actually used or will be used soon
- Follows YAGNI (You Aren't Gonna Need It) principle

### Negative
- Phase 7 will require a Dockerfile modification to add system dependencies
- The requirements.txt diff in Phase 7 will be larger than if weasyprint were already present

## Alternatives Considered
1. **Include weasyprint now**: Rejected -- bloats image for 7 phases with no benefit
2. **Use a different PDF library (e.g., reportlab)**: Deferred -- weasyprint is specified in the tech stack; if it causes issues in Phase 7, this can be revisited
3. **Use a separate Docker stage for reports**: Over-engineering for a BISP project
