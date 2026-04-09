# ADR-001: Use python-magic-bin instead of python-magic

## Status
Accepted

## Date
2026-04-08

## Phase
Phase 0 -- Environment + Infrastructure

## Context
The Phase 0 spec (OQ-1) listed `python-magic==0.4.27` as a dependency for MIME type detection via magic bytes (used in Phase 4 attachment checking). `python-magic` requires the `libmagic` system library to be installed on the host. On Linux (including Docker), this is straightforward (`apt-get install libmagic1`). On Windows, `libmagic` is not natively available, requiring either WSL, manual DLL installation, or a different package.

Local development on Windows is a project requirement -- the developer's primary machine runs Windows 11.

## Decision
Replace `python-magic==0.4.27` with `python-magic-bin==0.4.14` in `requirements.txt`. The Dockerfile continues to install `libmagic1` as a system dependency for the Linux container environment.

## Consequences

### Positive
- Local development on Windows works without WSL or manual library installation
- The package bundles `libmagic` as a pre-compiled wheel, so `pip install` is self-contained
- API is compatible with `python-magic` -- no code changes needed in future phases
- Docker image still has native `libmagic1` for optimal performance in containers

### Negative
- `python-magic-bin` lags slightly behind `python-magic` in version (0.4.14 vs 0.4.27)
- Bundled library may be slightly slower than system-native on Linux (irrelevant in Docker where system lib is available)

## Alternatives Considered
1. **Keep python-magic, require WSL for local dev**: Rejected -- adds friction to development workflow
2. **Keep python-magic, install libmagic DLL manually on Windows**: Rejected -- fragile, hard to document
3. **Conditional requirements (python-magic on Linux, python-magic-bin on Windows)**: Rejected -- adds complexity to requirements management for minimal benefit
