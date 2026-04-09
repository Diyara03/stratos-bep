# ADR-007: Streaming Export via HttpResponse (No Disk Write)

## Status: Accepted

## Date: 2026-04-09

## Context

Phase 7 adds CSV and JSON export functionality for email summaries, IOC lists, and TI statistics. The exports need to support datasets of potentially thousands of records. The standard approaches are:

1. Write a temporary file to disk, serve it, then clean up.
2. Generate the file in memory (BytesIO/StringIO), serve from buffer.
3. Stream directly to HttpResponse using csv.writer with the response as the file-like object.

The system also needs an audit trail of all export actions for compliance.

## Decision

Use Django HttpResponse as the file-like object for csv.writer (CSV exports) and json.dumps for JSON exports. No temporary files are written to disk. Audit trail is maintained via Report and IOCExport model records that log the export metadata (user, timestamp, format, filters, record count) without storing the actual file content.

For large querysets, use QuerySet.iterator() to prevent loading the entire result set into memory.

## Consequences

### Positive
- No temporary file cleanup logic needed (no orphaned files, no cron jobs)
- No disk space management for export files
- No security risk from sensitive email data in temporary files
- Simpler code: csv.writer(response) is the Django-recommended pattern
- Audit log captures who exported what, when, with which filters
- Memory-efficient: iterator() streams rows without full materialization

### Negative
- Cannot resume a failed download (no stored file to re-serve)
- Large exports could time out on very slow connections (mitigated: BISP scope is <10,000 emails)
- Audit record does not contain the actual exported data (by design -- reduces storage, avoids duplicating sensitive data)

## Alternatives Considered

1. **Disk-based temp files**: Rejected -- adds cleanup complexity, security risk with sensitive data on disk, unnecessary for BISP scale.
2. **In-memory BytesIO buffer**: Rejected -- materializes entire export in memory before serving. Worse than streaming for large datasets.
3. **Celery task + file storage**: Rejected -- over-engineered for BISP scope. Appropriate for enterprise-scale exports (100K+ records) but adds significant complexity.
4. **weasyprint PDF export**: Deferred since Phase 0 (ADR-002). CSV and JSON are sufficient for BISP requirements.
