# ADR-003: Deduplication by gmail_id Instead of message_id

## Status
Accepted

## Date
2026-04-08

## Context
The email ingestion pipeline polls Gmail every 10 seconds. Each poll returns
up to 10 INBOX messages. We need to prevent reprocessing of already-ingested
emails. Two candidate keys exist for deduplication:

1. `message_id` -- the RFC 5322 Message-ID header (e.g., `<abc@example.com>`)
2. `gmail_id` -- Google's internal message identifier (e.g., `18dfa3b2c4e5f6a7`)

## Decision
Use `gmail_id` as the deduplication key in `GmailConnector.fetch_new_emails()`.
The connector checks `Email.objects.filter(gmail_id=msg_id).exists()` before
fetching the full message payload. The `gmail_id` field has `unique=True` and
`db_index=True` constraints (migration 0002).

## Consequences
- **Positive**: gmail_id is guaranteed unique by Google. Message-ID headers
  can be spoofed, missing, or duplicated across different messages (especially
  in phishing emails). Using gmail_id eliminates false dedup matches.
- **Positive**: Avoids an expensive full-message fetch for already-known emails.
  The list call returns gmail_ids cheaply; the full get call is only made for new IDs.
- **Negative**: Ties dedup to Google's identifier, making the connector
  Gmail-specific. If a different email source is added later, a separate dedup
  strategy would be needed.

## Alternatives Considered
- **message_id dedup**: Rejected because Message-ID can be spoofed or absent.
- **Content hash dedup**: Rejected as too expensive -- requires fetching the
  full message before dedup can occur.
