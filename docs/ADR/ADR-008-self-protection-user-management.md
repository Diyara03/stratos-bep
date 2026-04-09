# ADR-008: Self-Protection in User Management

## Status: Accepted

## Date: 2026-04-09

## Context

Phase 7 adds a user management page where ADMIN users can change roles and activate/deactivate accounts. Without safeguards, an admin could accidentally:

1. Demote themselves from ADMIN to VIEWER, losing access to the admin pages.
2. Deactivate their own account, locking themselves out entirely.

In both cases, recovery would require direct database access or Django shell, which may not be available during the viva demo.

## Decision

All mutating user management views (edit-role, toggle-active) compare the target user against the requesting user (`target == request.user`). If they match, the action is rejected with an error flash message and a redirect back to the user list. The user is never modified.

## Consequences

### Positive
- Prevents accidental admin lockout during viva or production use
- Standard pattern in enterprise identity management (Azure AD, Okta, AWS IAM all prevent self-demotion)
- Simple implementation: single equality check, no additional models or flags
- User gets immediate feedback via flash message explaining why the action was blocked

### Negative
- An admin who genuinely needs to change their own role must ask another admin to do it
- If there is only one admin in the system, they cannot be demoted (this is the correct behavior)

## Alternatives Considered

1. **No protection**: Rejected -- too high a risk of accidental lockout, especially during live demo.
2. **Confirmation dialog only**: Rejected -- a JavaScript confirm() dialog is insufficient for a security-critical action. Server-side enforcement is required.
3. **Require password re-entry**: Considered but over-engineered for BISP scope. The equality check is sufficient.
