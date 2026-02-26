# API Contracts (Frozen v1)

This document freezes cross-repo endpoint contracts so `Sitebuilder1.0`, `ai-webadmin-plugin`, and control-plane services can evolve independently.

## Versioning Rules
- Contract namespace remains path-based (`/q1/*`, `/plugin/*`, `/inspect*`).
- Non-breaking additions allowed: optional request fields, optional response fields.
- Breaking changes require a new endpoint version path (for example `/plugin/v2/...`) and deprecation window.

## Security Baseline
- No plaintext provider credentials in application DB records.
- Plugin-signed endpoints require:
  - `X-Plugin-Timestamp`
  - `X-Plugin-Signature` (`HMAC-SHA256(secret, "${timestamp}.${rawBody}")`)
  - replay window: 5 minutes.
- Access profile payloads reject plaintext passwords.

## Onboarding (`/q1/*`)

### `POST /q1/start`
Starts onboarding session.

Request (minimum):
```json
{ "first_name": "string", "last_name": "string", "turnstile_token": "string" }
```

Response (minimum):
```json
{ "ok": true, "user_id": "usr_*", "session_id": "ses_*", "next_state": "Q1_DESCRIBE", "prompt": "..." }
```

### `POST /q1/answer`
Advances state machine.

Request (minimum):
```json
{ "session_id": "ses_*", "state": "STATE", "answer": "..." }
```

Response:
```json
{ "ok": true, "prompt": "...", "next_state": "STATE" }
```

### `POST /q1/scan/start`
Starts inspector-backed scan for a session.

Request:
```json
{ "session_id": "ses_*", "url": "https://example.com" }
```

Response:
```json
{ "ok": true, "session_id": "ses_*", "target_url": "https://example.com", "scan": { "status": "running|done", "request_id": "scan_*" } }
```

### `GET /q1/scan/status?session_id=...`
Reads latest scan status/result bridge.

Response:
```json
{ "ok": true, "session_id": "ses_*", "status": "none|running|done|failed", "result": {} }
```

## Plugin (`/plugin/*`)

### Unsigned onboarding
- `POST /plugin/connect/start`
- `POST /plugin/connect/verify`

### Signed WordPress endpoints
- `POST /plugin/wp/comments/moderate`
- `POST /plugin/wp/audit/sync`
- `POST /plugin/wp/access/profile`
- `POST /plugin/wp/email/forward/config`
- `POST /plugin/wp/lead/forward`
- `POST /plugin/wp/schema/profile`
- `POST /plugin/wp/redirects/profile`
- `POST /plugin/wp/github/vault`
- `POST /plugin/wp/backup/snapshot`
- `POST /plugin/wp/auth/wallet/verify`

#### `POST /plugin/wp/comments/moderate`
Request:
```json
{ "site_url": "https://example.com", "comment_id": 123, "content": "..." }
```

Response:
```json
{ "ok": true, "action": "keep|hold|spam|trash", "wp_status": "approve|hold|spam|trash", "confidence": 0.0, "reason": "..." }
```

#### `POST /plugin/wp/schema/profile`
Request:
```json
{ "session_id": "ses_*", "site_url": "https://example.com" }
```

Response:
```json
{ "ok": true, "session_id": "ses_*", "schema_status": "not_started|in_progress|ready", "schema_profile": {}, "schema_jsonld": "..." }
```

#### `POST /plugin/wp/redirects/profile`
Request:
```json
{ "session_id": "ses_*", "site_url": "https://example.com" }
```

Response:
```json
{ "ok": true, "session_id": "ses_*", "checked_link_count": 0, "broken_link_count": 0, "redirect_paths": ["/broken-path"] }
```

## Inspector (`/inspect*`)

### `POST /inspect`
Request:
```json
{ "session_id": "ses_*", "url": "https://example.com", "request_id": "optional" }
```

Response:
```json
{ "ok": true, "request_id": "scan_*", "status": "done", "result": {} }
```

### `GET /inspect/status?session_id=...`
Response:
```json
{ "ok": true, "request": {}, "result": {} }
```

### `POST /market/nearby`
Request:
```json
{ "session_id": "ses_*", "business_type": "...", "location": "...", "intent_text": "...", "limit": 3 }
```

Response:
```json
{ "ok": true, "request_id": "market_*", "source": "...", "sites": [{ "title": "...", "url": "https://...", "snippet": "..." }] }
```
