# Relay HTTP API & CLI Reference

## Base URLs

- Default Server: `http://localhost:8080`
- API Route Prefix: `/api/v1`

---

## 1. Endpoints Overview

| Method | Path | Description | Auth |
|---|---|---|---|
| `GET` | `/health/live` | Liveness health check | None |
| `GET` | `/health/ready` | Readiness health check | None |
| `POST` | `/api/v1/links` | Create capability-governed short link | None |
| `GET` | `/{slug}` | Fast-path link resolution and redirection | None |

---

## 2. Health Probes

### GET `/health/live`
Confirms the HTTP server is alive and receiving traffic.

- **Status Code**: `200 OK`
- **Response**:
```json
{
  "status": "live"
}
```

### GET `/health/ready`
Confirms the application is ready to accept user connections.

- **Status Code**: `200 OK`
- **Response**:
```json
{
  "status": "ready"
}
```

---

## 3. Create Short Link

### POST `/api/v1/links`

Creates a new link for a destination URL with optional capability rules (expiration, maximum clicks, custom slug, fallback redirect, query parameter preservation).

#### Headers
```http
Content-Type: application/json
```

#### Request Schema

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination_url` | string | **Yes** | — | Target URL to redirect to. |
| `slug` | string | No | Auto 6-char | Custom path handle. Must be unique per domain. |
| `hostname` | string | No | Default host | Domain hostname to associate the slug with. |
| `redirect_code` | int | No | `302` | HTTP status code for redirection (`301`, `302`, `307`, `308`). |
| `preserve_query` | boolean | No | `false` | Whether to forward incoming URL query params to the destination. |
| `expires_at` | RFC3339 timestamp | No | `null` | Future timestamp after which the link becomes inaccessible. |
| `max_accesses` | integer | No | `null` | Maximum access count before the link is deactivated. |
| `fallback_url` | string | No | `null` | Alternative URL to redirect to if expired or max accesses exceeded. |

#### Request Example (Basic)
```json
{
  "destination_url": "https://news.ycombinator.com"
}
```

#### Request Example (Advanced Capabilities)
```json
{
  "destination_url": "https://example.com/promo-target",
  "slug": "promo2026",
  "redirect_code": 307,
  "preserve_query": true,
  "expires_at": "2026-11-01T00:00:00Z",
  "max_accesses": 50,
  "fallback_url": "https://example.com/expired-offer"
}
```

#### Response (201 Created)
```json
{
  "link_id": "7f0980aa-eb53-4bfd-a169-c6e7a27eb41a",
  "resource_id": "3bead70c-ce3b-4ce1-8f55-154dfdae1635",
  "slug": "promo2026",
  "url": "http://localhost:8080/promo2026",
  "destination_url": "https://example.com/promo-target",
  "expires_at": "2026-11-01T00:00:00Z",
  "created_at": "2026-10-10T11:20:00.123456Z"
}
```

#### Error Responses

- **400 Bad Request**:
  - Malformed JSON payload.
  - Missing `destination_url`.
- **409 Conflict**:
  ```json
  {
    "error": "slug already in use"
  }
  ```
- **500 Internal Server Error**:
  ```json
  {
    "error": "database or internal execution failure message"
  }
  ```

---

## 4. Resolve & Redirect

### GET `/{slug}`

Resolves the short link and triggers the HTTP redirect. Access event is recorded in the asynchronous analytics buffer.

#### Headers Handled
- `Host`: Used to match against configured `domains.hostname`.
- `X-Forwarded-For`: Used to extract and anonymize client IP.
- `User-Agent`: Recorded for browser/device analytics.
- `Referer`: Recorded for traffic source analytics.

#### Query Parameter Forwarding
When `preserve_query: true` is configured:
- Incoming: `GET /promo2026?source=newsletter&utm_medium=email`
- Redirect Destination: `https://example.com/promo-target?source=newsletter&utm_medium=email`
- Existing query parameters on the destination are merged using `&`.

#### Responses
- **301 / 302 / 307 / 308 (Redirect)**:
  - Header: `Location: <destination_url>`
- **302 Found (Fallback)**:
  - If expired or max accesses exceeded AND `fallback_url` is configured.
  - Header: `Location: <fallback_url>`
- **404 Not Found**:
  - Slug does not exist.
  - Slug exists but resource is expired, revoked, or max accesses exceeded (and no `fallback_url` is set).

---

## 5. CLI Reference (`relayctl`)

### Global Usage
```bash
relayctl <command> [options]
```

### Commands

#### `relayctl server`
Runs the HTTP service daemon.

```bash
relayctl server [--port=8080] [--db=relay.db] [--base-url=http://localhost:8080]
```

- `--port`: Port number to listen on (default: `8080`, env: `PORT`).
- `--db`: SQLite database file path (default: `relay.db`, env: `DATABASE_PATH`).
- `--base-url`: Default public base URL used in generated link responses (default: `http://localhost:<port>`).

#### `relayctl shorten`
Creates a shortened redirect link via a running Relay server.

```bash
relayctl shorten <destination_url> [options]
```

**Options**:
- `--slug=<custom>`: Custom slug name.
- `--endpoint=<url>`: Relay server address (default: `http://localhost:8080`).
- `--expire=<duration>`: Link expiration duration (`1h`, `24h`, `7d`).
- `--max=<number>`: Maximum number of allowed accesses (e.g., `--max=1` for single-use link).

**Examples**:
```bash
# Auto slug
relayctl shorten https://golang.org

# Expiring link
relayctl shorten https://secret.corp.internal --expire=1h --max=1

# Output
http://localhost:8080/aX7bQ9
```
