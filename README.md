# Relay

<p align="center">
  <strong>High-performance, programmable, capability-governed redirection engine and secure sharing platform written in Go.</strong>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Design](#architecture--design)
  - [Hexagonal (Ports & Adapters) Structure](#hexagonal-ports--adapters-structure)
  - [Directory Layout](#directory-layout)
- [Key Features](#key-features)
- [Database & Schema](#database--schema)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building the Binaries](#building-the-binaries)
- [Running the Server](#running-the-server)
  - [Configuration Flags & Environment Variables](#configuration-flags--environment-variables)
- [CLI Tool (`relayctl`)](#cli-tool-relayctl)
  - [Start Server](#start-server)
  - [Shorten URLs](#shorten-urls)
- [HTTP API Reference](#http-api-reference)
  - [Health Probes](#health-probes)
  - [Create Redirect Link](#create-redirect-link)
  - [Resolve & Redirect](#resolve--redirect)
- [Testing](#testing)
- [Roadmap & Extensibility](#roadmap--extensibility)

---

## Overview

**Relay** is a URL redirection and secure link sharing service built with clean architecture in Go. Unlike traditional URL shorteners, Relay treats short links as capability-governed resource handles. Each link is backed by a resource lifecycle that enforces access limits, expirations, custom fallback policies, multi-tenant workspace/domain routing, in-memory caching, and asynchronous buffered analytics collection.

---

## Architecture & Design

Relay adheres to **Hexagonal Architecture (Ports and Adapters)**, separating domain rules and application business logic from external dependencies (HTTP frameworks, databases, and caches).

```
                      +-----------------------------+
                      |   HTTP / CLI Entrypoints    |
                      |   (cmd/relay, cmd/relayctl) |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   HTTP Handlers / Routes    |
                      |    (internal/http/handlers) |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |       Core Services         |
                      |  (internal/core/services)   |
                      +-------+--------------+------+
                              |              |
              +---------------+              +---------------+
              v                                              v
+---------------------------+                  +---------------------------+
|       Port Interfaces     |                  |       Domain Models       |
|   (internal/core/ports)   |                  |   (internal/core/domain)  |
+-------------+-------------+                  +---------------------------+
              |
      +-------+--------------------+
      |                            |
      v                            v
+----------------------+  +---------------------+  +-----------------------+
|  SQLite Repository   |  |   In-Memory Cache   |  |   Async Analytics     |
| (internal/platform/  |  | (internal/platform/ |  |  (internal/platform/  |
|       db)            |  |       cache)        |  |     analytics)        |
+----------------------+  +---------------------+  +-----------------------+
```

### Hexagonal (Ports & Adapters) Structure

1. **Domain Layer (`internal/core/domain`)**:
   - Pure domain models (`Resource`, `ResourceLink`, `RedirectResource`, `Workspace`, `Domain`, `AnalyticsEvent`).
   - Domain-level validation rules (e.g., `IsAccessible(now time.Time)` checking expiration, revocation, and access quota).
   - Zero external infrastructure dependencies.

2. **Ports Layer (`internal/core/ports`)**:
   - Defines abstract interfaces:
     - `Repository`: CRUD operations for workspaces, domains, links, resources, and analytics.
     - `Cache`: Fast lookups (`Get`, `Set`, `Delete`) for resolved links.
     - `AnalyticsBuffer`: Asynchronous event buffering (`Enqueue`, `Flush`, `Close`).

3. **Service Layer (`internal/core/services`)**:
   - `LinkService` orchestrates link generation, custom or random slug generation, access control verification, cache warming, query string preservation, and asynchronous analytics dispatch.

4. **Platform / Adapters Layer (`internal/platform`)**:
   - `db`: Modern embedded SQLite using pure-Go `modernc.org/sqlite` (no CGO required) with WAL mode, foreign key enforcement, and automated migrations via Goose.
   - `cache`: Thread-safe in-memory cache protected by `sync.RWMutex`.
   - `analytics`: Background buffered channel worker (`AsyncBuffer`) that flushes access events in configurable batches (default: 50 items or 1s interval) with client IP anonymization.

5. **Presentation Layer (`internal/http`)**:
   - Chi router (`github.com/go-chi/chi/v5`) with middleware for Request ID tracking, Real IP extraction, and panic recovery.

---

### Directory Layout

```
.
├── cmd/
│   ├── relay/              # Main HTTP server binary entrypoint
│   │   └── main.go
│   └── relayctl/           # CLI tool for management and quick shortening
│       └── main.go
├── internal/
│   ├── app/                # Application bootstrapping, configuration, and graceful shutdown
│   │   └── server.go
│   ├── core/
│   │   ├── domain/         # Core domain entities, status enums, errors
│   │   │   ├── analytics.go
│   │   │   └── resource.go
│   │   ├── ports/          # Repository, cache, and buffer interfaces
│   │   │   └── ports.go
│   │   └── services/       # Business logic (link creation and resolution)
│   │       └── link_service.go
│   ├── http/
│   │   └── handlers/       # REST API endpoints, redirect handler, health checks
│   │       ├── api.go
│   │       └── api_test.go # End-to-end HTTP integration tests
│   └── platform/
│       ├── analytics/      # Asynchronous batched analytics worker
│       │   └── buffer.go
│       ├── cache/          # In-memory thread-safe cache
│       │   └── memory.go
│       └── db/             # SQLite repository implementation & Goose migrations
│           ├── migrations/
│           │   └── 00001_initial_schema.sql
│           └── sqlite.go
├── migrations/             # Schema migration files for Goose
│   └── 00001_initial_schema.sql
├── go.mod
├── go.sum
└── README.md
```

---

## Key Features

- **Capability-Governed Access Control**:
  - Expiration timestamps (`expires_at`): Automatically expire links after a set date or duration.
  - Access quota limits (`max_accesses`): Turn any link into a one-time link (or limited *N*-use link). Once quota is reached, access is denied.
  - Revocation & Invalidation: Immediate revocation via `revoked_at` and status flags.
  - Custom Fallbacks: Configurable `fallback_url` redirect when an expired/exhausted link is visited, instead of showing a generic error.
- **Fast-Path Resolution**:
  - Thread-safe in-memory caching warm-up on write and high-hit-rate read resolution.
  - Embedded SQLite running in WAL mode with indexing on `(domain_id, slug)`.
- **Privacy-Aware Async Analytics**:
  - Background worker buffers link hits without stalling HTTP redirect latency.
  - Client IP addresses are automatically subnet-masked / anonymized (`192.168.1.0`).
  - Drains remaining buffered events cleanly on shutdown.
- **Query Parameter Preservation**:
  - Preserves incoming UTM tracking parameters, referral tags, and query strings on redirection.
- **Multi-Domain & Multi-Tenant Foundations**:
  - Links are partitioned by Workspace and Custom Domain (`hostname + slug`).
  - Automatically provisions a default workspace and domain (`localhost`) out of the box.
- **Zero CGO Dependency**:
  - Compiles to lightweight, portable static binaries using `modernc.org/sqlite`.

---

## Database & Schema

Relay uses SQLite with Goose migrations embedded directly into the binary:

```
  +---------------+        1:N       +---------------+
  |  workspaces   |<-----------------|    domains    |
  +---------------+                  +---------------+
          | 1:N                              | 1:N
          v                                  v
  +---------------+        1:N       +---------------+
  |   resources   |<-----------------| resource_links|
  +---------------+                  +---------------+
     | 1:1       | 1:N                       | 1:N
     v           v                           v
+----------+ +------------------+            |
| redirect | | analytics_events |<-----------+
|resources | +------------------+
+----------+
```

- **`workspaces`**: Tenant boundary (`id`, `name`, `slug`, `created_at`, `updated_at`).
- **`domains`**: Routing hostnames tied to a workspace (`id`, `workspace_id`, `hostname`, `is_default`, `created_at`).
- **`resources`**: Universal root entity for shareable objects (`id`, `workspace_id`, `type`, `status`, `expires_at`, `max_accesses`, `access_count`, `metadata`).
- **`resource_links`**: Slug handles pointing to a resource (`id`, `resource_id`, `domain_id`, `slug`, `enabled`, `created_at`), with unique constraint on `(domain_id, slug)`.
- **`redirect_resources`**: Destination metadata (`resource_id`, `destination_url`, `redirect_code`, `preserve_query`, `fallback_url`).
- **`analytics_events`**: Recorded access events (`id`, `link_id`, `resource_id`, `timestamp`, `ip`, `user_agent`, `referer`, `response_time_ms`).

---

## Getting Started

### Prerequisites

- [Go](https://go.dev/) 1.22+ (tested with Go 1.27)
- SQLite3 (optional, for inspecting `relay.db` directly)

### Building the Binaries

Build both the server (`relay`) and CLI (`relayctl`):

```bash
# Build Relay Server
go build -o bin/relay ./cmd/relay

# Build Relay CLI
go build -o bin/relayctl ./cmd/relayctl
```

---

## Running the Server

Start the server using `bin/relay`:

```bash
./bin/relay --port=8080 --db=relay.db --base-url=http://localhost:8080
```

Alternatively, use the CLI:

```bash
./bin/relayctl server --port=8080
```

### Configuration Flags & Environment Variables

| Flag | Environment Variable | Default | Description |
|------|----------------------|---------|-------------|
| `--port` | `PORT` | `8080` | Port for the HTTP server to listen on |
| `--db` | `DATABASE_PATH` | `relay.db` | Path to the SQLite database file |
| `--base-url` | — | `http://localhost:<port>` | Default public base URL used for link generation |

---

## CLI Tool (`relayctl`)

`relayctl` is a command-line client for starting the server and creating shortened links directly from your terminal.

### Start Server

```bash
./bin/relayctl server --port=8080 --db=relay.db
```

### Shorten URLs

```bash
# Quick shorten with auto-generated slug
./bin/relayctl shorten https://example.com/very/long/url

# Shorten with custom slug
./bin/relayctl shorten https://example.com --slug=my-link

# Shorten with an expiration time (e.g. 1h, 24h, 7d)
./bin/relayctl shorten https://example.com --expire=24h

# Shorten with maximum access count (e.g. 1-time view)
./bin/relayctl shorten https://example.com --max=1

# Specify custom Relay API endpoint
./bin/relayctl shorten https://example.com --endpoint=http://localhost:8080
```

---

## HTTP API Reference

### Health Probes

#### Liveness Probe
```http
GET /health/live
```
**Response (200 OK)**:
```json
{
  "status": "live"
}
```

#### Readiness Probe
```http
GET /health/ready
```
**Response (200 OK)**:
```json
{
  "status": "ready"
}
```

---

### Create Redirect Link

```http
POST /api/v1/links
Content-Type: application/json
```

#### Request Body
```json
{
  "destination_url": "https://docs.github.com/en",
  "slug": "gh-docs",
  "redirect_code": 302,
  "preserve_query": true,
  "expires_at": "2026-12-31T23:59:59Z",
  "max_accesses": 100,
  "fallback_url": "https://example.com/expired"
}
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `destination_url` | string | **Yes** | — | Target URL to redirect to |
| `slug` | string | No | Random 6-char | Desired custom slug |
| `hostname` | string | No | Default host | Custom domain hostname |
| `redirect_code` | int | No | `302` | HTTP redirect status code (`301`, `302`, `307`, `308`) |
| `preserve_query` | bool | No | `false` | Whether to append request query params to destination |
| `expires_at` | RFC3339 timestamp | No | `null` | Expiration time |
| `max_accesses` | int64 | No | `null` | Maximum allowed clicks before link is deactivated |
| `fallback_url` | string | No | `null` | URL redirected to if link is expired or maxed out |

#### Success Response (201 Created)
```json
{
  "link_id": "0192e4ab-1234-7000-8000-000000000001",
  "resource_id": "0192e4ab-1234-7000-8000-000000000002",
  "slug": "gh-docs",
  "url": "http://localhost:8080/gh-docs",
  "destination_url": "https://docs.github.com/en",
  "expires_at": "2026-12-31T23:59:59Z",
  "created_at": "2026-10-10T11:00:00Z"
}
```

#### Error Responses
- **400 Bad Request**: Invalid JSON request payload or empty `destination_url`.
- **409 Conflict**: `{"error": "slug already in use"}` if the requested slug already exists under the domain.

---

### Resolve & Redirect

```http
GET /{slug}
```

- When valid, returns HTTP `302 Found` (or configured redirect code) with the `Location` header set to the destination URL.
- Query parameters are appended to the destination if `preserve_query: true`.
- If link is expired, revoked, or max accesses exceeded:
  - If `fallback_url` was provided: Returns `302 Found` to the `fallback_url`.
  - If no `fallback_url` was provided: Returns `404 Not Found`.

#### Example with cURL:

```bash
# Follow redirect
curl -v -L http://localhost:8080/gh-docs

# Inspect redirect headers without following
curl -I http://localhost:8080/gh-docs?campaign=fall2026
```

---

## Testing

Run unit and integration tests across the codebase:

```bash
go test -v ./...
```

The test suite includes end-to-end integration tests (`internal/http/handlers/api_test.go`) validating:
- Database schema bootstrap and Goose migrations
- In-memory cache warming and resolution
- Query parameter forwarding (`?utm_source=chat`)
- Access quotas (`max_accesses = 1`) and subsequent 404 responses
- 404 responses for non-existent slugs

---

## Roadmap & Extensibility

Relay's architecture is designed from the ground up for multi-resource sharing. The underlying domain model supports extending beyond redirect links:
- `ResourceTypeSecret`: Ephemeral one-time secrets and encrypted credentials.
- `ResourceTypeFile`: Capability-governed file downloads with expiring download tokens.
- `ResourceTypePayload`: Ephemeral encrypted JSON payload exchange.
- `ResourceTypeRequest`: Drop-box / reverse collection links.
