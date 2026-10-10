# Relay Architecture & Design Specification

## 1. System Philosophy

Relay is designed as a **programmable, capability-governed redirection engine**. Traditional shorteners treat a short link merely as a row in a key-value store mapping `slug -> URL`. Relay decouples the routing handle (`ResourceLink`) from the underlying capability (`Resource`), allowing:
- Pluggable capability policies (access quotas, expiration, revocation, custom fallbacks).
- Multi-tenancy through workspaces and multi-domain routing.
- Support for multiple resource types (`redirect`, `secret`, `file`, `payload`, `request`).
- Fast-path redirection (< 2ms) with asynchronous, non-blocking analytics gathering.

---

## 2. Hexagonal Architecture (Ports and Adapters)

Relay strictly isolates core domain logic from infrastructure details.

```
+-------------------------------------------------------------------------------+
|                               Presentation Layer                              |
|   cmd/relay (daemon)   cmd/relayctl (cli)   internal/http/handlers (REST/Chi) |
+---------------------------------------+---------------------------------------+
                                        | Calls
                                        v
+-------------------------------------------------------------------------------+
|                                Service Layer                                  |
|                 internal/core/services (LinkService, etc.)                    |
+---------------------------------------+---------------------------------------+
                                        | Interacts via
                                        v
+-------------------------------------------------------------------------------+
|                                  Ports Layer                                  |
|   internal/core/ports (Repository, Cache, AnalyticsBuffer interfaces)         |
+---------------------------------------+---------------------------------------+
                                        | Implemented by
                                        v
+-------------------------------------------------------------------------------+
|                              Platform / Adapters                              |
|   internal/platform/db (SQLite + Goose)                                       |
|   internal/platform/cache (In-Memory RWMutex cache)                           |
|   internal/platform/analytics (Buffered batch worker)                         |
+-------------------------------------------------------------------------------+
                                        ^
                                        | Operates on
+---------------------------------------+---------------------------------------+
|                                 Domain Core                                   |
|   internal/core/domain (Resource, ResourceLink, RedirectResource, etc.)       |
+-------------------------------------------------------------------------------+
```

### Component Breakdown

| Layer | Package | Responsibilities |
|---|---|---|
| **Domain** | `internal/core/domain` | Defines entities (`Resource`, `ResourceLink`, `RedirectResource`, `Workspace`, `Domain`, `AnalyticsEvent`), error types, and core business invariants (`IsAccessible`). Has no imports outside the Go standard library and UUID generator. |
| **Ports** | `internal/core/ports` | Defines contracts (`Repository`, `Cache`, `AnalyticsBuffer`) and composite return types (`ResolvedRedirect`). |
| **Services** | `internal/core/services` | Implements business operations (`CreateRedirect`, `ResolveAndTrack`). Handles slug collision handling, query parameter preservation, cache warming, and IP anonymization. |
| **Platform / DB** | `internal/platform/db` | Implements `ports.Repository` using `modernc.org/sqlite`. Executes embedded schema migrations using Goose. Enforces SQLite WAL mode and foreign key constraints. |
| **Platform / Cache** | `internal/platform/cache` | Implements `ports.Cache` as a thread-safe in-memory cache using `sync.RWMutex`. |
| **Platform / Analytics** | `internal/platform/analytics` | Implements `ports.AnalyticsBuffer`. Uses a buffered channel worker that drains events in batches to avoid blocking HTTP request cycles. |
| **HTTP / Transport** | `internal/http/handlers` | Translates HTTP requests to service calls using `chi.Router`. Handles request deserialization, status codes, and error mappings. |
| **Application** | `internal/app` | Bootstraps repository, cache, analytics worker, and HTTP server with graceful shutdown on `SIGINT` / `SIGTERM`. |

---

## 3. Fast-Path Link Resolution Pipeline

When an incoming request hits `GET /{slug}`:

```
User Request: GET /{slug}
       |
       v
Extract hostname (strip port) & query string
       |
       v
Query in-memory cache with key: "{domain_id}:{slug}"
       |
  +----+----+
  |         |
[Hit]    [Miss]
  |         |
  |         v
  |    Fetch from SQLite via ResolveLink()
  |    (JOIN resource_links + resources + redirect_resources)
  |         |
  |         v
  |    Populate in-memory cache
  |         |
  +----+----+
       |
       v
Validate Accessibility:
- Status == 'active'?
- RevokedAt == nil or in the future?
- ExpiresAt == nil or in the future?
- AccessCount < MaxAccesses?
       |
  +----+----+
  |         |
[Valid]  [Invalid]
  |         |
  |         +--> Has FallbackURL?
  |                 |              |
  |               [Yes]           [No]
  |                 |              |
  |                 v              v
  |             Redirect to     HTTP 404
  |             FallbackURL
  v
Increment resource access_count
  |
  v
Enqueue AnalyticsEvent to buffered channel (non-blocking)
  |
  v
Append query params if preserve_query is true
  |
  v
HTTP 302/301 Redirect to DestinationURL
```

---

## 4. Concurrency & Performance Details

1. **Embedded SQLite in WAL Mode**:
   - SQLite is initiated with `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`.
   - WAL (Write-Ahead Logging) enables concurrent readers without locking the database file during writes.
2. **Asynchronous Batched Analytics**:
   - Links receive high throughput; direct database writes per redirect would throttle request handling.
   - The `AsyncBuffer` maintains an in-memory channel (`bufferCap = 5000`).
   - A dedicated background worker flushes batches upon hitting either:
     - `batchSize = 50` events, OR
     - `flushInterval = 1s` ticker.
   - On server shutdown, `Close()` triggers a final drain of all remaining channel items within a 5-second timeout window.
3. **In-Memory Cache**:
   - Cache keys are namespaced by domain: `{domain_id}:{slug}`.
   - Newly created links warm the cache immediately upon creation (`s.cache.Set(...)`).
   - Reads acquire a read lock (`RLock()`), preventing lock contention across concurrent redirections.
4. **IP Anonymization**:
   - To respect privacy standards (e.g. GDPR), IPv4 addresses are masked before being queued: `parts[0].parts[1].parts[2].0`.
