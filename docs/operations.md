# Operations guide

## Probes and metrics

- `GET /healthz`: process liveness; does not inspect credentials.
- `GET /readyz`: storage and usable credential readiness. Returns 503 when no
  enabled, non-cooling credential with token material is available.
- `GET /metrics`: low-cardinality Prometheus counters for request count,
  failures, inflight requests, response bytes, and total latency. Metrics
  require the Admin Bearer key by default; anonymous access can be enabled in
  the Runtime Settings page.

The Admin System page/API includes aggregate pool health. It never exposes
plaintext OAuth or client secrets.

Credential and client-key reads use versioned in-memory snapshots. Durable token
rotation and failure state remain synchronous; high-frequency `last_used`
timestamps are coalesced and flushed every 30 seconds and during graceful
shutdown.

Call statistics record only credential record id, model id, HTTP/network
outcome, latency and timestamp. Prompts, response bodies and tokens are never
stored in the statistics tables. Events are queued in memory and committed in
one-second SQLite batches; the newest 100,000 detailed events are retained while
per-credential lifetime totals remain in `credential_usage_stats`.

## Credential imports

The Admin credential page auto-detects canonical Grok auth JSON, CPA `type=xai`
OAuth JSON, and sub2api `accounts[].credentials` exports. A JSON file may hold a
single credential, an array, or a multi-account wrapper. ZIP uploads may contain
multiple JSON files or nested ZIP batches; archives are parsed in memory and are
never extracted to the data directory. macOS metadata and unrelated text/CSV
files are ignored.

ZIP nesting is limited to three levels, supported-file count to 20,000, and
total uncompressed JSON to `limits.max_import_bytes`. Invalid, encrypted, or
oversized archives fail before credentials are written. During normalization,
JWT claims fill missing account metadata, CPA/sub2api disabled and priority
values are preserved, and duplicate account rotations keep the credential with
the newest expiry. Raw SSO cookies are intentionally rejected because they must
first be exchanged through the OAuth flow.

## Runtime settings

The Admin **Runtime Settings** page persists validated overrides in SQLite and
applies them without a restart. It controls credential failover attempts,
selection strategy, sticky-session TTL, cooldown bounds, active-token refresh,
request body/timeout/concurrency/queue limits, log level, and anonymous metrics
access. `GET/PUT/DELETE /admin/settings` provide the same authenticated API;
DELETE restores values derived from the process configuration.

Listen address, data directory, upstream/OAuth identity, and bootstrap secrets
remain startup-only settings. They are intentionally excluded from the live UI
to prevent an accidental lockout or redirect of credential-bearing traffic.

### Adaptive credential health

Upstream failures are classified by semantic error code, not HTTP status
alone. The scheduler maintains an independent consecutive-failure streak for
each class and resets that streak when the class changes:

- `auth_invalid` starts at a one-minute quarantine and grows by 5x to a
  six-hour cap. Four consecutive failures mark the account as abnormal in the
  Admin UI, but do not delete it.
- `quota_exhausted` starts at five minutes and grows by 2x to a two-hour cap.
  Grok's `personal-team-blocked:spending-limit` response belongs to this class
  even when it is returned as HTTP 403.
- `rate_limited` starts at 30 seconds, grows by 2x to 30 minutes, and honors a
  shorter or longer upstream `Retry-After` within that cap.
- transport/5xx failures use a short transient schedule. OAuth endpoint
  network failures are transient; only invalid-grant/credential responses
  contribute to the authentication streak.

An expired quarantine does not immediately return to normal rotation. It enters
half-open state and receives one leased probe request. By default one recovery
probe is scheduled per 20 incoming picks and the lease lasts two minutes, which
prevents concurrent requests from creating a probe storm. One successful
upstream response clears the streak and immediately restores normal rotation;
another failure advances the class-specific schedule. If every account is
quarantined, a due probe is selected immediately instead of waiting for the
normal probe interval.

All timings, the abnormal threshold, probe frequency, and probe lease are live
settings under **Runtime Settings > Adaptive credential health**. Health state
is persisted in SQLite and survives restart. Credential filters expose
`quota_limited`, `probe_due`, and `abnormal` states without exposing tokens or
upstream response bodies.

## Logs

Logs are JSON on stdout. Request records include request ID, method, route
template, status, latency, and response size. Upstream retry records include the
credential record ID, attempt, status, and Retry-After duration.

Request bodies, prompts, OAuth tokens, client keys, and admin keys are never
logged. Send `X-Request-Id` with a safe value to correlate a client request; the
proxy generates one otherwise and returns it in the response header.

## Backup and restore

Stop the process before copying or restoring `data_dir`. The store holds
`.instance.lock` for its lifetime and rejects a second process using the same
directory.

Create and verify an online backup:

```bash
grokbuild-proxy -config config.yaml -backup
grokbuild-proxy -verify-backup /app/data/backups/grokbuild-....db
```

Restore while the service is stopped. The current database is retained as a
`grokbuild.db.pre-restore-*` snapshot:

```bash
grokbuild-proxy -config config.yaml -restore-backup /app/data/backups/grokbuild-....db
```

The Admin System page can also create a backup. Ten verified generations and
their SHA-256 sidecars are retained by default.

Docker Compose uses the `grokbuild-data` named volume. Stop the service before
backing that volume up with your normal Docker volume backup tooling.

Back up the entire directory, including:

- `grokbuild.db`: credentials, clients, bootstrap keys and runtime health;
- `grokbuild.db-wal` / `grokbuild.db-shm` when present;
- legacy `credentials.json`, `clients.json`, `meta.json` and `*.bak` files retained after migration.

Files contain secrets and must remain mode `0600`; the dedicated directory
should be accessible only to the service account. To restore, stop the process,
replace the whole directory from one consistent backup, verify ownership and
permissions, then start and check `/readyz`.

On first start after upgrading, the proxy imports the largest valid legacy JSON
snapshot into SQLite in one transaction and records a migration marker. Legacy
files remain untouched for rollback. Use `-print-keys` only while the service is
stopped when bootstrap keys must be recovered; its output contains secrets.

## Upgrade and rollback

1. Back up `data_dir`.
2. Read `CHANGELOG.md` and the GitHub release notes.
3. Verify `checksums.txt` and its Sigstore bundle.
4. Replace the binary or image, preserving configuration and data.
5. Check `/healthz`, `/readyz`, Admin pool summary, and one synthetic request.

For rollback, stop the new process and restore both the prior executable/image
and the pre-upgrade data backup. Never run two versions against one data
directory.

## Public deployment

Loopback is the default. A non-loopback bind requires
`allow_public_listen: true` or `ALLOW_PUBLIC_LISTEN=true`. If remote access is
required, place the proxy behind a trusted TLS reverse proxy, restrict source
networks, protect `/admin`, `/metrics`, and all `/v1` endpoints, and rotate any
key exposed to browsers or logs.
