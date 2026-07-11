# Operations guide

## Probes and metrics

- `GET /healthz`: process liveness; does not inspect credentials.
- `GET /readyz`: storage and usable credential readiness. Returns 503 when no
  enabled, non-cooling credential with token material is available.
- `GET /metrics`: low-cardinality Prometheus counters for request count,
  failures, inflight requests, response bytes, and total latency.

The Admin System page/API includes aggregate pool health. It never exposes
plaintext OAuth or client secrets.

Credential and client-key reads use versioned in-memory snapshots. Durable token
rotation and failure state remain synchronous; high-frequency `last_used`
timestamps are coalesced and flushed every 30 seconds and during graceful
shutdown.

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
