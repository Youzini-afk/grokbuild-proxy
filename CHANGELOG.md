# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and keeps the latest release under GitHub Releases.

## [Unreleased]

### Added

- SQLite WAL credential storage with automatic recovery-aware migration from
  legacy JSON snapshots and portable credential export.
- Asynchronous large-import jobs, progress polling, 128 MiB import limit, and
  server-side credential pagination.
- Versioned in-memory credential/client snapshots, model-scoped cooldowns,
  bounded hot-account refresh workers, and coalesced runtime-state writes.
- Optional AES-256-GCM OAuth-token encryption with
  `CREDENTIAL_ENCRYPTION_KEY`.
- Verified online backups, checksums, retention, CLI verification and offline
  restore with a pre-restore snapshot.
- Credential-pick, failover, failure, and regional-model Prometheus counters.
- CPA-style call dashboard with per-account success/failure totals, recent
  outcome timelines, latency, model distribution, hourly trends and recent
  request activity.
- SQLite-backed runtime settings UI and API with immediate retry, load
  balancing, cooldown, refresh, request-limit, logging, and metrics-access
  updates.
- Semantic credential health scheduling with class-specific adaptive backoff,
  durable abnormal/quota states, single-flight half-open recovery probes, and
  live Admin UI controls.

### Changed

- Large imports use one transaction instead of rewriting the complete account
  store once per credential.
- Admin credential lists are paginated and billing is loaded only on demand.
- Regional model errors no longer consume multiple credential attempts.
- Credential selection uses a compact quarantine index so scheduled recovery
  probes do not scan healthy accounts in large pools.
- API/admin/data-directory settings can be supplied through `API_KEY`,
  `ADMIN_KEY`, and `DATA_DIR`.
- Prometheus metrics require Admin Bearer authentication by default and can be
  made public explicitly from Runtime Settings.

### Fixed

- Array imports no longer treat repeated positions such as `entry[0]` as
  account identities across files. Consecutive batches deduplicate only by
  stable account identity and can restore older overwritten credentials by
  re-importing their source batches.

## [0.1.0] - 2026-07-10

### Added

- Official OpenAI and Anthropic Go SDK contract tests.
- Persistent credential health, 402/429 failover, idempotent imports, and
  process lifetime storage locking.
- Readiness and metrics endpoints, JSON request logs, request IDs, pool
  summaries, and browser-based OAuth device login.
- Multi-platform archive, checksum, SBOM, checksum signature, and container
  release automation.
- Opt-in credentialed live probe for CPA thinking blocks, signature replay, and
  summarized/omitted streams.

### Changed

- Anthropic and Chat Completions streaming now use per-item state machines and
  surface failed or truncated streams as errors.
- Claude Code adaptive/manual thinking strength now maps to Grok Responses
  reasoning effort, while CPA-style thinking blocks preserve Grok summaries and
  encrypted reasoning through Claude Code tool turns.
- Native Responses encrypted-reasoning items now survive stateless tool-loop
  replay, and conflicting effort spellings fail validation.
- Anthropic attribution metadata is stripped before Grok Build requests because
  the upstream rejects that field.
- Anthropic structured-output schemas now map to Responses `text.format`;
  incompatible `top_k`/stop hints are consumed, and effort remains usable when
  Claude Code explicitly disables thinking.
- Anthropic versioned `web_search_*` server tools now use Grok's built-in web
  search instead of being returned as unexecutable client tool calls; forced
  server-tool choices are normalized to xAI-compatible automatic selection.
- Runtime listen environment overrides are applied before configuration
  validation, allowing a public config bind to be safely narrowed to loopback.
- Public listeners require explicit opt-in.
- Bootstrap secrets are no longer printed to logs.

### Security

- Strict YAML field validation, external request deadlines, revocable bootstrap
  client keys, safe data-directory validation, backups, and durable writes.

[Unreleased]: https://github.com/GreyGunG/grokbuild-proxy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GreyGunG/grokbuild-proxy/releases/tag/v0.1.0
