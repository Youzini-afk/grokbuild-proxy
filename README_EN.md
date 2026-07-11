# grokbuild-proxy

[简体中文](README.md) | **English**

[![CI](https://github.com/GreyGunG/grokbuild-proxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GreyGunG/grokbuild-proxy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GreyGunG/grokbuild-proxy)](https://github.com/GreyGunG/grokbuild-proxy/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go)](go.mod)

`grokbuild-proxy` is a local, self-hosted compatibility proxy for using an
operator-owned Grok Build account with Anthropic Messages and OpenAI-compatible
clients.

It translates Claude Code requests to the Grok Build Responses backend,
including SSE, client tools, structured output, reasoning effort, CPA-style
thinking blocks, encrypted reasoning replay, and Grok-hosted web search.

> [!CAUTION]
> This is an unofficial project for technical learning and interoperability
> research. It is not affiliated with xAI, Grok, Anthropic, or OpenAI. Use only
> accounts you own and are authorized to automate. Usage may violate an
> upstream provider's terms or result in account restrictions. You assume all
> risk. Read the full [Disclaimer](DISCLAIMER.md) before use.

## Features

- Anthropic-compatible `POST /v1/messages`
- OpenAI-compatible Responses, Chat Completions, and Models endpoints
- Incremental SSE translation
- Client function tools and parallel calls
- Anthropic hosted web search mapped to Grok `web_search`
- JSON Schema output mapped to Responses `text.format`
- Adaptive/manual reasoning-effort compatibility
- Summarized/omitted thinking and encrypted reasoning replay
- Multi-account selection, sticky sessions, cooldown, and failover
- Grok CLI import and browser OAuth device login
- Transactional SQLite WAL storage with automatic legacy JSON migration
- Embedded Admin Web UI
- Health, readiness, Prometheus metrics, request IDs, and structured logs
- Multi-platform archives, checksums, SBOMs, and GHCR images

## One-command installation

Linux / macOS:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/GreyGunG/grokbuild-proxy/main/scripts/install.sh \
  | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/GreyGunG/grokbuild-proxy/main/scripts/install.ps1 | iex
```

The installers detect the OS/architecture, download the latest Release, verify
SHA-256, install the binary, and create a local configuration. Set
`GROKBUILD_VERSION=v0.1.0` to pin a release.

## Run from source

Requirements: Go 1.26.5 or newer, or Docker.

```bash
git clone https://github.com/GreyGunG/grokbuild-proxy.git
cd grokbuild-proxy
cp config.example.yaml config.yaml
go run ./cmd/grokbuild-proxy
```

The proxy listens on `127.0.0.1:8080`. Managed deployments should set
`API_KEY` and `ADMIN_KEY`. Empty values are generated into `data/grokbuild.db`;
stop the service and use `-print-keys` only when recovery is necessary.

```bash
API_KEY=sk-your-client-key ADMIN_KEY=sk-your-admin-key \
  go run ./cmd/grokbuild-proxy
```

Admin UI:

```text
http://127.0.0.1:8080/admin
```

Complete browser device login in the Admin UI. Prefer this over importing a
potentially stale `~/.grok/auth.json` refresh-token snapshot.

## Claude Code

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_AUTH_TOKEN="${API_KEY}"
export ANTHROPIC_MODEL=grok-4.5

claude --effort high
```

Configured Claude aliases can also be mapped to Grok models.

## OpenAI-compatible clients

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY="${API_KEY}"
```

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:8080/v1/responses \
  -H "Authorization: Bearer ${OPENAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4.5","input":"Reply with exactly: ok"}'
```

## Docker Compose

```bash
cp config.example.yaml config.yaml
docker compose up --build -d
```

Set `API_KEY` and `ADMIN_KEY` in `.env` before starting Compose.

Published image:

```text
ghcr.io/greygung/grokbuild-proxy
```

## Documentation

- [Build and run guide](docs/build-and-run.md)
- [Design](DESIGN.md)
- [Compatibility matrix](COMPATIBILITY.md)
- [Operations](docs/operations.md)
- [Zeabur deployment](docs/zeabur.md)
- [Security policy](SECURITY.md)
- [Disclaimer](DISCLAIMER.md)
- [Contributing](CONTRIBUTING.md)

## Known limitations

- Anthropic `count_tokens` is not implemented.
- Thinking signatures are proxy-scoped and account/model-bound.
- Some Anthropic reasoning controls are approximated.
- `top_k` and `stop_sequences` are not forwarded to Grok reasoning models.
- Rich Anthropic hosted-tool result/citation blocks are reduced.
- Only hosted web search has a dedicated Anthropic server-tool mapping.
- Cold-account OAuth refresh is demand-driven; recently active accounts use a bounded background scheduler.
- The upstream CLI protocol is unstable and may change.
- This is a trusted-operator tool, not a multi-tenant service.

See [COMPATIBILITY.md](COMPATIBILITY.md) for details.

## Build and test

```bash
make build
make check
make release-snapshot

# Or invoke Go directly
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/grokbuild-proxy
```

See [docs/build-and-run.md](docs/build-and-run.md) for cross-compilation,
containers, GoReleaser, live probes, and troubleshooting.

## Community

Friendly link: [LINUX DO](https://linux.do)

## Acknowledgements

This project studied or was inspired by:

- [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) — protocol
  translators, executor patterns, and CPA-style thinking compatibility
- [open-grok-build](https://github.com/kenryu42/open-grok-build) — Grok CLI
  OAuth, request normalization, models, and billing observations
- [pi-grok-cli](https://github.com/kenryu42/pi-grok-cli) — Grok CLI endpoint,
  headers, authentication, and model behavior
- [kiro.rs](https://github.com/hank9999/kiro.rs) — credential-pool and compact
  self-hosted admin patterns
- [Sub2API](https://github.com/Wei-Shaw/sub2api) — multi-account operations and
  admin workflow references

These projects are independent and do not endorse or support this repository.

## License

[MIT](LICENSE). The license covers repository code only and grants no right to
third-party accounts, subscriptions, APIs, quota, trademarks, or services.
