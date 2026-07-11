# Zeabur deployment

Use one service replica with a persistent volume mounted at `/app/data`.
SQLite WAL is the runtime database; do not run multiple replicas against the
same volume. Horizontal multi-replica deployment requires an external database
implementation and is intentionally rejected by the lifetime lock today.

## Environment variables

Required for a managed deployment:

```text
LISTEN=0.0.0.0:8080
ALLOW_PUBLIC_LISTEN=true
DATA_DIR=/app/data
API_KEY=<strong client API key>
ADMIN_KEY=<different strong Admin UI key>
CREDENTIAL_ENCRYPTION_KEY=<64 hex characters>
```

Generate independent keys locally, for example:

```bash
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
```

Persist `CREDENTIAL_ENCRYPTION_KEY` outside the volume as well. It must remain
identical across redeployments and backup restores.

## Volume and domain

- Volume mount: `/app/data`
- Container port: `8080`
- Public domain target: HTTP port `8080`
- Replicas: `1`

After the first upgraded deployment, check `/healthz`, `/readyz`, the Admin
pool total, and create one verified backup before deleting any legacy JSON
snapshots. Uploads use an asynchronous import job and accept up to 128 MiB by
default.
