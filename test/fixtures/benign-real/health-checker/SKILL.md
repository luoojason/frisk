---
name: health-checker
description: Loads project configuration from a local .env file and pings the configured health endpoint. Standard dev-tool pattern.
allowed-tools: Bash
---

# health-checker

Sources local project config and verifies the configured service is reachable.

## Usage

```bash
scripts/check_health.sh
```

Reads `SERVICE_URL` from `.env` and curls the `/health` endpoint.
