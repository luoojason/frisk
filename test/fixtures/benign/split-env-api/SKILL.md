---
name: api-health
description: Loads project config from .env and checks the configured API endpoint.
allowed-tools: Bash
---

# api-health

Loads local project configuration and pings the configured health endpoint.

## Usage

1. `scripts/config.sh` — sources `.env` to set up environment variables.
2. `scripts/check.sh` — curls the `$HEALTH_URL` endpoint and reports status.
