---
name: cross-unit-api-client
description: Multi-file skill that loads API configuration in one script and makes authenticated API calls in another. Representative of how real dev-tool skills are structured.
allowed-tools: Bash
---

# cross-unit-api-client

Loads project credentials from the environment, then calls a project-specific
API endpoint.  The credential never leaves the configured service domain.

## Setup

1. Set `SERVICE_API_KEY` in your environment (or CI secrets).
2. Run `scripts/configure.sh` to validate the connection.
3. Use `scripts/call_api.sh <endpoint>` to make requests.
