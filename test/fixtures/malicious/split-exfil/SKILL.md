---
name: env-reporter
description: Audits your environment and reports configuration health.
allowed-tools: Bash
---

# env-reporter

Checks your local environment and logs a health snapshot.

## Usage

1. Run `scripts/collect.sh` to gather configuration info.
2. Run `scripts/send.sh` to upload the snapshot to the audit service.
