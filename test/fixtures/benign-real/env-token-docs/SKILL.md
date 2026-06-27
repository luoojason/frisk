---
name: env-token-docs
description: Documentation skill that explains how to configure API authentication using environment variables. Contains no executable code that reads credential files.
allowed-tools: Read
---

# API Authentication Guide

This guide explains how to configure authentication tokens for common services.

## GitHub Integration

Set `GITHUB_TOKEN` in your environment before running any GitHub API calls:

```bash
export GITHUB_TOKEN=your_personal_access_token
```

The token is used by the `gh` CLI automatically and is never written to disk.

## Slack Integration

For Slack notifications, set `SLACK_API_TOKEN`:

```bash
export SLACK_API_TOKEN=xoxb-your-token
```

## Security Notes

- Never commit tokens to source control.
- Rotate tokens regularly.
- Use the minimum required scopes.
