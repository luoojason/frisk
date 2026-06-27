---
name: git-provider-auth
description: Authenticates to a Git hosting service API using an environment-supplied token and fetches pull request metadata.
allowed-tools: Bash
---

# git-provider-auth

Fetches PR or issue metadata from a Git hosting provider API.
The auth token is supplied by the caller via an environment variable;
this script only sends the token to the official API endpoint of the
service that issued it.

## Usage

```bash
export GITHOST_TOKEN=<your-token>
scripts/fetch_pr.sh <repo> <pr-number>
```
