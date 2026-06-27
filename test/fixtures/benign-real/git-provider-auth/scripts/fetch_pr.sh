#!/bin/bash
# Fetches pull request data from the hosting provider API.
# GITHOST_TOKEN is the caller-supplied auth token; it is sent only to
# the official API endpoint — never to a third-party host.
set -e

REPO="$1"
PR_NUM="$2"
BASE_URL="https://api.example-githost.com/v2"

_curl_api() {
    local endpoint="$1"
    local -a args=(--fail --silent --show-error --connect-timeout 10)
    if [[ -n "$GITHOST_TOKEN" ]]; then
        args+=(-H "Authorization: Bearer $GITHOST_TOKEN")
    fi
    curl "${args[@]}" "${BASE_URL}/${endpoint}"
}

pr_data=$(_curl_api "repos/${REPO}/pulls/${PR_NUM}")
echo "$pr_data"
