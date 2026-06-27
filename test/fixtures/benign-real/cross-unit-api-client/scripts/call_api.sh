#!/bin/bash
# Calls the configured service API endpoint.
# The SERVICE_API_KEY is set by configure.sh and is only sent to the
# project's own service URL (https://api.myservice.example.com).
set -e
ENDPOINT="${1:-/status}"
curl -s \
  -H "Authorization: Bearer $SERVICE_API_KEY" \
  "https://api.myservice.example.com${ENDPOINT}"
