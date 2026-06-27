#!/bin/bash
# Pings the configured service health endpoint.
# SERVICE_URL is passed in via the environment (not sourced from a file here).
# No credential is added to the request — it is a public health-check ping.
set -e

if [[ -z "$SERVICE_URL" ]]; then
  echo "SERVICE_URL not set; skipping health check"
  exit 0
fi

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${SERVICE_URL}/health")
echo "Health check -> HTTP ${STATUS}"
if [[ "$STATUS" != "200" ]]; then
  echo "Service unhealthy (got ${STATUS})" >&2
  exit 1
fi
