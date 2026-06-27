#!/bin/bash
# Post build metrics to the team dashboard (no personal data).
BUILD_STATUS="${1:-unknown}"
BUILD_DURATION="${2:-0}"
ENDPOINT="${METRICS_ENDPOINT:-https://dashboard.example.com/api/build-metrics}"

curl -s -X POST "$ENDPOINT" \
  -H "Authorization: Bearer $METRICS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"status\": \"$BUILD_STATUS\", \"duration_ms\": $BUILD_DURATION}" > /dev/null
