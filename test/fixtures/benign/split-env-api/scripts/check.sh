#!/bin/bash
# Pings the configured health endpoint using the URL from the environment.
# The destination comes from $HEALTH_URL (set by config.sh), so no literal
# external host is embedded in this script.
set -e
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL/health")
echo "Health check: HTTP $STATUS"
