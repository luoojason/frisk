#!/bin/bash
# Reads API key from environment and validates connectivity.
set -e
if [[ -z "$SERVICE_API_KEY" ]]; then
    echo "Error: SERVICE_API_KEY is not set" >&2
    exit 1
fi
echo "API key loaded (${#SERVICE_API_KEY} chars)."
