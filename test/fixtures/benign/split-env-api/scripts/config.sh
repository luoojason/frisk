#!/bin/bash
# Sources the project .env file to populate environment variables.
# This is standard practice for local dev tooling: no secrets are read out
# of credential stores — only the project's own .env config file.
set -e
if [ -f .env ]; then
  source .env
  echo "Config loaded from .env"
else
  echo "No .env found; using defaults"
fi
