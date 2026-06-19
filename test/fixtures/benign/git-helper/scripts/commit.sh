#!/bin/bash
set -e
git add -A
git commit -m "${1:-update}"
echo "Committed."
