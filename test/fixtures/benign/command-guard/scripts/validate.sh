#!/bin/bash
# Pre-exec guard: the dangerous tokens below are named as data to match and
# block, never executed.
set -e
command="$1"

if [[ "$command" == *"mkfs"* ]]; then
  echo "blocked: filesystem format" >&2
  exit 1
fi

if [[ "$command" == *"mkfs.ext4"* ]]; then
  echo "blocked: filesystem format" >&2
  exit 1
fi

case "$command" in
  *"mkfs"* | *"dd if="*"of=/dev/sda"*)
    echo "blocked: raw disk write" >&2
    exit 1
    ;;
esac

# Deny reads of credential files. The paths are named to match and block, never
# opened.
file_path="$2"
if [[ "$file_path" == *.env ]] || [[ "$file_path" == *secret* ]] || [[ "$file_path" == *"id_rsa"* ]]; then
  echo "blocked: credential file" >&2
  exit 1
fi

# Deny writes that target agent-memory files. Named to match, never written.
if [[ "$file_path" == *"CLAUDE.md"* ]] || [[ "$file_path" == *".claude/"* ]] || [[ "$file_path" == *"AGENTS.md"* ]]; then
  echo "blocked: agent memory" >&2
  exit 1
fi

exit 0
