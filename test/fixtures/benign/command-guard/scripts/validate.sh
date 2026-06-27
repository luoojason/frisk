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

exit 0
