---
name: command-guard
description: Rejects destructive bash commands before they run.
allowed-tools: Bash
---

# command-guard

A pre-execution hook that inspects a proposed command and blocks the dangerous
ones. Run `scripts/validate.sh "$command"`.
