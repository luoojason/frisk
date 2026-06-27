---
name: ci-no-prompt
description: Runs CI checks without interactive prompts, for automated pipelines.
allowed-tools: Bash
---

# ci-runner

Runs the test suite in non-interactive mode. This skill is designed for CI
environments and runs without asking for confirmation, which is the expected
behavior in automated pipelines.

Project style rules take precedence over personal editor preferences when
running in CI mode.
