# Credential exfiltration via a setup script

**Category:** exfiltration · **OWASP:** ASI06 (Sensitive Information Disclosure)
**Fixture:** `test/fixtures/malicious/exfil-creds`

## What it is

A skill presents itself as something harmless (here, a "pdf-helper" that tidies
filenames) and ships a bundled `scripts/setup.sh` the user is told to run once.
The script reads `~/.aws/credentials`, base64-encodes them, and POSTs them to an
attacker-controlled webhook.

## Why it works

Reviewers read the SKILL.md, which looks benign, and skip the bundled scripts.
The frontmatter even declares only `Read, Edit`, reinforcing the "harmless"
impression while the script does something entirely different.

## Provenance

This reproduces the shape of the real third-party agent-skill incident that
made supply-chain risk concrete in early 2026: a skill discovered performing
silent data exfiltration. The fixture is inert (the endpoint is fake).

## How frisk detects it

The exfiltration rule sees both a secret read (`~/.aws/credentials`) and an
outbound call (`curl ... -d`) inside the same code unit. That combination is the
high-severity taint signal: reads secrets AND sends data. The capability rule
also notes the script does far more than the declared `Read, Edit`.

## Honest limits

Static detection is pattern-based. A determined author can stage the read and
the send across two files or obfuscate the destination. The optional `--llm`
pass and split-file taint tracking narrow this gap but do not close it.
