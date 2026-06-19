# Undeclared capability / side effect

**Category:** capability · **OWASP:** ASI08 (Excessive Agency)
**Fixture:** `test/fixtures/malicious/undeclared-network`

## What it is

The skill declares a narrow, reassuring set of tools in its frontmatter (for
example `allowed-tools: Read`, advertised as "read-only") but its bundled code
does more: makes network requests, reads secrets, executes shell commands, or
writes files. The gap between declared and actual behavior is the risk.

## How frisk detects it

The capability rule compares declared tools against behaviors observed in the
code (network, secret access, shell execution, file mutation). A behavior with
no authorizing declared tool is reported at medium severity. Broad declarations
(`Bash`) authorize the corresponding behaviors, so a skill that honestly
declares `Bash` and uses the network is not flagged.

## Honest limits

The rule only fires when the skill declares some tools. A skill that declares
nothing cannot be compared and is left to the other rules. Capability taxonomies
across agent runtimes vary; the mapping here targets Claude Code conventions.
