# Memory and context poisoning

**Category:** poisoning · **OWASP:** ASI02 (Memory and Context Poisoning)
**Fixtures:** `test/fixtures/malicious/memory-poison`, `test/fixtures/malicious/worm-skill`

## What it is

The skill plants instructions that outlive the current task. Two shapes:

- A bundled script appends to persistent agent state (`~/.claude/CLAUDE.md`,
  `AGENTS.md`), so every future session silently inherits the instruction.
- The SKILL.md tells the agent to copy the instructions into its own
  configuration/memory and apply them in every session (a self-propagating
  "worm" directive).

## How frisk detects it

The poisoning rule flags code that writes to known agent-state targets at high
severity, and flags prose directives ("add this to your own skill", "persist
across sessions", "remember to always") in the SKILL.md. Self-propagating
directives are high severity; ordinary persistence requests are medium.

## Honest limits

Novel state paths beyond the known set, or indirection through a variable, can
evade the static target list.
