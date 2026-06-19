# Hidden instructions (prompt injection)

**Category:** injection · **OWASP:** ASI01 (Prompt Injection)
**Fixtures:** `test/fixtures/malicious/hidden-injection`, `test/fixtures/malicious/zerowidth-injection`

## What it is

The SKILL.md carries instructions the agent will read but a human reviewer
will not: text inside an HTML comment, or text separated/obscured with
zero-width and bidirectional control characters. The hidden text tells the
agent to ignore its own instructions, run a command, or hide its actions from
the user.

## Why it works

The agent ingests the raw markdown, including comments and invisible characters.
A person skimming the rendered file sees only the benign visible text.

## How frisk detects it

The markdown parser records hidden spans (HTML comments, zero-width, bidi,
white/0px text) against the raw bytes. The injection rule flags a hidden span as
high severity when it carries imperative/instruction content. Visible
"ignore previous instructions" style phrasing is flagged at medium, since it can
appear legitimately in documentation about prompt injection.

## Honest limits

Paraphrased or semantically-obfuscated injection that uses none of the trigger
phrases will pass the static rule; the `--llm` pass exists for exactly that case.
