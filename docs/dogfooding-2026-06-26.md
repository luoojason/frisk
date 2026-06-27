# Dogfooding sweep — 2026-06-26

frisk was run against every `SKILL.md` installed under `~/.claude` (the author's
own machine): 322 skills across `skills/`, `plugins/`, and `toolkits/`. This is
the precision test the synthetic corpus cannot give, because real skills are
written by people who were not trying to look benign.

## Result (after the fixes in this batch)

| Verdict | Count | Share |
|---------|------:|------:|
| GREEN   | 305   | 94.7% |
| YELLOW  | 12    | 3.7%  |
| RED     | 5     | 1.6%  |

Several of the non-GREEN entries are duplicate plugin-cache versions of the same
skill (e.g. superpowers 6.0.0 / 6.0.2 / 6.0.3), so the distinct flagged skills
are fewer than 17. Malicious-corpus recall stayed at 9/9 throughout.

## Fixed in this batch (commit history)

These were false positives on benign official skills. All three were fixed
because the matched text is, by definition, not executable code; the malicious
corpus recall was unaffected.

1. **HTML comment inside a fenced code block** read as a hidden instruction
   (ASI01). A `<!-- ... -->` inside a ` ``` ` block is example code the reviewer
   sees, not hidden text. The markdown parser now skips comments inside fences.
   Was flagging the `algorithmic-art` p5.js skill RED.
2. **State path mentioned only in a `#` / `//` code comment** read as a write to
   that path (ASI02). Code rules now match a comment-stripped copy of the source
   (string contents preserved, so a `#`/`//` inside a literal is never mistaken
   for a comment). Was flagging `impeccable`'s own cleanup script RED.
3. **Line attribution for multi-line matches.** A regex spanning several lines
   (e.g. a multi-line `subprocess.Popen(... shell=True)`) fell back to line 1.
   `lineFor` now locates the match in the full source and reports its starting
   line. Was pointing `webapp-testing`'s finding at the shebang.

## Remaining precision limitations (NOT fixed — they need a judgment call)

These are real tensions between precision and recall. Fixing them naively would
widen frisk's blind spots, which is the wrong trade for a security scanner. They
are documented here so the trade can be made deliberately, not by accident.

### A. Defensive-guard scripts (RESOLVED)

A script whose whole job is to *block* dangerous commands must name those
commands as data, which read as the command itself.

- `plugin-dev/hook-development` `examples/validate-bash.sh` was RED, ASI05
  "Formats a filesystem", matched `mkfs` inside `[[ "$command" == *"mkfs"* ]]`.
- `plugin-dev/plugin-settings` `examples/read-settings-hook.sh` was YELLOW,
  ASI06, matched `.env` / `secret` inside `[[ "$file_path" == *".env"* ]]`, a
  hook that *denies* access to those files.

Fixed without stripping string literals (which would miss payloads that live in
strings). For bash, the destructive-command signatures (mkfs / rm -rf / dd) and
the exfiltration secret/egress patterns now fire only at a command position, not
when the token appears solely inside a `[[ ]]` / `[ ]` test or a `case` pattern.
A command substitution `$( )` or backtick inside a test still counts as
executing, so `[[ $(mkfs ...) ]]` is not laundered, and a real command chained
after a guard (`[[ x ]] && mkfs ...`) still fires. After the fix, both skills
above are GREEN and the full sweep moved to 307 GREEN / 11 YELLOW / 4 RED with
malicious recall unchanged at 23/23.

### B. Authenticated API clients (defensible, but RED is too strong)

- `project-session-manager` `lib/providers/bitbucket.sh:17` and `gitea.sh:17` —
  RED, ASI06. They read `$BITBUCKET_TOKEN` / `$GITEA_TOKEN` and send it in an
  `Authorization: Bearer` header to that token's own API.
- `superpowers/brainstorming` `scripts/server.cjs:133` — YELLOW, ASI06. Reads
  its own `BRAINSTORM_TOKEN` for a localhost server.

Using a token to authenticate to the service that issued it is not exfiltration.
The "reads a credential + makes a network call" heuristic cannot tell that from
theft. Option worth considering: downgrade severity when the only network
destination is the same host family the credential is named for, or when the
credential is a named service token (`*_TOKEN`) used in an `Authorization`
header rather than copied into a request body.

### C. Paths and directives in docstrings / prose (mixed)

- `skill-creator` `scripts/run_eval.py:45` — RED, ASI02. The match is a Python
  docstring line ("Creates a command file in `.claude/commands/` ..."). Comment
  stripping does not touch docstrings because they are string literals, and a
  string literal can also be a real write argument. The script does create a
  temporary command file for its eval harness, so a finding is defensible, but
  the evidence line is documentation, not a write.
- cli-anything browser `agent-harness` `SKILL.md:1` — YELLOW, ASI02. Prose
  directive "persist across sessions"; attributed to line 1 because visible-text
  matches do not carry a real line number yet.

### D. Meta-documentation about agent behavior (defensible)

- `superpowers/using-superpowers` `SKILL.md:16` — YELLOW, ASI01. Matched
  "override default" in "Superpowers skills override default system prompt
  behavior", which is documentation about how skills work, not an injection.
  A medium "review" verdict here is conservative but not unreasonable.

## Recommendation before a public launch

- Ship the three fixes in this batch (done).
- Class A (defensive guards) is fixed with the command-position check (done).
- Decide B deliberately: a severity downgrade for same-service credential use
  would remove the last noise class most likely to look wrong on legitimate
  developer tooling, the credibility risk on a Show HN.
- Treat C and D as acceptable "review" outcomes, or add narrow allowances.
- Re-run this full sweep (`for d in $(find ~/.claude -name SKILL.md); do frisk
  "$(dirname "$d")" --quiet; done`) before each release. It catches what the
  fixed corpus cannot.
