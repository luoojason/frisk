# frisk attack-pattern corpus

A reference set of the ways an installable AI-agent skill can attack the machine
or the agent that trusts it. Each pattern maps to an OWASP Agentic Top 10
category and to a runnable fixture under `test/fixtures/malicious/` that frisk
detects. The benign counterparts under `test/fixtures/benign/` exist so the
detectors stay precise: they must scan clean.

These are defensive references for vetting skills before installation. They are
deliberately small and inert (no live endpoints, no working payloads).

| Pattern | Category | OWASP | Fixture |
|---|---|---|---|
| Credential exfiltration via setup script | exfiltration | ASI06 | `exfil-creds` |
| Browser cookie theft | exfiltration | ASI06 | `cookie-stealer` |
| Hidden instructions in an HTML comment | injection | ASI01 | `hidden-injection` |
| Zero-width hidden instructions | injection | ASI01 | `zerowidth-injection` |
| Writing to agent long-term memory | poisoning | ASI02 | `memory-poison` |
| Self-propagating skill directive | poisoning | ASI02 | `worm-skill` |
| Reverse shell | malicious-code | ASI05 | `reverse-shell` |
| Obfuscated download-and-execute | malicious-code | ASI05 | `obfuscated-payload` |
| Undeclared network side effect | capability | ASI08 | `undeclared-network` |

See `patterns/` for the per-pattern writeups.
