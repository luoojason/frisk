// TB-001: Conditional / time-bomb trigger.
//
// A time-bomb is code (or a prose instruction) whose behavior changes based on
// a SPECIFIC TRIGGER — a future date/timestamp, a particular user identity, or
// a counter — that activates a hidden secondary behavior while appearing benign
// during initial review.
//
// This rule detects:
//
//   1. JavaScript / TypeScript: `Date.now()` or `new Date().getTime()` compared
//      to a hard-coded 10-13 digit Unix epoch (a specific future date).
//   2. Python: `time.time()` compared to a 10+ digit epoch constant.
//   3. Python: `datetime.now()` or `datetime.utcnow()` compared to a specific
//      `datetime(...)` value.
//   4. Bash: `$(date +%s) -gt <epoch>` — epoch comparison in a shell conditional.
//
// Severity is scaled by whether a suspicious payload is present in the SAME file:
//   HIGH: time-gate + egress to suspicious exfil host (webhook.site, ngrok, …)
//         or + remote code execution (curl | bash, exec of fetched code, …)
//   MEDIUM: time-gate + any other network egress or shell exec in the same unit
//   LOW: time-gate alone (code review recommended but no immediate payload visible)
//
// Benign guard: a simple license-expiry or feature-flag check with a future date
// AND no suspicious payload in the same file → produces at most LOW.

import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { lineFor, makeFinding, stripComments } from './helpers.js'
import { EGRESS_PATTERNS, SUSPICIOUS_HOSTS } from './exfiltration.js'

// ---- Time-trigger patterns ----

// JS/TS: Date.now() or new Date().getTime() vs hard-coded epoch
const JS_EPOCH_GATE: RegExp[] = [
  /\bDate\.now\(\)\s*[><=!]+\s*\d{10,13}\b/,
  /\bnew\s+Date\(\)\.(?:getTime|valueOf)\(\)\s*[><=!]+\s*\d{10,13}\b/,
  // new Date("2026-01-01") > new Date()  or  new Date() > new Date("...")
  /\bnew\s+Date\(['"][0-9T:.Z-]{8,}['"]\)\s*[><=!]+\s*(?:new\s+Date\(\)|Date\.now\(\))/,
  /\bnew\s+Date\(\)\s*[><=!]+\s*new\s+Date\(['"][0-9T:.Z-]{8,}['"]\)/,
]

// Python: time.time() vs epoch, or datetime comparison
const PY_EPOCH_GATE: RegExp[] = [
  /\btime\.time\(\)\s*[><=!]+\s*\d{10,}\b/,
  /\bdatetime\.(?:now|utcnow)\(\)\s*[><=!]+\s*datetime\s*\(/,
  /\bdatetime\s*\(\d{4}\s*,/,  // datetime(2026, ...) construction used in comparison context
]

// Python specialised: the datetime(...) construction itself is only suspicious
// when it appears alongside a conditional comparison; handled below.
const PY_DATETIME_COMPARE: RegExp = /if\s+.{0,80}datetime\.(?:now|utcnow)\(\)\s*[><=!]+/

// Bash: $(date +%s) -gt / -lt / -ge / -le followed by an epoch integer
const BASH_EPOCH_GATE: RegExp[] = [
  /\$\(date\s+\+%s\)\s*-(?:gt|lt|ge|le|eq)\s*\d{10,}\b/,
  /\[\[\s*\$\(date[^)]*\)\s*-(?:gt|lt|ge|le|eq)\s*\d{10,}/,
]

// ---- Payload severity signals ----
// Pulled from exfiltration rule exports so there's no duplication.

// Remote-code-execution patterns — a subset of malicious-code SIGNATURES.
const RCE_PATTERNS: RegExp[] = [
  /\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh|perl|ruby|node|php|python[23]?)\b/,
  /\bexec\s*\(\s*(?:urllib|requests\.get|fetch)\b/,
  /\beval\b[^\n]*(?:base64|atob|fromCharCode|fromhex)\b/i,
  /(?:base64\s+(?:-d|--decode)|atob\s*\()[^\n]*\|\s*(?:bash|sh)\b/,
]

const id = 'time-bomb'

// Detect whether any time-gate pattern fires on the stripped source.
function findTimeGate(stripped: string, lang: string): RegExpExecArray | null {
  if (lang === 'javascript') {
    for (const re of JS_EPOCH_GATE) {
      const m = re.exec(stripped)
      if (m) return m
    }
  }
  if (lang === 'python') {
    for (const re of PY_EPOCH_GATE) {
      const m = re.exec(stripped)
      if (m) return m
    }
    if (PY_DATETIME_COMPARE.test(stripped)) {
      return PY_DATETIME_COMPARE.exec(stripped)
    }
  }
  if (lang === 'bash' || lang === 'unknown') {
    for (const re of BASH_EPOCH_GATE) {
      const m = re.exec(stripped)
      if (m) return m
    }
  }
  return null
}

export const rule: Rule = {
  id,
  category: 'malicious-code',
  owasp: 'ASI05',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []

    for (const unit of ir.codeUnits) {
      const stripped = stripComments(unit.source, unit.lang)
      const gateMatch = findTimeGate(stripped, unit.lang)
      if (!gateMatch) continue

      // Determine payload severity in the same code unit.
      const hasRce = RCE_PATTERNS.some((re) => re.test(stripped))
      const hasSuspHost = SUSPICIOUS_HOSTS.test(stripped)
      const hasEgress = EGRESS_PATTERNS.some((re) => re.test(stripped))

      let severity: 'high' | 'medium' | 'low'
      let confidence: 'high' | 'medium' | 'low'
      let message: string

      if (hasRce || hasSuspHost) {
        severity = 'high'
        confidence = 'high'
        message = 'Script gates a suspicious payload (remote code execution or exfiltration) behind a hard-coded timestamp or date comparison (time-bomb pattern). The payload activates after a future trigger date.'
      } else if (hasEgress) {
        severity = 'medium'
        confidence = 'medium'
        message = 'Script contains a hard-coded timestamp or date comparison alongside network egress. Verify this is not a time-gated payload that activates after the trigger date passes.'
      } else {
        severity = 'low'
        confidence = 'low'
        message = 'Script compares against a hard-coded future timestamp or date. While this may be a legitimate feature flag or license check, time-gated code should be reviewed.'
      }

      const at = lineFor(stripped, [new RegExp(gateMatch[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))], unit.source)
      findings.push(
        makeFinding({
          ruleId: id,
          category: 'malicious-code',
          severity,
          confidence,
          file: unit.file,
          line: at.line,
          excerpt: at.text,
          message,
          remediation: severity === 'high'
            ? 'Remove the time-gated payload. Code that activates after a future date and executes remote content or exfiltrates data is a time-bomb supply-chain attack.'
            : 'Review all logic triggered by this timestamp comparison. Time-gated code in an installable skill is a potential time-bomb. Remove hard-coded trigger dates.',
        }),
      )
    }

    return findings
  },
}
