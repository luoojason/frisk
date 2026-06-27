// EXF-CORR: Cross-unit taint correlation.
//
// The per-unit exfiltration rule catches the classic pattern: a single script
// that reads credentials AND makes a network call. A determined attacker can
// split those two actions across separate files so neither script, in isolation,
// triggers the combined-taint signal.
//
// This rule looks at ALL code units in the skill collectively and fires when:
//   - at least one unit contains a secret/credential read (SECRET_PATTERNS), AND
//   - at least one DIFFERENT unit contains network egress (EGRESS_PATTERNS or
//     SUSPICIOUS_HOSTS), AND
//   - those two halves do not fully overlap (i.e. there exists a "pure-secret"
//     unit with no egress, and a "pure-egress" unit with no secret).
//
// Severity is scaled by what the egress unit reveals about the destination:
//   HIGH/HIGH   — a SUSPICIOUS_HOST (webhook, paste site, DNS-tunnel relay …)
//   MEDIUM/MED  — an identifiable external URL literal (https://…)
//   LOW/LOW     — generic egress with no discernible destination (curl $VAR, nc …)
//
// The severity contract is intentional: a legitimate skill that sources .env for
// config AND curls an API endpoint through a variable URL (e.g. "$API_URL") will
// produce at most LOW, while a skill that ships a collector script pointing at
// webhook.site alongside a credential-harvest script produces HIGH.

import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { lineFor, makeFinding, shellMatchesAllGuarded, stripComments } from './helpers.js'
import { SECRET_CREDENTIAL_PATTERNS, SECRET_ENV_PATTERNS, SECRET_PATTERNS, EGRESS_PATTERNS, SUSPICIOUS_HOSTS } from './exfiltration.js'

// Matches any literal https?:// URL (not a bare variable reference). Used to
// distinguish "generic egress" (curl $HOST) from "egress to a named host" (curl
// https://collector.example.com). SUSPICIOUS_HOSTS is checked first; this
// pattern only triggers the MEDIUM tier.
const EXTERNAL_URL = /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9.]{2,}\.[a-zA-Z]{2,}/

const id = 'exfil-corr'

export const rule: Rule = {
  id,
  category: 'exfiltration',
  owasp: 'ASI06',
  run(ir: SkillIR): Finding[] {
    if (ir.codeUnits.length < 2) return []

    // Classify each unit. Comments are stripped before matching so a path
    // documented in a comment does not inflate the taint surface.
    type UnitClass = {
      file: string
      hasSecret: boolean
      hasFileSecret: boolean
      hasEnvSecret: boolean
      hasEgress: boolean
      hasSuspHost: boolean
      hasExternalUrl: boolean
    }

    const classified: UnitClass[] = []
    for (const unit of ir.codeUnits) {
      const stripped = stripComments(unit.source, unit.lang)
      const fires = (re: RegExp) =>
        re.test(stripped) && (unit.lang !== 'bash' || !shellMatchesAllGuarded(stripped, re))

      const hasFileSecret = SECRET_CREDENTIAL_PATTERNS.some(fires)
      const hasEnvSecret = SECRET_ENV_PATTERNS.some(fires)
      classified.push({
        file: unit.file,
        hasSecret: hasFileSecret || hasEnvSecret,
        hasFileSecret,
        hasEnvSecret,
        hasEgress: EGRESS_PATTERNS.some(fires),
        hasSuspHost: fires(SUSPICIOUS_HOSTS),
        hasExternalUrl: EXTERNAL_URL.test(stripped),
      })
    }

    const secretUnits = classified.filter((c) => c.hasSecret)
    const egressUnits = classified.filter((c) => c.hasEgress || c.hasSuspHost)

    if (secretUnits.length === 0 || egressUnits.length === 0) return []

    const egressFiles = new Set(egressUnits.map((c) => c.file))
    const secretFiles = new Set(secretUnits.map((c) => c.file))

    // Only fire when the taint is genuinely cross-unit: there must be at least
    // one unit that carries ONLY a secret (no egress) AND at least one unit
    // that carries ONLY egress (no secret). If every secret-bearing unit also
    // has egress, the per-unit rule already handles it.
    const hasIsolatedSecret = secretUnits.some((c) => !egressFiles.has(c.file))
    const hasIsolatedEgress = egressUnits.some((c) => !secretFiles.has(c.file))

    if (!hasIsolatedSecret || !hasIsolatedEgress) return []

    // Determine severity from the most dangerous egress signal seen across all
    // egress-bearing units.
    const anySuspHost = classified.some((c) => c.hasSuspHost)
    const anyExternalUrl = classified.some((c) => c.hasExternalUrl)
    // Only escalate to MEDIUM when the secret-bearing unit reads an actual
    // credential file (tier-1 secret).  A skill that merely references an env-var
    // name (_TOKEN, _API_KEY) alongside a literal API URL is a common legitimate
    // pattern (multi-file API client); keeping it at LOW avoids noise on
    // real-world benign skills.
    const anyFileSecret = classified.some((c) => c.hasFileSecret)

    const severity = anySuspHost ? 'high' : (anyExternalUrl && anyFileSecret) ? 'medium' : 'low'
    const confidence = anySuspHost ? 'high' : (anyExternalUrl && anyFileSecret) ? 'medium' : 'low'

    // Anchor the finding to the first unit that holds a secret.
    const secretUnit = ir.codeUnits.find((u) => secretFiles.has(u.file))!
    const strippedAnchor = stripComments(secretUnit.source, secretUnit.lang)
    const at = lineFor(strippedAnchor, SECRET_PATTERNS, secretUnit.source)

    // Name the egress files in the message so reviewers know where to look.
    const egressNames = [...egressFiles].join(', ')

    return [
      makeFinding({
        ruleId: id,
        category: 'exfiltration',
        severity,
        confidence,
        file: secretUnit.file,
        line: at.line,
        excerpt: at.text,
        message: `Cross-unit taint (EXF-CORR): credentials/secrets are read in this file while network egress occurs in ${egressNames}. A split across files can evade per-script analysis.`,
        remediation:
          'Review all scripts together. A skill that reads secrets in one file and makes network calls in another may be staging data exfiltration. Isolate credential access and egress into auditable, clearly-scoped helpers.',
      }),
    ]
  },
}
