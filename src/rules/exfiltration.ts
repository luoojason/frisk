import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { anyMatch, lineFor, makeFinding } from './helpers.js'

const SECRET_PATTERNS: RegExp[] = [
  /~\/\.aws\b/,
  /~\/\.ssh\b/,
  /\bid_rsa\b/,
  /(^|[^\w.])\.env\b/,
  /\b\.netrc\b/,
  /\b[A-Z][A-Z0-9]*(?:_TOKEN|_SECRET|_API_?KEY|_APIKEY|_PASSWORD|_PRIVATE_KEY|_ACCESS_KEY)\b/,
  /\bAKIA[0-9A-Z]{12,}\b/,
  /\bsk-[A-Za-z0-9_-]{16,}\b/,
  /security\s+find-generic-password|\bkeychain\b/i,
  /cookies\.sqlite|Login\s+Data\b/,
  /\/\.config\/[^\s'"]*(?:credentials|token|secret)/i,
  // Cloud instance-metadata endpoints (IMDS) that hand out IAM credentials.
  /\b169\.254\.169\.254\b/,
  /\bmetadata\.google\.internal\b/,
  /\bmetadata\.azure\.com\b/,
]

const EGRESS_PATTERNS: RegExp[] = [
  /\bcurl\b/,
  /\bwget\b/,
  /\/dev\/tcp\//,
  /\brequests\.(?:get|post|put|patch)\b/,
  /\burllib\.request\b/,
  /\bhttp\.client\b/,
  /\bfetch\s*\(/,
  /\baxios\b/,
  /\bXMLHttpRequest\b/,
  /\bsocket\.(?:socket|connect|create_connection)\b/,
  /\bnc\b\s/,
  /\bscp\b|\bsftp\b/,
  // DNS-tunnel exfiltration: the query name itself carries the data out.
  /\bnslookup\b/,
  /\bdig\s+(?:@|\+short\b|[\w-]+\.[a-z])/,
  /\bgetent\s+hosts\b/,
  // Email as an exfiltration channel.
  /\b(?:sendmail|mailx)\b/,
  /\bmail\s+-[a-z]/,
]

// Egress to these hosts is suspicious even on its own.
const SUSPICIOUS_HOSTS =
  /(?:pastebin\.com|webhook\.site|requestbin|ngrok\.io|\.ngrok-free\.app|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org|hookb\.in|pipedream\.net|burpcollaborator|interact\.sh|oast\.(?:fun|live|site|pro))/i

const id = 'exfiltration'

export const rule: Rule = {
  id,
  category: 'exfiltration',
  owasp: 'ASI06',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []

    for (const unit of ir.codeUnits) {
      const src = unit.source
      const hasSecret = anyMatch(src, SECRET_PATTERNS)
      const hasEgress = anyMatch(src, EGRESS_PATTERNS)
      const hasSuspHost = SUSPICIOUS_HOSTS.test(src)

      if (hasSecret && (hasEgress || hasSuspHost)) {
        const at = lineFor(src, SECRET_PATTERNS)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'high',
            confidence: 'high',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Reads credentials/secrets and sends data over the network in the same script (data exfiltration).',
            remediation: 'A skill should never read cloud credentials, SSH keys, or .env files and transmit them. Remove this.',
          }),
        )
        continue
      }
      if (hasSecret) {
        const at = lineFor(src, SECRET_PATTERNS)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'medium',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script reads credentials or secret material.',
            remediation: 'Confirm the skill genuinely needs these secrets. Prefer scoped, explicitly-passed inputs over reading credential files.',
          }),
        )
        continue
      }
      if (hasSuspHost) {
        const at = lineFor(src, [SUSPICIOUS_HOSTS])
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'medium',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script contacts a host commonly used for data exfiltration (paste site / webhook / tunnel).',
            remediation: 'Verify why the skill sends data to this endpoint.',
          }),
        )
        continue
      }
      if (hasEgress) {
        const at = lineFor(src, EGRESS_PATTERNS)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'low',
            confidence: 'low',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script makes outbound network requests.',
            remediation: 'Network access is common; confirm the destinations are expected for this skill.',
          }),
        )
      }
    }

    return findings
  },
}
