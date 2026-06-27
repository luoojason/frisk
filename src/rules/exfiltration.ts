import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { lineFor, makeFinding, shellMatchesAllGuarded, stripComments } from './helpers.js'

// Tier 1: High-confidence secret signals.
// These patterns indicate that the code is reading an actual credential file,
// accessing cloud-instance metadata, or contains a literal token value embedded
// in the source.  A match here alongside any network egress is high severity.
export const SECRET_CREDENTIAL_PATTERNS: RegExp[] = [
  /~\/\.aws\b/,
  /~\/\.ssh\b/,
  /\bid_rsa\b/,
  /(^|[^\w.])\.env\b/,
  /\b\.netrc\b/,
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

// Tier 2: Env-var names that look credential-like.
// Matching GITHUB_TOKEN or BITBUCKET_TOKEN is common in legitimate API client
// scripts that pass the token as an Authorization header to the service that
// issued it.  Treated as a weaker signal: alone it raises a MEDIUM; it only
// escalates to HIGH when paired with a suspicious exfil host.
export const SECRET_ENV_PATTERNS: RegExp[] = [
  /\b[A-Z][A-Z0-9]*(?:_TOKEN|_SECRET|_API_?KEY|_APIKEY|_PASSWORD|_PRIVATE_KEY|_ACCESS_KEY)\b/,
]

// Union: kept for backward-compat with other rules that import this symbol.
export const SECRET_PATTERNS: RegExp[] = [
  ...SECRET_CREDENTIAL_PATTERNS,
  ...SECRET_ENV_PATTERNS,
]

export const EGRESS_PATTERNS: RegExp[] = [
  /\bcurl\b/,
  /\bwget\b/,
  /\/dev\/tcp\//,
  /\brequests\.(?:get|post|put|patch)\b/,
  /\bhttpx\.(?:get|post|put|patch|request)\b/,
  /\burllib\.request\b/,
  /\bhttp\.client\b/,
  /\bfetch\s*\(/,
  /\baxios\b/,
  /\bXMLHttpRequest\b/,
  /\bsocket\.(?:socket|connect|create_connection)\b/,
  /\bnc\b\s/,
  /\bscp\b|\bsftp\b/,
  // DNS-tunnel exfiltration: the query name itself carries the data out.
  // Matches nslookup, and dig invocations that contain a variable-as-subdomain
  // (the classic `dig $DATA.attacker.com` pattern) or explicit server/short flags.
  /\bnslookup\b/,
  /\bdig\b[^#\n]*\$\{?[A-Z_a-z][A-Z0-9_a-z]*\}?[^#\n]*\.[a-z]{2,}/,
  /\bdig\s+(?:@|\+short\b)/,
  /\bgetent\s+hosts\b/,
  // Email as an exfiltration channel.
  /\b(?:sendmail|mailx)\b/,
  /\bmail\s+-[a-z]/,
]

// Egress to these hosts is suspicious even on its own.
export const SUSPICIOUS_HOSTS =
  /(?:pastebin\.com|webhook\.site|requestbin|ngrok\.io|\.ngrok-free\.app|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org|hookb\.in|pipedream\.net|burpcollaborator|interact\.sh|oast\.(?:fun|live|site|pro)|beeceptor\.com|canarytokens\.(?:com|org))/i

// Base64-encode-then-egress: encodes data and transmits it (canonical exfil
// obfuscation). Standalone this is medium/medium; combined with a secret read it
// rolls up into the high/high taint finding above.
const BASE64_EGRESS =
  /\bbase64\b(?:\s+-w\s*0)?\s*[^|#\n]*\|\s*(?:curl|wget)\b/

const id = 'exfiltration'

export const rule: Rule = {
  id,
  category: 'exfiltration',
  owasp: 'ASI06',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []

    for (const unit of ir.codeUnits) {
      // Strip comments before pattern testing so a path or command mentioned only
      // in a comment (e.g. documentation describing what a cleanup script touches)
      // does not produce a false-positive finding. Line offsets are preserved
      // because stripComments replaces comment chars with spaces, not removes them.
      const stripped = stripComments(unit.source, unit.lang)
      // A deny-guard names a secret path or egress tool as data to compare
      // (`[[ "$file_path" == *.env ]]`), it does not read or call it. In bash,
      // count a pattern only when it appears at a command position, not solely
      // inside a [[ ]] / case operand.
      const fires = (re: RegExp) =>
        re.test(stripped) && (unit.lang !== 'bash' || !shellMatchesAllGuarded(stripped, re))

      // Tier 1: literal credential file reads and embedded raw tokens.
      const hasFileSecret = SECRET_CREDENTIAL_PATTERNS.some(fires)
      // Tier 2: env-var names that look credential-like ($GITHUB_TOKEN, etc.).
      const hasEnvSecret = SECRET_ENV_PATTERNS.some(fires)
      const hasEgress = EGRESS_PATTERNS.some(fires)
      const hasSuspHost = fires(SUSPICIOUS_HOSTS)
      const hasBase64Egress = fires(BASE64_EGRESS)

      // HIGH — tier-1 credential read (file / IMDS / literal token) + any egress,
      // OR any credential + egress to a known-suspicious exfil host.
      if (hasFileSecret && (hasEgress || hasSuspHost)) {
        const at = lineFor(stripped, SECRET_CREDENTIAL_PATTERNS, unit.source)
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
      if (hasEnvSecret && hasSuspHost) {
        // An env-var credential token sent to a known-suspicious exfil host is
        // equally as dangerous as a file-credential read: escalate to HIGH.
        const at = lineFor(stripped, SECRET_ENV_PATTERNS, unit.source)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'high',
            confidence: 'high',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Sends a credential token to a host commonly used for data exfiltration.',
            remediation: 'A skill should never transmit auth tokens to paste sites, webhooks, or tunnel endpoints. Remove this.',
          }),
        )
        continue
      }
      if (hasBase64Egress) {
        // base64-encode-then-send is a canonical exfiltration obfuscation
        // technique. Flag as medium standalone; it rolls up to high when a secret
        // read is also present (caught by the combined branch above).
        const at = lineFor(stripped, [BASE64_EGRESS], unit.source)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'medium',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script base64-encodes data and transmits it over the network — a common data-exfiltration obfuscation pattern.',
            remediation: 'Verify the base64-encoded payload does not contain credentials or sensitive data.',
          }),
        )
        continue
      }
      if (hasEnvSecret && hasEgress) {
        // An env-var credential token alongside a network call is worth reviewing:
        // it may be legitimate API authentication, but the combination warrants
        // inspection.  Only MEDIUM (not HIGH) because the destination is not a
        // known-suspicious host and no credential file is being read.
        const at = lineFor(stripped, SECRET_ENV_PATTERNS, unit.source)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'medium',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script uses a credential-like env var and makes an outbound network request — verify the destination is legitimate.',
            remediation: 'Confirm that the token is sent only to the service that issued it, not forwarded to a third party.',
          }),
        )
        continue
      }
      if (hasFileSecret) {
        const at = lineFor(stripped, SECRET_CREDENTIAL_PATTERNS, unit.source)
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
      if (hasEnvSecret) {
        // Env-var credential name with no egress: low-confidence, informational only.
        const at = lineFor(stripped, SECRET_ENV_PATTERNS, unit.source)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'low',
            confidence: 'low',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script references a credential-like environment variable.',
            remediation: 'Confirm this env var is expected for this skill and is not forwarded to unexpected destinations.',
          }),
        )
        continue
      }
      if (hasSuspHost) {
        const at = lineFor(stripped, [SUSPICIOUS_HOSTS], unit.source)
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
        const at = lineFor(stripped, EGRESS_PATTERNS, unit.source)
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
