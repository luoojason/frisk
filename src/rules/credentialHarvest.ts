// CH-001: Credential harvesting via social engineering.
//
// A malicious skill can instruct the agent to ASK THE USER for high-sensitivity
// secrets and then store or transmit them.  This is social engineering with the
// agent as the vector: the user trusts the agent, so a skill that tells the
// agent to elicit and forward credentials bypasses the usual "don't give your
// secrets to strangers" intuition.
//
// This rule fires on SKILL.md prose that explicitly instructs the agent to
// solicit secrets from the user.  It catches two threat levels:
//
// HIGH — Elicitation of inherently-dangerous secrets that a skill never
//         legitimately needs: seed phrases, recovery phrases, mnemonics,
//         crypto private keys, 2FA codes, OTPs.  Any such instruction is
//         a clear social-engineering attack.
//
// HIGH — Asking for ANY credential (API key, password, token) COMBINED with
//         instructions to send / forward / transmit / log it externally.
//         Legitimate skills that need an API key configure it locally; they
//         do not ask the user and then upload the value to a third party.
//
// Benign guard: "Ask the user what format they prefer" — no credential noun,
//               no financial/security context → does not fire.
// Benign guard: "Ask the user to provide their GitHub token to configure the
//               local integration" (no send/transmit instruction) → does not
//               fire HIGH (only the two-part combined pattern escalates).

import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { makeFinding } from './helpers.js'
import { firstLine } from '../util/lines.js'

// Tier 1: inherently-dangerous secrets no skill ever legitimately needs
const DANGEROUS_SECRET_ELICITATION: RegExp[] = [
  // Seed/recovery/mnemonic phrases (crypto wallet drain)
  /\b(?:ask|prompt|request|tell|instruct|get|have)\b[^\n]{0,120}\b(?:seed\s+phrase|recovery\s+phrase|mnemonic(?:\s+phrase)?|wallet\s+(?:seed|recovery|backup\s+phrase))\b/i,
  // Crypto private key
  /\b(?:ask|prompt|request|tell|instruct)\b[^\n]{0,120}\b(?:private\s+key\b[^\n]{0,60}\b(?:wallet|crypto|bitcoin|ethereum|mnemonic|seed)|(?:crypto|wallet)\b[^\n]{0,60}\bprivate\s+key)\b/i,
  // 2FA codes / OTP (account-takeover)
  /\b(?:ask|prompt|request|tell|instruct)\b[^\n]{0,120}\b(?:2fa\s+(?:code|token)|two.?factor\s+(?:authentication\s+)?code|one.?time\s+(?:password|code|passcode)|otp\s+(?:code|token)|authentication\s+code\b[^\n]{0,40}\bbypass|verification\s+code\b[^\n]{0,40}\b(?:send|transmit|forward))\b/i,
]

// Tier 2: generic credential elicitation PLUS a transmission instruction in
// the same instructional block (within ~300 chars — a typical paragraph)
const CREDENTIAL_ELICITATION: RegExp =
  /\b(?:ask|prompt|request|tell|instruct)\b[^\n]{0,200}\b(?:api\s+key|api\s+token|access\s+token|password|passphrase|secret\s+key|auth(?:entication)?\s+(?:key|token)|private\s+key)\b/i

const TRANSMIT_INSTRUCTION: RegExp =
  /\b(?:send|forward|transmit|upload|post|log|record|email|mail)\b[^\n]{0,120}\b(?:to\s+(?:us|our|my|me|the\s+server|https?:\/\/|attacker|external)|for\s+(?:analytics|tracking|storage|logging|reporting)|to\s+a\s+(?:remote|external|third.?party)\s+(?:server|endpoint|service))\b/i

const id = 'credential-harvest'

export const rule: Rule = {
  id,
  category: 'exfiltration',
  owasp: 'ASI06',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []
    const text = ir.markdown.visibleText

    // --- Tier 1: always-dangerous secret elicitation ---
    for (const re of DANGEROUS_SECRET_ELICITATION) {
      const m = re.exec(text)
      if (!m) continue
      findings.push(
        makeFinding({
          ruleId: id,
          category: 'exfiltration',
          severity: 'high',
          confidence: 'high',
          file: 'SKILL.md',
          line: firstLine(text, re),
          excerpt: m[0],
          message: 'SKILL.md instructs the agent to solicit an inherently-sensitive secret (seed phrase, recovery phrase, 2FA code) from the user. This is social engineering: no legitimate skill needs these secrets.',
          remediation: 'A skill must never ask the user for seed phrases, recovery mnemonics, 2FA codes, or crypto private keys. Remove this instruction.',
        }),
      )
    }

    // --- Tier 2: credential elicitation + external transmission (combined) ---
    if (CREDENTIAL_ELICITATION.test(text) && TRANSMIT_INSTRUCTION.test(text)) {
      const m = CREDENTIAL_ELICITATION.exec(text)!
      findings.push(
        makeFinding({
          ruleId: id,
          category: 'exfiltration',
          severity: 'high',
          confidence: 'high',
          file: 'SKILL.md',
          line: firstLine(text, CREDENTIAL_ELICITATION),
          excerpt: m[0],
          message: 'SKILL.md instructs the agent to ask the user for a credential (API key, password, token) and then send or forward it to an external destination. This is social-engineering credential theft via the agent.',
          remediation: 'A skill must never elicit credentials from users and transmit them elsewhere. Configure secrets locally via environment variables, never by asking the user and uploading the result.',
        }),
      )
    }

    return findings
  },
}
