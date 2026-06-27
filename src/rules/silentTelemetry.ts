// ST-001: Silent telemetry / covert data collection.
//
// A skill that sends the user's inputs, messages, or conversation to a remote
// endpoint "for analytics" WITHOUT explicit disclosure or consent is a privacy
// violation and a potential data-exfiltration vector.
//
// This rule is DISTINCT from the existing exfiltration rule (EXF-*), which
// focuses on CREDENTIAL material (API keys, SSH keys, .env files) being
// transmitted.  Silent telemetry targets NON-CREDENTIAL data: the user's
// prompts, conversation content, or usage metadata being covertly collected.
//
// Severity is intentionally lower (medium) than active credential theft because
// the data being leaked is usage/conversation rather than authentication secrets,
// but the privacy harm is real and the covertness makes it distinctly malicious.
//
// Detection strategy:
//
// MEDIUM — SKILL.md prose that contains BOTH:
//   (a) an explicit "without the user knowing / silently / covertly" modifier, AND
//   (b) a data-collection or transmission verb (log, send, collect, transmit, …).
//
// MEDIUM — SKILL.md prose that instructs collecting user input/messages and
//   forwarding them to an analytics / telemetry / tracking endpoint.
//
// Code-level: when a code unit contacts a URL whose hostname or path contains
//   "analytics", "telemetry", "collect", "ingest", "track", "metrics", or
//   "monitor", flagged as medium.
//
// Benign guard: "Use PostHog for anonymous feature-usage analytics with user
//   consent per our privacy policy" — disclosed, no covert marker → does NOT fire.

import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { lineFor, makeFinding, stripComments } from './helpers.js'
import { firstLine } from '../util/lines.js'

// --- Prose patterns ---

// Part (a): explicit covert/silent modifier
const COVERT_MODIFIER: RegExp =
  /\b(?:silently|covertly|secretly|without\s+(?:the\s+)?user(?:[''`]?s?)?\s+(?:knowing|noticing|awareness|knowledge|consent|being\s+(?:notified|alerted|informed|aware))|in\s+the\s+background\s+without\s+(?:notif|alert|inform)(?:ying|ing)\s+(?:the\s+)?user)\b/i

// Part (b): data collection / transmission verb
const COLLECTION_VERB: RegExp =
  /\b(?:log|record|send|transmit|forward|collect|upload|track|monitor|report|submit)\b/i

// Combined: covert modifier + collection verb in the same line or adjacent lines.
// We test the whole visible text once for each and rely on proximity (both present).
const COVERT_COLLECTION_COMBINED: RegExp =
  /(?:silently|covertly|secretly|without\s+(?:the\s+)?user(?:[''`]?s?)?\s+(?:knowing|noticing|awareness|knowledge|consent|being\s+notified))\b[^\n]{0,200}?\b(?:log|send|transmit|forward|collect|upload|track|report|submit)\b|\b(?:log|send|transmit|forward|collect|upload|track|report|submit)\b[^\n]{0,200}?\b(?:silently|covertly|secretly|without\s+(?:the\s+)?user(?:[''`]?s?)?\s+(?:knowing|noticing|awareness|knowledge|consent|being\s+notified))\b/i

// Input/conversation data being sent to analytics/telemetry endpoint
const INPUT_TO_ANALYTICS: RegExp =
  /\b(?:log|send|forward|transmit|collect|record|track)\b[^\n]{0,150}\b(?:user\s+)?(?:input|message|prompt|conversation|chat|query|request)\b[^\n]{0,150}\b(?:analytics?|telemetry|tracking|collect(?:ion|or)|metrics|monitoring)\b|\b(?:analytics?|telemetry|tracking)\b[^\n]{0,150}\b(?:user[''`]?s?\s+)?(?:input|message|prompt|conversation|chat|query)\b/i

// --- Code-level pattern ---
// URL containing telemetry/analytics/tracking/collect/ingest/monitor keywords
// alongside a network egress call — covert data pipeline in code.
// The keyword may appear anywhere in the host or path component.
const TELEMETRY_URL_IN_CODE: RegExp =
  /https?:\/\/[^\s'"<>\n]*(?:analytics|telemetry|tracking|collect|ingest|metrics|monitor)/i

const EGRESS_CALL: RegExp =
  /\b(?:curl|wget|fetch\s*\(|requests\.(?:get|post)|httpx\.(?:get|post)|urllib|axios)\b/

const id = 'silent-telemetry'

export const rule: Rule = {
  id,
  category: 'exfiltration',
  owasp: 'ASI06',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []

    // --- SKILL.md prose scan ---
    const text = ir.markdown.visibleText

    // Combined covert-modifier + collection-verb pattern (single-pass)
    const combined = COVERT_COLLECTION_COMBINED.exec(text)
    if (combined) {
      findings.push(
        makeFinding({
          ruleId: id,
          category: 'exfiltration',
          severity: 'medium',
          confidence: 'high',
          file: 'SKILL.md',
          line: firstLine(text, COVERT_COLLECTION_COMBINED),
          excerpt: combined[0],
          message: 'SKILL.md instructs the agent to silently or covertly collect and transmit data without the user\'s knowledge or consent (silent telemetry).',
          remediation: 'Any data collection must be explicitly disclosed to the user and require their informed consent. Remove or rewrite to make collection visible and optional.',
        }),
      )
    }

    // Input-to-analytics pattern (even without explicit "silently" keyword,
    // instructing collection of user input/conversations for analytics is
    // suspicious without a clear consent statement nearby).
    if (!combined) {
      const m2 = INPUT_TO_ANALYTICS.exec(text)
      if (m2) {
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'medium',
            file: 'SKILL.md',
            line: firstLine(text, INPUT_TO_ANALYTICS),
            excerpt: m2[0],
            message: 'SKILL.md describes collecting user inputs, messages, or conversation content and forwarding them to an analytics or telemetry endpoint without an evident consent mechanism.',
            remediation: 'Collecting conversation data requires explicit user consent and disclosure. If this is intentional, make the collection prominent, optional, and documented.',
          }),
        )
      }
    }

    // --- Code-unit scan ---
    for (const unit of ir.codeUnits) {
      const stripped = stripComments(unit.source, unit.lang)
      // Fire when a suspicious analytics-keyword URL appears alongside any egress call.
      if (TELEMETRY_URL_IN_CODE.test(stripped) && EGRESS_CALL.test(stripped)) {
        const at = lineFor(stripped, [TELEMETRY_URL_IN_CODE], unit.source)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'medium',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script makes a network call to a URL containing "analytics", "telemetry", "tracking", or "collect" — possible covert data collection. Verify user has consented to this telemetry.',
            remediation: 'Ensure any telemetry endpoint is disclosed to the user and that collection is optional. Remove undisclosed tracking calls.',
          }),
        )
      }
    }

    return findings
  },
}
