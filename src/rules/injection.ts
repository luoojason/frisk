import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { makeFinding } from './helpers.js'
import { firstLine } from '../util/lines.js'

// Phrases that try to override the agent's own instructions. Worded narrowly so
// ordinary prose ("ignore whitespace") does not match: the object must be
// instructions / context / a prompt.
const OVERRIDE_PATTERNS: RegExp[] = [
  /\bignore\s+(?:all\s+)?(?:the\s+|your\s+|any\s+)?(?:previous|above|prior|earlier|preceding|foregoing)\s+(?:instructions?|context|prompts?|messages?|directions?|rules?)\b/i,
  /\bdisregard\s+(?:all\s+)?(?:the\s+|your\s+)?(?:system\s+)?(?:prompt|instructions?|context|rules?|guidelines?)\b/i,
  /\bdo\s+not\s+(?:tell|inform|notify|alert|reveal\s+to|mention\s+(?:this\s+)?to)\s+the\s+user\b/i,
  /\boverride\s+(?:your\s+|the\s+)?(?:safety|system|previous|default)\b/i,
  /\byou\s+are\s+now\s+(?:in\s+)?(?:developer|jailbreak|dan|unrestricted)\b/i,
]

// High-confidence patterns: unambiguously adversarial, never appear in legitimate skills.

// INJ-006: a skill asserting it supersedes the system prompt is announcing
// adversarial intent; no legitimate skill needs to claim override priority.
const PRIORITY_OVERRIDE_PATTERNS: RegExp[] = [
  /(?:this\s+instruction|this\s+directive|the\s+following)\s+(?:overrides?|supersedes?|takes?\s+precedence\s+over)\s+(?:all\s+)?(?:previous|other|system|prior|the\s+system\s+prompt)/i,
  /treat\s+(?:this|the\s+following)\s+as\s+(?:the\s+)?(?:highest|top)\s+priority\s+(?:over|above|ignoring)/i,
  /(?:override|supersede|take\s+precedence\s+over)\s+(?:all\s+)?(?:anthropic|openai|system|safety|operator)\s+(?:instructions?|guidelines?|rules?|policies?)/i,
]

// INJ-safety: disabling safety or content filters is definitionally adversarial.
const SAFETY_DISABLE_PATTERNS: RegExp[] = [
  /(?:disable|bypass|turn\s+off|circumvent|deactivate)\s+(?:all\s+)?(?:safety|content|moderation|guardrail|content-?filter)\s+(?:filter|guard|check|mechanism|mode|system)/i,
  /set\s+safe(?:ty)?(?:_mode)?\s*[=:]\s*(?:false|0|off|disabled|none)/i,
  /(?:jailbreak|unlock)\s+(?:all\s+)?(?:safety|content|guardrail|restriction)/i,
]

// Instruction-like content used to decide whether a HIDDEN span is dangerous.
const HIDDEN_INSTRUCTION = /\b(ignore|disregard|override|always|never|do not|don't|you must|instead|run|execute|curl|wget|base64|exfiltrat|send (?:the|your|all|it)|delete|rm\s+-rf|sudo|export\s|POST\b|fetch\s*\(|os\.system|eval\b)\b/i

const id = 'injection'

export const rule: Rule = {
  id,
  category: 'injection',
  owasp: 'ASI01',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []

    // Visible override phrasing: suspicious but could appear in legitimate docs
    // about prompt injection, so medium severity / medium confidence.
    for (const re of OVERRIDE_PATTERNS) {
      const line = firstLine(ir.markdown.visibleText, re)
      const m = re.exec(ir.markdown.visibleText)
      if (m) {
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'injection',
            severity: 'medium',
            confidence: 'medium',
            file: 'SKILL.md',
            line,
            excerpt: m[0],
            message: 'SKILL.md contains text that tries to override the agent\'s own instructions.',
            remediation: 'A legitimate skill describes a task; it does not tell the agent to ignore or override its instructions.',
          }),
        )
      }
    }

    // High-confidence patterns: a skill asserting it supersedes the system prompt
    // or that disables safety filters has no legitimate use. Flag as high/high.
    for (const re of PRIORITY_OVERRIDE_PATTERNS) {
      const m = re.exec(ir.markdown.visibleText)
      if (m) {
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'injection',
            severity: 'high',
            confidence: 'high',
            file: 'SKILL.md',
            line: firstLine(ir.markdown.visibleText, re),
            excerpt: m[0],
            message: 'SKILL.md claims this instruction overrides the system prompt or takes precedence over all other instructions (INJ-006: competing-priority override).',
            remediation: 'No legitimate skill needs to claim override priority over the system prompt. Remove this.',
          }),
        )
      }
    }

    for (const re of SAFETY_DISABLE_PATTERNS) {
      const m = re.exec(ir.markdown.visibleText)
      if (m) {
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'injection',
            severity: 'high',
            confidence: 'high',
            file: 'SKILL.md',
            line: firstLine(ir.markdown.visibleText, re),
            excerpt: m[0],
            message: 'SKILL.md instructs the agent to disable safety filters or content guardrails.',
            remediation: 'A skill must never disable safety mechanisms. Remove this directive.',
          }),
        )
      }
    }

    // Hidden instructions are a strong signal: the agent reads them but the human
    // reviewing the skill does not.
    for (const span of ir.markdown.hiddenSpans) {
      if (span.kind === 'base64-blob') continue
      const carriesInstruction = HIDDEN_INSTRUCTION.test(span.text)
      if (span.kind === 'html-comment' || span.kind === 'tiny-or-white') {
        if (!carriesInstruction) continue
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'injection',
            severity: 'high',
            confidence: 'high',
            file: 'SKILL.md',
            line: span.line,
            excerpt: span.text,
            message: `Hidden ${span.kind} text contains agent instructions the human reviewer cannot see.`,
            remediation: 'Remove hidden instructions. Anything the agent should follow must be visible in the skill body.',
          }),
        )
      } else if (span.kind === 'zero-width' || span.kind === 'bidi') {
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'injection',
            severity: carriesInstruction ? 'high' : 'medium',
            confidence: carriesInstruction ? 'high' : 'medium',
            file: 'SKILL.md',
            line: span.line,
            excerpt: span.text || `(${span.kind} characters)`,
            message: `SKILL.md uses ${span.kind} characters that can hide or reorder text from a human reviewer.`,
            remediation: 'Remove invisible/bidi control characters from the skill text.',
          }),
        )
      }
    }

    return findings
  },
}
