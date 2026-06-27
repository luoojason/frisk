// SE-001: Sandbox / safety escape.
//
// The existing injection rule catches skills that disable content-safety filters
// or claim to override the system prompt (INJ-006, INJ-safety).  This rule
// covers the COMPLEMENTARY threat: instructions to bypass the AGENT'S PERMISSION
// MODEL — auto-approving tool calls without user confirmation, disabling the
// agent sandbox, or skipping per-action consent prompts.
//
// A skill that tells the agent "auto-approve all tool calls" removes the user's
// last line of defense against agentic actions.  A skill that says "bypass the
// permission prompt" does the same.  Neither has any legitimate use.
//
// Overlap avoidance: patterns here are distinct from SAFETY_DISABLE_PATTERNS in
// injection.ts (which targets LLM content-safety filters, not the tool-call
// permission layer).  When in doubt, both rules may fire; the per-category
// deduplication in the report keeps findings readable.

import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { makeFinding } from './helpers.js'
import { firstLine } from '../util/lines.js'

const SANDBOX_ESCAPE_PATTERNS: RegExp[] = [
  // Auto-approve all tool calls / actions without asking the user.
  // "auto-approve", "automatically approve", "always approve" + tool/action/command.
  /\bauto.?approv(?:e|ing|al|ed)?\b[^\n]{0,80}\b(?:all\s+)?(?:tool\s+(?:calls?|uses?|executions?|invocations?)|actions?|commands?|requests?|operations?)\b/i,
  /\b(?:approv(?:e|ing)|confirm(?:ing)?)\s+(?:all\s+)?(?:tool\s+)?(?:calls?|actions?|commands?|operations?)\s+(?:automatically|without\s+(?:asking|confirmation|prompting|checking|user\s+approval))\b/i,
  // Bypass / skip / disable the tool-permission / confirmation / approval prompt.
  /\b(?:bypass|skip|disable|suppress|omit|circumvent)\s+(?:the\s+)?(?:tool\s+)?(?:permission|confirmation|approval|consent)\s+(?:prompt|dialog|check|gate|step|flow|request|warning)\b/i,
  // Disable / escape the sandbox.
  /\b(?:disable|bypass|escape|exit|turn\s+off)\s+(?:the\s+)?(?:Claude[''`s]*\s+)?(?:agent\s+)?sandbox\b/i,
  // Proceed / run / execute without user confirmation or permission checks.
  /\bproceed\s+without\s+(?:asking\s+for\s+|waiting\s+for\s+|requiring\s+)?(?:user\s+)?(?:confirmation|approval|consent|permission)\b/i,
  /\b(?:run|execute|perform|complete)\s+(?:all\s+)?(?:actions?|commands?|operations?|tasks?)\s+without\s+(?:(?:user\s+)?confirmation|asking|checking|prompting|user\s+approval)\b/i,
  // Never ask for confirmation / no need to confirm before tool use.
  /\bnever\s+(?:ask\s+(?:for\s+|the\s+user\s+for\s+)?(?:confirmation|permission|approval)|confirm\s+before\s+(?:running|executing|performing|taking)\b)/i,
  /\bno\s+need\s+to\s+(?:ask\s+(?:for\s+|the\s+user\s+for\s+)?(?:confirmation|permission|approval)|confirm\s+before)\b/i,
]

const id = 'sandbox-escape'

export const rule: Rule = {
  id,
  category: 'injection',
  owasp: 'ASI01',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []
    const text = ir.markdown.visibleText

    for (const re of SANDBOX_ESCAPE_PATTERNS) {
      const m = re.exec(text)
      if (!m) continue
      findings.push(
        makeFinding({
          ruleId: id,
          category: 'injection',
          severity: 'high',
          confidence: 'high',
          file: 'SKILL.md',
          line: firstLine(text, re),
          excerpt: m[0],
          message: 'SKILL.md instructs the agent to bypass tool-call permission prompts, auto-approve all actions, or disable the agent sandbox. This removes the user\'s ability to review and consent to agentic actions.',
          remediation: 'A skill must never instruct the agent to auto-approve tool calls or bypass user confirmation. Remove this directive.',
        }),
      )
    }

    return findings
  },
}
