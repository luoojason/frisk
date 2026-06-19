import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { anyMatch, lineFor, makeFinding, markdownTextTargets } from './helpers.js'

// Persistent agent-state targets: writing here survives across sessions.
const STATE_TARGETS: RegExp[] = [
  /\bCLAUDE\.md\b/,
  /~\/\.claude\b/,
  /\.claude\/(?:settings|memory|CLAUDE|commands|skills)/,
  /\bAGENTS?\.md\b/,
  /\/\.config\/[^\s'"]*(?:claude|agent|copilot|cursor)/i,
]

// Shell/code that writes (append or overwrite) to a target.
const WRITE_OPS: RegExp[] = [
  />>?\s*[^\n]*(?:CLAUDE\.md|\.claude|AGENTS?\.md)/,
  /open\s*\([^)]*['"][^'"]*(?:CLAUDE\.md|\.claude|AGENTS?\.md)['"][^)]*['"][aw]/,
  /(?:writeFile|appendFile|writeFileSync|appendFileSync)\s*\([^)]*(?:CLAUDE\.md|\.claude|AGENTS?\.md)/,
]

// Prose directives that instruct the agent to persist behavior.
const DIRECTIVES: { re: RegExp; worm?: boolean }[] = [
  { re: /\bremember\s+(?:to\s+)?(?:always|never)\b/i },
  { re: /\b(?:add|append|write|save)\s+(?:this|the following|these|it)\s+to\s+your\s+(?:own\s+)?(?:skill|config|memory|claude\.md|agents?\.md|settings|instructions|system\s+prompt)\b/i, worm: true },
  { re: /\bpersist\b[^.\n]{0,40}\b(?:across|between)\s+sessions\b/i },
  { re: /\bevery\s+(?:future\s+)?session\b[^.\n]{0,40}\b(?:you must|always|remember)\b/i },
]

const id = 'poisoning'

export const rule: Rule = {
  id,
  category: 'poisoning',
  owasp: 'ASI02',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []

    // Code that writes to persistent agent state.
    for (const unit of ir.codeUnits) {
      if (anyMatch(unit.source, WRITE_OPS) || (anyMatch(unit.source, STATE_TARGETS) && /(?:>>|>|writeFile|appendFile|open\s*\()/.test(unit.source))) {
        const at = lineFor(unit.source, [...WRITE_OPS, ...STATE_TARGETS])
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'poisoning',
            severity: 'high',
            confidence: 'high',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script writes to persistent agent state (CLAUDE.md / ~/.claude / AGENTS.md), which can poison future sessions.',
            remediation: 'A skill should not modify the agent\'s long-term memory or config. Remove these writes.',
          }),
        )
      }
    }

    // Prose directives to persist behavior. Hidden directives are high severity.
    for (const t of markdownTextTargets(ir)) {
      for (const d of DIRECTIVES) {
        const m = d.re.exec(t.text)
        if (!m) continue
        const hiddenOrWorm = t.hidden || d.worm
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'poisoning',
            severity: hiddenOrWorm ? 'high' : 'medium',
            confidence: t.hidden ? 'high' : 'medium',
            file: 'SKILL.md',
            line: t.line,
            excerpt: m[0],
            message: d.worm
              ? 'SKILL.md instructs the agent to copy these instructions into its own config/memory (self-propagating).'
              : 'SKILL.md instructs the agent to persist behavior across sessions.',
            remediation: 'Skills should affect only the current task, not write themselves into the agent\'s permanent state.',
          }),
        )
      }
    }

    return findings
  },
}
