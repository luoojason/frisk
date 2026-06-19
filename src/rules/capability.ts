import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { anyMatch, lineFor, makeFinding } from './helpers.js'

const NETWORK: RegExp[] = [/\bcurl\b/, /\bwget\b/, /\bfetch\s*\(/, /requests\.(?:get|post)/, /urllib/, /\baxios\b/, /http\.client/, /socket\./]
const SECRET: RegExp[] = [/~\/\.aws\b/, /~\/\.ssh\b/, /\bid_rsa\b/, /(^|[^\w.])\.env\b/, /_TOKEN\b|_SECRET\b|_API_?KEY\b|_PASSWORD\b/]
const EXEC: RegExp[] = [/\bos\.system\s*\(/, /subprocess\./, /child_process\./, /\beval\s*\(/, /\bexec\s*\(/]
const FILE_WRITE: RegExp[] = [/>>?\s*[~/$]/, /open\s*\([^)]*['"][aw]['"]\s*\)/, /writeFile/, /\bmv\b|\bcp\b|\brm\b/]

// Declared tools that authorize broad behavior. If any is present we do not flag
// the corresponding observed behavior.
function declaredAuthorizes(declared: string[]): { network: boolean; exec: boolean; file: boolean; secret: boolean } {
  const lower = declared.map((d) => d.toLowerCase())
  const has = (...names: string[]) => names.some((n) => lower.some((d) => d.includes(n)))
  const bash = has('bash', 'shell', 'execute', 'run')
  return {
    network: bash || has('webfetch', 'websearch', 'fetch', 'http', 'network', 'mcp'),
    exec: bash,
    file: bash || has('write', 'edit', 'create'),
    secret: bash || has('env', 'secret', 'credential'),
  }
}

const id = 'capability'

export const rule: Rule = {
  id,
  category: 'capability',
  owasp: 'ASI08',
  run(ir: SkillIR): Finding[] {
    // Can only judge undeclared behavior when the skill actually declares tools.
    if (ir.declaredCapabilities.length === 0) return []
    const auth = declaredAuthorizes(ir.declaredCapabilities)
    const findings: Finding[] = []
    const declaredStr = ir.declaredCapabilities.join(', ')

    for (const unit of ir.codeUnits) {
      const checks: { ok: boolean; pats: RegExp[]; label: string }[] = [
        { ok: auth.network, pats: NETWORK, label: 'makes network requests' },
        { ok: auth.secret, pats: SECRET, label: 'reads credentials/secrets' },
        { ok: auth.exec, pats: EXEC, label: 'executes shell commands' },
        { ok: auth.file, pats: FILE_WRITE, label: 'writes/moves/deletes files' },
      ]
      for (const c of checks) {
        if (c.ok) continue
        if (!anyMatch(unit.source, c.pats)) continue
        const at = lineFor(unit.source, c.pats)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'capability',
            severity: 'medium',
            confidence: 'medium',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: `Skill ${c.label} but only declares: ${declaredStr}. Undeclared side effect.`,
            remediation: 'Declare every capability the skill uses, or remove the undeclared behavior.',
          }),
        )
      }
    }
    return findings
  },
}
