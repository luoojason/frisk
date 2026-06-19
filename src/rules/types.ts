import type { Category, Finding, SkillIR } from '../ir/types.js'

// Every detection rule has the same shape: read the IR, return findings.
// Rules never touch IO or rendering.
export interface Rule {
  id: string
  category: Category
  owasp: string
  run(ir: SkillIR): Finding[]
}

// Mapping of our detection categories onto the OWASP Agentic Top 10. The ids
// are shown in the report so findings are traceable to a recognized taxonomy.
export const OWASP: Record<Category, { id: string; name: string }> = {
  injection: { id: 'ASI01', name: 'Prompt Injection' },
  poisoning: { id: 'ASI02', name: 'Memory and Context Poisoning' },
  'malicious-code': { id: 'ASI05', name: 'Code Execution and Supply Chain' },
  exfiltration: { id: 'ASI06', name: 'Sensitive Information Disclosure' },
  capability: { id: 'ASI08', name: 'Excessive Agency' },
}

export function owaspFor(category: Category): string {
  return OWASP[category].id
}
