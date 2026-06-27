import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { rule as injection } from './injection.js'
import { rule as exfiltration } from './exfiltration.js'
import { rule as poisoning } from './poisoning.js'
import { rule as maliciousCode } from './maliciousCode.js'
import { rule as capability } from './capability.js'
import { rule as crossUnitTaint } from './crossUnitTaint.js'
import { rule as installHook } from './installHook.js'
import { rule as credentialHarvest } from './credentialHarvest.js'
import { rule as sandboxEscape } from './sandboxEscape.js'
import { rule as silentTelemetry } from './silentTelemetry.js'
import { rule as timeBomb } from './timeBomb.js'
import { llmJudge } from './llmJudge.js'

export function allRules(): Rule[] {
  return [injection, exfiltration, poisoning, maliciousCode, capability, crossUnitTaint, installHook, credentialHarvest, sandboxEscape, silentTelemetry, timeBomb]
}

export interface RunRulesOptions {
  disabled?: string[]
  llm?: boolean
  apiKey?: string
  fetchImpl?: typeof fetch
  model?: string
}

export async function runRules(ir: SkillIR, opts: RunRulesOptions = {}): Promise<Finding[]> {
  const disabled = new Set(opts.disabled ?? [])
  const findings: Finding[] = []
  for (const r of allRules()) {
    if (disabled.has(r.id)) continue
    findings.push(...r.run(ir))
  }

  const key = opts.apiKey ?? process.env['ANTHROPIC_API_KEY']
  if (opts.llm) {
    if (!key) {
      console.error('frisk: --llm requested but no ANTHROPIC_API_KEY found; running static rules only.')
    } else {
      const llmFindings = await llmJudge(ir, { apiKey: key, fetchImpl: opts.fetchImpl, model: opts.model })
      findings.push(...llmFindings)
    }
  }
  return findings
}
