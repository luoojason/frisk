import path from 'node:path'
import type { Confidence, Finding, Report, Severity } from './ir/types.js'
import { resolveSkill, type Cloner } from './resolve/skill.js'
import { buildIR } from './parse/ir.js'
import { runRules } from './rules/registry.js'
import { applySuppressions } from './score/suppress.js'
import { score } from './score/scorer.js'
import { fingerprint } from './util/fingerprint.js'

export type { Report, Finding } from './ir/types.js'
export { renderTerminal } from './report/terminal.js'
export { renderJson } from './report/json.js'
export { renderSarif } from './report/sarif.js'
export { renderBadge } from './report/badge.js'

export interface ScanOptions {
  llm?: boolean
  apiKey?: string
  failOn?: Severity
  minConfidence?: Confidence
  allow?: string[]
  disabled?: string[]
  ignoreFile?: string
  cloner?: Cloner
  fetchImpl?: typeof fetch
  model?: string
}

export async function scan(target: string, opts: ScanOptions = {}): Promise<Report> {
  const start = process.hrtime.bigint()
  const bundles = await resolveSkill(target, { cloner: opts.cloner })

  const apiKey = opts.apiKey ?? process.env['ANTHROPIC_API_KEY']
  const llm = opts.llm ?? !!apiKey
  const multi = bundles.length > 1

  const allFindings: Finding[] = []
  const sources = new Map<string, string>()
  let filesScanned = 0

  for (const bundle of bundles) {
    const ir = buildIR(bundle)
    filesScanned += Math.max(1, ir.files.length)
    const prefix = multi ? `${bundle.skillName}/` : ''

    sources.set(`${prefix}SKILL.md`, ir.markdown.rawText)
    for (const unit of ir.codeUnits) sources.set(`${prefix}${unit.file}`, unit.source)

    const raw = await runRules(ir, {
      disabled: opts.disabled,
      llm,
      apiKey,
      fetchImpl: opts.fetchImpl,
      model: opts.model,
    })

    for (const f of raw) {
      if (!multi) {
        allFindings.push(f)
        continue
      }
      const file = `${prefix}${f.file}`
      allFindings.push({ ...f, file, fingerprint: fingerprint([f.ruleId, file, String(f.line), f.excerpt]) })
    }
  }

  const ignoreFile = opts.ignoreFile ?? (bundles[0] ? path.join(bundles[0].root, '.friskignore') : undefined)
  const suppressed = await applySuppressions(allFindings, {
    allow: opts.allow,
    ignoreFile,
    sources,
  })

  const durationMs = Number(process.hrtime.bigint() - start) / 1e6
  return score(target, suppressed, {
    filesScanned,
    durationMs,
    failOn: opts.failOn ?? 'high',
    minConfidence: opts.minConfidence ?? 'medium',
  })
}
