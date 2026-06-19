import type { Confidence, Finding, Report, Severity, Verdict } from '../ir/types.js'

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3 }
const CONF_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 }

export interface ScoreMeta {
  filesScanned: number
  durationMs: number
  failOn: Severity
  minConfidence: Confidence
}

function emptyCounts(): Record<Severity, number> {
  return { high: 0, medium: 0, low: 0, info: 0 }
}

export function score(target: string, findings: Finding[], meta: ScoreMeta): Report {
  const minConf = CONF_RANK[meta.minConfidence]
  const kept = findings
    .filter((f) => CONF_RANK[f.confidence] >= minConf)
    .sort((a, b) => {
      const s = SEV_RANK[b.severity] - SEV_RANK[a.severity]
      if (s !== 0) return s
      const c = CONF_RANK[b.confidence] - CONF_RANK[a.confidence]
      if (c !== 0) return c
      if (a.file !== b.file) return a.file < b.file ? -1 : 1
      return a.line - b.line
    })

  const counts = emptyCounts()
  for (const f of kept) counts[f.severity]++

  // A high finding only drives the verdict to red when we are at least
  // medium-confident; otherwise it is yellow at most.
  const hasHighConfident = kept.some((f) => f.severity === 'high' && CONF_RANK[f.confidence] >= CONF_RANK.medium)
  const hasMedium = kept.some((f) => f.severity === 'medium')
  let verdict: Verdict = 'green'
  if (hasHighConfident) verdict = 'red'
  else if (hasMedium || counts.high > 0) verdict = 'yellow'

  const failRank = SEV_RANK[meta.failOn]
  const triggered = kept.some((f) => SEV_RANK[f.severity] >= failRank)
  const exitCode = triggered ? 2 : 0

  return {
    target,
    verdict,
    findings: kept,
    counts,
    filesScanned: meta.filesScanned,
    durationMs: meta.durationMs,
    exitCode,
  }
}
