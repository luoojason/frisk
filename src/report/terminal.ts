import type { Finding, Report, Severity, Verdict } from '../ir/types.js'

const ESC = String.fromCharCode(27)
const C = {
  reset: `${ESC}[0m`,
  bold: `${ESC}[1m`,
  dim: `${ESC}[2m`,
  red: `${ESC}[31m`,
  yellow: `${ESC}[33m`,
  green: `${ESC}[32m`,
  gray: `${ESC}[90m`,
}

const VERDICT_LINE: Record<Verdict, { word: string; tail: string; color: keyof typeof C }> = {
  red: { word: 'RED', tail: 'do not install', color: 'red' },
  yellow: { word: 'YELLOW', tail: 'review before installing', color: 'yellow' },
  green: { word: 'GREEN', tail: 'no high-risk findings', color: 'green' },
}

const SEV_COLOR: Record<Severity, keyof typeof C> = {
  high: 'red',
  medium: 'yellow',
  low: 'gray',
  info: 'gray',
}

export function renderTerminal(report: Report, opts: { color?: boolean } = {}): string {
  const useColor = opts.color ?? false
  const paint = (s: string, c: keyof typeof C) => (useColor ? `${C[c]}${s}${C.reset}` : s)

  const out: string[] = []
  out.push(`${paint('frisk', 'bold')}  scanning ${report.target}`)
  out.push('')

  const v = VERDICT_LINE[report.verdict]
  out.push(`  ${paint('●', v.color)}  ${paint(v.word, v.color)} - ${v.tail}`)
  out.push('')

  for (const f of report.findings) {
    const label = f.severity.toUpperCase().padEnd(6)
    const head = `  ${paint(label, SEV_COLOR[f.severity])}  ${f.category}  ${f.owasp}  ${f.file}:${f.line}`
    out.push(f.source === 'llm' ? `${head} ${paint('(llm)', 'gray')}` : head)
    out.push(`    ${f.message}`)
    if (f.excerpt) out.push(paint(`    > ${f.excerpt}`, 'gray'))
    out.push(paint(`    fix: ${f.remediation}`, 'dim'))
    out.push('')
  }

  const flaggedFiles = new Set(report.findings.map((f) => f.file)).size
  const summary =
    `${count(report.findings.length, 'finding')} ` +
    `(${report.counts.high} high, ${report.counts.medium} medium` +
    (report.counts.low ? `, ${report.counts.low} low` : '') +
    `) · ${count(flaggedFiles, 'file')} flagged · ${Math.round(report.durationMs)}ms`
  out.push(`  ${paint(summary, 'dim')}`)

  return out.join('\n')
}

function count(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}

export type { Finding }
