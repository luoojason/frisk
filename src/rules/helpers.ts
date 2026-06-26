import type { Category, CodeUnit, Confidence, Finding, Lang, Severity, SkillIR } from '../ir/types.js'
import { fingerprint } from '../util/fingerprint.js'
import { owaspFor } from './types.js'

// Blank out comments while preserving line count and character offsets, so code
// rules match executable code rather than path mentions or examples in comments
// (which a reviewer can already see). String contents are left intact so a `#`
// or `//` inside a literal is never mistaken for a comment, which would risk a
// false negative, the worse failure for a scanner.
export function stripComments(source: string, lang: Lang): string {
  if (lang === 'unknown') return source
  const out: string[] = []
  let str = '' // active string delimiter, or '' when outside a string
  let block = false // inside a /* */ block (javascript)
  for (let i = 0; i < source.length; i++) {
    const c = source[i]!
    const two = source.slice(i, i + 2)
    if (block) {
      if (two === '*/') { out.push('  '); i++; block = false; continue }
      out.push(c === '\n' ? '\n' : ' ')
      continue
    }
    if (str) {
      out.push(c)
      if (c === '\\' && i + 1 < source.length) { out.push(source[i + 1]!); i++; continue }
      if (c === str) str = ''
      continue
    }
    if (c === '"' || c === "'" || (lang === 'javascript' && c === '`')) { str = c; out.push(c); continue }
    if (lang === 'javascript' && two === '/*') { out.push('  '); i++; block = true; continue }
    const isComment = lang === 'javascript' ? two === '//' : c === '#'
    if (isComment) {
      while (i < source.length && source[i] !== '\n') { out.push(' '); i++ }
      i-- // leave the newline for the next iteration
      continue
    }
    out.push(c)
  }
  return out.join('')
}

// Redact things that look like secret values so frisk never prints a credential
// it found in the scanned skill.
export function redact(s: string): string {
  return s
    .replace(/\bsk-[A-Za-z0-9_-]{8,}/g, 'sk-[REDACTED]')
    .replace(/\bAKIA[0-9A-Z]{12,}\b/g, '[REDACTED-AWS-KEY]')
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED-GH-TOKEN]')
    .replace(/\b[A-Za-z0-9+/]{60,}={0,2}\b/g, (m) => `${m.slice(0, 8)}...[REDACTED-BLOB]`)
}

export function makeFinding(p: {
  ruleId: string
  category: Category
  severity: Severity
  confidence: Confidence
  file: string
  line: number
  excerpt: string
  message: string
  remediation: string
  source?: 'static' | 'llm'
}): Finding {
  const excerpt = redact(p.excerpt.trim()).slice(0, 200)
  return {
    ruleId: p.ruleId,
    category: p.category,
    owasp: owaspFor(p.category),
    severity: p.severity,
    confidence: p.confidence,
    file: p.file,
    line: p.line,
    excerpt,
    message: p.message,
    remediation: p.remediation,
    source: p.source ?? 'static',
    fingerprint: fingerprint([p.ruleId, p.file, String(p.line), excerpt]),
  }
}

export function anyMatch(source: string, patterns: RegExp[]): boolean {
  return patterns.some((re) => re.test(source))
}

// First 1-based line of `source` that matches any of the patterns, else 1.
// `original` supplies the excerpt text when `source` has been comment-stripped,
// so reported snippets show the real code, not blanked-out lines.
export function lineFor(
  source: string,
  patterns: RegExp[],
  original: string = source,
): { line: number; text: string } {
  const lines = source.split('\n')
  const origLines = original.split('\n')
  const reOf = (re: RegExp) => new RegExp(re.source, re.flags.replace(/[gy]/g, ''))
  for (let i = 0; i < lines.length; i++) {
    if (patterns.some((re) => reOf(re).test(lines[i] ?? ''))) {
      return { line: i + 1, text: origLines[i] ?? lines[i] ?? '' }
    }
  }
  // No single line matched (e.g. a regex that spans several lines). Locate the
  // match in the whole source and report the line where it begins.
  for (const re of patterns) {
    const m = reOf(re).exec(source)
    if (m) {
      const line = source.slice(0, m.index).split('\n').length
      return { line, text: origLines[line - 1] ?? '' }
    }
  }
  return { line: 1, text: origLines[0] ?? '' }
}

export const SKILL_MD = 'SKILL.md'

// Convenience: scan both markdown bodies (visible + each hidden span) for a rule
// that works on prose.
export function markdownTextTargets(ir: SkillIR): { text: string; line: number; hidden: boolean }[] {
  const targets: { text: string; line: number; hidden: boolean }[] = []
  targets.push({ text: ir.markdown.visibleText, line: 1, hidden: false })
  for (const span of ir.markdown.hiddenSpans) {
    targets.push({ text: span.text, line: span.line, hidden: true })
  }
  return targets
}

export type { CodeUnit }
