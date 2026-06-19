import type { Category, CodeUnit, Confidence, Finding, Severity, SkillIR } from '../ir/types.js'
import { fingerprint } from '../util/fingerprint.js'
import { owaspFor } from './types.js'

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
export function lineFor(source: string, patterns: RegExp[]): { line: number; text: string } {
  const lines = source.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i] ?? ''
    if (patterns.some((re) => new RegExp(re.source, re.flags.replace(/[gy]/g, '')).test(text))) {
      return { line: i + 1, text }
    }
  }
  return { line: 1, text: lines[0] ?? '' }
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
