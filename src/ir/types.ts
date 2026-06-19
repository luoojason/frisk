// Core data model for frisk. These types are the contract every layer shares:
// the parse layer produces a SkillIR, rules consume it and emit Findings, the
// scorer rolls Findings into a Report. Nothing here knows about IO or rendering.

export type Category =
  | 'injection'
  | 'exfiltration'
  | 'poisoning'
  | 'malicious-code'
  | 'capability'

export type Severity = 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'
export type Verdict = 'red' | 'yellow' | 'green'

export type HiddenKind =
  | 'zero-width'
  | 'bidi'
  | 'html-comment'
  | 'tiny-or-white'
  | 'base64-blob'

export interface HiddenSpan {
  kind: HiddenKind
  text: string
  line: number
}

export type Lang = 'bash' | 'python' | 'javascript' | 'unknown'

export interface CodeUnit {
  file: string
  lang: Lang
  source: string
  calls: string[]
  strings: string[]
  imports: string[]
}

export interface SkillMarkdown {
  rawText: string
  visibleText: string
  hiddenSpans: HiddenSpan[]
}

export interface SkillFile {
  path: string
  size: number
  sha256: string
  type: string
}

export interface SkillIR {
  skillName: string
  frontmatter: Record<string, unknown>
  declaredCapabilities: string[]
  markdown: SkillMarkdown
  codeUnits: CodeUnit[]
  files: SkillFile[]
}

export interface Finding {
  ruleId: string
  category: Category
  owasp: string
  severity: Severity
  confidence: Confidence
  file: string
  line: number
  excerpt: string
  message: string
  remediation: string
  source: 'static' | 'llm'
  fingerprint: string
}

export interface Report {
  target: string
  verdict: Verdict
  findings: Finding[]
  counts: Record<Severity, number>
  filesScanned: number
  durationMs: number
  exitCode: number
}

// A resolved skill ready to be parsed. Produced by the resolver, consumed by buildIR.
export interface SkillBundle {
  skillName: string
  skillMd: string
  root: string
  files: { path: string; content: string; size: number }[]
  notes: string[]
}
