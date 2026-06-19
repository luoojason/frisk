import type { CodeUnit, Lang } from '../ir/types.js'

const EXT_LANG: Record<string, Lang> = {
  sh: 'bash',
  bash: 'bash',
  zsh: 'bash',
  py: 'python',
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'javascript',
  mts: 'javascript',
  cts: 'javascript',
}

export function detectLang(file: string, source: string): Lang {
  const ext = file.split('.').pop()?.toLowerCase() ?? ''
  if (ext in EXT_LANG) return EXT_LANG[ext] as Lang
  const firstLine = source.split('\n', 1)[0] ?? ''
  if (/^#!.*\b(bash|sh|zsh)\b/.test(firstLine)) return 'bash'
  if (/^#!.*\bpython[0-9.]*\b/.test(firstLine)) return 'python'
  if (/^#!.*\bnode\b/.test(firstLine)) return 'javascript'
  return 'unknown'
}

const CALL_RE = /([A-Za-z_][\w.]*)\s*\(/g
const DQ_STRING = /"(?:[^"\\]|\\.)*"/g
const SQ_STRING = /'(?:[^'\\]|\\.)*'/g

// Heads of shell commands: the first token of each statement, where statements
// are separated by newlines, pipes, semicolons, and && / ||.
function shellCommandHeads(source: string): string[] {
  const heads: string[] = []
  for (const rawLine of source.split('\n')) {
    const line = rawLine.replace(/#.*$/, '').trim()
    if (!line) continue
    for (const seg of line.split(/\||;|&&|\|\|/)) {
      const m = /^\s*([A-Za-z_][\w./-]*)/.exec(seg)
      if (m && m[1]) heads.push(m[1])
    }
  }
  return heads
}

function extractStrings(source: string): string[] {
  const out: string[] = []
  for (const m of source.matchAll(DQ_STRING)) out.push(m[0].slice(1, -1))
  for (const m of source.matchAll(SQ_STRING)) out.push(m[0].slice(1, -1))
  return out
}

function extractImports(source: string, lang: Lang): string[] {
  const out = new Set<string>()
  if (lang === 'python') {
    for (const m of source.matchAll(/^\s*import\s+([\w.]+)/gm)) if (m[1]) out.add(m[1])
    for (const m of source.matchAll(/^\s*from\s+([\w.]+)\s+import/gm)) if (m[1]) out.add(m[1])
  } else if (lang === 'javascript') {
    for (const m of source.matchAll(/import\s+(?:[\s\S]*?)\s+from\s+['"]([^'"]+)['"]/g)) if (m[1]) out.add(m[1])
    for (const m of source.matchAll(/import\s+['"]([^'"]+)['"]/g)) if (m[1]) out.add(m[1])
    for (const m of source.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)) if (m[1]) out.add(m[1])
  } else if (lang === 'bash') {
    for (const m of source.matchAll(/^\s*(?:source|\.)\s+(\S+)/gm)) if (m[1]) out.add(m[1])
  }
  return [...out]
}

export function parseCode(file: string, source: string): CodeUnit {
  const lang = detectLang(file, source)
  const calls = new Set<string>()
  for (const m of source.matchAll(CALL_RE)) if (m[1]) calls.add(m[1])
  if (lang === 'bash') for (const h of shellCommandHeads(source)) calls.add(h)
  return {
    file,
    lang,
    source,
    calls: [...calls],
    strings: extractStrings(source),
    imports: extractImports(source, lang),
  }
}

export function isScriptFile(path: string, content: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? ''
  if (ext in EXT_LANG || ['rb', 'pl', 'php', 'ps1'].includes(ext)) return true
  const firstLine = content.split('\n', 1)[0] ?? ''
  return /^#!/.test(firstLine)
}
