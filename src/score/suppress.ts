import { promises as fs } from 'node:fs'
import type { Finding } from '../ir/types.js'

export interface SuppressOptions {
  allow?: string[]
  ignoreFile?: string
  // file path -> source text, used to honor inline ignore comments
  sources?: Map<string, string>
}

interface IgnoreConfig {
  ruleIds: Set<string>
  fps: Set<string>
  files: string[]
}

async function loadIgnore(ignoreFile?: string): Promise<IgnoreConfig> {
  const cfg: IgnoreConfig = { ruleIds: new Set(), fps: new Set(), files: [] }
  if (!ignoreFile) return cfg
  let text: string
  try {
    text = await fs.readFile(ignoreFile, 'utf8')
  } catch {
    return cfg
  }
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    if (line.startsWith('fp:')) cfg.fps.add(line.slice(3).trim())
    else if (line.startsWith('file:')) cfg.files.push(line.slice(5).trim())
    else cfg.ruleIds.add(line)
  }
  return cfg
}

function matchFile(file: string, glob: string): boolean {
  if (glob.includes('*')) {
    const re = new RegExp('^' + glob.split('*').map(escapeRe).join('.*') + '$')
    return re.test(file)
  }
  return file === glob || file.includes(glob)
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const INLINE = /frisk:ignore\s+([A-Za-z0-9*_-]+)/

function inlineIgnored(source: string | undefined, line: number, ruleId: string): boolean {
  if (!source) return false
  const lines = source.split('\n')
  for (const idx of [line - 1, line - 2]) {
    const text = lines[idx]
    if (text === undefined) continue
    const m = INLINE.exec(text)
    if (m && (m[1] === ruleId || m[1] === 'all' || m[1] === '*')) return true
  }
  return false
}

export async function applySuppressions(findings: Finding[], opts: SuppressOptions = {}): Promise<Finding[]> {
  const allow = new Set(opts.allow ?? [])
  const ig = await loadIgnore(opts.ignoreFile)
  return findings.filter((f) => {
    if (allow.has(f.ruleId)) return false
    if (ig.ruleIds.has(f.ruleId)) return false
    if (ig.fps.has(f.fingerprint)) return false
    if (ig.files.some((g) => matchFile(f.file, g))) return false
    if (inlineIgnored(opts.sources?.get(f.file), f.line, f.ruleId)) return false
    return true
  })
}
