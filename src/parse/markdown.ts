import { parse as parseYaml } from 'yaml'
import type { HiddenSpan, SkillMarkdown } from '../ir/types.js'

// Zero-width and invisible formatting code points: ZWSP, ZWNJ, ZWJ, LRM, RLM,
// word joiner, BOM/ZWNBSP, soft hyphen.
const ZERO_WIDTH_CODES = new Set([
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2060, 0xfeff, 0x00ad,
])
// Bidirectional override/isolate controls used to visually reorder text.
const BIDI_CODES = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
])

const HTML_COMMENT = /<!--([\s\S]*?)-->/g
const BASE64_BLOB = /[A-Za-z0-9+/]{64,}={0,2}/g
// Inline element styled to be invisible (white/transparent text or zero font size).
const HIDDEN_STYLE =
  /<([a-z]+)\b[^>]*style\s*=\s*["'][^"']*(?:color\s*:\s*(?:#fff(?:fff)?|white|transparent)|font-size\s*:\s*0(?:px|pt|em)?)[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi

export interface ParsedMarkdown extends SkillMarkdown {
  frontmatter: Record<string, unknown>
  declaredCapabilities: string[]
}

function hasCodes(s: string, set: Set<number>): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0)
    if (c !== undefined && set.has(c)) return true
  }
  return false
}

function stripCodes(s: string, ...sets: Set<number>[]): string {
  let out = ''
  for (const ch of s) {
    const c = ch.codePointAt(0)
    if (c !== undefined && sets.some((set) => set.has(c))) continue
    out += ch
  }
  return out
}

function lineOf(text: string, index: number): number {
  let line = 1
  const end = Math.min(index, text.length)
  for (let i = 0; i < end; i++) {
    if (text[i] === '\n') line++
  }
  return line
}

// Character ranges covered by fenced code blocks (``` or ~~~). Content inside a
// fence is shown to the reviewer as literal code, so an HTML comment there is
// not "hidden" the way a comment in prose is.
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})/
function fencedRanges(raw: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = []
  let open: { char: string; len: number; start: number } | null = null
  let offset = 0
  for (const line of raw.split('\n')) {
    const lineStart = offset
    const lineEnd = offset + line.length
    if (!open) {
      const m = FENCE_OPEN.exec(line)
      if (m) open = { char: m[1]![0]!, len: m[1]!.length, start: lineStart }
    } else {
      const close = new RegExp(`^ {0,3}\\${open.char}{${open.len},}\\s*$`)
      if (close.test(line)) {
        ranges.push([open.start, lineEnd])
        open = null
      }
    }
    offset = lineEnd + 1 // +1 for the '\n' removed by split
  }
  if (open) ranges.push([open.start, raw.length])
  return ranges
}

function splitFrontmatter(raw: string): { fm: Record<string, unknown>; body: string; bodyOffset: number } {
  // Frontmatter is a leading `---` ... `---` block.
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(raw)
  if (!m) return { fm: {}, body: raw, bodyOffset: 0 }
  let fm: Record<string, unknown> = {}
  try {
    const parsed = parseYaml(m[1] ?? '')
    if (parsed && typeof parsed === 'object') fm = parsed as Record<string, unknown>
  } catch {
    fm = {}
  }
  return { fm, body: raw.slice(m[0].length), bodyOffset: m[0].length }
}

function toCapabilities(fm: Record<string, unknown>): string[] {
  const raw = fm['allowed-tools'] ?? fm['allowed_tools'] ?? fm['tools']
  if (Array.isArray(raw)) return raw.map((x) => String(x).trim()).filter(Boolean)
  if (typeof raw === 'string') {
    return raw
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean)
  }
  return []
}

export function parseMarkdown(raw: string): ParsedMarkdown {
  const { fm, body, bodyOffset } = splitFrontmatter(raw)
  const declaredCapabilities = toCapabilities(fm)
  const hiddenSpans: HiddenSpan[] = []

  // Hidden spans are detected against the original raw text so line numbers are
  // accurate and so nothing is lost to normalization.
  const fences = fencedRanges(raw)
  const insideFence = (i: number) => fences.some(([s, e]) => i >= s && i < e)
  for (const m of raw.matchAll(HTML_COMMENT)) {
    const idx = m.index ?? 0
    if (insideFence(idx)) continue // a comment shown as code is not hidden
    hiddenSpans.push({ kind: 'html-comment', text: (m[1] ?? '').trim(), line: lineOf(raw, idx) })
  }
  for (const m of raw.matchAll(HIDDEN_STYLE)) {
    hiddenSpans.push({ kind: 'tiny-or-white', text: (m[2] ?? '').trim(), line: lineOf(raw, m.index ?? 0) })
  }
  // Zero-width / bidi: report once per affected line.
  raw.split('\n').forEach((text, i) => {
    if (hasCodes(text, ZERO_WIDTH_CODES)) hiddenSpans.push({ kind: 'zero-width', text: text.trim(), line: i + 1 })
    if (hasCodes(text, BIDI_CODES)) hiddenSpans.push({ kind: 'bidi', text: text.trim(), line: i + 1 })
  })
  for (const m of body.matchAll(BASE64_BLOB)) {
    hiddenSpans.push({ kind: 'base64-blob', text: m[0], line: lineOf(raw, bodyOffset + (m.index ?? 0)) })
  }

  // Visible text approximates what a human sees: hidden content removed, then
  // NFKC-normalized and stripped of zero-width/bidi characters.
  const visibleText = stripCodes(
    body.replace(HTML_COMMENT, '').replace(HIDDEN_STYLE, '').normalize('NFKC'),
    ZERO_WIDTH_CODES,
    BIDI_CODES,
  )

  return { frontmatter: fm, declaredCapabilities, rawText: raw, visibleText, hiddenSpans }
}
