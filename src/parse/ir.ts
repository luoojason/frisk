import { createHash } from 'node:crypto'
import type { CodeUnit, SkillBundle, SkillFile, SkillIR } from '../ir/types.js'
import { isScriptFile, parseCode } from './code.js'
import { parseMarkdown } from './markdown.js'

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex')
}

function extOf(path: string): string {
  const base = path.split('/').pop() ?? path
  const dot = base.lastIndexOf('.')
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : ''
}

export function buildIR(bundle: SkillBundle): SkillIR {
  const md = parseMarkdown(bundle.skillMd)
  const skillName =
    (typeof md.frontmatter['name'] === 'string' && (md.frontmatter['name'] as string)) ||
    bundle.skillName

  const codeUnits: CodeUnit[] = []
  const files: SkillFile[] = []
  for (const f of bundle.files) {
    files.push({ path: f.path, size: f.size, sha256: sha256(f.content), type: extOf(f.path) })
    if (isScriptFile(f.path, f.content)) {
      codeUnits.push(parseCode(f.path, f.content))
    }
  }

  return {
    skillName,
    frontmatter: md.frontmatter,
    declaredCapabilities: md.declaredCapabilities,
    markdown: { rawText: md.rawText, visibleText: md.visibleText, hiddenSpans: md.hiddenSpans },
    codeUnits,
    files,
  }
}
