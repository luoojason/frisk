import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import type { SkillBundle } from '../ir/types.js'

const execFileAsync = promisify(execFile)

export type Cloner = (repo: string, dest: string) => Promise<void>

const MAX_FILE_BYTES = 512 * 1024
const MAX_FILES = 200
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', '.venv', '__pycache__', '.idea'])
const BINARY_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'pdf', 'zip', 'tar', 'gz', 'tgz',
  'mp4', 'mov', 'mp3', 'wav', 'woff', 'woff2', 'ttf', 'otf', 'bin', 'exe', 'so',
  'dylib', 'class', 'jar', 'wasm',
])

function extOf(p: string): string {
  const base = p.split('/').pop() ?? p
  const dot = base.lastIndexOf('.')
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : ''
}

async function listFiles(dir: string, rel = '', acc: string[] = []): Promise<string[]> {
  const entries = await fs.readdir(path.join(dir, rel), { withFileTypes: true })
  for (const e of entries) {
    const relPath = rel ? `${rel}/${e.name}` : e.name
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue
      await listFiles(dir, relPath, acc)
    } else if (e.isFile()) {
      acc.push(relPath)
    }
  }
  return acc
}

async function loadBundle(skillDir: string, name: string): Promise<SkillBundle | null> {
  const skillMdPath = path.join(skillDir, 'SKILL.md')
  let skillMd: string
  try {
    skillMd = await fs.readFile(skillMdPath, 'utf8')
  } catch {
    return null
  }

  const notes: string[] = []
  const files: SkillBundle['files'] = []
  const all = await listFiles(skillDir)
  let count = 0
  for (const relPath of all) {
    if (count >= MAX_FILES) {
      notes.push(`file cap reached (${MAX_FILES}); remaining files not scanned`)
      break
    }
    if (BINARY_EXT.has(extOf(relPath))) continue
    const abs = path.join(skillDir, relPath)
    const stat = await fs.stat(abs)
    if (stat.size > MAX_FILE_BYTES) {
      notes.push(`skipped large file ${relPath} (${stat.size} bytes)`)
      continue
    }
    const content = await fs.readFile(abs, 'utf8')
    if (content.includes(String.fromCharCode(0))) {
      notes.push(`skipped binary-looking file ${relPath}`)
      continue
    }
    files.push({ path: relPath, content, size: stat.size })
    count++
  }

  return { skillName: name, skillMd, root: skillDir, files, notes }
}

async function resolveLocal(dir: string): Promise<SkillBundle[]> {
  const stat = await fs.stat(dir).catch(() => null)
  if (!stat) throw new Error(`path not found: ${dir}`)

  // A path to the SKILL.md file itself -> its containing directory.
  if (stat.isFile()) {
    if (path.basename(dir) === 'SKILL.md') {
      const skillDir = path.dirname(dir)
      const b = await loadBundle(skillDir, path.basename(skillDir))
      return b ? [b] : []
    }
    throw new Error(`expected a skill directory or a SKILL.md file: ${dir}`)
  }

  // A directory that is itself a skill.
  const direct = await loadBundle(dir, path.basename(dir))
  if (direct) return [direct]

  // Otherwise a directory of skill subdirectories.
  const entries = await fs.readdir(dir, { withFileTypes: true })
  const bundles: SkillBundle[] = []
  for (const e of entries) {
    if (!e.isDirectory() || SKIP_DIRS.has(e.name)) continue
    const b = await loadBundle(path.join(dir, e.name), e.name)
    if (b) bundles.push(b)
  }
  if (bundles.length === 0) throw new Error(`no SKILL.md found in ${dir} or its subdirectories`)
  return bundles
}

export function parseRemote(target: string): string | null {
  let m = /^gh:([\w.-]+)\/([\w.-]+)$/.exec(target)
  if (m) return `https://github.com/${m[1]}/${m[2]}.git`
  m = /^https?:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(target)
  if (m) return `https://github.com/${m[1]}/${m[2]}.git`
  return null
}

const gitCloner: Cloner = async (repo, dest) => {
  // Shallow clone only. The repository is never executed; we read its files.
  await execFileAsync('git', ['clone', '--depth', '1', repo, dest])
}

export async function resolveSkill(
  target: string,
  opts: { cloner?: Cloner } = {},
): Promise<SkillBundle[]> {
  const remote = parseRemote(target)
  if (!remote) return resolveLocal(target)

  const cloner = opts.cloner ?? gitCloner
  const dest = await fs.mkdtemp(path.join(os.tmpdir(), 'frisk-'))
  try {
    await cloner(remote, dest)
    return await resolveLocal(dest)
  } finally {
    await fs.rm(dest, { recursive: true, force: true })
  }
}
