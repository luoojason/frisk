import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { resolveSkill, parseRemote } from '../src/resolve/skill.js'

let tmp: string

beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'frisk-test-'))
})
afterEach(async () => {
  await fs.rm(tmp, { recursive: true, force: true })
})

async function writeSkill(dir: string, name: string, body: string, scripts: Record<string, string> = {}) {
  const skillDir = path.join(dir, name)
  await fs.mkdir(path.join(skillDir, 'scripts'), { recursive: true })
  await fs.writeFile(path.join(skillDir, 'SKILL.md'), body)
  for (const [file, content] of Object.entries(scripts)) {
    await fs.writeFile(path.join(skillDir, file), content)
  }
  return skillDir
}

describe('parseRemote', () => {
  it('parses gh: shorthand', () => {
    expect(parseRemote('gh:acme/skill')).toBe('https://github.com/acme/skill.git')
  })
  it('parses a github url', () => {
    expect(parseRemote('https://github.com/acme/skill')).toBe('https://github.com/acme/skill.git')
  })
  it('returns null for a local path', () => {
    expect(parseRemote('./my-skill')).toBeNull()
  })
})

describe('resolveSkill (local)', () => {
  it('resolves a single skill directory with bundled scripts', async () => {
    const dir = await writeSkill(tmp, 'pdf-helper', '# pdf-helper', { 'scripts/setup.sh': 'echo hi' })
    const bundles = await resolveSkill(dir)
    expect(bundles).toHaveLength(1)
    expect(bundles[0]?.skillName).toBe('pdf-helper')
    expect(bundles[0]?.files.some((f) => f.path === 'scripts/setup.sh')).toBe(true)
  })
  it('resolves a folder of skills', async () => {
    await writeSkill(tmp, 'a', '# a')
    await writeSkill(tmp, 'b', '# b')
    const bundles = await resolveSkill(tmp)
    expect(bundles.map((b) => b.skillName).sort()).toEqual(['a', 'b'])
  })
  it('resolves a direct SKILL.md path', async () => {
    const dir = await writeSkill(tmp, 'solo', '# solo')
    const bundles = await resolveSkill(path.join(dir, 'SKILL.md'))
    expect(bundles[0]?.skillName).toBe('solo')
  })
})

describe('resolveSkill (remote, injected cloner)', () => {
  it('clones then scans, never executing the repo', async () => {
    const fixture = await writeSkill(tmp, 'remote-skill', '# remote-skill', { 'scripts/x.sh': 'echo hi' })
    const cloner = async (_repo: string, dest: string) => {
      await fs.cp(fixture, dest, { recursive: true })
    }
    const bundles = await resolveSkill('gh:acme/remote-skill', { cloner })
    expect(bundles[0]?.skillName).toBe(path.basename(bundles[0]!.root))
    expect(bundles[0]?.files.some((f) => f.path === 'scripts/x.sh')).toBe(true)
  })
})
