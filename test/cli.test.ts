import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { main } from '../src/cli.js'

let out: string[]
let logSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  out = []
  logSpy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    out.push(a.join(' '))
  })
})
afterEach(() => {
  logSpy.mockRestore()
})

describe('cli main()', () => {
  it('returns 0 and prints GREEN for a benign skill', async () => {
    const code = await main(['test/fixtures/benign/minimalist'])
    expect(code).toBe(0)
    expect(out.join('\n')).toContain('GREEN')
  })
  it('returns 2 and prints RED for a malicious skill', async () => {
    const code = await main(['test/fixtures/malicious/exfil-creds'])
    expect(code).toBe(2)
    expect(out.join('\n')).toContain('RED')
  })
  it('emits valid JSON with --json', async () => {
    const code = await main(['test/fixtures/malicious/exfil-creds', '--json'])
    expect(code).toBe(2)
    const parsed = JSON.parse(out.join('\n'))
    expect(parsed.verdict).toBe('red')
  })
  it('writes a badge file with --badge', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'frisk-cli-'))
    const badge = path.join(dir, 'badge.json')
    await main(['test/fixtures/benign/minimalist', '--badge', badge])
    const parsed = JSON.parse(await fs.readFile(badge, 'utf8'))
    expect(parsed.schemaVersion).toBe(1)
    expect(parsed.color).toBe('brightgreen')
    await fs.rm(dir, { recursive: true, force: true })
  })
  it('--help returns 0', async () => {
    const code = await main(['--help'])
    expect(code).toBe(0)
    expect(out.join('\n')).toContain('Usage')
  })
  it('errors with exit 2 on no target', async () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const code = await main([])
    expect(code).toBe(2)
    errSpy.mockRestore()
  })
})
