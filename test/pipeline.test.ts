import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type { Finding } from '../src/ir/types.js'
import { applySuppressions } from '../src/score/suppress.js'
import { score } from '../src/score/scorer.js'
import { renderTerminal } from '../src/report/terminal.js'
import { renderJson } from '../src/report/json.js'
import { renderSarif } from '../src/report/sarif.js'
import { renderBadge } from '../src/report/badge.js'

function f(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'exfiltration',
    category: 'exfiltration',
    owasp: 'ASI06',
    severity: 'high',
    confidence: 'high',
    file: 'SKILL.md',
    line: 1,
    excerpt: 'x',
    message: 'm',
    remediation: 'fix',
    source: 'static',
    fingerprint: 'fp1',
    ...over,
  }
}

const meta = { filesScanned: 1, durationMs: 1, failOn: 'high' as const, minConfidence: 'medium' as const }

describe('scorer', () => {
  it('high+high is red and fails (exit 2)', () => {
    const r = score('t', [f()], meta)
    expect(r.verdict).toBe('red')
    expect(r.exitCode).toBe(2)
  })
  it('medium is yellow and passes by default', () => {
    const r = score('t', [f({ severity: 'medium', confidence: 'medium' })], meta)
    expect(r.verdict).toBe('yellow')
    expect(r.exitCode).toBe(0)
  })
  it('medium fails when --fail-on medium', () => {
    const r = score('t', [f({ severity: 'medium', confidence: 'medium' })], { ...meta, failOn: 'medium' })
    expect(r.exitCode).toBe(2)
  })
  it('no findings is green', () => {
    const r = score('t', [], meta)
    expect(r.verdict).toBe('green')
    expect(r.exitCode).toBe(0)
  })
  it('minConfidence filters low-confidence findings', () => {
    const r = score('t', [f({ severity: 'high', confidence: 'low' })], meta)
    expect(r.findings).toHaveLength(0)
    expect(r.verdict).toBe('green')
  })
})

describe('suppress', () => {
  it('--allow removes matching rule findings', async () => {
    const out = await applySuppressions([f()], { allow: ['exfiltration'] })
    expect(out).toHaveLength(0)
  })
  it('honors a fingerprint in .friskignore', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'frisk-ig-'))
    const ignoreFile = path.join(dir, '.friskignore')
    await fs.writeFile(ignoreFile, '# ignore that one\nfp:fp1\n')
    const out = await applySuppressions([f({ fingerprint: 'fp1' }), f({ fingerprint: 'fp2' })], { ignoreFile })
    expect(out.map((x) => x.fingerprint)).toEqual(['fp2'])
    await fs.rm(dir, { recursive: true, force: true })
  })
  it('honors an inline ignore comment', async () => {
    const sources = new Map([['SKILL.md', 'line1\nbad code here # frisk:ignore exfiltration']])
    const out = await applySuppressions([f({ line: 2 })], { sources })
    expect(out).toHaveLength(0)
  })
})

describe('reporters', () => {
  const report = score('./pdf-helper', [
    f({ severity: 'high', message: 'reads creds and posts them', file: 'scripts/setup.sh', line: 14 }),
    f({ ruleId: 'injection', category: 'injection', owasp: 'ASI01', severity: 'medium', confidence: 'medium', line: 31, fingerprint: 'fp2' }),
  ], meta)

  it('terminal output is readable and uncolored when color is off', () => {
    const t = renderTerminal(report, { color: false })
    expect(t).toContain('RED')
    expect(t).toContain('exfiltration')
    expect(t).toContain('ASI06')
    expect(t).toContain('scripts/setup.sh:14')
    expect(t).toContain('finding')
    expect(t).not.toContain(String.fromCharCode(27))
  })
  it('json round-trips', () => {
    const parsed = JSON.parse(renderJson(report))
    expect(parsed.verdict).toBe('red')
    expect(parsed.findings).toHaveLength(2)
  })
  it('sarif is well formed', () => {
    const s = JSON.parse(renderSarif(report))
    expect(s.version).toBe('2.1.0')
    expect(s.runs[0].tool.driver.name).toBe('frisk')
    expect(s.runs[0].results).toHaveLength(2)
    expect(s.runs[0].results[0].level).toBe('error')
  })
  it('badge reflects the verdict', () => {
    const red = JSON.parse(renderBadge(report).json)
    expect(red.color).toBe('red')
    const green = JSON.parse(renderBadge(score('t', [], meta)).json)
    expect(green.color).toBe('brightgreen')
    expect(green.message).toBe('0 high-risk findings')
  })
})
