import { describe, it, expect } from 'vitest'
import { promises as fs } from 'node:fs'
import { parse as parseYaml } from 'yaml'

describe('action.yml', () => {
  it('is a valid composite action with the expected inputs and command', async () => {
    const doc = parseYaml(await fs.readFile('action/action.yml', 'utf8')) as {
      runs: { using: string; steps: unknown[] }
      inputs: Record<string, unknown>
    }
    expect(doc.runs.using).toBe('composite')
    for (const k of ['path', 'fail-on', 'llm', 'min-confidence']) {
      expect(doc.inputs[k], `missing input ${k}`).toBeDefined()
    }
    const steps = JSON.stringify(doc.runs.steps)
    expect(steps).toContain('frisk')
    expect(steps).toContain('--sarif')
    expect(steps).toContain('--badge')
    expect(steps).toContain('upload-sarif')
  })
})

describe('README', () => {
  it('leads with the framing and documents install, badge, and limits', async () => {
    const r = await fs.readFile('README.md', 'utf8')
    expect(r).toContain('npx frisk')
    expect(r).toContain('SKILL.md')
    expect(r).toContain('shields.io')
    expect(r.toLowerCase()).toContain('limitation')
    expect(r).not.toContain(String.fromCharCode(0x2014)) // no em dashes
  })
})
