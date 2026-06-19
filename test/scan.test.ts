import { describe, it, expect } from 'vitest'
import { scan } from '../src/index.js'

describe('scan() integration', () => {
  it('flags the credential-exfil skill as red', async () => {
    const report = await scan('test/fixtures/malicious/exfil-creds')
    expect(report.verdict).toBe('red')
    expect(report.findings.some((f) => f.category === 'exfiltration' && f.severity === 'high')).toBe(true)
    expect(report.exitCode).toBe(2)
  })
  it('passes a benign minimalist skill as green', async () => {
    const report = await scan('test/fixtures/benign/minimalist')
    expect(report.verdict).toBe('green')
    expect(report.exitCode).toBe(0)
  })
})
