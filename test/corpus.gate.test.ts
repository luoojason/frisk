import { describe, it, expect } from 'vitest'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import { scan } from '../src/index.js'
import type { Category } from '../src/ir/types.js'

const MAL_DIR = 'test/fixtures/malicious'
const BEN_DIR = 'test/fixtures/benign'

// Each malicious fixture must be flagged in this category (recall).
const EXPECTED: Record<string, Category> = {
  'exfil-creds': 'exfiltration',
  'cookie-stealer': 'exfiltration',
  'dns-exfil': 'exfiltration',
  'hidden-injection': 'injection',
  'zerowidth-injection': 'injection',
  'memory-poison': 'poisoning',
  'worm-skill': 'poisoning',
  'reverse-shell': 'malicious-code',
  'perl-revshell': 'malicious-code',
  'ruby-revshell': 'malicious-code',
  'obfuscated-payload': 'malicious-code',
  'remote-exec': 'malicious-code',
  'download-exec': 'malicious-code',
  'curl-pipe-interp': 'malicious-code',
  'exec-obfuscated': 'malicious-code',
  'proc-sub-exec': 'malicious-code',
  'ssh-backdoor': 'malicious-code',
  'sudoers-backdoor': 'malicious-code',
  'disk-wipe': 'malicious-code',
  'email-exfil': 'exfiltration',
  'aws-metadata': 'exfiltration',
  'gcp-metadata': 'exfiltration',
  'undeclared-network': 'capability',
  // New fixtures added with frisk/dig
  'priority-override': 'injection',
  'safety-disable': 'injection',
  'chmod-setuid': 'malicious-code',
  'base64-exfil': 'exfiltration',
  // Cross-unit taint correlation (EXF-CORR): secret in one file, egress in another
  'split-exfil': 'exfiltration',
}

describe('corpus gate', () => {
  it('flags every malicious fixture in its intended category', async () => {
    const dirs = (await fs.readdir(MAL_DIR, { withFileTypes: true })).filter((d) => d.isDirectory())
    let recalled = 0
    let total = 0
    for (const d of dirs) {
      const expected = EXPECTED[d.name]
      expect(expected, `no expected category mapped for fixture ${d.name}`).toBeDefined()
      total++
      const report = await scan(path.join(MAL_DIR, d.name))
      const hit = report.findings.some((f) => f.category === expected)
      if (hit) recalled++
      expect(report.verdict, `${d.name} should not be green`).not.toBe('green')
      expect(hit, `${d.name} should produce a ${expected} finding`).toBe(true)
    }
    console.log(`malicious recall: ${recalled}/${total}`)
    expect(total).toBeGreaterThanOrEqual(8)
    const categories = new Set(Object.values(EXPECTED))
    expect(categories.size, 'corpus should span all five categories').toBe(5)
  })

  it('produces zero high-severity findings on benign skills (precision gate)', async () => {
    const dirs = (await fs.readdir(BEN_DIR, { withFileTypes: true })).filter((d) => d.isDirectory())
    let green = 0
    for (const d of dirs) {
      const report = await scan(path.join(BEN_DIR, d.name))
      const highs = report.findings.filter((f) => f.severity === 'high')
      expect(highs, `${d.name} has high-severity false positives: ${JSON.stringify(highs)}`).toHaveLength(0)
      if (report.verdict === 'green') green++
    }
    console.log(`benign green: ${green}/${dirs.length}`)
    expect(dirs.length).toBeGreaterThanOrEqual(6)
  })
})
