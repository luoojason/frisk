/**
 * Precision regression gate — benign real-skill excerpts.
 *
 * Each fixture in test/fixtures/benign-real/ is a sanitized excerpt from a
 * real installed skill that triggered (or would trigger) findings before the
 * EXF-CORR / exfiltration rule precision tuning.  The gate asserts:
 *
 *   1. ZERO high-severity findings across the entire corpus.
 *   2. No regressions: the fixtures are hermetic (no ~/.claude dependency).
 *
 * The malicious recall gate (corpus.gate.test.ts) ensures precision gains
 * do not come at the cost of detection.
 *
 * Fixtures represent these canonical real-world patterns:
 *   git-provider-auth    — env token ($GITHOST_TOKEN) + curl to official API
 *   cross-unit-api-client — multi-file: env token in one file, API call in another
 *   env-token-docs       — SKILL.md prose mentioning token env vars (no exec code)
 *   health-checker       — source .env then curl $SERVICE_URL (variable URL)
 *   mcp-integration      — SKILL.md with $API_KEY code snippets + external URL
 */
import { describe, it, expect } from 'vitest'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import { scan } from '../src/index.js'

const BENIGN_REAL_DIR = 'test/fixtures/benign-real'

describe('precision gate — real-skill benign corpus', () => {
  it('produces ZERO high-severity findings on all benign-real fixtures', async () => {
    const dirs = (await fs.readdir(BENIGN_REAL_DIR, { withFileTypes: true })).filter((d) =>
      d.isDirectory(),
    )

    expect(dirs.length, 'benign-real corpus must have at least 3 fixtures').toBeGreaterThanOrEqual(3)

    const highsByFixture: Record<string, string[]> = {}
    for (const d of dirs) {
      const report = await scan(path.join(BENIGN_REAL_DIR, d.name))
      const highs = report.findings.filter((f) => f.severity === 'high')
      if (highs.length > 0) {
        highsByFixture[d.name] = highs.map((f) => `${f.ruleId}: ${f.message}`)
      }
    }

    const fp = Object.entries(highsByFixture)
    if (fp.length > 0) {
      const detail = fp.map(([name, msgs]) => `  ${name}:\n${msgs.map((m) => `    - ${m}`).join('\n')}`).join('\n')
      throw new Error(`High-severity false positives in benign-real corpus:\n${detail}`)
    }
    console.log(`benign-real precision: 0 HIGH findings across ${dirs.length} fixtures`)
  })

  it('git-provider-auth: env-token + curl to official API endpoint is at most MEDIUM', async () => {
    const report = await scan(path.join(BENIGN_REAL_DIR, 'git-provider-auth'))
    const highs = report.findings.filter((f) => f.severity === 'high')
    expect(
      highs,
      'Using $GITHOST_TOKEN with curl to the official API must not be HIGH',
    ).toHaveLength(0)
  })

  it('cross-unit-api-client: multi-file env-token skill is at most MEDIUM overall', async () => {
    const report = await scan(path.join(BENIGN_REAL_DIR, 'cross-unit-api-client'))
    const highs = report.findings.filter((f) => f.severity === 'high')
    expect(
      highs,
      'Cross-unit env token + API call to the token\'s own service must not be HIGH',
    ).toHaveLength(0)
  })

  it('health-checker: source .env + curl variable URL is at most MEDIUM', async () => {
    const report = await scan(path.join(BENIGN_REAL_DIR, 'health-checker'))
    const highs = report.findings.filter((f) => f.severity === 'high')
    expect(highs, 'Standard .env-source + health-check curl must not produce HIGH').toHaveLength(0)
  })

  it('mcp-integration: SKILL.md with env-var API key snippets is at most MEDIUM', async () => {
    const report = await scan(path.join(BENIGN_REAL_DIR, 'mcp-integration'))
    const highs = report.findings.filter((f) => f.severity === 'high')
    expect(highs, 'Instructional SKILL.md with $API_KEY code examples must not be HIGH').toHaveLength(0)
  })
})
