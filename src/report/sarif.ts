import type { Finding, Report, Severity } from '../ir/types.js'

// SARIF 2.1.0, so findings render in GitHub code-scanning (PR annotations + the
// Security tab) when uploaded by the Action.
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
}

export function renderSarif(report: Report): string {
  const ruleIds = [...new Set(report.findings.map((f) => f.ruleId))]
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'frisk',
            informationUri: 'https://github.com/luoojason/frisk',
            rules: ruleIds.map((id) => ({ id })),
          },
        },
        results: report.findings.map((f: Finding) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: `[${f.category}/${f.owasp}] ${f.message}` },
          partialFingerprints: { friskFingerprint: f.fingerprint },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: Math.max(1, f.line) },
              },
            },
          ],
        })),
      },
    ],
  }
  return JSON.stringify(sarif, null, 2)
}
