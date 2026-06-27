import type { Finding, Report, Severity } from '../ir/types.js'

// SARIF 2.1.0, so findings render in GitHub code-scanning (PR annotations + the
// Security tab) when uploaded by the Action.
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
}

// GitHub code scanning uses the numeric `security-severity` property (CVSS-like
// 0–10 scale) on the rule to decide whether to block PRs. Without it the finding
// is not treated as security-relevant.
const SECURITY_SEVERITY: Record<Severity, string> = {
  high: '8.0',
  medium: '5.5',
  low: '2.0',
  info: '0.0',
}

interface SarifRuleMeta {
  name: string
  shortDescription: string
  helpUri: string
  tags: string[]
}

const RULE_META: Record<string, SarifRuleMeta> = {
  injection: {
    name: 'PromptInjection',
    shortDescription: 'Prompt injection or instruction override detected in skill',
    helpUri: 'https://github.com/luoojason/frisk/blob/main/corpus/patterns/injection-hidden.md',
    tags: ['ASI01', 'prompt-injection', 'security'],
  },
  poisoning: {
    name: 'MemoryPoisoning',
    shortDescription: 'Memory or context poisoning — skill writes to persistent agent state',
    helpUri: 'https://github.com/luoojason/frisk/blob/main/corpus/patterns/poisoning-memory.md',
    tags: ['ASI02', 'memory-poisoning', 'security'],
  },
  'malicious-code': {
    name: 'MaliciousCode',
    shortDescription: 'Malicious code execution pattern detected (reverse shell, remote exec, privilege escalation)',
    helpUri: 'https://github.com/luoojason/frisk/blob/main/corpus/patterns/malicious-code.md',
    tags: ['ASI05', 'code-execution', 'supply-chain', 'security'],
  },
  exfiltration: {
    name: 'DataExfiltration',
    shortDescription: 'Credential or secret data exfiltration detected',
    helpUri: 'https://github.com/luoojason/frisk/blob/main/corpus/patterns/exfiltration-credentials.md',
    tags: ['ASI06', 'data-exfiltration', 'security'],
  },
  capability: {
    name: 'CapabilityMismatch',
    shortDescription: 'Skill exercises capabilities not declared in its frontmatter',
    helpUri: 'https://github.com/luoojason/frisk/blob/main/corpus/patterns/capability-mismatch.md',
    tags: ['ASI08', 'excessive-agency', 'security'],
  },
  'llm-judge': {
    name: 'LlmJudge',
    shortDescription: 'Suspicious pattern detected by the LLM judge',
    helpUri: 'https://github.com/luoojason/frisk',
    tags: ['security'],
  },
}

function ruleEntry(ruleId: string, maxSeverity: Severity) {
  const meta = RULE_META[ruleId] ?? {
    name: ruleId,
    shortDescription: `frisk: ${ruleId}`,
    helpUri: 'https://github.com/luoojason/frisk',
    tags: ['security'],
  }
  return {
    id: ruleId,
    name: meta.name,
    shortDescription: { text: meta.shortDescription },
    helpUri: meta.helpUri,
    properties: {
      tags: meta.tags,
      // Numeric severity used by GitHub code scanning to gate branch protection.
      // We use the highest severity observed for this rule in this scan.
      'security-severity': SECURITY_SEVERITY[maxSeverity],
    },
  }
}

export function renderSarif(report: Report): string {
  // Compute the highest severity seen per rule for the security-severity property.
  const maxSevByRule = new Map<string, Severity>()
  const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3 }
  for (const f of report.findings) {
    const cur = maxSevByRule.get(f.ruleId)
    if (!cur || SEV_RANK[f.severity] > SEV_RANK[cur]) {
      maxSevByRule.set(f.ruleId, f.severity)
    }
  }

  const ruleIds = [...new Set(report.findings.map((f) => f.ruleId))]
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'frisk',
            version: '0.1.0',
            informationUri: 'https://github.com/luoojason/frisk',
            rules: ruleIds.map((id) => ruleEntry(id, maxSevByRule.get(id) ?? 'info')),
          },
        },
        results: report.findings.map((f: Finding) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: `[${f.category}/${f.owasp}] ${f.message}` },
          partialFingerprints: {
            // GitHub uses this to deduplicate findings across commits so already-
            // dismissed findings are not re-annotated on subsequent pushes.
            primaryLocationLineHash: f.fingerprint,
          },
          properties: {
            confidence: f.confidence,
            category: f.category,
            owasp: f.owasp,
            severity: f.severity,
            remediation: f.remediation,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file, uriBaseId: '%SRCROOT%' },
                region: { startLine: Math.max(1, f.line), startColumn: 1 },
              },
            },
          ],
        })),
      },
    ],
  }
  return JSON.stringify(sarif, null, 2)
}
