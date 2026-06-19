#!/usr/bin/env node
import { promises as fs } from 'node:fs'
import { pathToFileURL } from 'node:url'
import type { Confidence, Severity } from './ir/types.js'
import { scan } from './index.js'
import { renderTerminal } from './report/terminal.js'
import { renderJson } from './report/json.js'
import { renderSarif } from './report/sarif.js'
import { renderBadge } from './report/badge.js'

const VERSION = '0.1.0'

const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info']
const CONFIDENCES: Confidence[] = ['high', 'medium', 'low']

const USAGE = `frisk ${VERSION} - scan an AI-agent skill before you install it

Usage:
  frisk <path | gh:owner/repo | github-url> [options]

Options:
  --llm                     Run the optional LLM judge (auto-on if ANTHROPIC_API_KEY is set)
  --json                    Output the report as JSON
  --sarif                   Output SARIF 2.1.0 (for CI / code scanning)
  --badge <file>            Write a shields.io endpoint badge JSON to <file>
  --fail-on <severity>      Exit non-zero at this severity or above (default: high)
  --min-confidence <level>  Hide findings below this confidence (default: medium)
  --allow <ruleId>          Suppress a rule (repeatable)
  --disable <ruleId>        Do not run a rule (repeatable)
  --quiet                   Print only the verdict line
  --no-color                Disable colored output
  -h, --help                Show this help
  -v, --version             Show version

Severities: high, medium, low, info     Rules: injection, exfiltration, poisoning, malicious-code, capability`

interface Parsed {
  target?: string
  llm: boolean
  json: boolean
  sarif: boolean
  badge?: string
  failOn: Severity
  minConfidence: Confidence
  allow: string[]
  disable: string[]
  quiet: boolean
  color: boolean
  help: boolean
  version: boolean
  error?: string
}

function parseArgs(argv: string[]): Parsed {
  const p: Parsed = {
    llm: false,
    json: false,
    sarif: false,
    failOn: 'high',
    minConfidence: 'medium',
    allow: [],
    disable: [],
    quiet: false,
    color: process.stdout.isTTY === true,
    help: false,
    version: false,
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    const next = () => argv[++i]
    switch (a) {
      case '--llm': p.llm = true; break
      case '--json': p.json = true; break
      case '--sarif': p.sarif = true; break
      case '--badge': p.badge = next(); break
      case '--quiet': p.quiet = true; break
      case '--no-color': p.color = false; break
      case '-h': case '--help': p.help = true; break
      case '-v': case '--version': p.version = true; break
      case '--allow': { const v = next(); if (v) p.allow.push(v); break }
      case '--disable': { const v = next(); if (v) p.disable.push(v); break }
      case '--fail-on': {
        const v = next() as Severity
        if (!SEVERITIES.includes(v)) p.error = `invalid --fail-on: ${v}`
        else p.failOn = v
        break
      }
      case '--min-confidence': {
        const v = next() as Confidence
        if (!CONFIDENCES.includes(v)) p.error = `invalid --min-confidence: ${v}`
        else p.minConfidence = v
        break
      }
      default:
        if (a && a.startsWith('-')) p.error = `unknown option: ${a}`
        else if (!p.target && a) p.target = a
    }
  }
  return p
}

export async function main(argv: string[]): Promise<number> {
  const p = parseArgs(argv)
  if (p.help) {
    console.log(USAGE)
    return 0
  }
  if (p.version) {
    console.log(VERSION)
    return 0
  }
  if (p.error) {
    console.error(`frisk: ${p.error}`)
    return 2
  }
  if (!p.target) {
    console.error(USAGE)
    return 2
  }

  let report
  try {
    report = await scan(p.target, {
      llm: p.llm || undefined,
      failOn: p.failOn,
      minConfidence: p.minConfidence,
      allow: p.allow,
      disabled: p.disable,
    })
  } catch (err) {
    console.error(`frisk: ${(err as Error).message}`)
    return 2
  }

  if (p.badge) {
    await fs.writeFile(p.badge, renderBadge(report).json)
  }

  if (p.json) {
    console.log(renderJson(report))
  } else if (p.sarif) {
    console.log(renderSarif(report))
  } else if (p.quiet) {
    console.log(`frisk: ${report.verdict.toUpperCase()} (${report.findings.length} findings) ${report.target}`)
  } else {
    console.log(renderTerminal(report, { color: p.color }))
  }

  return report.exitCode
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href

if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`frisk: ${(err as Error).message}`)
      process.exit(2)
    },
  )
}
