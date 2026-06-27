// IH-001: Install-time hook / supply-chain abuse.
//
// A skill that bundles a setup script which installs packages from a non-standard
// registry (non-PyPI --index-url, npm URL/git tarball) or pipes a remote script
// into a shell at install time represents a supply-chain attack: code that was
// never published to a vetted registry runs with the user's privileges.
//
// This rule detects:
//   1. pip install from a non-official index (--index-url / --extra-index-url
//      pointing to a host other than pypi.org / files.pythonhosted.org)
//   2. pip install from a direct URL or git remote
//   3. npm install from a git URL, github: shorthand, or a URL tarball
//   4. Package-manager install commands appearing in SKILL.md prose/code blocks
//      that reference these same suspicious sources
//
// Existing rules (malicious-code) already catch curl-pipe-bash; this rule adds
// the subtler "fetch a package from an attacker-controlled registry" variant.

import type { Finding, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { lineFor, makeFinding, stripComments } from './helpers.js'
import { firstLine } from '../util/lines.js'

// pip install from a non-standard index URL.
// Whitelisted prefixes: pypi.org and files.pythonhosted.org (the only two
// official PyPI distribution hosts). Everything else is suspicious.
const PIP_INDEX_URL: RegExp[] = [
  /pip\d*\s+install\b[^\n]*--(?:index-url|extra-index-url)\s+https?:\/\/(?!(?:pypi\.org|files\.pythonhosted\.org)(?:\/|$))\S+/i,
]

// pip install from a direct URL (archive) or from a git remote.
const PIP_URL_INSTALL: RegExp[] = [
  /pip\d*\s+install\b[^\n]*\shttps?:\/\/\S+\.(?:tar\.gz|whl|zip|egg)\b/i,
  /pip\d*\s+install\b[^\n]*\sgit\+https?:\/\/\S+/i,
  /pip\d*\s+install\b[^\n]*\sgit\+ssh:\/\/\S+/i,
]

// npm / yarn install from a git URL, github shorthand, or a tarball URL
// (all bypass the npm registry's publishing vetting).
const NPM_URL_INSTALL: RegExp[] = [
  /npm\s+(?:install|i|add)\b[^\n]*\s(?:git\+https?:\/\/|git\+ssh:\/\/)\S+/i,
  /npm\s+(?:install|i|add)\b[^\n]*\shttps?:\/\/\S+\.(?:tgz|tar\.gz|zip)\b/i,
  /npm\s+(?:install|i|add)\b[^\n]*\s(?:github|gitlab|bitbucket):[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+/i,
  /yarn\s+(?:add)\b[^\n]*\s(?:git\+https?:\/\/|https?:\/\/\S+\.(?:tgz|tar\.gz|zip))\b/i,
]

const ALL_CODE_PATTERNS: RegExp[] = [...PIP_INDEX_URL, ...PIP_URL_INSTALL, ...NPM_URL_INSTALL]

// Same patterns for SKILL.md prose/code-block scanning (instructions visible
// to the user but also read by the agent that might execute them verbatim).
const ALL_PROSE_PATTERNS: RegExp[] = ALL_CODE_PATTERNS

const id = 'install-hook'

export const rule: Rule = {
  id,
  category: 'malicious-code',
  owasp: 'ASI05',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []

    // --- Code-unit scan ---
    for (const unit of ir.codeUnits) {
      const stripped = stripComments(unit.source, unit.lang)
      for (const re of ALL_CODE_PATTERNS) {
        if (!re.test(stripped)) continue
        const at = lineFor(stripped, [re], unit.source)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'malicious-code',
            severity: 'high',
            confidence: 'high',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: 'Script installs packages from a non-standard source (non-PyPI index, URL, or git remote). This bypasses registry vetting and can introduce attacker-controlled code at install time.',
            remediation: 'Only install packages from official registries (pypi.org, registry.npmjs.org). Remove non-standard --index-url, git+, or URL-tarball installs.',
          }),
        )
        break // one finding per code unit is enough
      }
    }

    // --- SKILL.md prose / code-block scan ---
    // A skill that documents install commands pointing at attacker-controlled
    // sources teaches the user (or the agent) to run a supply-chain attack.
    const text = ir.markdown.visibleText
    for (const re of ALL_PROSE_PATTERNS) {
      const m = re.exec(text)
      if (!m) continue
      const line = firstLine(text, re)
      findings.push(
        makeFinding({
          ruleId: id,
          category: 'malicious-code',
          severity: 'high',
          confidence: 'medium',
          file: 'SKILL.md',
          line,
          excerpt: m[0],
          message: 'SKILL.md installation instructions reference a non-standard package source (non-PyPI index, URL, or git remote). Following these installs attacker-controlled code.',
          remediation: 'Installation instructions must only reference official package registries. Remove or replace the non-standard source.',
        }),
      )
      break // one finding per markdown is enough
    }

    return findings
  },
}
