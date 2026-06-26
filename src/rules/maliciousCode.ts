import type { Finding, Severity, SkillIR } from '../ir/types.js'
import type { Rule } from './types.js'
import { lineFor, makeFinding, stripComments } from './helpers.js'

interface Sig {
  re: RegExp
  severity: Severity
  message: string
}

const SIGNATURES: Sig[] = [
  // Download-and-execute remote code.
  { re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh|perl|ruby|node|php)\b/, severity: 'high', message: 'Pipes downloaded content directly into an interpreter (remote code execution).' },
  // curl | python (executing stdin). Excludes -m / -c, which are benign (e.g. json.tool).
  { re: /\b(?:curl|wget)\b[^\n|]*\|\s*python[23]?\b(?![^\n]*\s-[mc]\b)/, severity: 'high', message: 'Pipes downloaded content into a Python interpreter (remote code execution).' },
  { re: /\b(?:curl|wget)\b[^\n]*\$\([^)]*\)[^\n]*\|\s*(?:bash|sh)\b/, severity: 'high', message: 'Downloads and executes remote code.' },
  // Execute the output of a network download via process substitution: `source <(curl ...)`.
  { re: /(?:\b(?:source|bash|sh|zsh|eval)\b|(?:^|[\s;&|])\.)\s+<\(\s*(?:curl|wget)\b/, severity: 'high', message: 'Executes the output of a network download via process substitution.' },
  // exec/eval of a value fetched over the network (Python/JS remote code execution).
  { re: /\b(?:exec|eval)\s*\(\s*(?:urllib(?:\.request)?\.urlopen|urlopen|requests\.(?:get|post)|httpx\.(?:get|post|request))\b/, severity: 'high', message: 'Executes code fetched from the network (remote code execution).' },
  // Download a file then make it executable: installing and running a remote binary.
  { re: /\b(?:curl|wget)\b[^\n]*\s-[oO]\b[\s\S]{0,160}?\bchmod\s+\+x/, severity: 'medium', message: 'Downloads a file and marks it executable (runs a remote binary).' },
  // Reverse shells.
  { re: /\/dev\/tcp\/[0-9a-zA-Z.]/, severity: 'high', message: 'Opens a raw TCP socket to a remote host (reverse shell pattern).' },
  { re: /\bnc\b[^\n]*\s-e\b/, severity: 'high', message: 'Uses netcat with command execution (reverse shell).' },
  { re: /\bbash\b\s+-i\b[^\n]*(?:>&|\/dev\/tcp)/, severity: 'high', message: 'Interactive bash redirected to a socket (reverse shell).' },
  { re: /python[0-9.]*\s+-c\s+['"][^'"]*socket[^'"]*(?:connect|SOCK_STREAM)/i, severity: 'high', message: 'Inline Python opening a socket (reverse shell pattern).' },
  // Destructive operations.
  { re: /\brm\s+-rf?\b[^\n]*(?:\s|^)(?:~|\/|\$HOME|\$\{HOME\})(?:\s|\/|$)/, severity: 'high', message: 'Recursively deletes a home or root path.' },
  { re: /\bdd\s+if=[^\n]*of=\/dev\/(?:sd|disk|nvme|hd)/, severity: 'high', message: 'Writes directly to a block device (data destruction).' },
  { re: /\bmkfs(?:\.\w+)?\b/, severity: 'high', message: 'Formats a filesystem.' },
  { re: /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:/, severity: 'high', message: 'Fork bomb.' },
  // Obfuscated execution.
  { re: /\b(?:eval|exec)\b[^\n]*(?:\$\(|atob\s*\(|base64|fromCharCode|b64decode)/, severity: 'high', message: 'Evaluates obfuscated/decoded content at runtime.' },
  { re: /(?:base64\s+(?:-d|--decode)|atob\s*\(|b64decode\s*\()[^\n]*\|\s*(?:bash|sh)/, severity: 'high', message: 'Decodes a blob and pipes it into a shell.' },
  // Dynamic execution (weaker signal).
  { re: /\bos\.system\s*\(/, severity: 'medium', message: 'Executes a shell command via os.system().' },
  { re: /\bsubprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True/, severity: 'medium', message: 'Runs a subprocess with shell=True.' },
  { re: /\bchild_process\.(?:exec|execSync)\s*\(/, severity: 'medium', message: 'Executes a shell command via child_process.exec.' },
  { re: /\beval\s*\(/, severity: 'medium', message: 'Uses eval().' },
  { re: /\bFunction\s*\(\s*['"]/, severity: 'medium', message: 'Constructs code from a string via Function().' },
]

const id = 'malicious-code'

export const rule: Rule = {
  id,
  category: 'malicious-code',
  owasp: 'ASI05',
  run(ir: SkillIR): Finding[] {
    const findings: Finding[] = []
    for (const unit of ir.codeUnits) {
      const scan = stripComments(unit.source, unit.lang)
      for (const sig of SIGNATURES) {
        if (!sig.re.test(scan)) continue
        const at = lineFor(scan, [sig.re], unit.source)
        findings.push(
          makeFinding({
            ruleId: id,
            category: 'malicious-code',
            severity: sig.severity,
            confidence: sig.severity === 'high' ? 'high' : 'medium',
            file: unit.file,
            line: at.line,
            excerpt: at.text,
            message: sig.message,
            remediation: 'Confirm this code is necessary and safe. Dynamic/remote execution in an installable skill is high risk.',
          }),
        )
      }
    }
    return findings
  },
}
