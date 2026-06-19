// Helpers for locating a pattern's line within a source string. Rules use these
// to attach a line number to a finding without threading positions through the IR.

function perLine(re: RegExp): RegExp {
  // Strip the global/sticky flags so .test() is stateless per line.
  const flags = re.flags.replace(/[gy]/g, '')
  return new RegExp(re.source, flags)
}

export function linesMatching(source: string, re: RegExp): { line: number; text: string }[] {
  const test = perLine(re)
  const out: { line: number; text: string }[] = []
  source.split('\n').forEach((text, i) => {
    if (test.test(text)) out.push({ line: i + 1, text })
  })
  return out
}

export function firstLine(source: string, re: RegExp): number {
  const hit = linesMatching(source, re)[0]
  return hit ? hit.line : 1
}
