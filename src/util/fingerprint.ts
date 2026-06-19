import { createHash } from 'node:crypto'

// A stable, short identifier for a finding. Normalizes each part so that
// cosmetic differences (whitespace, case) do not change the fingerprint.
// Used for suppression (.friskignore fp:<...>) and stable CI diffs.
export function fingerprint(parts: string[]): string {
  const normalized = parts
    .map((p) => p.trim().replace(/\s+/g, ' ').toLowerCase())
    .join(' ')
  return createHash('sha1').update(normalized).digest('hex').slice(0, 12)
}
