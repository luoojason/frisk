import type { Report } from '../ir/types.js'

export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2)
}
