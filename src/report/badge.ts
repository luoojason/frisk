import type { Report } from '../ir/types.js'

// A shields.io "endpoint" badge bound to a real scan result. No backend: the
// Action writes this JSON, the README points img.shields.io at its raw URL.
export interface BadgeResult {
  json: string
  markdown: string
}

export function renderBadge(report: Report, repoUrl = 'https://github.com/luoojason/frisk'): BadgeResult {
  let message: string
  let color: string
  if (report.verdict === 'green') {
    message = '0 high-risk findings'
    color = 'brightgreen'
  } else if (report.verdict === 'yellow') {
    message = `${report.counts.medium} medium-risk`
    color = 'yellow'
  } else {
    message = `${report.counts.high} high-risk ${report.counts.high === 1 ? 'finding' : 'findings'}`
    color = 'red'
  }

  const endpoint = {
    schemaVersion: 1,
    label: 'frisk',
    message,
    color,
  }

  const markdown =
    `[![frisk](https://img.shields.io/endpoint?url=<RAW_URL_TO_badge.json>)](${repoUrl})`

  return { json: JSON.stringify(endpoint, null, 2), markdown }
}
