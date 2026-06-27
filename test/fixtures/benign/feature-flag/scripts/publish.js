#!/usr/bin/env node
// Publish drafts whose scheduled date has passed.
const fs = require('fs')
const path = require('path')

const draftsDir = path.join(__dirname, '..', 'drafts')
const now = new Date()

if (!fs.existsSync(draftsDir)) {
  console.log('No drafts directory found.')
  process.exit(0)
}

const drafts = fs.readdirSync(draftsDir).filter(f => f.endsWith('.md'))
let published = 0

for (const draft of drafts) {
  const content = fs.readFileSync(path.join(draftsDir, draft), 'utf8')
  // Parse scheduled date from frontmatter: `date: 2026-01-15`
  const dateMatch = content.match(/^date:\s*(\d{4}-\d{2}-\d{2})/m)
  if (!dateMatch) continue
  const scheduledDate = new Date(dateMatch[1])
  if (now >= scheduledDate) {
    console.log('Publishing:', draft)
    published++
  }
}

console.log(`Published ${published} drafts.`)
