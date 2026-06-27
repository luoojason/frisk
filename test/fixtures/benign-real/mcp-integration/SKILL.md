---
name: mcp-integration
description: Guides MCP server development against external APIs. Includes patterns for passing API keys via environment variables (not reading credential files).
allowed-tools: WebFetch, Bash
---

# MCP Integration Guide

Build MCP servers that connect to external APIs.

## Authentication Pattern

Pass credentials via environment variables, never hardcode them:

```typescript
const client = new MyServiceClient({
  apiKey: process.env['MY_SERVICE_API_KEY'],
  baseUrl: 'https://api.myservice.example.com',
})
```

## Making API Calls

```typescript
const result = await client.fetch('/endpoint', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${process.env['MY_SERVICE_API_KEY']}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ query: 'hello' }),
})
```

## Health Check

```bash
curl -H "Authorization: Bearer $MY_SERVICE_API_KEY" \
  https://api.myservice.example.com/v1/ping
```
