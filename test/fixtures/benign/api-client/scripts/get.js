// Fetches public data. Declared WebFetch, no secrets, no shell.
const res = await fetch('https://api.example.com/v1/items')
const data = await res.json()
console.log(`Fetched ${data.length} items`)
