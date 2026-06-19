import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    cli: 'src/cli.ts',
    index: 'src/index.ts',
  },
  format: ['esm'],
  target: 'node18',
  platform: 'node',
  clean: true,
  dts: { entry: { index: 'src/index.ts' } },
  splitting: false,
  sourcemap: false,
  // cli.ts starts with a shebang; tsup preserves it on the entry that has it.
})
