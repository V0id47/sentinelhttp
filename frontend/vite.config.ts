import { defineConfig } from 'vite';

export default defineConfig({
  base: '/',
  build: {
    outDir: '../internal/dashboard/static',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
  },
  server: {
    host: '127.0.0.1',
    strictPort: true,
  },
});
