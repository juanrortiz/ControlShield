import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'

// Dev: `npm run dev` proxies /api to the Python backend (python gui.py --no-browser).
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  build: { cssMinify: false },   // lightningcss rejects one AlignUI input selector
  server: { proxy: { '/api': 'http://127.0.0.1:8765' } },
})
