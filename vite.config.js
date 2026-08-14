import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    watch: {
      // Never watch repositories cloned for analysis. A target repo may contain
      // tsconfig.json/vite.config.* files that would otherwise trigger a full
      // reload of the Software Vetter UI while a scan is running.
      ignored: ['**/reposec-runs/**', '**/software-vetter-reposec-runs/**'],
    },
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${process.env.API_PORT || 8787}`,
        changeOrigin: true,
      },
    },
  },
})
