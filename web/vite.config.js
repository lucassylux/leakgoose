import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发代理到本地规则中心（leakgoose center serve 默认 :8280）。
// changeOrigin 必须关：center 的 CSRF 中间件按 Host 校验 Origin 同源，
// 改写 Host 会导致浏览器 POST 全部 403「跨源写请求被拒绝」
export default defineConfig({
  plugins: [vue()],
  optimizeDeps: { exclude: ['@xzsoft/sketch-ui'] },
  server: {
    port: 65175, strictPort: true,
    proxy: { '/api': { target: 'http://127.0.0.1:8280', changeOrigin: false } },
  },
  build: {
    sourcemap: false,
    // 输出到仓库根的 web/dist（go:embed all:web/dist 嵌入二进制）
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        advancedChunks: {
          groups: [
            { name: 'vue', test: /[\/]node_modules[\/](@vue|vue|vue-router)[\/]/ },
            { name: 'sketch-ui', test: /[\/]node_modules[\/]@xzsoft[\/]sketch-ui[\/]/ },
          ],
        },
      },
    },
  },
})
