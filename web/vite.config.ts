import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 控制台最终挂在管理端口的 /_goproxy/ui/ 下（见 Go 侧 webui.go）。
// base 必须和它一致：否则打包出来引用的是 /assets/xxx.js，上线必然 404。
const UI_BASE = '/_goproxy/ui/'

// 开发时后端地址。默认管理端口就是 127.0.0.1:8080（config.go 的 defaultAdminAddr）。
const BACKEND = process.env.GOPROXY_ADMIN || 'http://127.0.0.1:8080'

export default defineConfig({
  base: UI_BASE,
  plugins: [
    react(),
    {
      // 开发服务器也把 / 指到控制台，和生产环境
      // 「浏览器访问管理端口根路径 → 302 到 UI」保持一致，省得记两个地址。
      name: 'goproxy-console-root-redirect',
      configureServer(server) {
        server.middlewares.use((req, _res, next) => {
          if (req.url === '/' || req.url === '') {
            req.url = UI_BASE
          }
          next()
        })
      },
    },
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // 产物直接进 Go 二进制的 embed，sourcemap 会把体积翻好几倍且对用户没用
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    // 只代理管理接口，UI 静态资源仍由 Vite 自己服务
    proxy: {
      '^/_goproxy/(routes|config|stats|logs|events|ports|reload)': {
        target: BACKEND,
        changeOrigin: true,
      },
      '^/(healthz|readyz|metrics)$': { target: BACKEND, changeOrigin: true },
    },
  },
})
