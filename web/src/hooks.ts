import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * 定时轮询。两个刻意的行为：
 *   - 页面切到后台就跳过这次请求（浏览器会对后台标签页降频，堆积的请求只会白占连接）；
 *   - 单次失败不打断循环，否则后端一下抖动整个页面就永久停止刷新了。
 */
export function usePolling(fn: () => void | Promise<void>, intervalMs: number, enabled = true): void {
  const ref = useRef(fn)
  ref.current = fn

  useEffect(() => {
    if (!enabled) return
    let stopped = false
    let timer: number | undefined

    const tick = async () => {
      if (stopped) return
      if (!document.hidden) {
        try {
          await ref.current()
        } catch {
          /* 交给调用方自己提示，这里不能中断轮询 */
        }
      }
      if (!stopped) timer = window.setTimeout(tick, intervalMs)
    }

    void tick()

    const onVisible = () => {
      if (!document.hidden && !stopped) {
        window.clearTimeout(timer)
        void tick()
      }
    }
    document.addEventListener('visibilitychange', onVisible)

    return () => {
      stopped = true
      window.clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [intervalMs, enabled])
}

// 顺序即左侧页签顺序。acl = 「IP 名单」页，紧挨 routes：
// 名单决定的是「谁能进来」，和路由是同一条链路上的事。
export const TAB_KEYS = ['dashboard', 'routes', 'acl', 'certs', 'logs', 'settings'] as const
export type TabKey = (typeof TAB_KEYS)[number]

function readHash(): TabKey {
  const raw = window.location.hash.replace(/^#\/?/, '')
  return (TAB_KEYS as readonly string[]).includes(raw) ? (raw as TabKey) : 'dashboard'
}

/**
 * 用 hash 做页签路由：零依赖，且刷新/前进后退都能停在原来的页签上。
 * （控制台挂在 /_goproxy/ui/ 下，用 history 路由需要在服务端配 fallback，
 * hash 不需要。）
 */
export function useHashTab(): [TabKey, (tab: TabKey) => void] {
  const [tab, setTab] = useState<TabKey>(readHash)

  useEffect(() => {
    const onChange = () => setTab(readHash())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  const navigate = useCallback((next: TabKey) => {
    window.location.hash = `#/${next}`
  }, [])

  return [tab, navigate]
}

export type Theme = 'dark' | 'light'

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() =>
    document.documentElement.dataset.theme === 'light' ? 'light' : 'dark',
  )

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('goproxy.theme', theme)
    } catch {
      /* 忽略 */
    }
  }, [theme])

  const toggle = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), [])
  return [theme, toggle]
}

/** 复制到剪贴板。http 页面上 navigator.clipboard 可能不存在，回退到 execCommand。 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    /* 落到下面的兜底 */
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
