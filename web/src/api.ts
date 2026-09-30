/**
 * 统一请求封装：同源会话 cookie 认证；401 一律回登录页（真实会话有效性由后端裁决）。
 * 错误提示由调用方按场景处理（toast 或表单内联），这里只抛带 message 的异常。
 */
export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const resp = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await resp.text()
  const data = text ? (JSON.parse(text) as unknown) : null
  if (!resp.ok) {
    if (resp.status === 401 && !url.startsWith('/api/auth/login') && !location.pathname.startsWith('/login')) {
      localStorage.removeItem('lg_center_session')
      location.href = '/login'
    }
    const msg = (data as { error?: string })?.error || `请求失败（${resp.status}）`
    throw new ApiError(resp.status, msg)
  }
  return data as T
}

export const api = {
  get: <T>(url: string) => request<T>('GET', url),
  post: <T>(url: string, body?: unknown) => request<T>('POST', url, body),
  put: <T>(url: string, body?: unknown) => request<T>('PUT', url, body),
  del: <T>(url: string) => request<T>('DELETE', url),
}

// ---------- 领域类型（与 center API 同构） ----------

export interface Me {
  username: string
  role: string
}

export interface Rule {
  'id': string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  pattern: string
  validate?: string
  keywords?: string[]
  'include-paths'?: string[]
  'exclude-paths'?: string[]
  enabled: boolean
  description?: string
  updatedBy?: string
  updatedAt?: string
}

export interface TestCase {
  id?: number
  ruleId: string
  input: string
  expectMatch: boolean
}

export interface PackRow {
  version: string
  sha256: string
  changelog: string
  publishedBy: string
  publishedAt: string
}

export interface Pack extends PackRow {
  rules: Rule[]
}

export interface TokenRow {
  id: number
  name: string
  createdAt: string
  lastUsed?: string
}

export interface AuditRow {
  id: number
  at: string
  actor: string
  action: string
  entity: string
  detail?: string
}
