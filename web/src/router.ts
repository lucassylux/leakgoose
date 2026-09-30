import { createRouter, createWebHistory } from 'vue-router'

// 登录标记仅作快速判定（非凭证；会话真实有效性由后端 cookie 裁决，401 拦截器收口）
export function markSession() {
  localStorage.setItem('lg_center_session', '1')
}
export function clearSession() {
  localStorage.removeItem('lg_center_session')
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    // meta.plain：不套 App.vue 外壳（登录页独立成版）
    { path: '/login', name: 'login', component: () => import('./views/login.vue'), meta: { plain: true } },
    // SSO（OIDC）回调落地页：Provider 302 回此处，换 code 后进入规则中心
    { path: '/oidc/callback', name: 'oidc-callback', component: () => import('./views/oidc-callback.vue'), meta: { plain: true } },
    { path: '/rules', name: 'rules', component: () => import('./views/rules.vue') },
    { path: '/publish', name: 'publish', component: () => import('./views/publish.vue') },
    { path: '/audit', name: 'audit', component: () => import('./views/audit.vue') },
    { path: '/access', name: 'access', component: () => import('./views/access.vue') },
    { path: '/', redirect: '/rules' },
    { path: '/:pathMatch(.*)*', redirect: '/rules' },
  ],
})

router.beforeEach((to) => {
  // 回调页豁免：SSO code/state 换会话前本就没有本地登录标记
  if (to.name === 'login' || to.name === 'oidc-callback') return true
  if (!localStorage.getItem('lg_center_session')) {
    return { path: '/login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : {} }
  }
  return true
})

export default router
