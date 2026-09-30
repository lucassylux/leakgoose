import { createRouter, createWebHistory } from 'vue-router'
// 视图全部急切导入：应用仅 6 个视图且整体内嵌 Go 二进制，代码分割无收益；
// 更重要的是异步路由组件在「布局整树卸载」竞态下触发 vue 3.5 卸载崩溃
// （unmountComponent 空引用，视图冻结在旧页面），急切导入彻底绕开该路径
import Shell from './views/shell.vue'
import Login from './views/login.vue'
import OidcCallback from './views/oidc-callback.vue'
import Rules from './views/rules.vue'
import Publish from './views/publish.vue'
import Audit from './views/audit.vue'
import Access from './views/access.vue'
import Settings from './views/settings.vue'

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
    { path: '/login', name: 'login', component: Login },
    // SSO（OIDC）回调落地页：Provider 302 回此处，换 code 后进入规则中心
    { path: '/oidc/callback', name: 'oidc-callback', component: OidcCallback },
    // 后台外壳为布局路由组件（children 挂各页）：
    // 登录页 ↔ 外壳的整树切换由路由层级承担，不在 App 级 v-if 换分支
    {
      path: '/',
      component: Shell,
      children: [
        { path: 'rules', name: 'rules', component: Rules },
        { path: 'publish', name: 'publish', component: Publish },
        { path: 'audit', name: 'audit', component: Audit },
        { path: 'access', name: 'access', component: Access },
        { path: 'settings', name: 'settings', component: Settings },
        { path: '', redirect: '/rules' },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/rules' },
  ],
})

router.beforeEach((to) => {
  if (to.name === 'login' || to.name === 'oidc-callback') return true
  if (!localStorage.getItem('lg_center_session')) {
    return { path: '/login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : {} }
  }
  return true
})

export default router
