<template>
  <div class="app-shell">
    <!-- 移动端抽屉遮罩：点按关闭（桌面端 mobileOpen 恒 false 不渲染） -->
    <div v-if="mobileOpen" class="sider-mask" @click="mobileOpen = false"></div>
    <SkSidebar
      class="sider" :class="{ 'is-mobile-open': mobileOpen }"
      :collapsed="isMobile ? false : collapsed"
      @update:collapsed="onCollapsed"
      :collapsible="!isMobile" :width="200" :collapsed-width="60"
    >
      <template #brand>
        <span class="brand-click" @click="goPage('/rules')">
          <GooseLogo :size="28" />
          <span class="sk-sidebar-brand-text">LeakGoose 规则中心</span>
        </span>
      </template>

      <SkSidebarGroup label="规则中心">
        <SkSidebarItem :icon="SkIconKey" label="规则维护" :active="route.path === '/rules'" @click="goPage('/rules')">规则维护</SkSidebarItem>
        <SkSidebarItem :icon="SkIconUpload" label="发布与版本" :active="route.path === '/publish'" @click="goPage('/publish')">发布与版本</SkSidebarItem>
        <SkSidebarItem :icon="SkIconHistory" label="审计日志" :active="route.path === '/audit'" @click="goPage('/audit')">审计日志</SkSidebarItem>
        <SkSidebarItem :icon="SkIconLink" label="接入与令牌" :active="route.path === '/access'" @click="goPage('/access')">接入与令牌</SkSidebarItem>
        <SkSidebarItem :icon="SkIconFileText" label="数据字典" :active="route.path === '/dict'" @click="goPage('/dict')">数据字典</SkSidebarItem>
        <SkSidebarItem :icon="SkIconLock" label="系统设置" :active="route.path === '/settings'" @click="goPage('/settings')">系统设置</SkSidebarItem>
      </SkSidebarGroup>
    </SkSidebar>

    <div class="main-col">
      <header class="topbar">
        <span class="sk-space">
          <button type="button" class="sider-toggle" aria-label="打开导航菜单" @click="mobileOpen = true">
            <SkIconMenu />
          </button>
          <SkBreadcrumb v-if="crumbs.length" :items="crumbs.map((c) => ({ label: c }))" class="crumbs" />
        </span>
        <span class="sk-space topbar-right">
          <SkThemeSwitch />
          <SkDropdown :items="userMenuItems" @select="onUserMenu">
            <div class="sk-sidebar-user" title="账号菜单">
              <SkAvatar :char="avatarChar" size="md" />
              <span class="sk-sidebar-user-name">{{ me?.username || '未登录' }}</span>
              <SkIconChevronDown class="sk-sidebar-user-caret" />
            </div>
          </SkDropdown>
        </span>
      </header>
      <main class="content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  SkIconKey,
  SkIconUpload,
  SkIconHistory,
  SkIconLink,
  SkIconMenu,
  SkIconLock,
  SkIconFileText,
  SkIconChevronDown,
} from '@xzsoft/sketch-ui/icons'
import GooseLogo from '../components/GooseLogo.vue'
import { api, type Me } from '../api'
import { clearSession } from '../router'

const route = useRoute()
const router = useRouter()
// 展示名只读本地非敏感标记（登录时写入）：外壳不发认证请求——
// 否则未登录时 401 → 拦截器整页跳 /login → 外壳再挂载再 401，形成刷新死循环。
// 外壳仅在登录后的路由层级挂载，setup 时读一次即可
const me = ref<Me | null>(null)
{
  const username = localStorage.getItem('lg_center_user')
  if (username) me.value = { username, role: 'viewer' }
}

// 折叠态持久化（SkSidebar 底部自带折叠按钮）
const collapsed = ref(localStorage.getItem('lg_sider_collapsed') === '1')
watch(collapsed, (v) => localStorage.setItem('lg_sider_collapsed', v ? '1' : '0'))

// 移动端抽屉：断点与 CSS 媒体查询同口径；抽屉恒展开、不渲染折叠按钮
const isMobile = ref(window.matchMedia('(max-width: 768px)').matches)
window.matchMedia('(max-width: 768px)').addEventListener('change', (e) => { isMobile.value = e.matches })
const onCollapsed = (v: boolean) => { if (!isMobile.value) collapsed.value = v }
const mobileOpen = ref(false)
watch(mobileOpen, (v) => { document.documentElement.style.overflow = v ? 'hidden' : '' })
watch(() => route.path, () => { mobileOpen.value = false })
const goPage = (p: string) => { mobileOpen.value = false; router.push(p) }

// 顶栏面包屑：侧栏分组名作父级、当前页为末项
const crumbsMap: Record<string, string[]> = {
  '/rules': ['规则中心', '规则维护'],
  '/publish': ['规则中心', '发布与版本'],
  '/audit': ['规则中心', '审计日志'],
  '/access': ['规则中心', '接入与令牌'],
  '/settings': ['规则中心', '系统设置'],
  '/dict': ['规则中心', '数据字典'],
}
const crumbs = computed(() => crumbsMap[route.path] ?? [])
const avatarChar = computed(() => (me.value?.username || 'U').slice(0, 1).toUpperCase())

const userMenuItems = [
  { key: 'logout', label: '退出登录', danger: true },
]
const onUserMenu = (key: string | number) => {
  if (key === 'logout') {
    clearSession()
    localStorage.removeItem('lg_center_user')
    void api.post('/api/auth/logout').catch(() => {})
    router.push('/login')
  }
}
</script>

<style>
.app-shell { display: flex; height: 100vh; overflow: hidden; }
.brand-click { display: flex; align-items: center; gap: 8px; min-width: 0; cursor: pointer; }

.main-col { flex: 1; min-width: 0; display: flex; flex-direction: column; height: 100vh; }
.topbar {
  height: 48px; flex: none;
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 20px;
  background: var(--sk-surface, #fff); border-bottom: var(--sk-border-divider, 1px solid #e5e7eb);
}
.crumbs { display: inline-flex; align-items: center; min-width: 0; overflow: hidden; }
.topbar-right { gap: 4px; }
.topbar-right .sk-sidebar-user { flex: none; }
.sider-toggle { display: none; }

.content { flex: 1; min-height: 0; overflow-y: auto; padding: 16px; }

/* 移动端：侧边栏改抽屉（桌面布局零影响——768px 以下才生效） */
@media (max-width: 768px) {
  .sider-toggle {
    display: inline-flex; align-items: center; justify-content: center;
    width: 30px; height: 30px; padding: 0;
    border: var(--sk-border-input, 1px solid #ddd); border-radius: var(--sk-radius-btn, var(--sk-radius, 8px));
    background: var(--sk-surface, #fff); color: var(--sk-text-muted, #888); cursor: pointer;
  }
  .sider-toggle svg { width: 15px; height: 15px; }
  .sider {
    position: fixed; top: 0; bottom: 0; left: 0; z-index: 110;
    width: min(78vw, 240px) !important;
    transform: translateX(-100%); transition: transform 0.2s ease;
    padding-bottom: env(safe-area-inset-bottom);
    box-shadow: none;
  }
  .sider.is-mobile-open { transform: translateX(0); box-shadow: 0 0 40px rgba(0, 0, 0, 0.3); }
  .sider-mask { position: fixed; inset: 0; z-index: 100; background: rgba(0, 0, 0, 0.4); }
  .sider .sk-sidebar-item { padding-block: 11px; }
  .sider .sk-sidebar-user { padding-block: 9px; }
}
</style>
