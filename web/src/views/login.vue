<template>
  <div class="login-page">
    <div class="top-actions"><SkThemeSwitch /></div>
    <div class="box">
      <div class="hero">
        <GooseLogo :size="56" />
      </div>
      <h1 class="headline">LeakGoose 规则中心</h1>
      <p class="sub">敏感信息规则 · 集中维护 / 版本化发布</p>

      <div class="form-box">
        <SkForm ref="loginFormRef" @submit.prevent="doLogin">
          <SkFormField name="username" label="用户名" required>
            <SkInput v-model="username" placeholder="请输入用户名" autocomplete="off" @keyup.enter="doLogin" />
          </SkFormField>
          <SkFormField name="password" label="密码" required>
            <SkInput v-model="password" type="password" placeholder="请输入密码" autocomplete="current-password" @keyup.enter="doLogin" />
          </SkFormField>
          <SkButton variant="primary" html-type="submit" block :loading="loading" @click.prevent="doLogin">
            登 录
          </SkButton>
        </SkForm>
        <template v-if="ssoEnabled">
          <div class="divider"><span>或</span></div>
          <SkButton block @click="goSso">
            <svg class="sso-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <rect x="3" y="11" width="18" height="10" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            SSO 登录
          </SkButton>
        </template>
      </div>

      <div class="foot">© {{ year }} LeakGoose · v{{ version }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { skMessage } from '@xzsoft/sketch-ui'
import GooseLogo from '../components/GooseLogo.vue'
import { api, type Me } from '../api'
import { markSession } from '../router'
import { version } from '../../package.json'

const router = useRouter()
const route = useRoute()
const year = computed(() => new Date().getFullYear())
const loading = ref(false)
const username = ref('')
const password = ref('')
const ssoEnabled = ref(false)

// 探测 SSO 可用性：后端未配置 OIDC 时按钮不出现，本地登录不受影响
onMounted(async () => {
  try {
    ssoEnabled.value = (await api.get<{ enabled: boolean }>('/api/auth/oidc/config')).enabled
  } catch {
    /* 探测失败按未启用处理 */
  }
})

// SSO：后端 302 到 Provider 授权端点，回跳 /oidc/callback 由回调页完成登录
function goSso(): void {
  window.location.href = '/api/auth/oidc/login?prompt=select_account'
}

const doLogin = async () => {
  if (!username.value || !password.value) return skMessage.warning('请输入用户名与密码')
  if (loading.value) return
  loading.value = true
  try {
    const me = await api.post<Me>('/api/auth/login', { username: username.value, password: password.value })
    markSession()
    localStorage.setItem('lg_center_user', me.username)
    skMessage.success('登录成功')
    router.push(String(route.query.redirect || '/rules'))
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  padding: 40px 16px;
  background: var(--sk-bg-pattern, none), var(--sk-paper, #f5f6f8);
  background-size: var(--sk-bg-pattern-size, auto), auto;
}

/* 右上角主题切换（与看门鹅登录页同款） */
.top-actions {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 10;
}
.box { width: 380px; position: relative; z-index: 1; }
.hero { display: flex; justify-content: center; margin-bottom: 14px; }
.headline {
  text-align: center; font-size: 22px; font-weight: 700;
  color: var(--sk-text, #222); letter-spacing: 0.02em;
}
.sub { text-align: center; margin: 8px 0 22px; color: var(--sk-text-muted, #888); font-size: var(--sk-font-size-sm, 13px); }

.form-box {
  background: var(--sk-surface, #fff);
  border: var(--sk-border, 1px solid #e5e7eb);
  border-radius: var(--sk-radius-card, var(--sk-radius, 10px));
  box-shadow: var(--sk-shadow-pop, 0 4px 16px rgba(0, 0, 0, 0.08));
  padding: 22px;
}

.divider {
  display: flex; align-items: center; gap: 10px;
  margin: 16px 0; color: var(--sk-text-faint, #aaa); font-size: var(--sk-font-size-xs, 12px);
}
.divider::before, .divider::after { content: ''; flex: 1; border-top: var(--sk-border-divider, 1px solid #e5e7eb); }
.sso-icon { width: 14px; height: 14px; }

/* 页脚与看门鹅登录页同款：11px / 字距 2px */
.foot {
  margin-top: 26px;
  text-align: center;
  color: var(--sk-text-faint, #888);
  font-size: 11px;
  letter-spacing: 2px;
}
</style>
