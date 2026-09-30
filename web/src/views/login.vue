<template>
  <div class="login-page">
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
      </div>

      <div class="foot">© {{ new Date().getFullYear() }} LeakGoose · 扫描在本地，规则集中管</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { skMessage } from '@xzsoft/sketch-ui'
import GooseLogo from '../components/GooseLogo.vue'
import { api, type Me } from '../api'
import { markSession } from '../router'

const router = useRouter()
const route = useRoute()
const loading = ref(false)
const username = ref('')
const password = ref('')
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

.foot {
  margin-top: 18px; text-align: center;
  color: var(--sk-text-faint, #aaa); font-size: var(--sk-font-size-xs, 12px);
}
</style>
