<template>
  <div class="cb-wrap">
    <SkSpin v-if="!error" block tip="正在完成 SSO 登录…" />
    <div v-else class="cb-error">
      <SkEmpty :description="`SSO 登录失败：${error}`" />
      <SkButton variant="primary" @click="$router.push('/login')">返回登录</SkButton>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { skMessage } from '@xzsoft/sketch-ui'
import { api, type Me } from '../api'
import { markSession } from '../router'

// SSO 回调落地页：Provider 302 回 /oidc/callback?code&state，
// 此页把 code/state 交给后端换会话（与本地登录同一 cookie 体系），然后进入规则中心。
const route = useRoute()
const router = useRouter()
const error = ref('')

onMounted(async () => {
  const code = typeof route.query.code === 'string' ? route.query.code : ''
  const state = typeof route.query.state === 'string' ? route.query.state : ''
  if (!code || !state) {
    error.value = '回调参数缺失，请重新发起 SSO 登录'
    return
  }
  try {
    const me = await api.post<Me>('/api/auth/oidc/callback', { code, state })
    markSession()
    localStorage.setItem('lg_center_user', me.username)
    skMessage.success(`欢迎，${me.username}`)
    router.push('/rules')
  } catch (e) {
    error.value = (e as Error).message
  }
})
</script>

<style scoped>
.cb-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--sk-bg-pattern, none), var(--sk-paper, #f5f6f8); }
.cb-error { display: flex; flex-direction: column; align-items: center; gap: 14px; }
</style>
