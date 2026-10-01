<template>
  <div class="settings-layout">
    <SkCard title="SSO 登录（OIDC）" class="flex-card">
      <template #extra>
        <SkTag :color="enabled ? 'success' : 'default'">{{ enabled ? '已启用' : '未启用' }}</SkTag>
      </template>
      <SkAlert v-if="!me || me.role !== 'admin'" tone="warning">仅管理员可查看与维护 SSO 配置</SkAlert>
      <SkForm v-else label-width="120px" style="max-width: 640px">
        <SkFormField name="issuer" label="Issuer 地址" hint="标准 OIDC Provider 的 Issuer，如 http://localhost:8080（看门鹅）">
          <SkInput v-model="form.issuer" placeholder="https://auth.example.com" />
        </SkFormField>
        <SkFormField name="clientId" label="Client ID" hint="认证中心「应用接入」里注册的 client_id">
          <SkInput v-model="form.clientId" placeholder="leakgoose-center" />
        </SkFormField>
        <SkFormField name="secret" label="Client Secret" :hint="secretSet ? '已设置（公开客户端无 secret 也正常）——留空不修改，填 - 清除' : 'PKCE 公开客户端可留空'">
          <SkInput v-model="form.clientSecret" type="password" autocomplete="new-password" placeholder="留空不修改；- 表示清除" />
        </SkFormField>
        <SkFormField name="redirect" label="回调基准地址" hint="反代场景填对外地址（如 https://rules.example.com）；本机/直连留空自动推断">
          <SkInput v-model="form.redirectBase" placeholder="（自动推断）" />
        </SkFormField>
        <SkFormField name="allowed" label="登录白名单" required hint="允许 SSO 登录的账号，逗号分隔（粘贴空格/换行文本也可）；清空即整体停用 SSO">
          <LgTextarea v-model="form.allowedUsers" :rows="3" placeholder="admin, terence" />
        </SkFormField>
        <SkFormField name="admins" label="管理员名单" hint="名单内 SSO 登录即 admin 角色，其余 viewer；每次登录同步（逗号分隔）">
          <LgTextarea v-model="form.adminUsers" :rows="2" placeholder="admin" />
        </SkFormField>
        <SkFormField name="ops" label=" ">
          <SkButton variant="primary" :loading="saving" @click="save">保存配置</SkButton>
          <span v-if="savedAt" class="saved-tip">已保存 {{ savedAt }}（即时生效，登录页刷新可见 SSO 按钮）</span>
        </SkFormField>
      </SkForm>
    </SkCard>

    <SkCard title="对接看门鹅速查">
      <ol class="guide">
        <li>看门鹅管理台「应用接入」新建应用：<code>authorization_code</code> + 范围 <code>openid profile email</code> + 强制 PKCE，回调地址填 <code>{{ redirectHint }}</code></li>
        <li>本页填 Issuer（<code>http://localhost:8080</code>）与 Client ID；公开客户端 Secret 留空</li>
        <li>把允许登录的看门鹅账号填进白名单，需要管理权限的加进管理员名单，保存</li>
        <li>SSO 用户按 OIDC sub 绑定，与本地账号同名会拒绝（防接管）；本地密码登录始终可用</li>
      </ol>
    </SkCard>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { skMessage } from '@xzsoft/sketch-ui'
import { api, type Me } from '../api'
import LgTextarea from '../components/LgTextarea.vue'

const me = ref<Me | null>(null)
const enabled = ref(false)
const secretSet = ref(false)
const saving = ref(false)
const savedAt = ref('')
const form = reactive({
  issuer: '',
  clientId: '',
  clientSecret: '',
  redirectBase: '',
  allowedUsers: '',
  adminUsers: '',
})

const load = async () => {
  try {
    me.value = await api.get<Me>('/api/auth/me')
    if (me.value.role !== 'admin') return
    const s = await api.get<OidcSettings>('/api/auth/oidc/settings')
    form.issuer = s.issuer || ''
    form.clientId = s.clientId || ''
    form.redirectBase = s.redirectBase || ''
    form.allowedUsers = s.allowedUsers || ''
    form.adminUsers = s.adminUsers || ''
    enabled.value = s.enabled
    secretSet.value = s.clientSecretSet
  } catch (e) {
    skMessage.error((e as Error).message)
  }
}
onMounted(load)

// 展示用回调提示：固定基准时用之，否则按当前地址推断
const redirectHint = computed(() =>
  form.redirectBase ? `${form.redirectBase.replace(/\/$/, '')}/oidc/callback`
    : `${location.protocol}//${location.host}/oidc/callback`)

const save = async () => {
  if (saving.value) return
  saving.value = true
  try {
    const body: Partial<OidcSettings> & { clientSecret?: string } = {
      issuer: form.issuer.trim(),
      clientId: form.clientId.trim(),
      redirectBase: form.redirectBase.trim(),
      allowedUsers: form.allowedUsers.split(/[\n,;\s]+/).map(s => s.trim()).filter(Boolean).join(', '),
      adminUsers: form.adminUsers.split(/[\n,;\s]+/).map(s => s.trim()).filter(Boolean).join(', '),
    }
    if (form.clientSecret.trim()) body.clientSecret = form.clientSecret.trim()
    const s = await api.put<OidcSettings>('/api/auth/oidc/settings', body)
    enabled.value = s.enabled
    secretSet.value = s.clientSecretSet
    form.clientSecret = ''
    savedAt.value = new Date().toTimeString().slice(0, 5)
    skMessage.success(s.enabled ? 'SSO 配置已保存并启用' : '已保存（白名单为空，SSO 处于停用状态）')
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    saving.value = false
  }
}

interface OidcSettings {
  issuer: string
  clientId: string
  clientSecretSet: boolean
  redirectBase: string
  allowedUsers: string
  adminUsers: string
  enabled: boolean
}
</script>

<style scoped>
.settings-layout { display: flex; flex-direction: column; gap: 14px; height: 100%; }
.settings-layout > .flex-card { flex: 1; min-height: 0; }
.saved-tip { margin-left: 12px; font-size: 12px; color: var(--sk-text-faint, #aaa); }
.guide { padding-left: 20px; margin: 0; color: var(--sk-text-muted); font-size: 13px; line-height: 2; }
.guide code { background: var(--sk-muted-soft, #f5f6f8); border-radius: 4px; padding: 1px 6px; font-size: 12px; }
</style>
