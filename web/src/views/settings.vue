<template>
  <div class="settings-layout">
    <SkCard title="系统设置" class="fill-card">
      <SkTabs v-model="activeTab" :tabs="tabs" class="setting-tabs" />

      <!-- ===== SSO 登录 ===== -->
      <div v-if="activeTab === 'sso'">
        <SkAlert v-if="!me || me.role !== 'admin'" tone="warning">仅管理员可维护 SSO 配置</SkAlert>
        <template v-else>
          <SkForm label-width="120px" style="max-width: 640px">
            <SkFormField name="issuer" label="Issuer 地址" hint="标准 OIDC Provider 的 Issuer，如 http://localhost:8080（看门鹅）">
              <SkInput v-model="oidc.issuer" placeholder="https://auth.example.com" />
            </SkFormField>
            <SkFormField name="clientId" label="Client ID" hint="认证中心「应用接入」里注册的 client_id">
              <SkInput v-model="oidc.clientId" placeholder="leakgoose-center" />
            </SkFormField>
            <SkFormField name="secret" label="Client Secret" :hint="oidc.clientSecretSet ? '已设置（公开客户端无 secret 也正常）——留空不修改，填 - 清除' : 'PKCE 公开客户端可留空'">
              <SkInput v-model="oidc.clientSecret" type="password" autocomplete="new-password" placeholder="留空不修改；- 表示清除" />
            </SkFormField>
            <SkFormField name="redirect" label="回调基准地址" hint="反代场景填对外地址（如 https://rules.example.com）；本机/直连留空自动推断">
              <SkInput v-model="oidc.redirectBase" placeholder="（自动推断）" />
            </SkFormField>
            <SkFormField name="allowed" label="登录白名单" required hint="允许 SSO 登录的账号，逗号分隔；清空即整体停用 SSO。白名单内账号以「编辑」角色登录（可维护规则/用例）；发布、令牌、本页设置属管理面，请用本地管理员账号">
              <LgTextarea v-model="oidc.allowedUsers" :rows="3" placeholder="admin, terence" />
            </SkFormField>
            <SkFormField name="ops" label=" ">
              <SkButton variant="primary" :loading="savingOidc" @click="saveOidc">保存配置</SkButton>
              <span v-if="ssoEnabled" class="saved-tip">当前状态：已启用</span>
            </SkFormField>
          </SkForm>
          <SkCard title="对接看门鹅速查" style="margin-top: 6px">
            <ol class="guide">
              <li>看门鹅管理台「应用接入」新建应用：<code>authorization_code</code> + 范围 <code>openid profile email</code> + 强制 PKCE，回调地址填 <code>{{ redirectHint }}</code></li>
              <li>本页填 Issuer（<code>http://localhost:8080</code>）与 Client ID；公开客户端 Secret 留空</li>
              <li>把允许登录的看门鹅账号填进白名单，保存——登录页即出现「SSO 登录」按钮</li>
              <li>SSO 用户按 OIDC sub 绑定，与本地账号同名会拒绝（防接管）；本地密码登录始终可用</li>
            </ol>
          </SkCard>
        </template>
      </div>

      <!-- ===== 登录与安全 ===== -->
      <div v-else-if="activeTab === 'security'">
        <SkAlert v-if="!me || me.role !== 'admin'" tone="warning">仅管理员可维护会话设置</SkAlert>
        <template v-else>
          <SkForm label-width="120px" style="max-width: 640px">
            <SkFormField name="ttl" label="会话时长" hint="登录会话的有效期（小时，1-168）；修改后对新登录生效">
              <span class="sk-space">
                <SkInput v-model.number="sessionTtl" type="number" placeholder="12" style="width: 160px" />
                <SkButton variant="primary" :loading="savingSession" @click="saveSession">保存</SkButton>
              </span>
            </SkFormField>
          </SkForm>

          <div class="sec-title">修改密码<span class="sec-sub">（当前账号：{{ me?.username }}）</span></div>
          <SkForm label-width="120px" style="max-width: 640px">
            <SkFormField name="old" label="原密码" required>
              <SkInput v-model="pwForm.oldPassword" type="password" autocomplete="current-password" placeholder="当前密码" />
            </SkFormField>
            <SkFormField name="new" label="新密码" required :rules="pwRules">
              <SkInput v-model="pwForm.newPassword" type="password" autocomplete="new-password" placeholder="至少 8 位" />
            </SkFormField>
            <SkFormField name="confirm" label="确认新密码" required>
              <SkInput v-model="pwForm.confirm" type="password" autocomplete="new-password" placeholder="再输一次" />
            </SkFormField>
            <SkFormField name="ops" label=" ">
              <SkButton variant="primary" :loading="changingPw" @click="changePassword">修改密码</SkButton>
              <span class="saved-tip">SSO 账号无本地密码（后端会明确拒绝）；改密后当前会话保持有效</span>
            </SkFormField>
          </SkForm>
        </template>
      </div>

      <!-- ===== 关于 ===== -->
      <div v-else-if="activeTab === 'about'" class="about">
        <div class="about-row"><span class="about-k">规则中心版本</span><span class="mono">v{{ version }}</span></div>
        <div class="about-row"><span class="about-k">规则数（启用）</span><span>{{ about.rules }}</span></div>
        <div class="about-row"><span class="about-k">最新发布版本</span><span class="mono">{{ about.latestVersion || '未发布' }}</span></div>
        <div class="about-row"><span class="about-k">SSO 登录</span><span>{{ ssoEnabled ? '已启用' : '未启用' }}</span></div>
        <div class="about-row"><span class="about-k">运行形态</span><span>SQLite 单文件 · 会话 {{ sessionTtlLabel }} · 沙箱与扫描引擎同源</span></div>
      </div>
    </SkCard>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { skMessage } from '@xzsoft/sketch-ui'
import { api, type Me } from '../api'
import LgTextarea from '../components/LgTextarea.vue'
import { version } from '../../package.json'

const tabs = [
  { key: 'sso', label: 'SSO 登录' },
  { key: 'security', label: '登录与安全' },
  { key: 'about', label: '关于' },
]
const activeTab = ref('sso')

const me = ref<Me | null>(null)
const ssoEnabled = ref(false)

// ---------- SSO ----------
const savingOidc = ref(false)
const oidc = reactive({
  issuer: '',
  clientId: '',
  clientSecret: '',
  redirectBase: '',
  allowedUsers: '',
  clientSecretSet: false,
})
const redirectHint = computed(() =>
  oidc.redirectBase ? `${oidc.redirectBase.replace(/\/$/, '')}/oidc/callback`
    : `${location.protocol}//${location.host}/oidc/callback`)

const loadOidc = async () => {
  const s = await api.get<OidcSettings>('/api/auth/oidc/settings')
  oidc.issuer = s.issuer || ''
  oidc.clientId = s.clientId || ''
  oidc.redirectBase = s.redirectBase || ''
  oidc.allowedUsers = s.allowedUsers || ''
  oidc.clientSecretSet = s.clientSecretSet
  ssoEnabled.value = s.enabled
}
const saveOidc = async () => {
  if (savingOidc.value) return
  savingOidc.value = true
  try {
    const body: Record<string, string> = {
      issuer: oidc.issuer.trim(),
      clientId: oidc.clientId.trim(),
      redirectBase: oidc.redirectBase.trim(),
      allowedUsers: oidc.allowedUsers.split(/[\n,;\s]+/).map(x => x.trim()).filter(Boolean).join(', '),
    }
    if (oidc.clientSecret.trim()) body.clientSecret = oidc.clientSecret.trim()
    const s = await api.put<OidcSettings>('/api/auth/oidc/settings', body)
    ssoEnabled.value = s.enabled
    oidc.clientSecretSet = s.clientSecretSet
    oidc.clientSecret = ''
    skMessage.success(s.enabled ? 'SSO 配置已保存并启用' : '已保存（白名单为空，SSO 处于停用状态）')
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    savingOidc.value = false
  }
}

// ---------- 登录与安全 ----------
const sessionTtl = ref(12)
const savingSession = ref(false)
const loadSession = async () => {
  const s = await api.get<{ ttlHours: number }>('/api/settings/session')
  sessionTtl.value = s.ttlHours
}
const saveSession = async () => {
  if (!Number.isInteger(sessionTtl.value) || sessionTtl.value < 1 || sessionTtl.value > 168) {
    return skMessage.warning('会话时长需为 1-168 的整数小时')
  }
  savingSession.value = true
  try {
    await api.put('/api/settings/session', { ttlHours: sessionTtl.value })
    skMessage.success('会话时长已保存（对新登录生效）')
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    savingSession.value = false
  }
}

const pwForm = reactive({ oldPassword: '', newPassword: '', confirm: '' })
const changingPw = ref(false)
const pwRules = [
  { required: true, message: '新密码必填' },
  { min: 8, message: '至少 8 位' },
]
const changePassword = async () => {
  if (!pwForm.oldPassword || pwForm.newPassword.length < 8) {
    return skMessage.warning('请完整填写：原密码 + 至少 8 位新密码')
  }
  if (pwForm.newPassword !== pwForm.confirm) {
    return skMessage.warning('两次输入的新密码不一致')
  }
  changingPw.value = true
  try {
    await api.post('/api/auth/password', { oldPassword: pwForm.oldPassword, newPassword: pwForm.newPassword })
    pwForm.oldPassword = pwForm.newPassword = pwForm.confirm = ''
    skMessage.success('密码已修改')
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    changingPw.value = false
  }
}

// ---------- 关于 ----------
const about = reactive({ rules: 0, latestVersion: '' })
const sessionTtlLabel = computed(() => `${sessionTtl.value} 小时`)

onMounted(async () => {
  me.value = await api.get<Me>('/api/auth/me')
  if (me.value.role === 'admin') {
    loadOidc().catch(() => {})
    loadSession().catch(() => {})
  }
  try {
    const cfg = await api.get<{ enabled: boolean }>('/api/auth/oidc/config')
    ssoEnabled.value = cfg.enabled
  } catch { /* 忽略：探测失败按未启用 */ }
  api.get<unknown[]>('/api/rules?enabled=true').then(r => { about.rules = r.length }).catch(() => {})
  api.get<{ version: string }>('/api/packs/latest').then(p => { about.latestVersion = p.version || '' }).catch(() => {})
})

interface OidcSettings {
  issuer: string
  clientId: string
  clientSecretSet: boolean
  redirectBase: string
  allowedUsers: string
  enabled: boolean
}
</script>

<style scoped>
.settings-layout { height: 100%; }
.setting-tabs { margin-bottom: 14px; }
.saved-tip { margin-left: 12px; font-size: 12px; color: var(--sk-text-faint, #aaa); }
.guide { padding-left: 20px; margin: 0; color: var(--sk-text-muted); font-size: 13px; line-height: 2; }
.guide code { background: var(--sk-muted-soft, #f5f6f8); border-radius: 4px; padding: 1px 6px; font-size: 12px; }
.sec-title { font-size: 14px; font-weight: 600; margin: 18px 0 12px; }
.sec-sub { font-weight: 400; font-size: 12px; color: var(--sk-text-faint); }
.about { max-width: 560px; }
.about-row { display: flex; justify-content: space-between; padding: 10px 2px; border-bottom: var(--sk-border-divider, 1px solid #eee); font-size: 13px; }
.about-k { color: var(--sk-text-muted); }
</style>
