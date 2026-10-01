<template>
  <div>
    <SkCard>
      <div class="pub-row">
        <div v-if="latest" class="latest" style="flex: 1">
          当前已发布：<b>{{ latest.version }}</b>
          <span class="mono sha-full" title="点击复制完整 sha256" @click="copySha(latest.sha256)">sha256 {{ latest.sha256 }}</span>
          <span>{{ fmtTime(latest.publishedAt) }} · {{ latest.publishedBy }}</span>
          <span class="changelog">{{ latest.changelog }}</span>
        </div>
        <div v-else class="latest" style="flex: 1">尚未发布过版本</div>
        <SkButton variant="primary" :disabled="!me || me.role !== 'admin'" @click="publishOpen = true">
          发布新版本
        </SkButton>
      </div>
      <div v-if="me && me.role !== 'admin'" class="no-perm">仅管理员可发布（编辑角色可维护规则草稿）</div>
    </SkCard>

    <!-- 发布弹窗：点「发布新版本」后填写说明（必填行内校验），确认才真正发布 -->
    <SkModal v-model:open="publishOpen" title="发布新版本" width="560px">
      <SkAlert tone="info" style="margin-bottom: 12px">
        发布前会对全部启用规则跑用例回归，期望不符将拒绝发布；发布后生成不可变版本（版本号 + sha256）。
      </SkAlert>
      <SkForm ref="pubFormRef" label-width="80px">
        <SkFormField label="发布说明" name="changelog" required :rules="[{ required: true, message: '发布说明必填（进入版本历史与审计）' }]">
          <LgTextarea v-model="changelog" :rows="3" placeholder="如：新增中国护照号规则；cn-mobile 收窄测试路径豁免" />
        </SkFormField>
      </SkForm>
      <template #footer>
        <SkButton @click="publishOpen = false">取消</SkButton>
        <SkButton variant="primary" :loading="publishing" style="margin-left: 8px" @click="publish">确认发布</SkButton>
      </template>
    </SkModal>

    <SkTable style="margin-top: 14px" :columns="columns" :data="packs" :loading="loading" row-key="version" size="md">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'sha256'">
          <span class="mono" :title="record.sha256">{{ record.sha256.slice(0, 12) }}…</span>
        </template>
        <template v-else-if="column.key === 'publishedAt'">
          {{ fmtTime(record.publishedAt) }}
        </template>
        <template v-else-if="column.key === 'changelog'">
          <span class="cell-break">{{ record.changelog }}</span>
        </template>
        <template v-else-if="column.key === 'ops'">
          <SkButton size="sm" @click="viewYaml(record.version)">查看 YAML</SkButton>
        </template>
      </template>
    </SkTable>

    <SkModal v-model:open="yamlOpen" :title="`规则包 ${viewingVersion}.yaml`" width="720px">
      <pre class="code">{{ yamlText }}</pre>
    </SkModal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { skMessage } from '@xzsoft/sketch-ui'
import { api, type PackRow, type Me } from '../api'
import LgTextarea from '../components/LgTextarea.vue'
import type { SkFormInstance } from '../types/form'

const me = ref<Me | null>(null)
const latest = ref<PackRow | null>(null)
const packs = ref<PackRow[]>([])
const loading = ref(false)
const changelog = ref('')
const publishing = ref(false)
const publishOpen = ref(false)
const pubFormRef = ref<SkFormInstance | null>(null)
const yamlOpen = ref(false)
const yamlText = ref('')
const viewingVersion = ref('')

// RFC3339 → 本地可读 "YYYY-MM-DD HH:mm"
const fmtTime = (s?: string) => (s ? s.replace('T', ' ').slice(0, 16) : '—')

const columns = [
  { title: '版本', key: 'version', width: 150 },
  { title: 'sha256', key: 'sha256', width: 130 },
  { title: '发布时间', key: 'publishedAt', width: 180 },
  { title: '发布人', key: 'publishedBy', width: 100 },
  { title: '说明', key: 'changelog' },
  { title: '操作', key: 'ops', width: 110, fixed: 'right' },
]

const load = async () => {
  loading.value = true
  try {
    packs.value = await api.get<PackRow[]>('/api/packs')
    latest.value = packs.value[0] || null
    me.value = await api.get<Me>('/api/auth/me')
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}
onMounted(load)

const publish = async () => {
  // 必填校验走表单规则（行内红字），不再弹 tip
  try { await pubFormRef.value?.validate() } catch { return }
  if (publishing.value) return
  publishing.value = true
  try {
    const p = await api.post<PackRow>('/api/packs', { changelog: changelog.value })
    skMessage.success(`已发布 ${p.version}（sha256 ${p.sha256.slice(0, 12)}…）`)
    changelog.value = ''
    publishOpen.value = false
    load()
  } catch (e) {
    // 422 = 用例回归失败，错误信息逐条列出——直接展示给操作者
    skMessage.error((e as Error).message)
  } finally {
    publishing.value = false
  }
}

const copySha = async (sha: string) => {
  try {
    await navigator.clipboard.writeText(sha)
    skMessage.success('sha256 已复制')
  } catch {
    skMessage.warning('复制失败，请手动选择复制')
  }
}

const viewYaml = async (version: string) => {
  const text = await fetch(`/api/packs/${version}.yaml`, { credentials: 'same-origin' }).then(r => {
    if (!r.ok) throw new Error(`拉取失败 ${r.status}`)
    return r.text()
  }).catch(e => String(e))
  yamlText.value = text
  viewingVersion.value = version
  yamlOpen.value = true
}
</script>

<style scoped>
.pub-row { display: flex; gap: 16px; align-items: flex-end; }
.pub-label { font-size: 13px; color: var(--sk-text-muted); margin-bottom: 6px; }
.latest { margin-top: 12px; font-size: 13px; color: var(--sk-text-muted); display: flex; gap: 12px; flex-wrap: wrap; }
.latest .changelog::before { content: '· '; }
.latest .sha-full { cursor: pointer; word-break: break-all; }
.latest .sha-full:hover { color: var(--sk-text); }
.no-perm { margin-top: 8px; font-size: 12px; color: var(--sk-warning, #d48806); }
</style>
