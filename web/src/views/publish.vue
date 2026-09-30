<template>
  <div>
    <SkCard>
      <div class="pub-row">
        <div style="flex: 1">
          <div class="pub-label">发布说明（changelog，必填——进入版本历史与审计）</div>
          <SkInput v-model="changelog" type="textarea" :rows="2" placeholder="如：新增中国护照号规则；cn-mobile 收窄测试路径豁免" />
        </div>
        <SkButton variant="primary" :loading="publishing" :disabled="!me || me.role !== 'admin'" @click="publish">
          发布新版本
        </SkButton>
      </div>
      <div v-if="latest" class="latest">
        当前已发布：<b>{{ latest.version }}</b>
        <span class="mono">sha256 {{ latest.sha256.slice(0, 12) }}…</span>
        <span>{{ fmtTime(latest.publishedAt) }} · {{ latest.publishedBy }}</span>
        <span class="changelog">{{ latest.changelog }}</span>
      </div>
      <div v-else class="latest">尚未发布过版本</div>
      <div v-if="me && me.role !== 'admin'" class="no-perm">仅管理员可发布（编辑角色可维护规则草稿）</div>
    </SkCard>

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

const me = ref<Me | null>(null)
const latest = ref<PackRow | null>(null)
const packs = ref<PackRow[]>([])
const loading = ref(false)
const changelog = ref('')
const publishing = ref(false)
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
  if (!changelog.value.trim()) return skMessage.warning('请填写发布说明')
  if (publishing.value) return
  publishing.value = true
  try {
    const p = await api.post<PackRow>('/api/packs', { changelog: changelog.value })
    skMessage.success(`已发布 ${p.version}（sha256 ${p.sha256.slice(0, 12)}…）`)
    changelog.value = ''
    load()
  } catch (e) {
    // 422 = 用例回归失败，错误信息逐条列出——直接展示给操作者
    skMessage.error((e as Error).message)
  } finally {
    publishing.value = false
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
.no-perm { margin-top: 8px; font-size: 12px; color: var(--sk-warning, #d48806); }
</style>
