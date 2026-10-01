<template>
  <div class="access-layout">
    <SkCard title="CI 拉取规则包（钉版本 + sha256 校验，供应链口径与二进制分发一致）">
      <pre class="code">{{ ciSnippet }}</pre>
    </SkCard>

    <SkCard title="读令牌（Bearer；明文仅创建时显示一次）" class="flex-card">
      <div class="token-ops">
        <SkButton variant="primary" size="sm" :disabled="!me || me.role !== 'admin'" @click="openCreate">新建令牌</SkButton>
      </div>
      <SkTable :columns="columns" :data="tokens" :loading="loading" row-key="id" size="sm">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'createdAt'">
            {{ fmtTime(record.createdAt) }}
          </template>
          <template v-else-if="column.key === 'lastUsed'">
            {{ fmtTime(record.lastUsed) }}
          </template>
          <template v-else-if="column.key === 'ops'">
            <SkPopconfirm title="确认删除该令牌？（使用它的 CI 将立即失效）" @confirm="removeToken(record.id)">
              <SkButton size="sm" variant="danger">删除</SkButton>
            </SkPopconfirm>
          </template>
        </template>
      </SkTable>
    </SkCard>

    <!-- 新建令牌弹窗：填用途 → 创建 → 原地展示一次性明文（复制后关闭） -->
    <SkModal v-model:open="createOpen" title="新建令牌" width="520px">
      <template v-if="!freshToken">
        <SkForm ref="tokenFormRef" label-width="60px">
          <SkFormField label="用途" name="name" required :rules="[{ required: true, message: '用途必填（如 watchgoose-ci，便于审计识别）' }]">
            <SkInput v-model="newTokenName" placeholder="如 watchgoose-ci" @keyup.enter="createToken" />
          </SkFormField>
        </SkForm>
      </template>
      <template v-else>
        <SkAlert tone="warning" style="margin: 0 0 12px">
          新令牌仅此一次显示，请立即复制并配置到 CI secrets——关闭后无法再查看。
        </SkAlert>
        <div class="fresh-token">
          <code class="mono">{{ freshToken }}</code>
          <SkButton size="sm" @click="copyToken">复制</SkButton>
        </div>
      </template>
      <template #footer>
        <template v-if="!freshToken">
          <SkButton @click="createOpen = false">取消</SkButton>
          <SkButton variant="primary" :loading="creating" style="margin-left: 8px" @click="createToken">确认创建</SkButton>
        </template>
        <SkButton v-else variant="primary" @click="closeCreate">我已保存，关闭</SkButton>
      </template>
    </SkModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { skMessage } from '@xzsoft/sketch-ui'
import { api, type TokenRow, type PackRow, type Me } from '../api'
import type { SkFormInstance } from '../types/form'

const me = ref<Me | null>(null)
const tokens = ref<TokenRow[]>([])
const latest = ref<PackRow | null>(null)
const loading = ref(false)
const newTokenName = ref('')
const freshToken = ref('')
const createOpen = ref(false)
const creating = ref(false)
const tokenFormRef = ref<SkFormInstance | null>(null)

const openCreate = () => {
  freshToken.value = ''
  newTokenName.value = ''
  createOpen.value = true
}
const closeCreate = () => {
  createOpen.value = false
  freshToken.value = ''
  load()
}
const copyToken = async () => {
  try {
    await navigator.clipboard.writeText(freshToken.value)
    skMessage.success('令牌已复制')
  } catch {
    skMessage.warning('复制失败，请手动选择复制')
  }
}

// RFC3339 → 本地可读 "YYYY-MM-DD HH:mm"；lastUsed 为空表示从未使用
const fmtTime = (s?: string) => (s ? s.replace('T', ' ').slice(0, 16) : '—')

const columns = [
  { title: '用途', key: 'name' },
  { title: '创建时间', key: 'createdAt', width: 190 },
  { title: '最近使用', key: 'lastUsed', width: 190 },
  { title: '操作', key: 'ops', width: 90, fixed: 'right' },
]

const load = async () => {
  loading.value = true
  try {
    me.value = await api.get<Me>('/api/auth/me')
    latest.value = await api.get<PackRow>('/api/packs/latest').catch(() => null)
    if (me.value.role === 'admin') {
      tokens.value = await api.get<TokenRow[]>('/api/tokens')
    }
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}
onMounted(load)

const ciSnippet = computed(() => {
  const v = latest.value?.version || '<版本号>'
  const sha = latest.value?.sha256 || '<sha256>'
  return [
    '# 1) 拉取钉版本的规则包（先在「发布与版本」页发布，把下面的版本与 sha256 换成目标版）',
    `curl -fsSL -H "Authorization: Bearer $RULES_TOKEN" -o .leakgoose/center-pack.yaml \\`,
    `  "\${LEAKGOOSE_CENTER}/api/packs/${v}.yaml"`,
    `# sha256（${sha.slice(0, 16)}…）人工核对或脚本校验后提交使用`,
    '',
    '# 2) 扫描：中心包 + 仓库本地叠加 + 基线（本地叠加与基线仍随仓库评审）',
    'leakgoose scan --mode history \\',
    '  -r .leakgoose/center-pack.yaml -r .leakgoose/rules.yaml -b .leakgoose/baseline.json',
  ].join('\n')
})

const createToken = async () => {
  // 必填校验走表单规则（行内红字），不再弹 tip
  try { await tokenFormRef.value?.validate() } catch { return }
  if (creating.value) return
  creating.value = true
  try {
    const r = await api.post<{ token: string }>('/api/tokens', { name: newTokenName.value.trim() })
    freshToken.value = r.token // 弹窗原地切换为一次性明文展示态
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    creating.value = false
  }
}

const removeToken = async (id: number) => {
  try {
    await api.del(`/api/tokens/${id}`)
    skMessage.success('已删除')
    load()
  } catch (e) {
    skMessage.error((e as Error).message)
  }
}
</script>

<style scoped>
.access-layout { display: flex; flex-direction: column; gap: 14px; height: 100%; }
.access-layout > .flex-card { flex: 1; min-height: 0; }
.token-ops { display: flex; gap: 10px; margin-bottom: 10px; }
.fresh-token { display: flex; align-items: center; gap: 10px; background: var(--sk-muted-soft, #f5f6f8); border: var(--sk-border-thin, 1px solid #e5e7eb); border-radius: 8px; padding: 10px 12px; }
.fresh-token code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: 12px; }
</style>
