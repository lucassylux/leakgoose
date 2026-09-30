<template>
  <div>
    <search-form>
      <SkFormField name="f">
        <SkInput v-model="query.q" placeholder="规则 id / 名称" clearable @keyup.enter="load" />
      </SkFormField>
      <SkFormField name="f">
        <SkSelect v-model="query.enabled" placeholder="启停（全部）" clearable :options="enabledOptions" />
      </SkFormField>
      <SkFormField name="f">
        <SkButton variant="primary" @click="load">查询</SkButton>
        <SkButton variant="primary" style="margin-left: 8px" @click="openEdit(null)">新建规则</SkButton>
      </SkFormField>
    </search-form>

    <SkTable :columns="columns" :data="rows" :loading="loading" row-key="id" size="md" :scroll-x="1100">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'severity'">
          <SkTag :color="sevColor[record.severity]">{{ record.severity }}</SkTag>
        </template>
        <template v-else-if="column.key === 'enabled'">
          <SkTag :color="record.enabled ? 'success' : 'default'">{{ record.enabled ? '启用' : '停用' }}</SkTag>
        </template>
        <template v-else-if="column.key === 'validate'">
          <span class="mono cell-clip" :title="record.validate || ''">{{ record.validate || '—' }}</span>
        </template>
        <template v-else-if="column.key === 'pattern'">
          <span class="mono cell-regex" :title="record.pattern">{{ record.pattern }}</span>
        </template>
        <template v-else-if="column.key === 'updatedAt'">
          {{ fmtTime(record.updatedAt) }}
        </template>
        <template v-else-if="column.key === 'ops'">
          <SkButton size="sm" @click="openEdit(record)">编辑</SkButton>
          <SkPopconfirm title="确认删除该规则（连同用例）？" @confirm="removeRule(record.id)">
            <SkButton size="sm" variant="danger" style="margin-left: 6px">删除</SkButton>
          </SkPopconfirm>
        </template>
      </template>
    </SkTable>

    <!-- 规则编辑器：表单 + 实时测试沙箱 + 用例 -->
    <SkModal v-model:open="editOpen" :title="form.id ? `编辑规则：${form.id}` : '新建规则'" width="760px">
      <div class="editor-grid">
        <div class="form-col">
          <SkForm ref="formRef" label-width="92px">
            <SkFormField name="id" label="规则 ID" required :rules="fRules.id">
              <SkInput v-model="form.id" :disabled="!!form._exists" placeholder="如 cn-passport" />
            </SkFormField>
            <SkFormField name="name" label="名称" required :rules="fRules.name">
              <SkInput v-model="form.name" placeholder="如 中国护照号" />
            </SkFormField>
            <SkFormField name="severity" label="严重级" required>
              <SkSelect v-model="form.severity" :options="sevOptions" />
            </SkFormField>
            <SkFormField name="pattern" label="正则" required :rules="fRules.pattern">
              <SkInput v-model="form.pattern" type="textarea" :rows="3" class="mono" placeholder="regexp2 语法，支持前后瞻 (?<!…)" />
            </SkFormField>
            <SkFormField name="validate" label="验真函数">
              <SkSelect v-model="form.validate" clearable placeholder="（无）" :options="validateOptions" />
            </SkFormField>
            <SkFormField name="paths" label="路径排除">
              <SkInput v-model="excludePathsText" placeholder="逗号分隔，如 **/test/**, docs/**" />
            </SkFormField>
            <SkFormField name="enabled" label="状态">
              <SkSelect v-model="form.enabled" :options="enabledOptions" />
            </SkFormField>
            <SkFormField name="desc" label="说明">
              <SkInput v-model="form.description" :maxlength="200" placeholder="规则背景/负责人/豁免口径" />
            </SkFormField>
          </SkForm>
        </div>
        <div class="sandbox-col">
          <div class="sb-title">实时测试沙箱 <span class="sb-sub">（扫描引擎同源，所测即所得）</span></div>
          <SkInput v-model="sandbox" type="textarea" :rows="6" class="mono" placeholder="粘贴样例文本，立即看命中…" @input="onSandboxInput" />
          <div v-if="sandboxError" class="sb-error">{{ sandboxError }}</div>
          <div v-else class="sb-hits">
            <SkTag v-for="h in sandboxHits" :key="h" color="danger" class="mono">{{ h }}</SkTag>
            <span v-if="sandbox && !sandboxHits.length && !sandboxError" class="sb-empty">（无命中）</span>
          </div>

          <div class="sb-title" style="margin-top: 14px">用例 <span class="sb-sub">（发布前全量回归，期望不符即拒绝发布）</span></div>
          <div v-for="(c, i) in cases" :key="i" class="case-row">
            <SkInput v-model="c.input" class="mono" :placeholder="`样例 ${i + 1}`" />
            <SkSelect v-model="c.expectMatch" class="case-expect" :options="expectOptions" />
            <SkButton size="sm" variant="danger" @click="cases.splice(i, 1)">删</SkButton>
          </div>
          <SkButton size="sm" style="margin-top: 6px" @click="cases.push({ ruleId: form.id || '', input: '', expectMatch: true })">
            加用例
          </SkButton>
        </div>
      </div>
      <template #footer>
        <SkButton @click="editOpen = false">取消</SkButton>
        <SkButton variant="primary" :loading="saving" style="margin-left: 8px" @click="save">保存草稿</SkButton>
      </template>
    </SkModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, nextTick } from 'vue'
import { skMessage } from '@xzsoft/sketch-ui'
import type { SkFormInstance, SkRule } from '../types/form'
import SearchForm from '../components/SearchForm.vue'
import { api, type Rule, type TestCase } from '../api'

interface EditForm extends Rule { _exists?: boolean }

// RFC3339 → 本地可读 "YYYY-MM-DD HH:mm"
const fmtTime = (s?: string) => (s ? s.replace('T', ' ').slice(0, 16) : '—')

const rows = ref<Rule[]>([])
const loading = ref(false)
const query = reactive<{ q: string; enabled: number | null }>({ q: '', enabled: null })

const sevColor: Record<string, string> = { critical: 'danger', high: 'warning', medium: 'info', low: 'default' }
const sevOptions = ['critical', 'high', 'medium', 'low'].map(v => ({ label: v, value: v }))
const validateOptions = [
  { label: '身份证校验位', value: 'builtin:id-card-checksum' },
  { label: '银行卡 Luhn', value: 'builtin:luhn' },
  { label: '手机号号段', value: 'builtin:cn-mobile-segment' },
]
const enabledOptions = [
  { label: '启用', value: 1 },
  { label: '停用', value: 0 },
]
const expectOptions = [
  { label: '应命中', value: true },
  { label: '不应命中', value: false },
]

// 长单 token 列（ID/验真/更新时间）不换行省略号；正则列放开采纳任意断行换行；
// 标签/时间/操作类居中，文本类左对齐；窄屏靠 scrollX 横滚
const columns = [
  { title: 'ID', key: 'id', width: 190, ellipsis: true },
  { title: '名称', key: 'name', width: 170, ellipsis: true },
  { title: '严重级', key: 'severity', width: 90, align: 'center' },
  { title: '正则', key: 'pattern' },
  { title: '验真', key: 'validate', width: 175, ellipsis: true },
  { title: '状态', key: 'enabled', width: 80, align: 'center' },
  { title: '更新', key: 'updatedAt', width: 150, ellipsis: true, align: 'center' },
  { title: '操作', key: 'ops', width: 150, fixed: 'right', align: 'center' },
]

const load = async () => {
  loading.value = true
  try {
    const q = new URLSearchParams()
    if (query.q) q.set('q', query.q)
    if (query.enabled !== null && query.enabled !== undefined) q.set('enabled', String(query.enabled === 1))
    rows.value = (await api.get<Rule[]>('/api/rules?' + q.toString())) ?? []
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}
onMounted(load)

// ---------- 编辑器 ----------
const editOpen = ref(false)
const saving = ref(false)
const formRef = ref<SkFormInstance | null>(null)
const form = reactive<EditForm>(blank())
const excludePathsText = ref('')
const cases = ref<TestCase[]>([])

function blank(): EditForm {
  return { id: '', name: '', severity: 'medium', pattern: '', validate: '', enabled: true, 'exclude-paths': [] }
}

const fRules: Record<string, SkRule[]> = {
  id: [{ required: true, message: '规则 ID 必填' }, { pattern: /^[a-z0-9][a-z0-9-]*$/, message: '小写字母数字与中划线' }],
  name: [{ required: true, message: '名称必填' }],
  pattern: [{ required: true, message: '正则必填' }],
}

const openEdit = async (r: Rule | null) => {
  Object.assign(form, blank(), r || {}, { _exists: !!r })
  excludePathsText.value = (r?.['exclude-paths'] || []).join(', ')
  cases.value = r ? await api.get<TestCase[]>(`/api/rules/${r.id}/cases`) : []
  editOpen.value = true
  nextTick(() => formRef.value?.clearValidate())
}

const save = async () => {
  try { await formRef.value?.validate() } catch { return }
  saving.value = true
  try {
    const body: Rule = {
      ...form,
      validate: form.validate || '',
      'exclude-paths': excludePathsText.value.split(',').map(s => s.trim()).filter(Boolean),
    }
    await api.post('/api/rules', body)
    if (cases.value.length || form.id) {
      await api.put(`/api/rules/${form.id}/cases`, cases.value.map(c => ({ ...c, ruleId: form.id })))
    }
    skMessage.success('已保存草稿（发布后生效）')
    editOpen.value = false
    load()
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    saving.value = false
  }
}

const removeRule = async (rid: string) => {
  try {
    await api.del(`/api/rules/${rid}`)
    skMessage.success('已删除')
    load()
  } catch (e) {
    skMessage.error((e as Error).message)
  }
}

// ---------- 沙箱（防抖即时测试） ----------
const sandbox = ref('')
const sandboxHits = ref<string[]>([])
const sandboxError = ref('')
let sbTimer: number | undefined
const patternReady = computed(() => !!form.pattern)

const runSandbox = async () => {
  if (!patternReady.value || !sandbox.value) { sandboxHits.value = []; sandboxError.value = ''; return }
  try {
    const r = await api.post<{ hits: string[] }>('/api/rules/test', {
      pattern: form.pattern, validate: form.validate || '', sample: sandbox.value,
    })
    sandboxHits.value = r.hits
    sandboxError.value = ''
  } catch (e) {
    sandboxHits.value = []
    sandboxError.value = (e as Error).message
  }
}
const onSandboxInput = () => {
  window.clearTimeout(sbTimer)
  sbTimer = window.setTimeout(runSandbox, 300)
}
// sandbox 输入触发（v-model 已绑定值，此处只做防抖）
</script>

<style scoped>
/* 正则列：放开采纳换行——长 token 任意断行（break-all），多行完整展示 */
.cell-regex {
  display: block;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.6;
  font-size: 12px;
}
</style>
