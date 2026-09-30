<template>
  <div class="dict-layout">
    <!-- 左：字典类型 -->
    <SkCard title="字典类型" class="fill-card type-card">
      <SkTable :columns="typeCols" :data="types" :loading="loadingTypes" row-key="type" size="sm"
        :highlight-current-row="true" @row-click="pickType">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'count'">
            <SkTag color="info">{{ record.count }}</SkTag>
          </template>
        </template>
      </SkTable>
      <div v-if="!loadingTypes && !types.length" class="empty-tip">暂无字典类型——右侧先新增字典项即可生成类型</div>
    </SkCard>

    <!-- 右：选中类型的字典项 -->
    <SkCard class="fill-card items-card">
      <template #title>
        字典项<span v-if="current" class="cur-type"> · {{ current.name }}（{{ current.type }}）</span>
      </template>
      <template #extra>
        <SkButton size="sm" variant="primary" :disabled="!me || me.role === 'viewer'" @click="openEdit(null)">新增字典项</SkButton>
      </template>
      <SkEmpty v-if="!current" description="先在左侧选择一个字典类型" />
      <SkTable v-else :columns="itemCols" :data="items" :loading="loadingItems" row-key="id" size="sm">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'enabled'">
            <SkTag :color="record.enabled ? 'success' : 'default'">{{ record.enabled ? '启用' : '停用' }}</SkTag>
          </template>
          <template v-else-if="column.key === 'ops'">
            <SkButton size="sm" @click="openEdit(record)">编辑</SkButton>
            <SkPopconfirm title="确认删除该字典项？" @confirm="removeItem(record.id)">
              <SkButton size="sm" variant="danger" style="margin-left: 6px">删除</SkButton>
            </SkPopconfirm>
          </template>
        </template>
      </SkTable>
    </SkCard>

    <!-- 编辑弹窗 -->
    <SkModal v-model:open="editOpen" :title="form.id ? '编辑字典项' : '新增字典项'" width="520px">
      <SkForm label-width="92px">
        <SkFormField label="字典类型" required hint="编码分组（如 rule-severity），同类型下 value 唯一">
          <SkInput v-model="form.type" placeholder="rule-severity" />
        </SkFormField>
        <SkFormField label="标签" required hint="展示名（如：严重）">
          <SkInput v-model="form.label" placeholder="严重" />
        </SkFormField>
        <SkFormField label="编码值" required hint="落库的值（如：critical），业务数据存编码、展示走标签">
          <SkInput v-model="form.value" placeholder="critical" class="mono" />
        </SkFormField>
        <SkFormField label="排序">
          <SkInput v-model.number="form.sort" type="number" placeholder="1" />
        </SkFormField>
        <SkFormField label="状态">
          <SkSelect v-model="form.enabled" :options="enabledOptions" />
        </SkFormField>
      </SkForm>
      <template #footer>
        <SkButton @click="editOpen = false">取消</SkButton>
        <SkButton variant="primary" :loading="saving" style="margin-left: 8px" @click="save">保存</SkButton>
      </template>
    </SkModal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { skMessage } from '@xzsoft/sketch-ui'
import { api, type Me } from '../api'

interface DictType { type: string; name: string; count: number }
interface DictItem { id?: number; type: string; label: string; value: string; sort: number; enabled: boolean }

const me = ref<Me | null>(null)
const types = ref<DictType[]>([])
const items = ref<DictItem[]>([])
const current = ref<DictType | null>(null)
const loadingTypes = ref(false)
const loadingItems = ref(false)
const editOpen = ref(false)
const saving = ref(false)
const form = reactive<DictItem>({ type: '', label: '', value: '', sort: 1, enabled: true })

const enabledOptions = [{ label: '启用', value: true }, { label: '停用', value: false }]
const typeCols = [
  { title: '类型', key: 'name', ellipsis: true },
  { title: '编码', key: 'type', ellipsis: true },
  { title: '项数', key: 'count', width: 70, align: 'center' },
]
const itemCols = [
  { title: '标签', key: 'label', width: 140 },
  { title: '编码值', key: 'value', ellipsis: true },
  { title: '排序', key: 'sort', width: 70, align: 'center' },
  { title: '状态', key: 'enabled', width: 80, align: 'center' },
  { title: '操作', key: 'ops', width: 150, align: 'center' },
]

const loadTypes = async () => {
  loadingTypes.value = true
  try {
    me.value = await api.get<Me>('/api/auth/me')
    types.value = await api.get<DictType[]>('/api/dict-types')
    if (!current.value && types.value.length) pickType(types.value[0])
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    loadingTypes.value = false
  }
}
onMounted(loadTypes)

const pickType = async (t: DictType) => {
  current.value = t
  loadingItems.value = true
  try {
    items.value = await api.get<DictItem[]>(`/api/dicts?type=${encodeURIComponent(t.type)}`)
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    loadingItems.value = false
  }
}

const openEdit = (d: DictItem | null) => {
  Object.assign(form, d || { type: current.value?.type || '', label: '', value: '', sort: (items.value.length + 1), enabled: true })
  editOpen.value = true
}

const save = async () => {
  if (!form.type.trim() || !form.label.trim() || !form.value.trim()) return skMessage.warning('类型 / 标签 / 编码值必填')
  if (saving.value) return
  saving.value = true
  try {
    await api.post('/api/dicts', { ...form })
    skMessage.success('已保存')
    editOpen.value = false
    await loadTypes()
    const t = types.value.find(x => x.type === form.type)
    if (t) await pickType(t)
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    saving.value = false
  }
}

const removeItem = async (id: number) => {
  try {
    await api.del(`/api/dicts/${id}`)
    skMessage.success('已删除')
    await loadTypes()
    if (current.value) {
      const still = types.value.find(x => x.type === current.value!.type)
      still ? await pickType(still) : (current.value = null)
    }
  } catch (e) {
    skMessage.error((e as Error).message)
  }
}
</script>

<style scoped>
/* 主从双栏等高占满（看门鹅 page-cols 同款）；窄屏堆叠退回自然生长 */
.dict-layout { display: flex; gap: 14px; height: 100%; }
.dict-layout > .type-card { width: 380px; flex: none; }
.dict-layout > .items-card { flex: 1; min-width: 0; }
.cur-type { font-weight: 400; font-size: 13px; color: var(--sk-text-muted); }
.empty-tip { padding: 18px 0; text-align: center; color: var(--sk-text-faint); font-size: 12px; }
@media (max-width: 900px) {
  .dict-layout { flex-direction: column; height: auto; }
  .dict-layout > .type-card { width: 100%; }
}
</style>
