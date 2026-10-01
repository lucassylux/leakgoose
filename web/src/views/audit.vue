<template>
  <div class="page-fill">
    <SkCard title="审计日志" class="fill-card">
    <SkTable :columns="columns" :data="rows" :loading="loading" row-key="id" size="md">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'action'">
          <SkTag :color="actionColor[record.action] || 'default'">{{ record.action }}</SkTag>
        </template>
        <template v-else-if="column.key === 'entity'">
          <span class="mono cell-clip" :title="record.entity">{{ record.entity }}</span>
        </template>
        <template v-else-if="column.key === 'at'">
          {{ fmtTime(record.at) }}
        </template>
        <template v-else-if="column.key === 'detail'">
          <span class="cell-break" :title="record.detail">{{ record.detail || '—' }}</span>
        </template>
      </template>
    </SkTable>
    </SkCard>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { skMessage } from '@xzsoft/sketch-ui'
import { api, type AuditRow } from '../api'

const rows = ref<AuditRow[]>([])
const loading = ref(false)

// RFC3339 → 本地可读 "YYYY-MM-DD HH:mm"
const fmtTime = (s?: string) => (s ? s.replace('T', ' ').slice(0, 16) : '—')

const actionColor: Record<string, string> = {
  publish: 'success',
  create: 'info',
  update: 'warning',
  'update-cases': 'warning',
  delete: 'danger',
  'create-token': 'info',
  'delete-token': 'danger',
}

const columns = [
  { title: '时间', key: 'at', width: 190 },
  { title: '操作者', key: 'actor', width: 110 },
  { title: '动作', key: 'action', width: 120 },
  { title: '对象', key: 'entity', width: 200 },
  { title: '详情', key: 'detail' },
]

onMounted(async () => {
  loading.value = true
  try {
    rows.value = await api.get<AuditRow[]>('/api/audit')
  } catch (e) {
    skMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
})
</script>
