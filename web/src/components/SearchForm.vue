<template>
  <SkSearchForm v-bind="$attrs">
    <slot />
  </SkSearchForm>
</template>

<script setup lang="ts">
// 薄壳：与看门鹅管理台同款——搜索区容器用 sketch-ui 的 SkSearchForm
//（响应式网格 + 无 label 按钮组沉底与控件底边对齐 + 窄屏两列紧凑）。
// 保留本文件只为页面 import 路径稳定；布局数值个性化可传 minCol/gap/rowGap。
import SkSearchForm from '@xzsoft/sketch-ui/components/SkSearchForm.vue'
</script>
