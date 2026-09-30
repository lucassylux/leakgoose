<template>
  <div class="search-form">
    <slot />
  </div>
</template>

<style scoped>
/* 与 watchgoose 管理台 SearchForm 同款网格：自适应换行、控件撑满列 */
.search-form {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 12px 24px;
  margin-bottom: 14px;
}
.search-form :deep(.sk-form-field) { margin: 0; }
</style>
