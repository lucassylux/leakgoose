<template>
  <!-- sketch-ui 的 SkInput 不支持多行（type="textarea" 会落成单行 input），
       这里用原生 textarea 补齐，视觉对齐 .sk-input-el -->
  <textarea
    class="lg-textarea mono"
    :value="modelValue ?? ''"
    :rows="rows"
    :placeholder="placeholder"
    :disabled="disabled"
    @input="$emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
  />
</template>

<script setup lang="ts">
defineProps<{
  modelValue?: string
  rows?: number
  placeholder?: string
  disabled?: boolean
}>()
defineEmits<{ (e: 'update:modelValue', v: string): void }>()
</script>

<script lang="ts">
export default { name: 'LgTextarea', inheritAttrs: true }
</script>

<style scoped>
.lg-textarea {
  width: 100%;
  box-sizing: border-box;
  padding: 7px 10px;
  font-size: 13px;
  line-height: 1.6;
  font-family: inherit;
  color: var(--sk-text, #1a1a1a);
  background: var(--sk-surface, #fff);
  border: var(--sk-border-input, 1px solid #d9d9d9);
  border-radius: var(--sk-radius-btn, var(--sk-radius, 8px));
  resize: vertical;
  outline: none;
  transition: border-color 0.15s;
}
.lg-textarea:focus {
  border-color: var(--sk-primary, #e8930c);
}
.lg-textarea:disabled {
  background: var(--sk-muted-soft, #f5f6f8);
  cursor: not-allowed;
}
.lg-textarea::placeholder { color: var(--sk-text-faint, #aaa); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
