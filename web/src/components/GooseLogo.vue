<template>
  <!-- LeakGoose 徽标：琥珀对角渐变圆角方块 + 白色粗体 LG（与 GLM 徽标同款版式，色调区分） -->
  <svg :width="size" :height="size" viewBox="0 0 512 512" fill="none" style="display: block">
    <defs>
      <linearGradient :id="gid" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="#FFC24B" />
        <stop offset="0.5" stop-color="#F59300" />
        <stop offset="1" stop-color="#D97706" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="512" height="512" rx="112" :fill="`url(#${gid})`" />
    <text x="256" y="364" text-anchor="middle" font-family="'Segoe UI', Inter, 'Helvetica Neue', Arial, sans-serif"
      font-size="300" font-weight="700" fill="#FFFFFF" textLength="448" lengthAdjust="spacingAndGlyphs">LG</text>
  </svg>
</template>

<script setup lang="ts">
import { useId } from 'vue'

withDefaults(defineProps<{ size?: number }>(), { size: 32 })
const gid = 'lgBg' + (useId() || '')
</script>
