<template>
  <router-view />
</template>

<script setup lang="ts">
// 外壳（侧边栏/顶栏）与登录页的结构切换全部由路由层级承担：
// App 只留一个根 router-view，外壳是 shell 路由组件（children 挂后台页面）。
// 不在 App 级用 v-if 按 meta 换渲染分支——外壳整树卸载与嵌套 router-view
// 的路由更新同帧竞争，会触发 unmountComponent 空引用导致视图冻结。
</script>

<style>
* { box-sizing: border-box; }
html, body, #app { height: 100%; margin: 0; }
</style>
