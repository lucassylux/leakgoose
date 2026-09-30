import { createApp } from 'vue'
import sketchUI, { setDefaultTheme } from '@xzsoft/sketch-ui'
import './style.css'
import App from './App.vue'
import router from './router'

// 与 watchgoose 管理台同款主题基线
setDefaultTheme('sketch')

createApp(App).use(router).use(sketchUI).mount('#app')
