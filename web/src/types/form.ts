/** sketch-ui 表单类型（与 watchgoose-web 同款口径的本地声明） */
export interface SkRule {
  required?: boolean
  message?: string
  trigger?: string
  pattern?: RegExp
  validator?: (v: unknown) => string | null
}

export interface SkFormInstance {
  validate: () => Promise<void>
  clearValidate: () => void
}
