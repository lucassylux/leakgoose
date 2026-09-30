// 杂项助手：口令哈希与 YAML 序列化（隔离依赖，便于测试替换）。
package center

import (
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// bcryptHash 口令哈希（cost 10：登录频次低，安全余量优先）
func bcryptHash(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	return string(b), err
}

// bcryptCompare 口令比对（常量时间，由 bcrypt 保证）
func bcryptCompare(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func yamlMarshal(v any) ([]byte, error) { return yaml.Marshal(v) }

func yamlUnmarshal(data []byte, v any) error { return yaml.Unmarshal(data, v) }
