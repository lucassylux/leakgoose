package rules

import "testing"

func TestIDCardChecksum(t *testing.T) {
	// 文档通用示例号（结构合法的公开测试向量）
	if !validIDCardChecksum("11010519491231002X") {
		t.Error("11010519491231002X 应通过校验位")
	}
	invalid := []string{
		"110105194912310021", // 校验位应为 X
		"110105194912310022", // 校验位错
		"1101051949123100",   // 位数不足
		"11010519491231002a", // 尾位非法
		"abc105194912310021", // 非数字
	}
	for _, s := range invalid {
		if validIDCardChecksum(s) {
			t.Errorf("%s 不应通过校验位", s)
		}
	}
}

func TestLuhn(t *testing.T) {
	// 4111111111111111：Visa 公开测试卡号；6212262502000000003：19 位借记卡形态自算 Luhn 合规向量
	for _, s := range []string{"4111111111111111", "6212262502000000003"} {
		if !validLuhn(s) {
			t.Errorf("%s 应通过 Luhn", s)
		}
	}
	if validLuhn("4111111111111112") {
		t.Error("校验位错误不应通过 Luhn")
	}
	if validLuhn("4111a11111111111") {
		t.Error("非数字不应通过")
	}
}

func TestCNMobileSegment(t *testing.T) {
	valid := []string{"13800138000", "15912345678", "19912345678", "16612345678"}
	for _, s := range valid {
		if !validCNMobileSegment(s) {
			t.Errorf("%s 应为合法号段", s)
		}
	}
	invalid := []string{
		"12345678901", // 12x 非号段
		"15412345678", // 154 卫星段
		"10000000000", // 10x
		"1380013800",  // 10 位
	}
	for _, s := range invalid {
		if validCNMobileSegment(s) {
			t.Errorf("%s 不应为合法号段", s)
		}
	}
}
