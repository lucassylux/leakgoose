// 验真函数注册表：PII/卡号类规则的正则命中必须再过一道算法验真，把误报压到可用水平。
package rules

import "strings"

// ValidatorFunc 验真函数：入参为正则命中的原文，返回是否为真实格式
type ValidatorFunc func(s string) bool

var validators = map[string]ValidatorFunc{
	"builtin:id-card-checksum":  validIDCardChecksum,
	"builtin:luhn":              validLuhn,
	"builtin:cn-mobile-segment": validCNMobileSegment,
}

func validatorNames() string {
	return "builtin:id-card-checksum / builtin:luhn / builtin:cn-mobile-segment"
}

// validIDCardChecksum GB11643 十八位身份证校验位：
// 前 17 位分别乘权重 [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]，和对 11 取模映射校验位 "10X98765432"
func validIDCardChecksum(s string) bool {
	if len(s) != 18 {
		return false
	}
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	check := "10X98765432"
	sum := 0
	for i := 0; i < 17; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * weights[i]
	}
	last := s[17]
	if last == 'x' {
		last = 'X'
	}
	return check[sum%11] == last
}

// validLuhn Luhn 算法（银行卡/信用卡校验）
func validLuhn(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validCNMobileSegment 中国大陆手机号号段验真（按运营商在网号段粗粒度校验，
// 拦截 1[3-9] 开头但非真实号段的随机 11 位数字）
func validCNMobileSegment(s string) bool {
	if len(s) != 11 || s[0] != '1' {
		return false
	}
	// 号段前两位 → 第三位合法集合（三大运营商 + 广电 + 虚商；卫星/保留段剔除）
	prefix3 := map[byte]string{
		'3': "0123456789", // 13x 全段
		'4': "579",        // 145/147/149
		'5': "012356789",  // 15x（154 卫星段剔除）
		'6': "2567",       // 16x
		'7': "012345678",  // 17x（179 卫星剔除）
		'8': "0123456789", // 18x 全段
		'9': "01356789",   // 19x
	}
	thirds, ok := prefix3[s[1]]
	return ok && strings.Contains(thirds, s[2:3])
}
