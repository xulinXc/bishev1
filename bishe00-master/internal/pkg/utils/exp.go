// Package utils 提供 EXP 相关工具函数
// 该模块包含处理 POC 结果和生成 EXP 的公共函数
package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// ToStr 类型转换函数，将任意类型转换为字符串
func ToStr(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	}
}

// ToHeaderMap 将任意 map 类型转换为 header map
// 支持 map[string]string, map[string]interface{}, map[interface{}]interface{}
func ToHeaderMap(v interface{}) map[string]string {
	out := map[string]string{}
	if v == nil {
		return out
	}
	switch m := v.(type) {
	case map[string]string:
		for k, vv := range m {
			out[k] = vv
		}
	case map[string]interface{}:
		for k, vv := range m {
			out[k] = ToStr(vv)
		}
	case map[interface{}]interface{}:
		for kk, vv := range m {
			out[ToStr(kk)] = ToStr(vv)
		}
	}
	return out
}

// BaseFromResultURL 从 URL 字符串提取 base URL（scheme + host）
func BaseFromResultURL(u string) string {
	pu, err := url.Parse(strings.TrimSpace(u))
	if err != nil || pu == nil || pu.Scheme == "" || pu.Host == "" {
		return ""
	}
	return pu.Scheme + "://" + pu.Host
}
