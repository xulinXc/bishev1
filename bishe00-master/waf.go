// Package main WAF绕过测试功能模块
// 该模块实现了WAF（Web Application Firewall）绕过测试功能，支持多种绕过策略和Payload变形
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WAFBypassReq WAF绕过测试请求
// 前端发送的WAF绕过测试请求参数
type WAFBypassReq struct {
	BaseURL     string   `json:"baseUrl"`     // 目标基础URL
	Path        string   `json:"path"`        // 请求路径
	Payloads    []string `json:"payloads"`    // 测试用的Payload列表
	Methods     []string `json:"methods"`     // HTTP方法列表（如GET、POST）
	Strategies  []string `json:"strategies"`  // 绕过策略列表：["case","urlencode","doubleencode"]
	Match       string   `json:"match"`       // 可选的成功标识字符串（响应体中包含此字符串表示成功）
	Concurrency int      `json:"concurrency"` // 并发数（默认50）
	TimeoutMs   int      `json:"timeoutMs"`   // 请求超时时间（毫秒，默认4000）
}

// sCase 大小写变换策略
// 将Payload转换为大写和小写两种形式
func sCase(p string) []string {
	alt := func(s string) string {
		var b strings.Builder
		upper := true
		for _, r := range s {
			if r >= 'a' && r <= 'z' {
				if upper {
					b.WriteRune(r - 32)
				} else {
					b.WriteRune(r)
				}
				upper = !upper
				continue
			}
			if r >= 'A' && r <= 'Z' {
				if upper {
					b.WriteRune(r)
				} else {
					b.WriteRune(r + 32)
				}
				upper = !upper
				continue
			}
			b.WriteRune(r)
		}
		return b.String()
	}
	return []string{strings.ToUpper(p), strings.ToLower(p), alt(p)}
}

// sUrlEncode URL编码策略
// 对Payload进行URL编码
func sUrlEncode(p string) []string {
	return []string{urlEncode(p)}
}

// sDoubleEncode 双重URL编码策略
// 对Payload进行两次URL编码
func sDoubleEncode(p string) []string {
	return []string{urlEncode(urlEncode(p))}
}

func sSpace2Comment(p string) []string {
	if !strings.Contains(p, " ") {
		return nil
	}
	return []string{strings.ReplaceAll(p, " ", "/**/")}
}

func sSplitKeywords(p string) []string {
	replaceWord := func(w string) string {
		if w == "" {
			return w
		}
		var b strings.Builder
		for i, r := range w {
			if i > 0 {
				b.WriteString("/**/")
			}
			b.WriteRune(r)
		}
		return b.String()
	}
	keywords := []string{"or", "union", "select", "script", "alert", "javascript"}
	out := []string{}
	low := strings.ToLower(p)
	changed := false
	for _, k := range keywords {
		if strings.Contains(low, k) {
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}
	v := p
	for _, k := range keywords {
		v = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(k)).ReplaceAllStringFunc(v, func(m string) string {
			return replaceWord(m)
		})
	}
	out = append(out, v)
	return out
}

func sHtmlEntity(p string) []string {
	repl := map[string]string{
		"<":  "&#x3c;",
		">":  "&#x3e;",
		"'":  "&#x27;",
		"\"": "&#x22;",
		" ":  "&#x20;",
		"=":  "&#x3d;",
		"(":  "&#x28;",
		")":  "&#x29;",
		"/":  "&#x2f;",
		":":  "&#x3a;",
	}
	var b strings.Builder
	changed := false
	for _, ch := range p {
		c := string(ch)
		if v, ok := repl[c]; ok {
			b.WriteString(v)
			changed = true
		} else {
			b.WriteString(c)
		}
	}
	if !changed {
		return nil
	}
	return []string{b.String()}
}

// urlEncode 简单的URL编码实现
// 将特殊字符转换为URL编码格式
// @param s 要编码的字符串
// @return 编码后的字符串
func urlEncode(s string) string {
	repl := map[string]string{
		" ": "%20", "<": "%3C", ">": "%3E", "\"": "%22",
		"'": "%27", "/": "%2F", "=": "%3D", "&": "%26",
		"(": "%28", ")": "%29", ":": "%3A", ";": "%3B",
	}
	var b strings.Builder
	for _, ch := range s {
		c := string(ch)
		if v, ok := repl[c]; ok {
			b.WriteString(v) // 使用编码后的字符
		} else {
			b.WriteString(c) // 保持原样
		}
	}
	return b.String()
}

// PayloadVariant Payload变体及其使用的策略
type PayloadVariant struct {
	Variant    string   // 变体内容
	Strategies []string // 使用的策略列表
}

// mutatePayload 根据策略列表对Payload进行变形
// 应用多种绕过策略，生成多个Payload变体，并记录每个变体使用的策略
// @param p 原始Payload
// @param strategies 策略列表
// @return Payload变体列表（包含策略信息）
func mutatePayload(p string, strategies []string) []PayloadVariant {
	variants := []PayloadVariant{
		{Variant: p, Strategies: []string{"original"}}, // 原始Payload
	}
	variantMap := map[string]bool{p: true} // 用于去重

	add := func(xs []string, strategy string) {
		for _, x := range xs {
			if !variantMap[x] {
				variantMap[x] = true
				variants = append(variants, PayloadVariant{
					Variant:    x,
					Strategies: []string{strategy},
				})
			}
		}
	}

	for _, s := range strategies {
		s = strings.ToLower(strings.TrimSpace(s))
		switch s {
		case "case":
			add(sCase(p), "case")
		case "urlencode":
			add(sUrlEncode(p), "urlencode")
		case "doubleencode":
			add(sDoubleEncode(p), "doubleencode")
		case "space2comment":
			add(sSpace2Comment(p), "space2comment")
		case "split":
			add(sSplitKeywords(p), "split")
		case "htmlentity":
			add(sHtmlEntity(p), "htmlentity")
		}
	}
	return variants
}

// wafBypassHandler WAF绕过测试处理器
// 处理前端发送的WAF绕过测试请求，生成Payload变体并测试
func wafBypassHandler(w http.ResponseWriter, r *http.Request) {
	var req WAFBypassReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pu, err := url.Parse(req.BaseURL)
	if err != nil || pu.Scheme == "" || pu.Host == "" {
		http.Error(w, "invalid baseUrl", http.StatusBadRequest)
		return
	}
	if pu.Scheme != "http" && pu.Scheme != "https" {
		http.Error(w, "invalid baseUrl scheme", http.StatusBadRequest)
		return
	}
	host := strings.ToLower(pu.Hostname())
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "0.0.0.0" {
		http.Error(w, "baseUrl must be localhost for demo", http.StatusBadRequest)
		return
	}
	methods := req.Methods
	if len(methods) == 0 {
		methods = []string{"GET", "POST"}
	}
	if len(req.Payloads) == 0 {
		http.Error(w, "no payloads", http.StatusBadRequest)
		return
	}
	cc := req.Concurrency
	if cc <= 0 {
		cc = 50
	}
	timeout := time.Duration(req.TimeoutMs)
	if timeout <= 0 {
		timeout = 4000 * time.Millisecond
	} else {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	// total tasks = payloads * methods
	total := len(req.Payloads) * len(methods)
	t := newTask(total)
	go func() {
		sem := make(chan struct{}, cc)
		var wg sync.WaitGroup
		for _, p := range req.Payloads {
			select {
			case <-t.stop:
				goto done
			default:
			}
			mut := mutatePayload(p, req.Strategies)
			for _, m := range methods {
				select {
				case <-t.stop:
					goto done
				default:
				}
				wg.Add(1)
				sem <- struct{}{}
				payload := p
				method := strings.ToUpper(m)
				muts := mut
				go func() {
					defer wg.Done()
					select {
					case <-t.stop:
						<-sem
						return
					default:
					}
					// try variants (original first, then mutations)
					var okVariant string
					var okStrategies []string
					var status int
					var firstStatus int
					var firstVariant string
					for _, variant := range muts {
						select {
						case <-t.stop:
							goto doneVariant
						default:
						}
						v := variant.Variant
						targetURL := strings.TrimRight(req.BaseURL, "/") + "/" + strings.TrimLeft(req.Path, "/")
						var body io.Reader
						reqHeaders := map[string]string{"User-Agent": "NeonScan"}
						if method == "GET" {
							actualVariant := v
							if !strings.Contains(v, "%") {
								if strings.Contains(v, "=") {
									parts := strings.SplitN(v, "=", 2)
									if len(parts) == 2 {
										actualVariant = parts[0] + "=" + url.QueryEscape(parts[1])
									}
								} else {
									actualVariant = url.QueryEscape(v)
								}
							}
							if strings.Contains(targetURL, "?") {
								targetURL += "&" + actualVariant
							} else {
								targetURL += "?" + actualVariant
							}
							if len(variant.Strategies) == 1 && variant.Strategies[0] == "original" {
								firstVariant = actualVariant
							}
						} else {
							body = strings.NewReader(v)
							reqHeaders["Content-Type"] = "application/x-www-form-urlencoded"
							if len(variant.Strategies) == 1 && variant.Strategies[0] == "original" {
								firstVariant = v
							}
						}
						req0, reqErr := http.NewRequest(method, targetURL, body)
						if reqErr != nil {
							continue
						}
						for k, vh := range reqHeaders {
							req0.Header.Set(k, vh)
						}
						resp, err := client.Do(req0)
						if err != nil {
							continue
						}
						b, _ := io.ReadAll(resp.Body)
						resp.Body.Close()
						status = resp.StatusCode
						if len(variant.Strategies) == 1 && variant.Strategies[0] == "original" {
							firstStatus = status
						}
						useful := status == 200 || status == 201 || status == 204 || status == 302
						if req.Match != "" {
							useful = useful || strings.Contains(strings.ToLower(string(b)), strings.ToLower(req.Match))
						}
						if useful {
							actualVariant := v
							if method == "GET" {
								if !strings.Contains(v, "%") {
									if strings.Contains(v, "=") {
										parts := strings.SplitN(v, "=", 2)
										if len(parts) == 2 {
											actualVariant = parts[0] + "=" + url.QueryEscape(parts[1])
										}
									} else {
										actualVariant = url.QueryEscape(v)
									}
								}
							}
							okVariant = actualVariant
							okStrategies = variant.Strategies
							goto doneVariant
						}
					}
				doneVariant:
					d, tot := t.IncDone()
					percent := int(math.Round(float64(d) / float64(tot) * 100))
					safeSend(t, SSEMessage{Type: "progress", TaskID: t.ID, Progress: fmt.Sprintf("%d/%d", d, tot), Percent: percent})
					if okVariant != "" {
						displayStrategies := []string{}
						for _, s := range okStrategies {
							if s != "original" {
								displayStrategies = append(displayStrategies, s)
							}
						}
						if len(displayStrategies) == 0 {
							displayStrategies = []string{"原始"}
						}
						safeSend(t, SSEMessage{
							Type:   "find",
							TaskID: t.ID,
							Data: map[string]interface{}{
								"method":     method,
								"payload":    payload,
								"variant":    okVariant,
								"status":     status,
								"strategies": displayStrategies,
							},
						})
					} else if firstStatus >= 400 {
						safeSend(t, SSEMessage{
							Type:   "scan_log",
							TaskID: t.ID,
							Data: map[string]interface{}{
								"method":     method,
								"payload":    payload,
								"variant":    firstVariant,
								"status":     firstStatus,
								"strategies": []string{"原始"},
							},
						})
					}
					<-sem
				}()
			}
		}
	done:
		wg.Wait()
		finishTask(t.ID)
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"taskId": t.ID})
}
