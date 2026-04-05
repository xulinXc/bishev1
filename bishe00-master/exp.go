// Package main EXP验证功能模块
// 该模块实现了基于步骤的EXP（漏洞利用）验证功能，支持多步骤HTTP请求、变量提取、响应验证等
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// Validation 响应验证规则
// 定义如何判断HTTP响应是否符合预期（漏洞是否成功利用）
type Validation struct {
	Status         StatusList        `json:"status"`         // 期望的HTTP状态码列表（支持字符串和整数）
	BodyContains   []string          `json:"bodyContains"`   // 响应体必须包含的字符串列表
	HeaderContains map[string]string `json:"headerContains"` // 响应头必须包含的键值对
}

// StatusList 支持字符串和整数两种格式的状态码列表
type StatusList []int

// parseStatusList 解析状态列表，支持多种输入格式
func parseStatusList(data interface{}) []int {
	var result []int

	switch v := data.(type) {
	case []int:
		return v
	case []interface{}:
		result = make([]int, 0, len(v))
		for _, item := range v {
			switch val := item.(type) {
			case int:
				result = append(result, val)
			case float64:
				result = append(result, int(val))
			case string:
				if val != "" && val != "suspect" {
					if i, err := strconv.Atoi(val); err == nil {
						result = append(result, i)
					}
				}
			}
		}
		return result
	case string:
		if v == "" || v == "suspect" {
			return []int{}
		}
		if i, err := strconv.Atoi(v); err == nil {
			return []int{i}
		}
	case int:
		return []int{v}
	case float64:
		return []int{int(v)}
	}
	return []int{}
}

// UnmarshalJSON 自定义JSON解析，支持字符串和整数两种格式
func (s *StatusList) UnmarshalJSON(data []byte) error {
	// 尝试作为整数数组解析
	var intList []int
	if err := json.Unmarshal(data, &intList); err == nil {
		*s = intList
		return nil
	}
	// 尝试作为字符串数组解析
	var strList []string
	if err := json.Unmarshal(data, &strList); err == nil {
		*s = parseStatusList(strList)
		return nil
	}
	// 尝试作为单个字符串解析
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = parseStatusList(str)
		return nil
	}
	// 尝试作为单个整数解析
	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		*s = []int{i}
		return nil
	}
	// 如果都失败，返回空列表
	*s = []int{}
	return nil
}

// UnmarshalYAML 自定义YAML解析，支持字符串和整数两种格式
func (s *StatusList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// 尝试作为整数数组解析
	var intList []int
	if err := unmarshal(&intList); err == nil {
		*s = intList
		return nil
	}
	// 尝试作为字符串数组解析
	var strList []string
	if err := unmarshal(&strList); err == nil {
		*s = parseStatusList(strList)
		return nil
	}
	// 尝试作为单个字符串解析
	var str string
	if err := unmarshal(&str); err == nil {
		*s = parseStatusList(str)
		return nil
	}
	// 尝试作为单个整数解析
	var i int
	if err := unmarshal(&i); err == nil {
		*s = []int{i}
		return nil
	}
	*s = []int{}
	return nil
}

// ExtractRule 变量提取规则
// 用于从HTTP响应中提取变量，供后续步骤使用
type ExtractRule struct {
	BodyRegex   []string          `json:"bodyRegex"`   // 从响应体中提取的正则表达式列表（第一个匹配的捕获组将被提取）
	HeaderRegex map[string]string `json:"headerRegex"` // 从响应头中提取的正则表达式（header key -> regex pattern）
}

// ExpStep EXP执行步骤
// 定义了单个HTTP请求的所有参数和验证规则
type ExpStep struct {
	Method       string                 `json:"method"`       // HTTP方法：GET, POST等
	Path         string                 `json:"path"`         // 请求路径（支持绝对URL和相对路径）
	Body         string                 `json:"body"`         // 请求体内容
	Headers      map[string]string      `json:"headers"`      // 请求头
	Validate     Validation             `json:"validate"`     // 响应验证规则
	Extract      map[string]ExtractRule `json:"extract"`      // 变量提取规则（变量名 -> 提取规则）
	Retry        int                    `json:"retry"`        // 重试次数（0表示不重试）
	RetryDelayMs int                    `json:"retryDelayMs"` // 重试延迟（毫秒）
	SleepMs      int                    `json:"sleepMs"`      // 请求后休眠时间（毫秒），用于控制请求频率
}

// ExpSpec EXP规范
// 定义一个完整的EXP，包含名称和步骤列表
type ExpSpec struct {
	Name              string    `json:"name"`              // EXP名称
	Steps             []ExpStep `json:"steps"`             // 执行步骤列表
	ExploitSuggestion string    `json:"exploitSuggestion"` // 漏洞利用建议
}

// ExpExecReq EXP执行请求
// 前端发送的EXP验证请求参数
type ExpExecReq struct {
	BaseURL     string    `json:"baseUrl"`     // 目标基础URL
	ExpDir      string    `json:"expDir"`      // EXP文件目录（如果指定，将从该目录加载所有EXP文件）
	ExpPaths    []string  `json:"expPaths"`    // EXP文件路径列表（如果指定，将加载这些文件）
	InlineExps  []ExpSpec `json:"inlineExps"`  // 内联EXP列表（直接在请求中提供的EXP）
	Concurrency int       `json:"concurrency"` // 并发数（默认50）
	TimeoutMs   int       `json:"timeoutMs"`   // 请求超时时间（毫秒，默认5000）
}

func buildExpKeyInfo(baseURL string, spec ExpSpec) string {
	var sb strings.Builder
	name := strings.TrimSpace(spec.Name)
	if name != "" {
		sb.WriteString("EXP: ")
		sb.WriteString(name)
		sb.WriteString("\n")
	}
	baseURL = strings.TrimSpace(baseURL)
	if baseURL != "" {
		sb.WriteString("Target: ")
		sb.WriteString(baseURL)
		sb.WriteString("\n")
	}

	phSet := map[string]struct{}{}
	phRe := regexp.MustCompile(`\{\{([a-zA-Z0-9_]+)\}\}`)
	addPh := func(s string) {
		m := phRe.FindAllStringSubmatch(s, -1)
		for _, mm := range m {
			if len(mm) >= 2 && mm[1] != "" {
				phSet[mm[1]] = struct{}{}
			}
		}
	}

	if strings.TrimSpace(spec.ExploitSuggestion) != "" {
		addPh(spec.ExploitSuggestion)
	}

	if len(spec.Steps) > 0 {
		sb.WriteString("Steps:\n")
		for i, st := range spec.Steps {
			method := strings.ToUpper(strings.TrimSpace(st.Method))
			if method == "" {
				method = "GET"
			}
			path := strings.TrimSpace(st.Path)
			sb.WriteString(fmt.Sprintf("- #%d %s %s\n", i+1, method, path))
			addPh(st.Path)
			addPh(st.Body)
			for _, v := range st.Headers {
				addPh(v)
			}

			if len(st.Headers) > 0 {
				keys := make([]string, 0, len(st.Headers))
				for k := range st.Headers {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				sb.WriteString("  headers:\n")
				for _, k := range keys {
					v := strings.TrimSpace(st.Headers[k])
					if len(v) > 200 {
						v = v[:200] + "..."
					}
					sb.WriteString(fmt.Sprintf("    %s: %s\n", k, v))
				}
			}

			if strings.TrimSpace(st.Body) != "" {
				body := strings.TrimSpace(st.Body)
				if len(body) > 400 {
					body = body[:400] + "..."
				}
				sb.WriteString("  body:\n")
				sb.WriteString("    ")
				sb.WriteString(strings.ReplaceAll(body, "\n", "\n    "))
				sb.WriteString("\n")
			}

			if len(st.Validate.Status) > 0 || len(st.Validate.BodyContains) > 0 || len(st.Validate.HeaderContains) > 0 {
				sb.WriteString("  validate:\n")
				if len(st.Validate.Status) > 0 {
					sb.WriteString("    status: ")
					sb.WriteString(fmt.Sprintf("%v", []int(st.Validate.Status)))
					sb.WriteString("\n")
				}
				if len(st.Validate.BodyContains) > 0 {
					sb.WriteString("    bodyContains: ")
					sb.WriteString(strings.Join(st.Validate.BodyContains, ", "))
					sb.WriteString("\n")
				}
				if len(st.Validate.HeaderContains) > 0 {
					keys := make([]string, 0, len(st.Validate.HeaderContains))
					for k := range st.Validate.HeaderContains {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					sb.WriteString("    headerContains:\n")
					for _, k := range keys {
						sb.WriteString(fmt.Sprintf("      %s: %s\n", k, st.Validate.HeaderContains[k]))
					}
				}
			}

			if len(st.Extract) > 0 {
				varNames := make([]string, 0, len(st.Extract))
				for vn := range st.Extract {
					varNames = append(varNames, vn)
				}
				sort.Strings(varNames)
				sb.WriteString("  extract:\n")
				for _, vn := range varNames {
					rule := st.Extract[vn]
					sb.WriteString(fmt.Sprintf("    %s:\n", vn))
					if len(rule.BodyRegex) > 0 {
						sb.WriteString("      bodyRegex:\n")
						for _, rx := range rule.BodyRegex {
							sb.WriteString(fmt.Sprintf("        - %s\n", rx))
						}
					}
					if len(rule.HeaderRegex) > 0 {
						keys := make([]string, 0, len(rule.HeaderRegex))
						for hk := range rule.HeaderRegex {
							keys = append(keys, hk)
						}
						sort.Strings(keys)
						sb.WriteString("      headerRegex:\n")
						for _, hk := range keys {
							sb.WriteString(fmt.Sprintf("        %s: %s\n", hk, rule.HeaderRegex[hk]))
						}
					}
				}
			}
		}
	}

	if len(phSet) > 0 {
		var ph []string
		for k := range phSet {
			ph = append(ph, k)
		}
		sort.Strings(ph)
		sb.WriteString("Placeholders: ")
		sb.WriteString(strings.Join(ph, ", "))
		sb.WriteString("\n")
	}

	out := strings.TrimSpace(sb.String())
	return out
}

// loadExps 从目录加载所有EXP文件
// 递归遍历目录，加载所有.json、.yaml、.yml格式的EXP文件
// @param dir 目录路径
// @return EXP规范列表和错误信息
func loadExps(dir string) ([]ExpSpec, error) {
	var exps []ExpSpec
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 跳过目录
		if info.IsDir() {
			return nil
		}
		// 只处理JSON和YAML文件
		name := strings.ToLower(info.Name())
		if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var e ExpSpec
			// 根据文件扩展名选择解析方式
			if strings.HasSuffix(name, ".json") {
				if err := json.Unmarshal(b, &e); err == nil {
					// 只添加有效的EXP（至少包含一个步骤）
					if len(e.Steps) > 0 {
						exps = append(exps, e)
					}
				}
			} else {
				if err := yaml.Unmarshal(b, &e); err == nil {
					if len(e.Steps) > 0 {
						exps = append(exps, e)
					}
				}
			}
		}
		return nil
	})
	return exps, err
}

// loadExpsFromFiles 从文件列表加载EXP
// 从指定的文件路径列表中加载EXP文件
// @param files 文件路径列表
// @return EXP规范列表和错误信息
func loadExpsFromFiles(files []string) ([]ExpSpec, error) {
	var exps []ExpSpec
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var e ExpSpec
		low := strings.ToLower(path)
		if strings.HasSuffix(low, ".json") {
			if err := json.Unmarshal(b, &e); err == nil {
				if len(e.Steps) > 0 {
					exps = append(exps, e)
				}
			}
		} else {
			if err := yaml.Unmarshal(b, &e); err == nil {
				if len(e.Steps) > 0 {
					exps = append(exps, e)
				}
			}
		}
	}
	return exps, nil
}

// validate 验证HTTP响应是否符合预期
// 检查状态码、响应体内容和响应头是否都符合验证规则
// @param resp HTTP响应对象
// @param body 响应体内容
// @param v 验证规则
// @return 是否符合预期
func validate(resp *http.Response, body []byte, v Validation) bool {
	ok := true

	// 验证状态码
	if len(v.Status) > 0 {
		match := false
		for _, s := range v.Status {
			if resp.StatusCode == s {
				match = true
				break
			}
		}
		ok = ok && match
	}

	// 验证响应体内容
	if len(v.BodyContains) > 0 {
		lb := strings.ToLower(string(body))
		match := true
		for _, sub := range v.BodyContains {
			if !strings.Contains(lb, strings.ToLower(sub)) {
				match = false
				break
			}
		}
		ok = ok && match
	}

	// 验证响应头
	if len(v.HeaderContains) > 0 {
		match := true
		for k, sub := range v.HeaderContains {
			vals := strings.ToLower(strings.Join(resp.Header.Values(k), ";"))
			if !strings.Contains(vals, strings.ToLower(sub)) {
				match = false
				break
			}
		}
		ok = ok && match
	}
	return ok
}

// substVars 替换字符串中的变量占位符
// 将字符串中的 {{变量名}} 替换为实际值
// @param s 包含占位符的字符串
// @param vars 变量映射表
// @return 替换后的字符串
func substVars(s string, vars map[string]string) string {
	out := s
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{{"+k+"}}", v)
	}
	return out
}

// extractVars 从HTTP响应中提取变量
// 根据提取规则，从响应体或响应头中使用正则表达式提取变量值
// @param resp HTTP响应对象
// @param body 响应体内容
// @param ex 提取规则映射（变量名 -> 提取规则）
// @param vars 变量存储映射（将被更新）
func extractVars(resp *http.Response, body []byte, ex map[string]ExtractRule, vars map[string]string) {
	if ex == nil {
		return
	}
	lb := string(body)
	for name, rule := range ex {
		// body regex
		for _, rx := range rule.BodyRegex {
			re, err := regexp.Compile(rx)
			if err != nil {
				continue
			}
			m := re.FindStringSubmatch(lb)
			if len(m) >= 2 {
				vars[name] = m[1]
				break
			}
		}
		// header regex
		for hk, rx := range rule.HeaderRegex {
			vals := strings.Join(resp.Header.Values(hk), ";")
			re, err := regexp.Compile(rx)
			if err != nil {
				continue
			}
			m := re.FindStringSubmatch(vals)
			if len(m) >= 2 {
				vars[name] = m[1]
				break
			}
		}
	}
}

// execExp 执行EXP验证
// 按照EXP规范中的步骤顺序执行HTTP请求，提取变量，验证响应
// @param base 基础URL
// @param spec EXP规范
// @param client HTTP客户端
// @return 是否所有步骤都成功、匹配的步骤数、最后的HTTP状态码、利用说明、利用建议
func execExp(base string, spec ExpSpec, client *http.Client) (bool, int, int, string, string) {
	matchedSteps := 0                    // 匹配的步骤数
	lastStatus := 0                      // 最后一步的HTTP状态码
	vars := make(map[string]string)      // 变量存储（用于步骤间传递数据）
	cookieJar := make(map[string]string) // Cookie存储（自动管理Cookie）

	// 从vars中生成使用说明
	usage := ""

	// 按顺序执行每个步骤
	for _, st := range spec.Steps {
		// build target URL, support absolute URLs in path
		rawPath := substVars(st.Path, vars)
		low := strings.ToLower(strings.TrimSpace(rawPath))
		url := ""
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
			url = rawPath
		} else {
			url = strings.TrimRight(base, "/") + rawPath
		}
		body := substVars(st.Body, vars)
		m := strings.ToUpper(strings.TrimSpace(st.Method))
		if m == "" {
			m = "GET"
		}
		attempts := st.Retry + 1
		if attempts <= 0 {
			attempts = 1
		}
		var resp *http.Response
		var err error
		var b []byte
		for i := 0; i < attempts; i++ {
			// rebuild request each attempt to reset body reader and avoid nil request panics
			var reqBody io.Reader
			if body != "" {
				reqBody = strings.NewReader(body)
			}
			req, e := http.NewRequest(m, url, reqBody)
			if e != nil {
				err = e
				// cannot build request; optional backoff then try next attempt
				if st.RetryDelayMs > 0 {
					time.Sleep(time.Duration(st.RetryDelayMs) * time.Millisecond)
				}
				continue
			}
			// headers
			for k, v := range st.Headers {
				req.Header.Set(k, substVars(v, vars))
			}
			// cookies from previous steps
			if len(cookieJar) > 0 {
				var pairs []string
				for ck, cv := range cookieJar {
					pairs = append(pairs, fmt.Sprintf("%s=%s", ck, cv))
				}
				req.Header.Set("Cookie", strings.Join(pairs, "; "))
			}
			resp, err = client.Do(req)
			if err == nil {
				b, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
				lastStatus = resp.StatusCode
				break
			}
			if st.RetryDelayMs > 0 {
				time.Sleep(time.Duration(st.RetryDelayMs) * time.Millisecond)
			}
		}
		if err != nil {
			continue
		}
		if st.SleepMs > 0 {
			time.Sleep(time.Duration(st.SleepMs) * time.Millisecond)
		}
		// capture Set-Cookie
		for _, sc := range resp.Header.Values("Set-Cookie") {
			parts := strings.Split(sc, ";")
			kv := strings.SplitN(parts[0], "=", 2)
			if len(kv) == 2 {
				cookieJar[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
		// extract variables
		extractVars(resp, b, st.Extract, vars)
		if validate(resp, b, st.Validate) {
			matchedSteps++
		}
	}

	// 如果有提取的变量，生成利用说明
	if len(vars) > 0 {
		var parts []string
		for k, v := range vars {
			// 过滤掉不需要显示的内部变量
			if !strings.HasPrefix(k, "_") {
				parts = append(parts, fmt.Sprintf("%s: %s", k, v))
			}
		}
		if len(parts) > 0 {
			usage = "提取到的信息:\n" + strings.Join(parts, "\n")
		}
	}

	// 生成利用建议，替换其中的变量
	suggestion := substVars(spec.ExploitSuggestion, vars)

	// success when all steps matched
	return matchedSteps == len(spec.Steps) && len(spec.Steps) > 0, matchedSteps, lastStatus, usage, suggestion
}

func expExecHandler(w http.ResponseWriter, r *http.Request) {
	var req ExpExecReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var exps []ExpSpec
	var err error
	if len(req.InlineExps) > 0 {
		exps = req.InlineExps
	} else if len(req.ExpPaths) > 0 {
		exps, err = loadExpsFromFiles(req.ExpPaths)
	} else {
		exps, err = loadExps(req.ExpDir)
	}
	if err != nil || len(exps) == 0 {
		http.Error(w, "load exps error or empty", http.StatusBadRequest)
		return
	}
	cc := req.Concurrency
	if cc <= 0 {
		cc = 50
	}
	timeout := time.Duration(req.TimeoutMs)
	if timeout <= 0 {
		timeout = 5000 * time.Millisecond
	} else {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	t := newTask(len(exps))
	go func() {
		sem := make(chan struct{}, cc)
		var wg sync.WaitGroup
		for _, e := range exps {
			select {
			case <-t.stop:
				break
			default:
			}
			wg.Add(1)
			sem <- struct{}{}
			es := e
			go func() {
				defer wg.Done()
				select {
				case <-t.stop:
					<-sem
					return
				default:
				}
				success, matched, lastStatus, usage, suggestion := execExp(req.BaseURL, es, client)
				keyInfo := buildExpKeyInfo(req.BaseURL, es)
				d, tot := t.IncDone()
				percent := int(math.Round(float64(d) / float64(tot) * 100))
				msg := SSEMessage{Type: "progress", TaskID: t.ID, Progress: fmt.Sprintf("%d/%d", d, tot), Percent: percent}
				if success {
					msg.Type = "find"
					msg.Data = map[string]interface{}{
						"name":         es.Name,
						"matchedSteps": matched,
						"lastStatus":   lastStatus,
						"usage":        usage,
						"suggestion":   suggestion,
						"keyInfo":      keyInfo,
					}
				} else {
					// 发送失败日志
					safeSend(t, SSEMessage{
						Type:   "scan_log",
						TaskID: t.ID,
						Data: map[string]interface{}{
							"name":         es.Name,
							"status":       "failed",
							"matchedSteps": matched,
							"lastStatus":   lastStatus,
							"keyInfo":      keyInfo,
						},
					})
				}
				safeSend(t, msg)
				<-sem
			}()
		}
		wg.Wait()
		finishTask(t.ID)
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"taskId": t.ID})
}
