package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"bishe/internal/mcp"
)

type AIGenPythonFromExpBatchReq struct {
	Provider      string    `json:"provider"`
	APIKey        string    `json:"apiKey"`
	BaseURL       string    `json:"baseUrl"`
	Model         string    `json:"model"`
	TargetBaseURL string    `json:"targetBaseUrl"`
	TimeoutMs     int       `json:"timeoutMs"`
	ExpDir        string    `json:"expDir"`
	ExpPaths      []string  `json:"expPaths"`
	InlineExps    []ExpSpec `json:"inlineExps"`
	Concurrency   int       `json:"concurrency"`
}

func aiGenPythonFromExpBatchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AIGenPythonFromExpBatchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.TargetBaseURL = strings.TrimSpace(req.TargetBaseURL)

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
		cc = 20
	}

	providerName := strings.TrimSpace(req.Provider)
	var provider mcp.AIProvider
	if providerName != "" {
		p, err := newAIProvider(providerName, req.APIKey, req.BaseURL, req.Model)
		if err == nil {
			provider = p
		}
	}

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

				keyInfo := buildExpKeyInfo(req.TargetBaseURL, es)
				py := generatePythonFromExpSpec(req.TargetBaseURL, es)
				if provider != nil {
					tmp := genPythonWithProvider(provider, req.TargetBaseURL, es)
					if strings.TrimSpace(tmp) != "" {
						py = tmp
					}
				}

				d, tot := t.IncDone()
				percent := int(math.Round(float64(d) / float64(tot) * 100))
				safeSend(t, SSEMessage{
					Type:     "find",
					TaskID:   t.ID,
					Progress: fmt.Sprintf("%d/%d", d, tot),
					Percent:  percent,
					Data: map[string]interface{}{
						"name":    es.Name,
						"keyInfo": keyInfo,
						"python":  py,
					},
				})

				<-sem
			}()
		}
		wg.Wait()
		finishTask(t.ID)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"taskId": t.ID})
}

func genPythonWithProvider(provider mcp.AIProvider, targetBaseURL string, spec ExpSpec) string {
	keyInfo := buildExpKeyInfo(targetBaseURL, spec)
	expJSON, _ := json.MarshalIndent(spec, "", "  ")
	targetArgDesc := "--target(必填)"
	targetUrlHint := "8) 构建请求URL时，请使用 urllib.parse.urljoin(target, path) 以正确处理相对路径，避免 'No scheme supplied' 错误。"
	if targetBaseURL != "" {

		targetArgDesc = fmt.Sprintf("--target(可选, 默认='%s')", targetBaseURL)
		targetUrlHint = fmt.Sprintf("8) 已知目标地址为 '%s'，请在脚本中将其设为 --target 的默认值。构建请求URL时，请务必使用 urllib.parse.urljoin(target, path) 拼接地址，确保 scheme (http/https) 存在。如果用户提供的 target 不包含 scheme，请自动添加 http:// 前缀。", targetBaseURL)
	}

	systemPrompt := "你是一位专业的渗透测试开发者。你将根据给定的 EXP 规范生成可运行的 Python 利用脚本。请根据实际的漏洞特征生成通用的EXP，不要假设目标一定是特定框架。"
	userPrompt := fmt.Sprintf(`请基于以下信息生成一个单文件 Python3 利用脚本，要求：
1) 只输出 Python 代码，不要输出解释/Markdown/代码块围栏。
2) 使用 requests.Session()；默认 verify=False，并禁用 urllib3 警告。
3) 命令行参数必须同时支持：%s、--timeout(可选)、--cmd(可选 单次命令)、--shell(可选 交互式命令执行)。
4) 若属于 RCE/命令执行类型：--cmd 模式要能传入命令执行；--shell 模式要循环读取命令并执行，exit/quit 退出。
5) 严格按 EXP steps 顺序发包，支持 {{var}} 占位符替换与变量提取（bodyRegex/headerRegex）。
6) 生成的脚本不得直接 print(response.text) 或输出整页 HTML。必须对回显做"去噪"处理。
7) 实现 validate(status/bodyContains/headerContains)，并在命中时输出 "VULNERABLE" 与关键证据。
8) 不依赖第三方库（除了 requests）。特别注意：禁止导入 readline 模块，以确保 Windows 兼容性。
%s
9) 【通用响应提取策略】无论目标是什么框架，执行命令后都需要从响应中提取命令输出。推荐策略：
   - 优先尝试定位响应中的特殊标记（如 NEONSCAN_BEGIN/NEONSCAN_END）
   - 如果没有标记，使用正则表达式截取 HTML 标签之前的内容：re.search(r"^(.*?)(?:<!DOCTYPE|<html|<!HTML)", resp.text, re.DOTALL|re.IGNORECASE)
   - 如果响应是纯文本，尝试直接提取
   - 如果响应包含错误信息，提取其中的关键报错内容
   - 确保不打印整个 HTML 页面给用户
   
10) 【关键执行日志】在脚本中增加详细的执行日志（类似 debug 模式），打印关键步骤：
    [INFO] Target: ...
    [INFO] Payload: ...
    [INFO] Sending request...
    [INFO] Response status: ...
    [INFO] Response length: ...
    [INFO] Extracting output...
    [RESULT] ...
    这样方便用户看到 AI 脚本的执行过程。
    
11) 【URL构建要求】构建请求URL时，请务必使用 urllib.parse.urljoin(target, path) 拼接地址，确保 scheme (http/https) 存在。如果用户提供的 target 不包含 scheme，请自动添加 http:// 前缀。

12) 【命令执行处理】如果EXP包含命令执行功能（通过 {{cmd}} 或 {{command}} 占位符）：
    - 使用 echo NEONSCAN_BEGIN; <COMMAND>; echo NEONSCAN_END 包裹命令
    - 执行后提取 NEONSCAN_BEGIN 和 NEONSCAN_END 之间的内容
    - 如果提取失败，使用正则 r"^(.*?)(?:<!DOCTYPE|<html)" 截取 HTML 之前的纯文本内容
    - 如果命令执行后返回的是错误页面，尝试提取 <pre> 或 <body> 中的文本内容
    - 确保无论响应是什么格式，都能提取并展示关键输出

EXP JSON:
%s
`, targetArgDesc, targetUrlHint, keyInfo, string(expJSON))

	messages := []mcp.ChatMessage{
		{Role: "system", Content: systemPrompt, Time: time.Now().Format(time.RFC3339)},
		{Role: "user", Content: userPrompt, Time: time.Now().Format(time.RFC3339)},
	}
	content, _, err := provider.Chat(messages, nil)
	if err != nil {
		return ""
	}
	return stripCodeFence(content)
}
