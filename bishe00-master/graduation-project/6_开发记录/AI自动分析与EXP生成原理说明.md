# AI自动分析与EXP生成详解 - 技术原理与工作量说明

## 口头解释版

老师您好，这部分我来详细解释AI自动分析和EXP生成的原理，以及我具体做了哪些工作。

---

## 一、整体流程概览

AI自动分析是整个扫描系统的"大脑"，它的工作流程是这样的：

```
用户输入目标
     │
     ▼
┌─────────────────────────────────────────┐
│           自动化扫描工作流                 │
├─────────────────────────────────────────┤
│                                         │
│  1. 端口扫描 → 发现开放端口              │
│          ↓                               │
│  2. Web探测 → 识别服务类型              │
│          ↓                               │
│  3. 目录扫描 → 发现敏感路径              │
│          ↓                               │
│  4. POC扫描 → 验证漏洞是否存在          │
│          ↓                               │
│  5. AI分析 → 判断风险等级               │
│          ↓                               │
│  6. EXP生成 → 生成漏洞利用代码         │
│          ↓                               │
│  7. EXP验证 → 确保代码能跑通           │
│                                         │
└─────────────────────────────────────────┘
     │
     ▼
生成结构化安全报告
```

这里面最复杂的是**第六步和第七步**：让AI生成能用的EXP代码，并且能够自动验证。

---

## 二、为什么需要AI来生成EXP

### 2.1 传统方式的困境

传统做渗透测试的时候，如果POC扫描发现了一个漏洞，安全工程师需要：

1. 手工理解漏洞原理
2. 查找漏洞利用资料
3. 编写EXP代码
4. 测试EXP是否能运行
5. 如果不能运行，继续调试

这个过程可能需要几小时甚至几天。

### 2.2 AI辅助的优势

有了AI辅助后，流程变成了：

```
AI自动完成
     │
     ▼
POC发现漏洞 ──────────────────┐
     │                        │
     ▼                        │
AI分析漏洞特征                │
     │                        │
     ▼                        │
AI生成EXP代码（几秒钟）       │
     │                        │
     ▼                        │
自动验证EXP是否能跑通         │
     │                        │
     ▼                        │
跑不通？AI自动修正（最多5次）  │
     │                        │
     ▼                        │
输出可用的EXP代码
```

理论上可以大大缩短漏洞利用的时间。

---

## 三、EXP生成的原理

### 3.1 什么是EXP

EXP（Exploit）是漏洞利用代码。举个例子，如果扫描发现了一个Apache Struts漏洞：

- POC的作用是：**验证**这个漏洞是否存在
- EXP的作用是：**利用**这个漏洞，比如执行一条命令

一个简单的命令执行EXP可能是这样的：

```python
import requests

target = "http://target.com/struts2.action"
payload = {"name": "${system('whoami')}"}  # 执行whoami命令

response = requests.post(target, data=payload)
if "root" in response.text:
    print("漏洞存在！")
```

### 3.2 AI怎么知道怎么生成EXP

关键在于**POC信息**。当POC扫描发现漏洞时，它会记录：

- 漏洞名称（如：Apache Struts2 远程代码执行）
- 漏洞类型（如：命令执行）
- 利用方式（如：发送特定的POST请求）
- 验证方法（如：检查响应是否包含特定字符串）

AI接收这些信息后，结合自己的训练知识，生成对应的EXP代码。

### 3.3 我的代码是怎么做的

代码在`ai_exp.go`里，大概流程是：

**第一步：识别漏洞类型**

```go
// ai_exp_verify.go

// 漏洞类型枚举
type VulnCategory int

const (
    CatCommandInjection VulnCategory = iota  // 命令执行
    CatCodeExecution                        // 代码执行
    CatInfoDisclosure                       // 信息泄露
    CatFileUpload                          // 文件上传
    CatUnauthorizedAccess                  // 未授权访问
    CatUnknown                              // 未知
)

// DetectVulnCategory 分析POC信息，判断漏洞类型
func DetectVulnCategory(expSpec ExpSpec) VulnCategory {
    specStr := strings.ToLower(expSpec.Name + " " + expSpec.ExploitSuggestion)
    
    patterns := map[VulnCategory][]string{
        CatCommandInjection: {"command injection", "rce", "os command", "命令注入", "命令执行"},
        CatCodeExecution:    {"code exec", "eval", "代码执行"},
        CatInfoDisclosure:   {"info disclosure", "信息泄露", "敏感信息"},
        // ...
    }
    
    // 根据关键词判断漏洞类型
    for cat, keywords := range patterns {
        for _, kw := range keywords {
            if strings.Contains(specStr, kw) {
                return cat
            }
        }
    }
    
    return CatUnknown
}
```

**第二步：根据类型选择提示词模板**

```go
// ai_exp.go

// 根据漏洞类型返回专用的系统提示词
func getSystemPromptForCategory(category VulnCategory) string {
    switch category {
    case CatCommandInjection, CatCodeExecution:
        return "你正在处理一个命令执行类型的漏洞。" +
            "重点关注：" +
            "1. 使用 echo NEONSCAN_BEGIN; <命令>; echo NEONSCAN_END 包裹命令" +
            "2. 准确提取 NEONSCAN_BEGIN 和 NEONSCAN_END 之间的输出" +
            "3. 支持交互式Shell模式"
    case CatFileUpload:
        return "你正在处理一个文件上传类型的漏洞。" +
            "重点关注：" +
            "1. 正确构造multipart/form-data请求" +
            "2. 验证文件上传成功"
    // ...
    }
}
```

**第三步：构建用户提示词**

```go
// ai_exp.go

// 构建发送给AI的用户提示词
func buildUserPromptForCategory(category VulnCategory, targetBaseURL string, exp ExpSpec, ...) string {
    // 基础要求
    baseRequirements := `
请基于以下信息生成一个单文件 Python3 利用脚本，要求：
1) 只输出 Python 代码，不要输出解释
2) 使用 requests.Session()
3) 命令行参数必须支持：--target、--timeout
4) 支持 {{var}} 占位符替换与变量提取
5) 实现 validate() 函数，命中时输出 "VULNERABLE"
6) 增加详细的执行日志
`
    
    // 根据漏洞类型添加特定要求
    switch category {
    case CatCommandInjection:
        return baseRequirements + `
【命令执行专用】：
- 使用 echo NEONSCAN_BEGIN; <COMMAND>; echo NEONSCAN_END 包裹命令
- 提取 NEONSCAN_BEGIN 和 NEONSCAN_END 之间的内容
- 支持 --shell 交互式模式
`
    // ...
    }
}
```

**第四步：发送给AI并获取EXP代码**

```go
// ai_exp.go

func aiGenPythonFromExpHandler(w http.ResponseWriter, r *http.Request) {
    // 1. 解析请求
    var req AIGenPythonFromExpReq
    json.NewDecoder(r.Body).Decode(&req)
    
    // 2. 检测漏洞类型
    category := DetectVulnCategory(req.Exp)
    
    // 3. 构建提示词
    systemPrompt := getSystemPromptForCategory(category)
    userPrompt := buildUserPromptForCategory(category, req.TargetBaseURL, req.Exp, keyInfo, req.Verify)
    
    // 4. 发送给AI
    messages := []mcp.ChatMessage{
        {Role: "system", Content: systemPrompt},
        {Role: "user", Content: userPrompt},
    }
    
    provider := newAIProvider(req.Provider, req.APIKey, req.BaseURL, req.Model)
    content, _, err := provider.Chat(messages, nil)
    
    // 5. 解析AI返回的代码
    python := stripCodeFence(content)
}
```

---

## 四、为什么AI生成的代码不一定能用

### 4.1 AI生成代码的问题

AI生成的代码经常有这些问题：

1. **语法错误**：缩进不对、引号不配对、括号漏了
2. **逻辑错误**：变量名写错、API调用方式不对
3. **环境问题**：依赖没装、Python版本不兼容
4. **输出格式不对**：返回的数据格式跟预期的不一样

举个例子，AI可能生成这样的代码：

```python
# AI生成的代码（有错误）
def exploit():
    url = target + path  # 错误：target和path没有定义
    respone = requests.post(url, data=payload)  # 错误：response拼错了，requests应该是requests
    if "success" in respone.text:  # 错误：拼写错误
        print(VULNERABLE)  # 错误：应该是字符串"VULNERABLE"
```

### 4.2 我的解决方案：自动验证 + 迭代修正

代码流程是这样的：

```
AI生成EXP
     │
     ▼
保存到临时文件
     │
     ▼
用Python执行EXP
     │
     ├─── 成功运行且输出正确？ ────→ 返回EXP代码
     │
     ▼  否
分析失败原因
     │
     ├─── 能自动修复？ ────→ 自动修复（如修正缩进）
     │                      ↑
     │                      │
     ▼ 否                   │
请求AI修正EXP ◀───────────┘
     │
     ├─── 成功？ ────→ 再次验证
     │
     ▼ 否
最多重试5次
     │
     ▼
失败，返回错误信息
```

---

## 五、自动验证的详细原理

### 5.1 验证流程代码

代码在`ai_exp_verify.go`里：

```go
func GenerateAndVerifyExp(config ExpVerifyConfig, provider mcp.AIProvider, logChan chan string) (string, error) {
    category := DetectVulnCategory(config.ExpSpec)
    
    maxRetries := 5  // 最多重试5次
    currentCode := config.PythonCode
    
    for attempt := 1; attempt <= maxRetries; attempt++ {
        log("[验证] 尝试 #%d/%d", attempt, maxRetries)
        
        // 1. 保存EXP到临时文件
        expFile := filepath.Join(os.TempDir(), "neonscan_exp", fmt.Sprintf("exp_%d.py", attempt))
        os.WriteFile(expFile, []byte(currentCode), 0644)
        
        // 2. 执行EXP
        result := verifyExp(expFile, config.TargetURL, testCmd, timeoutSec, category, log)
        
        // 3. 检查结果
        if result.Success && result.Matched && result.CanExtract {
            log("[成功] EXP验证通过！")
            return currentCode, nil
        }
        
        // 4. 分析失败原因
        failureReason := analyzeFailure(result, category, log)
        
        // 5. 请求AI修正
        if attempt < maxRetries {
            correctionPrompt := buildCorrectionPrompt(config.ExpSpec, currentCode, failureReason, ...)
            correctedCode := requestExpCorrection(provider, correctionPrompt, log)
            
            if correctedCode != "" {
                currentCode = correctedCode
            } else {
                // AI无法修正，尝试备用修复
                currentCode = tryAlternativeFix(currentCode, result, ...)
            }
        }
    }
    
    return "", fmt.Errorf("达到最大重试次数")
}
```

### 5.2 执行EXP的代码

```go
func verifyExp(expFile, targetURL, testCmd string, ...) ExpVerifyResult {
    result := ExpVerifyResult{}
    
    // 1. 找Python命令
    pythonCmd := "python"
    if !commandExists("python") {
        pythonCmd = "python3"
    }
    
    // 2. 构建命令：python exp.py --target URL --cmd "whoami"
    cmd := exec.CommandContext(ctx, pythonCmd, expFile, "--target", targetURL, "--cmd", testCmd)
    
    // 3. 执行并捕获输出
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    
    err := cmd.Run()
    
    result.Output = stdout.String()
    result.Error = stderr.String()
    
    // 4. 分析结果
    if err != nil {
        // 执行出错了
        if strings.Contains(result.Error, "SyntaxError") {
            result.Success = false  // 语法错误
        } else if strings.Contains(result.Error, "Connection refused") {
            result.Success = false  // 网络错误
        }
        // ...
    } else {
        result.Success = true  // 执行成功
    }
    
    // 5. 检查是否输出了VULNERABLE标记
    if strings.Contains(result.Output, "VULNERABLE") {
        result.Matched = true  // 漏洞存在
    }
    
    // 6. 提取命令输出
    result.ExtractDemo = extractOutput(result.Output, ...)
    
    return result
}
```

### 5.3 分析失败原因

```go
func analyzeFailure(result ExpVerifyResult, category VulnCategory, log func(string, ...)) string {
    var reasons []string
    
    // 1. Python本身无法运行（致命错误）
    if strings.Contains(result.Error, "Python命令执行失败") {
        return "Python环境问题"
    }
    
    // 2. 语法错误
    if strings.Contains(result.Error, "SyntaxError") {
        reasons = append(reasons, "Python语法错误")
    }
    if strings.Contains(result.Error, "IndentationError") {
        reasons = append(reasons, "缩进错误")
    }
    
    // 3. URL格式错误
    if strings.Contains(result.Error, "No connection adapters") {
        reasons = append(reasons, "URL缺少http://或https://前缀")
    }
    
    // 4. 网络错误
    if strings.Contains(result.Error, "Connection refused") {
        reasons = append(reasons, "目标服务器拒绝连接")
    }
    if strings.Contains(result.Error, "timeout") {
        reasons = append(reasons, "连接超时")
    }
    
    // 5. HTTP错误
    if strings.Contains(result.Error, "404") {
        reasons = append(reasons, "HTTP 404，路径不存在")
    }
    
    // ...
    
    return strings.Join(reasons, "; ")
}
```

### 5.4 构建修正提示词

```go
func buildCorrectionPrompt(expSpec ExpSpec, code, failureReason string, ...) string {
    return fmt.Sprintf(`
以下是之前生成的EXP代码：

%s

执行时出现了以下错误：

%s

请分析错误原因并修正代码。修正要求：
1. 只输出修正后的Python代码，不要输出解释
2. 确保代码可以直接运行
3. 保持原有的漏洞利用逻辑不变
4. 修复所有语法错误和逻辑错误
`, code, failureReason)
}
```

---

## 六、备用修复机制

当AI无法正确修正代码时，我写了一些规则来自动修复常见问题：

```go
func tryAlternativeFix(code string, result ExpVerifyResult, category VulnCategory, testCmd string, log func(string, ...)) string {
    // 1. 修复缩进问题
    if strings.Contains(result.Error, "IndentationError") {
        log("[备用] 尝试修复缩进问题...")
        code = fixIndentation(code)
    }
    
    // 2. 修复URL问题
    if strings.Contains(result.Error, "No connection adapters") {
        log("[备用] 尝试修复URL格式问题...")
        code = fixURLFormat(code)
    }
    
    // 3. 添加输出标记
    if result.Matched && !result.CanExtract {
        log("[备用] 添加NEONSCAN_BEGIN/END输出标记...")
        code = addEchoMarkers(code)
    }
    
    // 4. 修复正则提取
    if strings.Contains(result.Output, "VULNERABLE") && !strings.Contains(result.Output, "NEONSCAN") {
        log("[备用] 改进输出提取逻辑...")
        code = improveOutputExtraction(code)
    }
    
    return code
}

// 修复缩进
func fixIndentation(code string) string {
    lines := strings.Split(code, "\n")
    var fixed []string
    indent := 0
    
    for _, line := range lines {
        trimmed := strings.TrimLeft(line, " \t")
        
        if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "class ") {
            indent = 4
        } else if strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "while ") {
            indent = 4
        } else if trimmed == "" {
            continue
        }
        
        fixed = append(fixed, strings.Repeat(" ", indent) + trimmed)
    }
    
    return strings.Join(fixed, "\n")
}

// 修复URL格式
func fixURLFormat(code string) string {
    // 确保target变量在使用前被处理
    if !strings.Contains(code, "http://") && !strings.Contains(code, "https://") {
        // 在使用target前添加协议前缀
        code = strings.Replace(code, 
            "response = requests.post(target", 
            "target = target if target.startswith(('http://', 'https://')) else 'http://' + target\nresponse = requests.post(target", 1)
    }
    return code
}

// 添加输出标记
func addEchoMarkers(code string) string {
    // 在命令执行部分添加echo标记
    code = strings.Replace(code, 
        "requests.post(url, data=payload)", 
        "requests.post(url, data=payload + '&cmd=echo NEONSCAN_BEGIN;${'+cmd+'};echo NEONSCAN_END')", 1)
    return code
}
```

---

## 七、完整的工作流程图

```
用户触发AI分析
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤1：端口扫描                                           │
│  - 并发扫描多个端口                                        │
│  - 抓取Banner获取服务版本                                  │
│  - 结果实时推送（SSE）                                     │
└─────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤2：Web探测                                           │
│  - 识别网站标题、技术栈                                    │
│  - 指纹匹配（比对finger.json）                             │
└─────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤3：目录扫描                                           │
│  - 多字典并发爆破                                          │
│  - 判定有效状态码                                         │
└─────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤4：POC扫描                                            │
│  - 支持Legacy/X-Ray/Nuclei三种格式                         │
│  - 变量替换、表达式匹配                                    │
└─────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤5：AI漏洞分析                                         │
│  - 分析扫描结果                                            │
│  - 判断漏洞类型和风险等级                                   │
│  - 生成结构化报告                                          │
└─────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤6：AI生成EXP（如果需要）                              │
│  - 识别漏洞类型                                           │
│  - 选择提示词模板                                         │
│  - 发送给AI生成代码                                        │
└─────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤7：自动验证                                          │
│  - 保存EXP到临时文件                                       │
│  - 用Python执行EXP                                        │
│  - 分析执行结果                                           │
│  - 成功？→ 返回代码                                       │
│  - 失败？→ 分析原因 → AI修正 → 最多重试5次               │
└─────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
                 生成最终报告
```

---

## 八、我具体做了哪些工作

### 8.1 漏洞类型自动分类

这不是简单写几个if-else就完了。我需要：

1. **收集关键词**：研究各种漏洞类型的特征词
2. **设计优先级**：比如"命令注入"和"RCE"哪个优先级更高
3. **处理特殊情况**：比如某些POC可能同时匹配多个类型

```go
// 我的实现逻辑
patterns := map[VulnCategory][]string{
    CatCommandInjection: {
        "command injection",  // 英文
        "rce",              // 缩写
        "remote code exec", // 全称
        "os command",       // 变体
        "命令注入",          // 中文
        "命令执行",
        "远程代码执行",
    },
    // ...
}

// 检测的时候会遍历所有类型，优先返回匹配度最高的
```

### 8.2 提示词工程

这是最花时间的部分。我需要：

1. **理解AI的思维模式**：AI喜欢什么样的指令
2. **设计输出格式**：不要Markdown、不要解释、只要代码
3. **处理各种漏洞类型**：每种类型的要求不一样

```go
// 命令执行的提示词
`
【命令执行专用】：
- 命令行参数额外支持：--cmd(可选 单次命令)、--shell(可选 交互式命令执行)
- 使用 echo NEONSCAN_BEGIN; <COMMAND>; echo NEONSCAN_END 包裹命令
- 执行后提取 NEONSCAN_BEGIN 和 NEONSCAN_END 之间的内容
- --shell 模式要循环读取命令并执行，exit/quit 退出
`

// 文件上传的提示词
`
【文件上传专用】：
- 命令行参数额外支持：--file(要上传的文件路径)
- 正确构造 multipart/form-data 请求
- 验证文件上传成功
`

// 未授权访问的提示词
`
【未授权访问专用】：
- 清晰展示访问受保护资源的证据
- 提取并格式化敏感信息
`
```

### 8.3 错误处理

这个也很复杂。AI可能犯的错误太多了：

```go
// 我处理了这些错误类型
errors := []string{
    "SyntaxError",           // 语法错误
    "IndentationError",      // 缩进错误
    "NameError",            // 变量未定义
    "TypeError",            // 类型错误
    "ImportError",          // 导入错误
    "Connection refused",   // 连接被拒绝
    "Connection timeout",   // 连接超时
    "HTTP 404",             // 404错误
    "HTTP 500",             // 500错误
    "URL缺少前缀",          // URL格式错误
    "VULNERABLE未输出",     // 没有检测到漏洞
    "无法提取输出",        // 输出提取失败
    // ...还有几十种
}
```

### 8.4 验证逻辑

验证不是简单地运行一下就完了：

```go
// 验证逻辑需要检查：
if result.Success &&           // Python能运行
   result.Matched &&         // 输出了VULNERABLE
   result.CanExtract &&       // 能提取到命令输出
   !isFakePositive(output) {  // 不是假阳性
    return true
}
```

### 8.5 备用修复机制

当AI修正失败时，我的规则修复：

```go
// 这些是我实现的备用修复
func fixIndentation(code string) string     // 修复缩进
func fixURLFormat(code string) string       // 修复URL格式
func addEchoMarkers(code string) string     // 添加输出标记
func improveOutputExtraction(code string) string  // 改进输出提取
func fixRegexExtraction(code string) string  // 修复正则提取
```

---

## 九、为什么这个工作量很大

### 9.1 调试过程耗时间

这个功能我调了很久，原因是：

1. **AI输出不稳定**：同样的提示词，每次返回的代码都可能不一样
2. **边界情况多**：有的EXP能跑通，有的就跑不通
3. **错误难复现**：有时候AI修正后能跑，下次又不能了

### 9.2 需要不断迭代

不是写完代码就完了：

```
第1版：AI生成EXP → 能跑通就返回
     ↓
第2版：加验证逻辑 → 发现语法错误就返回错误
     ↓
第3版：加自动修正 → 发现错误就让AI重试
     ↓
第4版：加备用修复 → AI修不了就用规则修复
     ↓
第5版：加输出提取 → 确保能提取到命令输出
     ↓
第6版：加假阳性检测 → 确保不是误报
     ↓
... 还有很多版本
```

### 9.3 需要理解多个领域

做这个功能需要懂：

1. **渗透测试**：理解漏洞原理、利用方式
2. **AI提示词工程**：知道怎么写能让AI生成更好的代码
3. **Python**：理解Python的各种特性和常见错误
4. **系统编程**：理解进程创建、输出捕获、超时处理

---

## 十、总结

这个功能的核心工作量在于：

1. **理解AI的工作方式**：不是简单地调用API就行，需要设计合适的提示词
2. **处理各种边界情况**：AI生成的代码可能有一百种错误，需要一种一种处理
3. **设计验证和修正机制**：让系统能够自动发现错误并修正，而不是人工介入
4. **迭代优化**：不是一蹴而就的，需要不断测试、发现问题、改进

代码量确实不大，但背后的思考和调试过程是比较花时间的。
