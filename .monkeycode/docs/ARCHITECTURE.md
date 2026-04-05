# NeonScan 系统架构文档

## 1. 系统概述

NeonScan 是一个综合性的网络安全扫描平台，采用 Go 语言开发，提供实时 Web 界面操作。系统通过 SSE (Server-Sent Events) 实现扫描任务的实时进度推送，支持高并发扫描任务。

## 2. 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web Frontend                            │
│    (ports.html, dirs.html, poc.html, exp.html, probe.html)     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼ HTTP + SSE
┌─────────────────────────────────────────────────────────────────┐
│                      Go HTTP Server (main.go)                   │
│  ┌──────────────┬──────────────┬──────────────┬───────────────┐ │
│  │ Port Handler │ Dir Handler  │ POC Handler  │ EXP Handler   │ │
│  └──────────────┴──────────────┴──────────────┴───────────────┘ │
│  ┌──────────────┬──────────────┬──────────────┬───────────────┐ │
│  │ Probe Handler│ AI Handler   │ WAF Handler  │ SSE Handler   │ │
│  └──────────────┴──────────────┴──────────────┴───────────────┘ │
└─────────────────────────────────────────────────────────────────┘
         │                │                │                │
         ▼                ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Scanner    │  │    POC       │  │     EXP      │  │   Finger     │
│   Engine     │  │   Engine     │  │   Engine     │  │   Library    │
└──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
         │                │                │                │
         ▼                ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  TCP/UDP     │  │   X-Ray      │  │   Variable   │  │  Keyword     │
│  Connection  │  │   Nuclei     │  │   Extract    │  │  Matching    │
└──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
```

## 3. 核心模块

### 3.1 任务管理模块

**文件**: `main.go` (第 46-204 行)

```go
type Task struct {
    ID      string          // 任务唯一标识符
    Total   int             // 任务总数
    Done    int             // 已完成数量
    Created time.Time       // 创建时间
    ch      chan SSEMessage // SSE 消息通道
    stop    chan struct{}   // 停止信号
}
```

**特性**:
- 基于时间戳的任务 ID 生成
- 带缓冲区的 channel (容量 1024)
- 5 分钟自动清理机制
- 线程安全的任务状态管理

### 3.2 端口扫描模块

**文件**: `main.go` (第 330-507 行)

**功能**:
- TCP 连接扫描
- UDP 探测扫描
- Banner 抓取
- 支持自定义端口范围 (如 `1-1024,3306,5432`)

**并发模型**:
- 基于 semaphore 的并发控制
- 默认 500 并发
- 可配置超时时间

### 3.3 目录扫描模块

**文件**: `main.go` (第 509-678 行)

**功能**:
- 多字典支持
- 内置字典按技术栈分类 (PHP、Java、ASP、Python 等)
- 自定义字典路径
- HTTP/HTTPS 自动检测

**响应码处理**:
- 200: 成功
- 301/302: 重定向
- 403: 禁止访问

### 3.4 POC 扫描模块

**文件**: `main.go` (第 680-2572 行)

**支持的 POC 格式**:

#### 传统 POC 格式
```go
type POC struct {
    Name         string
    Method       string
    Path         string
    Body         string
    Match        string
    Headers      map[string]string
    MatchHeaders map[string]string
    MatchBodyAny []string
    MatchBodyAll []string
    Retry        int
}
```

#### X-Ray 风格 POC
```go
type XRPOC struct {
    ID         string
    Info       XRInfo
    Rules      map[string]XRRule
    Expression string
}
```

#### Nuclei 风格 POC
```go
type NucleiPOC struct {
    ID                string
    Info              NucleiInfo
    Requests          []NucleiRequest
    MatchersCondition string
    Matchers          []NucleiMatcher
}
```

### 3.5 EXP 验证模块

**文件**: `exp.go` (第 1-695 行)

**核心结构**:
```go
type ExpSpec struct {
    Name              string
    Steps             []ExpStep
    ExploitSuggestion string
}

type ExpStep struct {
    Method       string
    Path         string
    Body         string
    Headers      map[string]string
    Validate     Validation
    Extract      map[string]ExtractRule
    Retry        int
    SleepMs      int
}
```

**特性**:
- 多步骤 HTTP 请求链
- 变量提取 (bodyRegex/headerRegex)
- Cookie 自动管理
- 响应验证规则

### 3.6 AI EXP 生成模块

**文件**: `ai_exp.go` (第 1-578 行)

**支持的 AI 提供商**:
- DeepSeek
- OpenAI
- Anthropic
- Ollama

**漏洞分类**:
- `CatCommandInjection` - 命令执行
- `CatCodeExecution` - 代码执行
- `CatFileUpload` - 文件上传
- `CatUnauthorizedAccess` - 未授权访问
- `CatInfoDisclosure` - 信息泄露

### 3.7 Web Probe 模块

**文件**: `main.go` (第 2574-2699 行)

**功能**:
- 批量 URL 探测
- 指纹识别 (支持 keyword/faviconhash/regula)
- 自定义请求头
- Favicon 哈希采集
- robots.txt 采集

## 4. MCP 集成模块

**目录**: `internal/mcp/`

### AI Provider 实现
- `ai.go` - OpenAI、DeepSeek、Anthropic、Ollama 提供商
- `ai_stream.go` - 流式响应处理

### JADX 集成
- `jadx.go` - APK 反编译工具集成
- `jadx_handlers.go` - JADX MCP 协议处理

## 5. 前端架构

**目录**: `web/`

| 文件 | 功能 |
|------|------|
| `index.html` | 首页/导航 |
| `ports.html` | 端口扫描界面 |
| `dirs.html` | 目录扫描界面 |
| `poc.html` | POC 扫描界面 |
| `exp.html` | EXP 验证界面 |
| `probe.html` | Web Probe 界面 |
| `ai_analysis.html` | AI 分析界面 |
| `jadx_mcp.html` | JADX MCP 界面 |
| `waf.html` | WAF 检测界面 |
| `shouji.html` | 社工库收集界面 |
| `mcp.html` | MCP 配置界面 |
| `report.html` | 报告界面 |

## 6. 数据流

### 6.1 扫描任务流程

```
1. 前端发送 POST 请求 (如 /api/port/scan)
2. 后端创建 Task，返回 taskId
3. 前端通过 SSE 连接 /api/sse?task=<taskId>
4. 后端异步执行扫描，实时推送进度
5. 扫描完成，SSE 发送 end 消息
6. 前端展示结果
```

### 6.2 SSE 消息格式

```go
type SSEMessage struct {
    Type     string      // start, progress, find, end, ping, scan_log
    TaskID   string
    Progress string      // "10/100"
    Percent  int         // 0-100
    Data     interface{}
}
```

## 7. 目录结构

```
bishe00-master/
├── main.go                 # 主程序，HTTP handlers
├── exp.go                  # EXP 验证模块
├── ai_exp.go               # AI EXP 生成
├── waf.go                  # WAF 检测
├── upload.go               # 文件上传
├── ai_exp_batch.go         # AI 批量验证
├── ai_exp_verify.go        # AI 验证
├── main_autoscan_*         # 自动化测试
├── internal/
│   ├── mcp/                # MCP 协议实现
│   │   ├── ai.go
│   │   ├── ai_stream.go
│   │   ├── common.go
│   │   ├── jadx.go
│   │   └── jadx_handlers.go
│   └── shouji/             # JS 信息收集
│       └── shouji.go
├── web/                    # 前端界面
├── shili/
│   ├── poc/                # POC 库
│   │   ├── disclosure/     # 披露漏洞 POC
│   │   ├── ThinkPHP/       # ThinkPHP POC
│   │   └── vulnerability/  # 漏洞 POC
│   ├── library/            # 指纹库
│   └── 说明/               # 文档
├── dict/                   # 目录扫描字典
│   ├── php.txt
│   ├── java.txt
│   └── common.txt
└── go.mod
```

## 8. 技术选型

| 组件 | 技术选型 | 说明 |
|------|----------|------|
| 语言 | Go 1.x | 高并发、原生性能 |
| Web框架 | net/http | 标准库，轻量 |
| 模板引擎 | 原生 HTML | 无额外依赖 |
| JSON处理 | encoding/json | 标准库 |
| YAML处理 | gopkg.in/yaml.v3 | POC 解析 |
| HTTP客户端 | net/http | 标准库，支持超时 |
| 加密 | crypto/tls | HTTPS 支持 |
