# NeonScan 开发者指南

## 1. 开发环境搭建

### 1.1 环境要求

- Go 1.18 或更高版本
- Git
- Web 浏览器 (前端开发)

### 1.2 获取代码

```bash
git clone <repository-url>
cd bishe00-master
```

### 1.3 依赖安装

```bash
go mod download
```

### 1.4 运行开发服务器

```bash
go run main.go
```

服务器默认运行在 `http://localhost:8080`

## 2. 项目结构

```
bishe00-master/
├── main.go                 # 主程序入口，HTTP handlers
├── exp.go                  # EXP 验证模块
├── ai_exp.go               # AI EXP 生成
├── waf.go                  # WAF 检测
├── ai_exp_*.go             # AI 相关功能
├── internal/               # 内部包
│   ├── mcp/                # MCP 协议实现
│   └── shouji/             # JS 信息收集
├── web/                    # 前端资源
│   ├── *.html               # 各功能页面
│   ├── *.css                # 样式文件
│   └── *.js                 # JavaScript
├── shili/                  # 资源文件
│   ├── poc/                # POC 库
│   └── library/            # 指纹库
├── dict/                   # 字典文件
└── go.mod
```

## 3. 添加新的扫描模块

### 3.1 定义请求结构体

```go
// 扫描请求结构体
type MyScanReq struct {
    Target  string `json:"target"`
    Options string `json:"options"`
}
```

### 3.2 添加 Handler

```go
func myScanHandler(w http.ResponseWriter, r *http.Request) {
    var req MyScanReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // 创建任务
    t := newTask(totalCount)
    
    // 异步执行
    go func() {
        // 执行扫描逻辑
        // 发送进度: safeSend(t, SSEMessage{Type: "progress", ...})
        // 发送结果: safeSend(t, SSEMessage{Type: "find", ...})
        finishTask(t.ID)
    }()
    
    // 返回任务 ID
    json.NewEncoder(w).Encode(map[string]string{"taskId": t.ID})
}
```

### 3.3 注册路由

在 `main()` 函数中添加:

```go
http.HandleFunc("/api/my/scan", myScanHandler)
```

### 3.4 SSE 消息类型

| Type | 用途 |
|------|------|
| `start` | 任务开始 |
| `progress` | 进度更新 |
| `find` | 发现目标 (漏洞) |
| `scan_log` | 日志信息 (扫描中) |
| `end` | 任务结束 |
| `ping` | 心跳保活 |

## 4. 添加新的 POC 格式

### 4.1 定义 POC 结构

```go
type MyPOCFormat struct {
    Name    string `json:"name"`
    Request MyRequest `json:"request"`
    Match   MyMatch `json:"match"`
}
```

### 4.2 实现解析逻辑

在 `loadAllPOCs()` 函数中添加新的解析分支:

```go
var myPOC MyPOCFormat
if strings.HasSuffix(name, ".myext") {
    if err := yaml.Unmarshal(b, &myPOC); err == nil {
        if isValidMyPOC(myPOC) {
            myPOCs = append(myPOCs, myPOC)
        }
    }
}
```

### 4.3 实现执行逻辑

```go
func runMyPOCOnce(baseURL string, poc MyPOCFormat, client *http.Client) bool {
    // 构建请求
    req, _ := http.NewRequest(poc.Request.Method, baseURL+poc.Request.Path, nil)
    
    // 发送请求
    resp, err := client.Do(req)
    
    // 验证响应
    return checkMatch(resp, poc.Match)
}
```

## 5. 添加新的 AI 提供商

### 5.1 实现 Provider 接口

```go
type MyProvider struct {
    APIKey  string
    BaseURL string
    Model   string
}

func NewMyProvider(apiKey string) *MyProvider {
    return &MyProvider{
        APIKey:  apiKey,
        BaseURL: "https://api.myprovider.com",
        Model:   "my-model",
    }
}

func (p *MyProvider) Chat(messages []mcp.ChatMessage, tools []mcp.AITool) (string, []mcp.AIToolCall, error) {
    // 实现 Chat 接口
    // 1. 转换消息格式
    // 2. 发送 HTTP 请求
    // 3. 解析响应
    // 4. 返回结果
}
```

### 5.2 注册 Provider

在 `newAIProvider()` 函数中添加:

```go
switch providerName {
case "myprovider":
    p := NewMyProvider(apiKey)
    // 配置其他参数
    return p, nil
}
```

## 6. 前端开发

### 6.1 页面结构

```html
<!DOCTYPE html>
<html>
<head>
    <title>功能名称 - NeonScan</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <!-- 功能界面 -->
    </div>
    <script src="app.js"></script>
</body>
</html>
```

### 6.2 SSE 连接

```javascript
function connectSSE(taskId) {
    const eventSource = new EventSource(`/api/sse?task=${taskId}`);
    
    eventSource.addEventListener('start', (e) => {
        const data = JSON.parse(e.data);
        updateProgress(data);
    });
    
    eventSource.addEventListener('progress', (e) => {
        const data = JSON.parse(e.data);
        updateProgress(data);
    });
    
    eventSource.addEventListener('find', (e) => {
        const data = JSON.parse(e.data);
        showResult(data.data);
    });
    
    eventSource.addEventListener('end', (e) => {
        eventSource.close();
        showComplete();
    });
}
```

### 6.3 发送扫描请求

```javascript
async function startScan() {
    const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: 'example.com'})
    });
    
    const {taskId} = await response.json();
    connectSSE(taskId);
}
```

## 7. 测试

### 7.1 运行测试

```bash
go test ./...
```

### 7.2 添加测试

```go
func TestPortScan(t *testing.T) {
    // 准备测试数据
    req := PortScanReq{
        Host: "127.0.0.1",
        Ports: "80,443",
    }
    
    // 执行测试
    // 验证结果
}
```

## 8. 构建部署

### 8.1 本地构建

```bash
go build -o neonScan main.go
```

### 8.2 跨平台构建

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o neonScan-linux

# Windows
GOOS=windows GOARCH=amd64 go build -o neonScan.exe
```

### 8.3 Docker 部署

```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o neonScan
EXPOSE 8080
CMD ["./neonScan"]
```

## 9. 代码规范

### 9.1 命名规范

- 函数名: `驼峰命名` (如 `portScanHandler`)
- 结构体: `帕斯卡命名` (如 `PortScanReq`)
- 常量: `全大写+下划线` (如 `MaxConcurrency`)
- 包名: `小写+下划线` (如 `internal/mcp`)

### 9.2 错误处理

```go
// 优先处理错误
if err != nil {
    return nil, err
}

// 使用占位符描述未知错误
if err != nil {
    return nil, fmt.Errorf("操作失败: %w", err)
}
```

### 9.3 并发安全

```go
// 使用 mutex 保护共享资源
var mu sync.Mutex
mu.Lock()
defer mu.Unlock()
```

## 10. 调试

### 10.1 日志输出

```go
log.Printf("[模块名] 操作: %v", info)
```

### 10.2 性能分析

```bash
# 启用 pprof
go run -race main.go

# 访问 http://localhost:8080/debug/pprof/
```

## 11. 常见问题

### 11.1 端口被占用

```bash
# 查找占用进程
lsof -i :8080

# 更换端口
./neonScan -port 9090
```

### 11.2 扫描超时

调整 `timeoutMs` 参数:

```json
{
    "timeoutMs": 5000
}
```

### 11.3 POC 解析失败

检查 YAML/JSON 格式，确保包含必需字段。
