# NeonScan 接口文档

## 1. 概述

NeonScan 提供 RESTful API 接口进行扫描操作，通过 SSE (Server-Sent Events) 实时推送扫描进度和结果。

**基础 URL**: `http://localhost:端口号`

**通用响应头**:
```
Content-Type: application/json
```

## 2. SSE (Server-Sent Events)

### 连接端点
```
GET /api/sse?task=<taskId>
```

### 消息类型

| Type | 说明 | Data |
|------|------|------|
| `start` | 任务开始 | 初始进度 |
| `progress` | 进度更新 | 当前进度信息 |
| `find` | 发现目标 | 扫描结果详情 |
| `scan_log` | 扫描日志 | 未命中/安全记录 |
| `end` | 任务结束 | 最终结果 |
| `ping` | 心跳保活 | - |

### 响应示例
```
data: {"type":"start","taskId":"t-1234567890","progress":"0/100","percent":0}
data: {"type":"progress","taskId":"t-1234567890","progress":"10/100","percent":10}
data: {"type":"find","taskId":"t-1234567890","progress":"15/100","percent":15,"data":{"port":80,"status":"open","banner":"Apache"}}
```

## 3. 端口扫描 API

### POST /api/port/scan

**请求体**:
```json
{
    "host": "192.168.1.1",
    "ports": "1-1000,3306,5432",
    "concurrency": 500,
    "timeoutMs": 300,
    "scanType": "tcp",
    "grabBanner": true
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| host | string | 是 | 目标主机地址 |
| ports | string | 是 | 端口范围，格式: `1-1024,3306` |
| concurrency | int | 否 | 并发数，默认 500 |
| timeoutMs | int | 否 | 超时时间(毫秒)，默认 300 |
| scanType | string | 否 | 扫描类型: `tcp`(默认) 或 `udp` |
| grabBanner | bool | 否 | 是否抓取 Banner，默认 false |

**响应**:
```json
{"taskId": "t-1234567890"}
```

### 扫描结果格式
```json
{
    "port": 80,
    "status": "open",
    "proto": "tcp",
    "banner": "Apache/2.4.41"
}
```

## 4. 目录扫描 API

### POST /api/dir/scan

**请求体**:
```json
{
    "baseUrl": "http://example.com",
    "dictPaths": ["/path/to/custom.txt"],
    "builtinDicts": ["php", "common"],
    "concurrency": 200,
    "timeoutMs": 1500
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| baseUrl | string | 是 | 目标基础 URL |
| dictPaths | string[] | 否 | 自定义字典文件路径 |
| builtinDicts | string[] | 否 | 内置字典名称 |
| concurrency | int | 否 | 并发数，默认 200 |
| timeoutMs | int | 否 | 超时时间(毫秒)，默认 1500 |

**响应**:
```json
{"taskId": "t-1234567890"}
```

**结果格式**:
```json
{
    "path": "/admin",
    "url": "http://example.com/admin",
    "status": 200,
    "location": "",
    "length": 1234
}
```

### GET /api/dict/list

获取内置字典列表。

**响应**:
```json
{
    "PHP": [
        {"name": "php.txt", "path": "/path/to/php.txt", "category": "PHP"}
    ],
    "Java": [
        {"name": "java.txt", "path": "/path/to/java.txt", "category": "Java"}
    ],
    "通用": [
        {"name": "common.txt", "path": "/path/to/common.txt", "category": "通用"}
    ]
}
```

## 5. POC 扫描 API

### POST /api/poc/scan

**请求体**:
```json
{
    "baseUrl": "http://example.com",
    "pocDir": "/path/to/poc/dir",
    "pocPaths": ["/path/to/specific.poc"],
    "timeoutMs": 3000,
    "concurrency": 50
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| baseUrl | string | 是 | 目标基础 URL |
| pocDir | string | 否 | POC 目录路径 |
| pocPaths | string[] | 否 | 指定 POC 文件路径 |
| timeoutMs | int | 否 | 超时时间(毫秒)，默认 3000 |
| concurrency | int | 否 | 并发数，默认 50 |

**响应**:
```json
{"taskId": "t-1234567890"}
```

**发现漏洞格式**:
```json
{
    "poc": "ThinkPHP 5.0.23 Remote Code Execution",
    "url": "http://example.com/",
    "status": 500,
    "exp": "curl -i -X POST 'http://example.com/'",
    "info": {
        "name": "ThinkPHP 5.0.23 Remote Code Execution",
        "author": "Anonymous",
        "severity": "critical",
        "reference": ["https://...cve..."]
    },
    "req": {
        "method": "POST",
        "path": "/",
        "headers": {},
        "body": "_method=__construct&filter[]=system&cmd=whoami"
    }
}
```

## 6. EXP 验证 API

### POST /api/exp/exec

**请求体**:
```json
{
    "baseUrl": "http://example.com",
    "expDir": "/path/to/exp/dir",
    "expPaths": ["/path/to/specific.exp"],
    "inlineExps": [
        {
            "name": "Custom EXP",
            "steps": [
                {
                    "method": "GET",
                    "path": "/info",
                    "validate": {
                        "status": [200],
                        "bodyContains": ["version"]
                    }
                }
            ],
            "exploitSuggestion": "利用该漏洞执行命令"
        }
    ],
    "concurrency": 50,
    "timeoutMs": 5000
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| baseUrl | string | 是 | 目标基础 URL |
| expDir | string | 否 | EXP 目录路径 |
| expPaths | string[] | 否 | 指定 EXP 文件路径 |
| inlineExps | ExpSpec[] | 否 | 内联 EXP 定义 |
| concurrency | int | 否 | 并发数，默认 50 |
| timeoutMs | int | 否 | 超时时间(毫秒)，默认 5000 |

**响应**:
```json
{"taskId": "t-1234567890"}
```

**验证成功格式**:
```json
{
    "name": "ThinkPHP RCE",
    "matchedSteps": 3,
    "lastStatus": 200,
    "usage": "提取到的信息:\nusername: admin",
    "suggestion": "使用 admin 账号登录系统",
    "keyInfo": "EXP: ThinkPHP RCE\nTarget: http://example.com\n..."
}
```

## 7. Web Probe API

### POST /api/probe

**请求体**:
```json
{
    "urls": ["http://example.com", "http://test.com"],
    "concurrency": 50,
    "timeoutMs": 3000,
    "headers": {"User-Agent": "Mozilla/5.0"},
    "followRedirect": true,
    "fetchFavicon": true,
    "fetchRobots": true
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| urls | string[] | 是 | URL 列表 |
| concurrency | int | 否 | 并发数，默认 50 |
| timeoutMs | int | 否 | 超时时间(毫秒)，默认 3000 |
| headers | object | 否 | 自定义请求头 |
| followRedirect | bool | 否 | 是否跟随重定向 |
| fetchFavicon | bool | 否 | 是否获取 Favicon |
| fetchRobots | bool | 否 | 是否获取 robots.txt |

**响应**:
```json
{"taskId": "t-1234567890"}
```

**探测结果格式**:
```json
{
    "url": "http://example.com",
    "status": 200,
    "server": "Apache/2.4.41",
    "tech": ["PHP", "WordPress"],
    "title": "Example Home",
    "favicon": "/favicon.ico",
    "robots": "User-agent: *\nDisallow: /wp-admin/"
}
```

## 8. AI EXP 生成 API

### POST /api/ai/gen/python

**请求体**:
```json
{
    "provider": "deepseek",
    "apiKey": "your-api-key",
    "baseUrl": "",
    "model": "deepseek-chat",
    "targetBaseURL": "http://example.com",
    "timeoutMs": 60000,
    "exp": {
        "name": "ThinkPHP RCE",
        "steps": [...]
    },
    "verify": {
        "matchedSteps": 3,
        "lastStatus": 200,
        "usage": "...",
        "suggestion": "..."
    },
    "autoVerify": true,
    "targetURL": "http://example.com",
    "maxRetries": 5
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| provider | string | 是 | AI 提供商: `deepseek`, `openai`, `anthropic`, `ollama` |
| apiKey | string | 是 | API 密钥 |
| baseUrl | string | 否 | API 基础 URL |
| model | string | 否 | 模型名称 |
| targetBaseURL | string | 否 | 目标基础 URL |
| timeoutMs | int | 否 | 超时时间(毫秒) |
| exp | ExpSpec | 是 | EXP 规范 |
| verify | ExpVerifyInfo | 否 | 验证结果 |
| autoVerify | bool | 否 | 是否自动验证，默认 false |
| targetURL | string | 否 | 验证目标 URL |
| maxRetries | int | 否 | 最大重试次数，默认 5 |

**响应**:
```json
{
    "name": "ThinkPHP RCE",
    "keyInfo": "EXP: ThinkPHP RCE\n...",
    "python": "# -*- coding: utf-8 -*-\nimport requests\n...",
    "verified": true,
    "verifyAttempts": 3,
    "verifyLogs": ["[INFO] 执行验证..."],
    "category": "CatCodeExecution"
}
```

## 9. 任务控制 API

### POST /api/task/stop

停止指定任务。

**请求**: `POST /api/task/stop?task=<taskId>`

**响应**:
```json
{"status": "stopping"}
```

## 10. POC 格式说明

### 10.1 传统 POC 格式 (JSON)

```json
{
    "name": "漏洞名称",
    "method": "GET",
    "path": "/path",
    "body": "",
    "match": "响应体必须包含的字符串",
    "headers": {},
    "matchHeaders": {"Server": "Apache"},
    "matchBodyAny": ["string1", "string2"],
    "matchBodyAll": ["string1", "string2"],
    "retry": 0,
    "retryDelayMs": 0
}
```

### 10.2 X-Ray 风格 POC (YAML)

```yaml
id: xray-001
info:
  name: 漏洞名称
  author: 作者
  severity: high
  reference: []
rules:
  r0:
    request:
      method: GET
      path: /path
    expression: response.status == 200 && response.body.bcontains(b"pattern")
expression: r0()
```

### 10.3 Nuclei 风格 POC (YAML)

```yaml
id: nuclei-001
info:
  name: 漏洞名称
  author: 作者
  severity: high
requests:
  - method: GET
    path:
      - /path
    headers:
      User-Agent: Mozilla/5.0
    matchers:
      - type: word
        part: body
        words:
          - "pattern"
```

## 11. EXP 格式说明

### 11.1 单步骤 EXP

```json
{
    "name": "漏洞利用名称",
    "steps": [
        {
            "method": "POST",
            "path": "/admin/login",
            "headers": {
                "Content-Type": "application/json"
            },
            "body": "{\"username\":\"admin\",\"password\":\"admin\"}",
            "validate": {
                "status": [200],
                "bodyContains": ["login_success"]
            },
            "extract": {
                "session": {
                    "headerRegex": {
                        "Set-Cookie": "session=([^;]+)"
                    }
                }
            }
        }
    ],
    "exploitSuggestion": "使用提取的 session 访问管理后台"
}
```

### 11.2 多步骤 EXP (变量传递)

```json
{
    "name": "多步骤利用",
    "steps": [
        {
            "method": "GET",
            "path": "/init",
            "validate": {"status": [200]},
            "extract": {
                "token": {
                    "bodyRegex": ["token=([^&\"]+)"]
                }
            }
        },
        {
            "method": "POST",
            "path": "/api/submit",
            "body": "token={{token}}&data=exploit",
            "validate": {"status": [200]}
        }
    ],
    "exploitSuggestion": "利用提取的 token 提交数据"
}
```
