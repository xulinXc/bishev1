# NeonScan 项目文档

## 概述

NeonScan 是一个综合性的网络安全扫描工具，采用 Go 语言开发，提供 Web 界面操作。主要功能包括端口扫描、目录扫描、POC 漏洞扫描、EXP 验证、AI 生成 EXP 等。

## 文档结构

- [系统架构文档](./ARCHITECTURE.md) - 系统整体架构、模块设计、技术选型
- [接口文档](./INTERFACES.md) - HTTP API 接口详细说明
- [开发者指南](./DEVELOPER_GUIDE.md) - 开发环境、构建部署、代码规范

## 功能模块

| 模块 | 说明 | 核心文件 |
|------|------|----------|
| 端口扫描 | TCP/UDP 端口扫描，支持 Banner 抓取 | main.go |
| 目录扫描 | 基于字典的 Web 目录/文件爆破 | main.go |
| POC 扫描 | 支持传统 POC、X-Ray 风格、Nuclei 风格 | main.go |
| EXP 验证 | 多步骤 HTTP 请求、变量提取、响应验证 | exp.go |
| AI EXP 生成 | 基于漏洞类型生成 Python EXP 脚本 | ai_exp.go |
| Web Probe | Web 指纹识别和应用探测 | main.go |
| MCP 集成 | 支持 IDA Pro、JADX 集成 | internal/mcp/ |
| JS 收集 | JavaScript 信息提取和解包 | internal/shouji/ |

## 技术栈

- **后端**: Go 1.x
- **前端**: 原生 HTML/CSS/JavaScript
- **AI 提供商**: OpenAI、DeepSeek、Anthropic、Ollama
- **通信**: RESTful API + SSE (Server-Sent Events)
- **协议**: MCP (Model Context Protocol)
