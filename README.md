# 🔍 Poc-Monitor

> GitHub CVE / POC 情报监控系统 · 威胁情报实时推送

[![Stars](https://img.shields.io/github/stars/adminlove520/Poc-Monitor?style=flat)](https://github.com/adminlove520/Poc-Monitor)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

[🌐 在线访问](https://adminlove520.github.io/poc-monitor) · [📦 下载 Release](https://github.com/adminlove520/Poc-Monitor/releases)

---

## 🌟 功能特性

- **GitHub 实时监控**：监控 CVE/POC 相关仓库的最新动态
- **智能去重**：关联 CVE 同系列项目，不遗漏同源漏洞
- **多渠道推送**：Bark 推送通知（支持自定义通知渠道）
- **年份归档**：按年份自动整理，2009–2026 完整历史
- **优雅 Web UI**：可视化 CVE 列表，支持搜索/筛选/年份归档
- **每日自动更新**：GitHub Actions 零成本定时运行

---

## 🚀 快速上手

### 安装

```bash
git clone https://github.com/adminlove520/Poc-Monitor.git
cd Poc-Monitor
go mod download
```

### 方式一：Web UI（推荐）

```bash
# 首次运行抓取数据
go run search.go

# 启动 Web 可视化界面
go run search.go web
# 访问 http://localhost:8080
```

### 方式二：CLI 监控模式（后台运行）

```bash
# 设置 Bark 通知 Token（可选）
export barkToken=your_bark_token_here

# 运行监控
go run search.go
```

### Docker 部署

```bash
docker build -t poc-monitor .
docker run -d -p 8080:8080 -v $(pwd)/data:/app poc-monitor web
```

---

## 🖥 Web UI 功能

- **年份侧边栏**：按年份快速筛选
- **搜索过滤**：CVE ID / 描述 / 仓库名搜索
- **新增/更新标签**：🆕 新增 🟡 更新，直观展示今日变化
- **Star/Fork 统计**：每条 CVE 的社区关注度
- **深色主题**：保护眼睛，适合长时间浏览

---

## ⚙️ 配置说明

### 通知渠道

修改 `search.go` 中的 `Notice` 函数，可切换至任意通知方式：

```go
// Bark 推送（默认）
// 参考 https://github.com/sari3l/notify

// 也可自定义为企业微信/钉钉/飞书/Telegram 等
```

### 黑名单

编辑 `blacklist.yaml`，填入 GitHub 用户 ID（数字）即可屏蔽该用户的所有仓库。

### 查询关键字

修改 `search.go` 中的 `cveQuery` 常量：

```go
const cveQuery = "CVE-20"  // 默认搜索所有 CVE 年份
const cveQuery = "CVE-2024" // 仅搜索 2024 年
```

---

## 📂 数据文件

| 文件 | 说明 |
|------|------|
| `new.json` | 最近一次新增的 CVE 仓库 |
| `update.json` | 最近一次更新的 CVE 仓库 |
| `dateLog/YYYY-MM-DD.json` | 每日新增/更新记录 |
| `YYYY/*.json` | 按年份归档的 CVE 详情 |

---

## 🤖 CI 自动部署

本仓库已配置 GitHub Actions，每日自动运行监控脚本并更新数据。

1. 在 GitHub 仓库 Settings → Secrets 添加 `barkToken`
2. Actions 会自动在每日凌晨运行
3. 新增 CVE 会触发 Bark 推送通知

---

## 📝 License

MIT License · 东方隐侠·Anonymous
