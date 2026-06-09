# 安全漏洞 Wiki - 使用指南

本 Wiki 用于管理安全漏洞信息，采用三层架构（遵循 llm-wiki.md 理念）。

---

## 快速开始

### 浏览漏洞信息

| 方式 | 说明 |
|------|------|
| **vlwiki_viewer（推荐）** | 浏览器打开 `http://localhost:8080`，无需安装任何软件 |
| **VS Code + Foam** | `code /home/sistec/skill/vlWiki/vlWiki/wiki`，支持编辑和全文搜索 |
| **直接打开 Markdown** | 任意 Markdown 编辑器打开对应 `.md` 文件 |

### 启动查看器

```bash
# 方式一：使用启动脚本（推荐）
bash /home/sistec/skill/vlWiki/start_viewer.sh

# 方式二：手动启动
cd /home/sistec/skill/vlWiki
python3 vlwiki_viewer.py
# 访问 http://localhost:8080
```

> 查看器已配置开机自启（crontab `@reboot`），重启后自动运行。

### 添加新报告

1. 将 PDF 复制到 `../raw/pdf/` 目录
2. 按 `YYYY-MM-DD-安全报告.pdf` 格式重命名
3. 运行一键导入：
   ```bash
   cd /home/sistec/skill/vlWiki
   python3 scripts/report2wiki.py "../vlWiki/wiki/raw/pdf/报告.pdf"
   ```
4. 脚本自动完成阶段1（PDF→JSON）和阶段2（JSON→MD页面），并生成索引

---

## 目录结构

```
vlWiki/
├── SKILL.md               # 技能说明文档（使用方法、脚本说明）
├── vlwiki_viewer.py       # 独立 Python 查看器
├── start_viewer.sh        # 查看器启动脚本
├── scripts/               # 处理脚本
│   ├── appscanpdf2json.py   # 阶段1：PDF → 中间 JSON
│   ├── json2wiki.py         # 阶段2：JSON → VL 页面
│   ├── report2wiki.py       # 一键流程（阶段1+2）
│   ├── update_index.py      # 阶段3：更新索引
│   └── ...
├── templates/             # 页面模板
└── vlWiki/
    ├── SCHEMA.md          # 架构定义和操作规程
    └── wiki/             # 第二层：结构化知识库（Obsidian Vault）
        ├── index.md       # 多维度索引（主页）
        ├── log.md         # 处理日志
        ├── README.md      # 本文件
        ├── vulnerabilities/  # 漏洞详情页（VL-2026-XXX.md）
        ├── systems/         # 系统页面
        ├── vulnerability-types/ # 漏洞类型页面
        ├── reports/         # 按报告整理的视图
        ├── raw/pdf/         # 原始 PDF 报告
        └── assets/          # 证据图片
```

---

## 页面类型说明

### 1. 漏洞页面（`vulnerabilities/VL-YYYY-NNN.md`）

**用途**：记录单个漏洞的完整信息

**包含章节**：
- 基本信息（编号、系统、类型、等级、状态）
- 原因
- 修复建议
- 受影响实例（自动生成表格）
- 扫描原始数据（报告链接+截图）
- 沟通记录
- 状态追踪
- 相关链接

**交叉引用**：
- 链接到 `[[系统页面]]`
- 链接到 `[[漏洞类型页面]]`
- 链接到 `[[报告页面]]`

### 2. 系统页面（`systems/系统名称.md`）

**用途**：展示特定系统的安全状况

**包含章节**：
- 基本信息（系统名称、建设单位、测试时间、评级）
- 系统描述
- 发现漏洞列表（表格形式）
- 修复进展
- 待处理问题
- 相关报告
- 相关漏洞类型

### 3. 漏洞类型页面（`vulnerability-types/漏洞类型.md`）

**用途**：提供漏洞类型的通用知识

**包含章节**：
- 漏洞定义（引用 OWASP/CWE）
- 形成原因
- 危害等级
- 检测方法
- 修复建议
- 本 Wiki 中相关漏洞（按系统分组）

---

## YAML Frontmatter 字段

### 漏洞页面

```yaml
---
title: "漏洞标题"
date_discovered: "2026-04-16"
last_updated: "2026-04-20"
system: ["系统A", "系统B"]   # 数组，支持多系统
type: "SQL注入"
severity: "高危"              # 高危/中危/低危/信息
status: "待修复"              # 待修复/修复中/已修复/已拒绝
cve: ["CVE-2021-44228"]   # 数组，可选
cvss_score: "10.0"           # 字符串，可选
tags: ["SQL注入", "高危"]
---
```

### 系统页面

```yaml
---
title: "系统名称"
owner: "建设单位"
testing_date: "2026-04-16"
overall_rating: "高危"
testing_agency: "测试单位"
---
```

### 漏洞类型页面

```yaml
---
title: "漏洞类型名称"
owasp: "A03:2021"   # OWASP Top 10 分类，可选
cwe: "CWE-89"          # CWE 编号，可选
---
```

---

## 交叉引用约定

### 格式

- 使用 Obsidian-style `[[wiki链接]]` 格式
- 页面创建后，必须在 `index.md` 中注册
- 相关页面必须**双向链接**

### 示例

```markdown
## 相关链接
- [[全流程工程管理数字化系统]] - 受影响系统
- [[SQL注入]] - 漏洞类型详解
- [[2026-04-16报告]] - 发现此漏洞的原始报告
- [Raw Source](../raw/pdf/2026-04-16-安全报告.pdf) - 原始报告 PDF
```

---

## 维护检查清单

### 每次 Ingest 后

- [ ] 运行 `update_index.py` 更新 `index.md`
- [ ] 检查新页面的交叉引用
- [ ] 运行 `build_type_index.py` 更新漏洞类型页面
- [ ] 运行 `build_system_index.py` 更新系统页面

### 每周 Lint

- [ ] 检查孤立页面（无 inbound links）
- [ ] 检查过期状态（如"待修复"超过 30 天）
- [ ] 检查缺失的交叉引用
- [ ] 检查数据一致性（`index.md` 与实际页面不符）

### 每月审查

- [ ] 审查 CVE 关联准确性
- [ ] 更新漏洞类型页面
- [ ] 备份整个 Wiki 目录

---

## 常见问题

### 查看器无法访问（连接拒绝）

```bash
# 检查服务是否运行
ps aux | grep vlwiki_viewer | grep -v grep

# 如未运行，手动启动
bash /home/sistec/skill/vlWiki/start_viewer.sh

# 查看错误日志
cat /tmp/vlwiki.log
```

### 如何判断两个漏洞是否相同？

1. 对比**漏洞标题**（相似度 > 80%）
2. 对比**影响组件**（URL 或模块路径）
3. 对比**漏洞类型**（SQL 注入、XSS 等）
4. 如以上 3 点都高度相似 → 判定为同一漏洞

### 如何处理同一漏洞影响多个系统？

**不创建新页面**，在原页面操作：
1. 更新 `system:` 字段（添加新系统）
2. 添加**版本历史**（记录新增的系统）
3. 更新 `last_updated:` 字段

---

**最后更新**：2026-06-09
**维护者**：LLM Agent
