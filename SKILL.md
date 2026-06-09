---
name: vlWiki
description: 漏洞知识库管理技能，用于导入漏扫报告、生成漏洞页面、维护vlWiki系统。支持AppScan报告。当用户提到"vlWiki"、"漏洞知识库"、"导入漏扫报告"、"生成漏洞页面"、"更新vlWiki索引"时触发。
---

## 功能概述

| 功能 | 说明 | 对应脚本 |
|------|------|----------|
| 一键流程 | PDF 报告 → VL 页面（阶段1+2 串联） | `report2wiki.py` |
| 阶段1：报告→JSON | AppScan PDF → 标准中间 JSON | `appscanpdf2json.py` |
| 阶段2：JSON→实体 | 中间 JSON → VL 页面 `.md` + 系统页面 | `json2wiki.py` |
| 阶段3：索引/链接 | 重建 `index.md` + 自动轮转 `log.md` | `update_index.py` |
| 修复系统信息 | 批量修复 frontmatter 与正文不一致的 system/vul_category | `fix_system_info.py` |
| 查询漏洞 | 按等级/状态/系统/类型/CVE/日期过滤，终端表格或 MD 输出 | `query.py` |
| 本地查看器 | 纯标准库 Python HTTP 查看器，支持 `[[wiki链接]]` 导航 | `vlwiki_viewer.py` |
| 构建类型索引 | 从已有漏洞页面自动生成/更新漏洞类型页面 | `build_type_index.py` |
| 构建系统索引 | 从已有漏洞页面自动生成/更新系统页面 | `build_system_index.py` |

---

## 目录结构

| 目录 | 路径 | 说明 |
|------|------|------|
| Skill 代码目录 | `/home/sistec/skill/vlWiki` | 脚本和模板存放处 |
| 知识库目录 | `/home/sistec/skill/vlWiki/vlWiki/wiki` | Obsidian Vault，漏洞页面和索引 Markdown |
| 原始报告目录 | `/home/sistec/skill/vlWiki/vlWiki/wiki/raw/pdf/` | 导入的原始 PDF 报告 |
| 查看器 | `/home/sistec/skill/vlWiki/vlwiki_viewer.py` | 纯 Python 标准库 HTTP 查看器 |

三者中 Skill 代码目录和知识库目录同属 `vlWiki` 下，脚本处理完后输出到知识库目录。

---

## 脚本结构

```
vlWiki/
├── SKILL.md                  # 本文件（技能说明文档）
├── vlwiki_viewer.py          # 独立 Python 查看器（纯标准库）
├── start_viewer.sh           # 查看器启动脚本
├── codebuddy.md             # CodeBuddy 配置
├── scripts/
│   ├── appscanpdf2json.py   # 阶段1：AppScan PDF → 标准中间 JSON（直接调用 PyMuPDF）
│   ├── report2wiki.py       # 一键流程：PDF → VL 页面（内部调用阶段1+2）
│   ├── json2wiki.py         # 阶段2：中间 JSON → VL 页面 .md
│   ├── update_index.py      # 阶段3：独立索引更新（index.md + log.md）
│   ├── build_type_index.py  # 从漏洞页面自动生成漏洞类型页面
│   ├── build_system_index.py # 从漏洞页面自动生成系统页面
│   ├── vl_exporter.py       # VL 页面导出核心模块（被 json2wiki 调用）
│   ├── fix_system_info.py   # 批量修复系统信息/漏洞大类字段
│   ├── query.py             # 漏洞查询：按多条件过滤 + 终端/Markdown 输出
│   ├── utils.py             # 工具函数：frontmatter 解析、VL 编号、格式清理
│   └── parsers/
│       ├── __init__.py           # 解析器工厂（PARSER_MAP）
│       └── appscan_pdf_parser.py # AppScan PDF 报告解析器
├── templates/
│   ├── vulnerability.md     # VL 页面模板
│   ├── vulnerability-type.md # 漏洞类型页面模板
│   └── system.md           # 系统页面模板
└── vlWiki/
    ├── SCHEMA.md            # 知识库 Schema 定义
    └── wiki/               # Obsidian Vault（知识库）
        ├── index.md         # 多维度索引（主页）
        ├── log.md           # 处理日志
        ├── README.md        # Wiki 使用指南
        ├── vulnerabilities/  # 漏洞详情页（VL-2026-XXX.md）
        ├── systems/         # 系统页面
        ├── vulnerability-types/ # 漏洞类型页面
        ├── reports/         # 按报告整理的视图
        └── raw/pdf/         # 原始 PDF 报告
```

---

## 查看方式

### 方式一：vlwiki_viewer（推荐，纯 Python 标准库）

自带查看器，无需安装任何依赖，适合快速浏览。

```bash
# 启动查看器
bash /home/sistec/skill/vlWiki/start_viewer.sh

# 或手动启动
cd /home/sistec/skill/vlWiki
python3 vlwiki_viewer.py
```

- 访问地址：<http://localhost:8080>
- 功能：Markdown 渲染、[[wiki链接]]导航、YAML frontmatter 展示、侧边栏导航
- 开机自启：已通过 `@reboot` crontab 配置，重启后自动运行
- 日志：`/tmp/vlwiki.log`

### 方式二：VS Code + Foam 插件（完整功能）

适合需要编辑 wiki 链接、全文搜索的场景。

```bash
# 启动 VS Code，打开知识库目录
code /home/sistec/skill/vlWiki/vlWiki/wiki
```

- 安装插件：`foam.foam-vscode`
- VS Code 已安装至 `/opt/vscode/bin/code`（ARM64 Kylin Linux 适配版 1.75.0）

---

## 工作流

```
report2wiki (一键)        appscanpdf2json (阶段1)    json2wiki (阶段2)        update_index (阶段3)
─────────────────        ────────────────────      ─────────────────       ────────────────────
PDF 报告 → VL 页面        AppScan PDF → 中间 JSON   中间 JSON → 知识库实体    知识库实体 → 索引/链接
    ↓                         ↓                         ↓
appscanpdf2json         fulltxt.txt (调试用)       vl_exporter.py           index.md + log.md
  + json2wiki
```

三个阶段**完全独立**，可单独调试或重跑任一阶段：

| 阶段 | 脚本 | 输入 | 输出 |
|------|------|------|------|
| 一键流程 | `report2wiki` | AppScan PDF | VL页面 + JSON |
| 阶段1 | `appscanpdf2json` | AppScan PDF | `wiki/raw/{name}_{time}.json` |
| 阶段2 | `json2wiki` | 标准中间 JSON | `wiki/vulnerabilities/VL-*.md` |
| 阶段3 | `update_index` | `vulnerabilities/` 目录 | `wiki/index.md`, `wiki/log.md` |

---

## 使用方法

### 1. 一键流程：PDF → VL 页面（推荐）

内部串联阶段1+2，一条命令完成：

```bash
python3 scripts/report2wiki.py "<报告.pdf>" [--no-skip-low] [--vl-start <n>]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `<file_path>` | （必填） | AppScan PDF 报告路径 |
| `--skip-low` | `True` | 跳过低危漏洞 |
| `--no-skip-low` | — | 包含低危漏洞 |
| `--vl-start` | 自动递增 | VL 起始编号 |

### 2. 阶段1：AppScan PDF → 中间 JSON

```bash
python3 scripts/appscanpdf2json.py "<报告.pdf>" [--no-skip-low] [--output-dir <dir>]
```

**执行流程**：使用 PyMuPDF（`fitz`）直接提取 PDF 文本，按视觉顺序排序文字块 → AppScan 解析器 → 输出标准 JSON 到 `wiki/raw/`
额外输出 `_fulltxt.txt` 到报告同目录，便于调试原始提取文本。

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `<file_path>` | （必填） | AppScan PDF 报告路径 |
| `--skip-low` | `True` | 跳过低危/信息/提示级别 |
| `--no-skip-low` | — | 包含低危漏洞 |
| `--output-dir` | `wiki/raw/` | JSON 输出目录 |

> **注意**：PDF 文字顺序问题已修复。使用 PyMuPDF 直接提取，按 `(round(y,0), x)` 排序文字块，确保与视觉阅读顺序一致。

### 3. 阶段2：中间 JSON → 知识库实体

```bash
python3 scripts/json2wiki.py "<json路径>" [--vl-start <n>]
```

**执行流程**：读取 JSON → 调用 `vl_exporter` 生成每个 VL 页面（含截图、表格、YAML frontmatter）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `<json_path>` | （必填） | 阶段1 生成的标准中间 JSON |
| `--output-dir` | 自动检测 | VL 页面输出目录 |
| `--wiki-dir` | 自动检测 | wiki 根目录（截图/报告路径计算用） |
| `--vl-start` | 自动递增 | VL 起始编号（如 `25` → `VL-2026-025`） |

**自动检测的默认路径**：
- `output_dir`：`vlWiki/vlWiki/wiki/vulnerabilities`（基于 Skill 目录自动检测）
- `wiki_dir`：`vlWiki/vlWiki/wiki`（基于 Skill 目录自动检测）

### 4. 阶段3：更新索引

```bash
python3 scripts/update_index.py [--vuln-dir "<目录>"] [--output "<输出>"] [--skip-log]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--vuln-dir` | 自动检测 | VL 页面目录 |
| `--output` | `<wiki_dir>/index.md` | 索引输出路径 |
| `--skip-log` | `False` | 跳过 log.md 更新 |

**生成内容**：
- `index.md` — 六维索引（类型按等级/漏洞大类/系统/状态/日期/统计）
- `log.md` — 本次更新记录，超 800 行自动轮转保留最近 500 行

### 5. 构建漏洞类型和系统索引

```bash
# 从已有漏洞页面自动生成/更新漏洞类型页面
python3 scripts/build_type_index.py

# 从已有漏洞页面自动生成/更新系统页面
python3 scripts/build_system_index.py
```

### 6. 分步完整流程

```bash
# 三步串联（适合需要中间 JSON 调试的场景）
JSON_FILE=$(python3 scripts/appscanpdf2json.py "报告.pdf" | tail -1)
python3 scripts/json2wiki.py "$JSON_FILE"
python3 scripts/update_index.py
```

### 7. 修复系统信息

```bash
# 批量修复目录下所有 VL 页面
python3 scripts/fix_system_info.py --dir "<vuln_dir>" [--dry-run] [--fix-category]

# 修复单个文件
python3 scripts/fix_system_info.py --file "<VL页面>" [--dry-run] [--fix-category]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--dir` | — | 批量处理目录（与 `--file` 二选一） |
| `--file` | — | 单个文件路径 |
| `--dry-run` | `False` | 仅预览不写入 |
| `--fix-category` | `False` | 同时修复漏洞大类字段 |
| `--category` | `应用系统漏洞` | 指定漏洞大类 |

### 8. 查询漏洞

```bash
python3 scripts/query.py [过滤条件] [--output <路径>]
```

| 参数 | 说明 | 示例 |
|------|------|------|
| `--severity, -s` | 等级过滤（精确匹配） | `紧急` `高` `中` `低` |
| `--status` | 状态过滤（精确匹配） | `待修复` `修复中` `已修复` `已拒绝` |
| `--system` | 系统名模糊匹配 | `"前海"` |
| `--type` | 漏洞类型模糊匹配 | `"注入"` `"XSS"` |
| `--cve` | CVE 编号匹配 | `CVE-2024-1234` |
| `--cve-has` | 仅列出有 CVE 的漏洞 | （无值） |
| `--date-after` | 发现日期之后 | `2026-05-01` |
| `--date-before` | 发现日期之前 | `2026-05-01` |
| `--output, -o` | 输出到 Markdown 文件 | `wiki/query-result.md` |
| `--dir` | VL 页面目录 | 默认自动检测 |

**用法示例**：

```bash
# 终端表格输出
python3 scripts/query.py --severity 紧急 --status 待修复
python3 scripts/query.py --system "前海" --date-after 2026-05-01
python3 scripts/query.py --type "XSS" --cve-has

# 生成 Obsidian 可点击的 Markdown 报告
python3 scripts/query.py --severity 高 --output wiki/query-result.md
```

多种过滤条件之间为 **AND** 关系。默认按等级（紧急→高→中→低）排序。

---

## 依赖

| 依赖 | 用途 | 必需要求 |
|------|------|----------|
| `pymupdf`（PyMuPDF）| PDF 文本提取（阶段1 直接使用，不再依赖 document-reader） | **必需** |
| `Pillow` | 截图裁剪 | 可选 |
| `python3` 标准库 | `vlwiki_viewer.py` 查看器（http.server、html、urllib.parse 等） | 可选 |
| `utils.py` | 自实现 YAML frontmatter 解析（无外部库依赖） | 内部依赖 |

安装依赖：
```bash
pip3 install pymupdf pillow
```

---

## 中间 JSON Schema

阶段1 输出的标准 JSON 结构：

```json
{
  "meta": {
    "source_file": "报告.pdf",
    "source_path": "/abs/path/to/报告.pdf",
    "parser": "appscan_pdf",
    "parse_date": "2026-05-26T16:00:00",
    "total_instances": 10,
    "vulnerability_types": 3,
    "system": "系统名",
    "vul_category": "应用系统漏洞"
  },
  "types": [
    {
      "type": "跨站脚本",
      "title": "跨站脚本 (3个实例)",
      "severity": "高危",
      "instance_count": 3,
      "cvss_score": "7.5",
      "cve": ["CVE-2024-xxx"],
      "cwe": ["79"],
      "cause": "未过滤用户输入",
      "revision": "输出编码",
      "description": "...",
      "risk": "...",
      "affected_products": "...",
      "references": "...",
      "instances": [
        {"index": 1, "url": ["http://..."], "start_page": 10},
        {"index": 2, "url": ["http://..."], "start_page": 12}
      ]
    }
  ]
}
```

---

## VL 页面格式

每页 MD 文件由 YAML frontmatter 和 Markdown 正文组成，模板见 `templates/vulnerability.md`。

**frontmatter 字段**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `title` | str | 漏洞标题 |
| `severity` | str | 严重性：紧急/高危/中危/低危 |
| `cvss_score` | str | CVSS 评分 |
| `date_discovered` | str | 发现日期 `YYYY-MM-DD` |
| `type` | str | 漏洞类型名 |
| `status` | str | 待修复/修复中/已修复/已拒绝 |
| `cve` | list/null | CVE 编号列表 |
| `cwe` | list/null | CWE 编号列表 |
| `tags` | list | 标签（类型名 + CVE） |
| `system` | list | 受影响系统（至少 1 个） |
| `vul_category` | str | 漏洞大类（应用系统漏洞/主机漏洞/渗透测试漏洞） |

**正文固定章节**：原因 → 修复建议 → 受影响实例（自生成表格）→ 扫描原始数据（报告链接+截图）→ 沟通记录 → 状态追踪 → 相关链接

---

## vlwiki_viewer 查看器说明

纯 Python 标准库实现的轻量级 wiki 查看器，无需安装任何第三方依赖。

### 功能特性

- 纯标准库（http.server + socketserver），Python 3.6+ 可直接运行
- Markdown → HTML 实时转换（支持标题、表格、代码块、列表、引用、分隔线、图片）
- `[[wiki链接]]` → 自动转换为可点击的 HTML 链接，支持跨页面导航
- YAML frontmatter 解析，在页面顶部以卡片样式展示元数据
- 侧边栏导航，自动扫描 `vulnerabilities/`、`systems/`、`vulnerability-types/`、`reports/` 目录
- 暗色主题（类 Obsidian 风格）
- 支持中文 URL（百分号编码自动解码）
- 多线程处理（ThreadingMixIn），支持并发访问

### 启动和停止

```bash
# 启动（使用启动脚本，自动处理进程冲突）
bash /home/sistec/skill/vlWiki/start_viewer.sh

# 手动启动
cd /home/sistec/skill/vlWiki
python3 vlwiki_viewer.py
# 访问 http://localhost:8080

# 停止
pkill -f "vlwiki_viewer.py"
```

### 开机自启

已通过 crontab `@reboot` 配置，重启后自动启动：

```bash
# 查看当前 crontab
crontab -l
# 输出：@reboot nohup python3 /home/sistec/skill/vlWiki/vlwiki_viewer.py > /tmp/vlwiki.log 2>&1 &
```

### 日志和排错

```bash
# 查看服务状态
ps aux | grep vlwiki_viewer | grep -v grep

# 查看日志
cat /tmp/vlwiki.log

# 测试访问
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/
```

---

## 添加新报告格式

1. 在 `scripts/parsers/` 下创建新解析器，命名遵循 `{tool}_{format}_parser.py`
2. 实现 `parse(text: str, pdf_path: str | None) → dict` 方法
3. 在 `parsers/__init__.py` 的 `PARSER_MAP` 中注册
4. 新建专用入口脚本（参考 `appscanpdf2json.py`），或复用 `report2wiki.py` 添加新分支

**当前支持格式**：

| 工具 | PDF |
|------|-----|
| AppScan | ✅ |

---

## 常见问题

### PyMuPDF 未安装
```bash
pip3 install pymupdf
```

### 中间 JSON 找不到原始报告（截图无法生成）
`json2wiki.py` 会先尝试 `meta.source_path` 记录的绝对路径，再回退到 `wiki/raw/` 目录查找。确保 PDF 原始报告在阶段2 运行时仍可访问。

### 索引未自动更新
三个阶段完全独立，报告导入后需手动运行 `update_index.py` 更新索引。

### 查看器页面空白
1. 检查服务是否运行：`ps aux | grep vlwiki_viewer`
2. 检查日志：`cat /tmp/vlwiki.log`
3. 重启服务：`bash /home/sistec/skill/vlWiki/start_viewer.sh`

### 中文 URL 访问 400 错误
已修复。`vlwiki_viewer.py` 已添加 `urllib.parse.unquote()` 解码，支持中文路径访问。

---

**版本**：3.2.0 | **最后更新**：2026-06-09
