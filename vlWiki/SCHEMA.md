# 安全漏洞Wiki - Schema定义

本文档定义安全漏洞Wiki的架构、命名规范、工作流程和维护指南。

---

## 目录结构

Wiki采用三层架构（遵循llm-wiki.md理念）：

```
vlWiki/
├── SCHEMA.md               # 本文件（架构定义）
├── raw/                     # 第一层：Raw sources（原始数据）
│   ├── README.md
│   ├── reports/               # 安全报告PDF
│   ├── scan_data/             # 扫描原始数据（每类1个代表性样本）
│   │   ├── VL-2026-001/          # request.txt, response.txt, vuln_summary.json
│   │   └── ...                   # 按VL编号组织
│   └── cve_cache/           # CVE数据缓存（预留）
└── wiki/                    # 第二层：The wiki（结构化知识库）
    ├── index.md              # 多维度索引
    ├── log.md                # 处理日志
    ├── README.md            # Wiki使用说明
    ├── processing_state.json  # 批次处理状态
    ├── vulnerabilities/       # 漏洞详情页
    ├── systems/              # 目标系统页面
    ├── vulnerability-types/   # 漏洞类型页面
    ├── reports/              # 按报告整理的视图
    ├── assets/               # 证据图片和POC
    ├── scripts/              # 自动化脚本（预留）
    └── templates/            # 页面模板
```

---

## 命名规范

### 漏洞编号格式
- **格式**：`VL-YYYY-NNN`
  - `VL`: Vulnerability的缩写
  - `YYYY`: 发现年份
  - `NNN`: 年度内序号（从001开始）
- **示例**：`VL-2026-001`
- **重要原则**：
  - VL编号**全球唯一**，不按系统重置
  - 同一漏洞影响多个系统 → 在原页面更新`system:`数组
  - 不同系统的同类型漏洞 → 不同VL编号

### 文件命名
- **漏洞页面**：`VL-YYYY-NNN.md`
- **系统页面**：`系统名称.md`（中文）
- **漏洞类型**：`漏洞类型名称.md`（中文）
- **报告页面**：`YYYY-MM-DD.md`

---

## YAML Frontmatter字段定义

### 漏洞页面字段
```yaml
---
title: "漏洞标题"
date_discovered: "2026-04-16"   # ISO 8601格式
last_updated: "2026-04-20"
system: ["系统A", "系统B"]       # 数组，支持多系统
type: "SQL注入"
severity: "高危"                  # 高危/中危/低危/信息
status: "待修复"                  # 待修复/修复中/已修复/已拒绝
cve: ["CVE-2021-44228"]        # 数组，可选
cvss_score: "10.0"               # 字符串，可选
tags: ["SQL注入", "高危", "已拒绝"]
---
```

### 系统页面字段
```yaml
---
title: "系统名称"
owner: "建设单位"
testing_date: "2026-04-16"
overall_rating: "高危"
testing_agency: "测试单位"
---
```

### 漏洞类型页面字段
```yaml
---
title: "漏洞类型名称"
owasp: "A03:2021"   # OWASP Top 10分类，可选
cwe: "CWE-89"          # CWE编号，可选
---
```

---

## 交叉引用约定

### 格式
- 使用Obsidian-style `[[wiki链接]]`格式
- 页面创建后，必须在`index.md`中注册
- 相关页面必须**双向链接**

### 示例
```markdown
## 相关链接
- [[全流程工程管理数字化系统]] - 受影响系统
- [[SQL注入]] - 漏洞类型详解
- [[2026-04-16报告]] - 发现此漏洞的原始报告
```

---

## Ingest工作流程

### 输入
- 新的安全报告PDF

### 处理步骤
1. **复制PDF**到`raw/reports/`
2. **轻量级分析**：提取前10页了解结构（目录、漏洞类型）
3. **分批提取**：每批3-5个漏洞（约20页）
   - 使用`pdf_extract.py`提取文本
   - 对比PyMuPDF和RapidOCR结果
4. **去重检查**：
   - 检查`wiki/index.md`或扫描`wiki/vulnerabilities/*.md`
   - 如不存在 → 创建新漏洞页面
   - 如已存在 → 在原页面添加版本历史，更新`system:`数组
5. **生成Wiki页面**：
   - 创建`wiki/vulnerabilities/VL-YYYY-NNN.md`
   - 提取证据图片到`wiki/assets/screenshots/`
6. **更新状态文件**：
   - 更新`wiki/processing_state.json`（标记批次为"completed"）
   - 更新`wiki/log.md`（记录处理日志）
7. **批次完成后的整合**：
   - 生成/更新`wiki/index.md`（多维度索引）
   - 创建/更新`wiki/systems/*.md`
   - 创建/更新`wiki/vulnerability-types/*.md`

---

## Query工作流程

### 用户提问示例
- "全流程系统有哪些高危漏洞？"
- "建设方拒绝修复的漏洞有哪些？"
- "SQL注入类漏洞的修复建议是什么？"

### 处理步骤
1. 读取`wiki/index.md`找到相关页面
2. 读取相关漏洞页面
3. 综合信息生成回答
4. 如回答有综合价值，可归档为新页面（如对比分析、统计报告）

---

## Lint工作流程

### 定期检查（建议每周）
1. **检查孤立页面**（无inbound links）
2. **检查过期状态**（如"待修复"超过30天）
3. **检查缺失的交叉引用**
4. **检查数据一致性**（如`index.md`与实际页面不符）

---

## 批量处理规范

### 批次定义
- 每批次处理 **3-5个漏洞**（或一个完整章节）
- 或按**页码范围**（每批约20页）
- 避免拆分同一个漏洞（漏洞内容跨页时保持完整）

### 状态文件
- **位置**：`wiki/processing_state.json`
- **用途**：跟踪处理进度，支持断点续传

### 去重规则
1. 标题相似度 > 80% → 疑似同一漏洞
2. 影响组件相同 + 漏洞类型相同 → 疑似同一漏洞
3. 确认重复后 → 在原页面添加版本历史

### 增量更新
- 新报告中的同一漏洞 → **不创建新页面**
- 在原页面添加**版本历史**
- 更新`last_updated:`字段
- 如影响系统新增 → 更新`system:`数组

---

## CVE数据库对接规范（预留）

### 字段定义
- `cve`: 字符串或数组，存储关联的CVE编号
- `cvss_score`: 字符串或数字，CVSS评分
- `cve_verified`: 布尔值，是否经过人工验证

### 自动匹配流程（后续实现）
1. Ingest时：从漏洞标题/描述提取关键词
2. 查询NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`)
3. 取置信度最高的前3个结果
4. 自动选择或标记`needs_cve_review: true`

### 手动关联
在漏洞页面YAML中直接指定：
```yaml
cve:
  - CVE-2021-44228
  - CVE-2021-45046
cve_verified: true
```

### 缓存机制（后续实现）
- CVE查询结果缓存到`raw/cve_cache/CVE-YYYY-NNNN.json`
- 缓存有效期：30天
- 避免重复查询API

### 前置条件（后续准备）
1. 申请NVD API Key（免费）：https://nvd.nist.gov/developers/request-an-api-key
2. 配置API Key（环境变量或配置文件）
3. 安装依赖：`pip install requests`

---

## 后续扩展指南

### 添加新维度（示例）

#### 维度1：CVE数据库对接
- 在`raw/`中添加CVE JSON导出
- 在`wiki/vulnerability-types/`中关联CVE
- 在漏洞页面中添加cve字段

#### 维度2：漏洞扫描器输出
- 支持Nessus、OpenVAS、AWVS等扫描报告
- Ingest流程中增加"扫描器发现"来源标记
- 增加"人工验证状态"字段

#### 维度3：合规要求映射
- 创建`wiki/compliance/`目录
- 映射等保2.0、GDPR、PCI-DSS等要求
- 在漏洞页面中增加合规风险字段

---

## 维护检查清单

### 每次Ingest后
- [ ] 更新`processing_state.json`
- [ ] 更新`log.md`
- [ ] 检查新页面的交叉引用

### 每周Lint
- [ ] 检查孤立页面
- [ ] 检查过期状态
- [ ] 验证索引一致性

### 每月审查
- [ ] 审查CVEL关联准确性
- [ ] 更新漏洞类型页面
- [ ] 备份整个Wiki目录

---

**最后更新**：2026-05-09
**维护者**：LLM Agent
