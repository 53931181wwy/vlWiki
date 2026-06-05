# 自动化脚本目录

本目录存储用于自动化处理的Python脚本（后续实现）。

---

## 目录结构

```
scripts/
├── README.md              # 本文件
├── cve_lookup.py         # CVE查询脚本（待开发）
├── cve_sync.py          # CVE批量同步脚本（待开发）
└── __init__.py           # Python包初始化
```

---

## 脚本功能说明

### 1. cve_lookup.py（待开发）

**功能**：查询NVD CVE数据库

**输入**：
- 关键词（软件名、漏洞类型）
- 或CVE编号

**输出**：
- CVE列表（含CVSS评分、描述、参考链接）

**依赖**：
- `requests`库
- NVD API Key（可选，但有Key可提高查询限制）

**使用示例**：
```bash
python cve_lookup.py --keyword "Apache Log4j2"
python cve_lookup.py --cve "CVE-2021-44228"
```

---

### 2. cve_sync.py（待开发）

**功能**：批量同步CVE信息到漏洞页面

**操作**：
1. 扫描`wiki/vulnerabilities/*.md`
2. 对`cve`字段为空的页面，尝试自动匹配
3. 更新匹配成功的页面

**依赖**：
- `frontmatter`库（用于解析Markdown的YAML frontmatter）
- `requests`库

**使用示例**：
```bash
python cve_sync.py
```

---

### 3. batch_process.py（待开发，可选）

**功能**：按批次处理PDF报告

**操作**：
1. 读取`wiki/processing_state.json`
2. 按批次提取PDF内容
3. 生成/更新漏洞页面
4. 更新处理状态

**依赖**：
- `pdf_extract.py`（来自document-reader技能）
- `frontmatter`库

**使用示例**：
```bash
python batch_process.py --pdf "raw/reports/2026-04-16-安全报告.pdf" --batch 1
```

---

## 前置条件（后续准备）

### 1. 申请NVD API Key（免费）
- **网址**：https://nvd.nist.gov/developers/request-an-api-key
- **限制**：
  - 有API Key：每分钟100次查询
  - 无API Key：每分钟5次查询

### 2. 配置API Key
- **环境变量**（推荐）：
  ```bash
  # Linux/Mac
  export NVD_API_KEY="your-api-key-here"
  
  # Windows PowerShell
  $env:NVD_API_KEY = "your-api-key-here"
  ```

- **配置文件**（不推荐）：
  在`config.py`中硬编码（易被泄露）

### 3. 安装依赖
```bash
pip install requests
pip install python-frontmatter
```

---

## 开发状态

| 脚本名称 | 状态 | 优先级 | 预计开发时间 |
|---------|------|---------|------------|
| `cve_lookup.py` | ❌ 待开发 | 高 | 2小时 |
| `cve_sync.py` | ❌ 待开发 | 高 | 3小时 |
| `batch_process.py` | ❌ 待开发 | 中 | 4小时 |

---

## 使用流程

### 场景1：手动关联CVE
1. 在漏洞页面的YAML中添加：
   ```yaml
   cve:
     - CVE-2021-44228
     - CVE-2021-45046
   cve_verified: true
   ```
2. 手动添加CVE详情链接到"相关链接"章节

### 场景2：自动关联CVE（后续实现）
1. 运行`cve_sync.py`
2. 脚本自动为`cve`字段为空的页面匹配CVE
3. 检查匹配结果（在`wiki/log.md`中查看日志）
4. 对置信度低的匹配，手动审核

### 场景3：批量处理PDF（后续实现）
1. 更新`wiki/processing_state.json`（定义批次）
2. 运行`batch_process.py`
3. 脚本按批次提取PDF并生成页面
4. 出错时只需重处理单个批次

---

## 注意事项

1. **API Key安全**：
   - 不要将API Key提交到Git仓库
   - 使用环境变量或`.env`文件（添加到`.gitignore`）

2. **查询限制**：
   - 无API Key：每分钟最多5次查询
   - 有API Key：每分钟最多100次查询
   - 建议：批量查询时添加延迟（`time.sleep(1)`）

3. **缓存机制**（后续实现）：
   - CVE查询结果缓存到`raw/cve_cache/CVE-YYYY-NNNN.json`
   - 缓存有效期：30天
   - 避免重复查询API

---

**最后更新**：2026-05-09
**维护者**：LLM Agent
