---
name: vlWiki
description: 漏洞知识库管理技能，用于导入漏扫报告、生成漏洞页面、维护vlWiki系统。支持AppScan报告（后续将支持Nessus、OpenVAS、AWVS等）。当用户提到"vlWiki"、"漏洞知识库"、"导入漏扫报告"、"生成漏洞页面"、"修复系统信息"、"更新vlWiki索引"时触发。
---

## 功能概述

本技能用于管理安全漏洞知识库（vlWiki），支持：
1. **导入漏扫报告**：解析AppScan等报告，提取漏洞实例，生成标准化vlWiki页面
2. **修复系统信息**：批量修复VL页面中系统信息不一致的问题
3. **更新索引**：按多维度（类型、系统、状态、日期、漏洞大类）更新索引
4. **扩展支持**（后续）：主机漏洞、渗透测试漏洞、多报告格式

---

## 依赖关系

### 与 document-reader 的关系
- **document-reader**：底层通用文档提取技能（PDF/DOCX文字层+OCR双方案、智能分批）
- **vlWiki**：上层专用漏洞处理技能（解析报告结构、提取漏洞实例、生成页面）
- **集成方式**：vlWiki 调用 document-reader 的 `batch_process.py` 获取提取文本

---

## 使用方法

### 1. 导入AppScan报告
```bash
python <skill_dir>/scripts/import_report.py "<pdf_path>" --type appscan
```

**示例**：
```bash
python C:/Users/stc/.workbuddy/skills/vlWiki/scripts/import_report.py "D:/Users/个人项目/wb/vlWiki/raw/reports/qukuailian1.pdf" --type appscan
```

**功能**：
1. 调用 document-reader 提取PDF文本（智能分批）
2. 解析AppScan报告结构（漏洞类型、实例、严重性、系统信息）
3. 生成/更新vlWiki页面（Markdown + YAML frontmatter）
4. 更新索引文件（index.md）和处理日志（log.md）

**参数**：
- `--type`：报告类型（当前仅支持 `appscan`，后续将支持 `nessus`、`openvas`、`awvs`）
- `--skip-low`：跳过低危漏洞（默认：True）
- `--output-dir`：vlWiki目录路径（默认：自动检测）

### 2. 修复系统信息不一致
```bash
python <skill_dir>/scripts/fix_system_info.py --dir "<vulnerabilities_dir>"
```

**示例**：
```bash
python C:/Users/stc/.workbuddy/skills/vlWiki/scripts/fix_system_info.py --dir "D:/Users/个人项目/wb/vlWiki/wiki/vulnerabilities"
```

**功能**：
1. 扫描所有VL页面
2. 对比YAML frontmatter的`system:`字段与正文中的`**影响系统**:`字段
3. 修复不一致（以YAML为准）
4. 支持漏洞大类字段的修复

**参数**：
- `--dir`：VL页面目录路径
- `--dry-run`：仅显示将要修改的内容，不实际修改
- `--category`：修复漏洞大类字段（可选）

### 3. 更新vlWiki索引
```bash
python <skill_dir>/scripts/update_index.py --wiki-dir "<wiki_dir>"
```

**示例**：
```bash
python C:/Users/stc/.workbuddy/skills/vlWiki/scripts/update_index.py --wiki-dir "D:/Users/个人项目/wb/vlWiki/wiki"
```

**功能**：
1. 扫描 `vulnerabilities/` 目录
2. 解析每个页面的YAML frontmatter
3. 按多维度更新 `index.md`：
   - 按漏洞类型索引（按等级排列）
   - 按漏洞大类索引（应用系统漏洞、主机漏洞、渗透测试漏洞）
   - 按系统索引
   - 按状态索引
   - 按发现日期索引
4. 更新统计信息
5. 更新 `log.md`

**参数**：
- `--wiki-dir`：vlWiki的wiki目录路径
- `--skip-log`：跳过更新log.md（默认：False）

---

## 漏洞大类扩展

### 现有漏洞大类
- **应用系统漏洞**（默认）：Web应用、API等应用层漏洞

### 新增漏洞大类（计划中）
- **主机漏洞**：操作系统、数据库、中间件等主机层漏洞（来自Nessus、OpenVAS等主机漏扫）
- **渗透测试漏洞**：人工渗透测试发现的漏洞

### 对现有系统的影响
1. **模板扩展**：`templates/vulnerability.md` 添加 `vulnerability_category:` 字段
2. **索引扩展**：`index.md` 添加"按漏洞大类索引" section
3. **批量更新**：所有现有VL页面需要添加 `vulnerability_category: "应用系统漏洞"` 字段

---

## 多报告格式支持（后续实现）

### 支持的报告格式
1. **AppScan**（已实现）：IBM Security AppScan，PDF格式
2. **Nessus**（计划中）：Tenable Nessus，通常是XML或CSV格式
3. **OpenVAS**（计划中）：OpenVAS，XML格式
4. **AWVS**（计划中）：Acunetix Web Vulnerability Scanner，JSON或XML格式

### 解析器设计模式
使用**策略模式**设计解析器：
```python
# scripts/parsers/__init__.py
from .appscan_parser import AppScanParser
# from .nessus_parser import NessusParser  # 后续实现

PARSER_MAP = {
    'appscan': AppScanParser,
    # 'nessus': NessusParser,
}

def get_parser(report_type):
    parser_class = PARSER_MAP.get(report_type)
    if not parser_class:
        raise ValueError(f"不支持的报告类型: {report_type}")
    return parser_class()
```

---

## 安装依赖

### 必需依赖
```bash
pip install pymupdf rapidocr-onnxruntime numpy  # document-reader依赖
pip install python-docx olefile                      # DOCX/DOC处理
pip install pyyaml frontmatter                      # YAML frontmatter处理
```

### 可选依赖（后续实现）
```bash
pip install lxml requests  # XML解析和API请求（Nessus等）
```

---

## 常见问题

### 1. 报错："document-reader skill not found"
**原因**：vlWiki依赖document-reader skill，但未安装或路径错误
**解决**：
1. 确保document-reader skill已安装：检查 `C:\Users\stc\.workbuddy\skills\document-reader` 目录是否存在
2. 如不存在，先安装document-reader skill

### 2. 报错："No module named 'frontmatter'"
**原因**：缺少frontmatter库
**解决**：`pip install python-frontmatter`

### 3. 如何添加新的报告格式支持？
**步骤**：
1. 研究报告格式（获取样本、分析结构）
2. 在 `scripts/parsers/` 目录下创建新的解析器（如 `nessus_parser.py`）
3. 实现 `parse()` 方法，返回标准化的漏洞实例列表
4. 在 `scripts/parsers/__init__.py` 中注册新解析器
5. 更新 `SKILL.md` 中的使用示例

---

## 后续开发计划

### 高优先级（必须先完成）
1. 创建技能结构 + 编写SKILL.md（当前步骤）
2. 重构AppScan解析器（基于现有`parse_appscan_fixed_v3.py`）
3. 实现 `import_report.py`（主入口）
4. 修复现有VL页面（添加 `vulnerability_category` 字段）

### 中优先级（核心功能）
5. 实现 `fix_system_info.py`（优化版）
6. 实现 `update_index.py`
7. 集成测试

### 低优先级（扩展功能）
8. 研究并实现Nessus解析器
9. 研究并实现OpenVAS解析器
10. 研究并实现AWVS解析器
11. 部署与文档完善

---

**最后更新**：2026-05-18
**维护者**：LLM Agent
**版本**：1.0.0
