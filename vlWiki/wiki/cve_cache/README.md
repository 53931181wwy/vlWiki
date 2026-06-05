# CVE 数据缓存

本目录存储从NVD API获取的CVE数据（JSON格式），用于后续快速查询和离线分析。

---

## 目录结构

```
cve_cache/
├── README.md               # 本文件
├── CVE-2021-44228.json  # CVE数据文件
├── CVE-2021-45046.json
└── ...
```

---

## 文件格式

### 命名规则
- 文件名：`CVE-YYYY-NNNN.json`
- 必须大写"CVSS"
- 必须包含横杠"-"
- 必须包含年份和编号

### 内容格式
```json
{
  "cve_id": "CVE-2021-44228",
  "source_identifier": "cve@mitre.org",
  "published": "2021-12-10T10:15:30.307",
  "last_modified": "2023-07-19T16:53:42.893",
  "status": "Analyzed",
  "description": "...",
  "metrics": {
    "cvssMetricV31": [
      {
        "cvssData": {
          "version": "3.1",
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "baseScore": 10.0,
          "baseSeverity": "CRITICAL"
        }
      }
    ]
  },
  "weaknesses": [
    {
      "source": "nvd@nist.gov",
      "type": "Primary",
      "description": {
        "lang": "en",
        "value": "CWE-917"
      }
    }
  ],
  "references": [
    {
      "url": "https://lists.apache.org/thread/6mbhfpj816d9px80p8ooyr8n8rj13os",
      "source": "MLIST",
      "tags": ["Mailing List", "Patch"]
    }
  ],
  "cached_at": "2026-05-09T20:50:00",
  "cache_expires_at": "2026-06-08T20:50:00"
}
```

---

## 缓存策略

### 有效期
- **默认有效期**：30天
- **过期后**：自动重新从NVD API获取
- **强制刷新**：删除JSON文件，下次查询时自动重新获取

### 更新频率
- **建议**：每周运行一次`wiki/scripts/cve_sync.py`
- **自动清理**：超过90天的缓存文件可安全删除

---

## 使用场景

### 场景1：自动关联CVE
- **触发**：Ingest新漏洞时
- **操作**：从漏洞标题/描述提取关键词 → 查询`cve_cache/`目录
- **如命中**：直接读取JSON，无需调用API
- **如未命中**：调用NVD API，获取后存入`cve_cache/`

### 场景2：离线分析
- **用途**：无网络环境下分析CVE数据
- **操作**：直接读取`cve_cache/CVE-YYYY-NNNN.json`
- **注意**：数据可能过期，需定期联网更新

---

## 维护指南

### 定期检查（建议每月）
1. **检查过期文件**：
   ```bash
   # Linux/Mac
   find cve_cache/ -name "*.json" -mtime +30 -type f
   
   # Windows PowerShell
   Get-ChildItem cve_cache\*.json | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
   ```

2. **清理过期文件**：
   ```bash
   # 删除超过90天的缓存
   find cve_cache/ -name "*.json" -mtime +90 -type f -delete
   ```

3. **重建缓存**：
   - 删除所有JSON文件
   - 运行`wiki/scripts/cve_sync.py`

---

## 前置条件（后续实现）

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
  在`wiki/scripts/config.py`中硬编码（易被泄露）

### 3. 安装依赖
```bash
pip install requests
```

---

## 后续实现步骤

### 步骤1：创建CVEC查询脚本
- **文件**：`wiki/scripts/cve_lookup.py`
- **功能**：
  - 输入：关键词（软件名、漏洞类型）
  - 输出：CVE列表（含CVSS评分、描述、参考链接）

### 步骤2：创建CVE批量同步脚本
- **文件**：`wiki/scripts/cve_sync.py`
- **功能**：
  - 扫描`wiki/vulnerabilities/*.md`
  - 对`cve`字段为空的页面，尝试自动匹配
  - 更新匹配成功的页面

### 步骤3：更新SCHEMA.md
- 增加"CVEC数据库对接规范"章节
- 定义`cve:`字段的使用规范
- 定义缓存更新策略

---

**最后更新**：2026-05-09
**维护者**：LLM Agent
