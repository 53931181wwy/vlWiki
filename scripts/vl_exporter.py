"""
vlWiki Skill - VL 页面导出模块
功能：
1. 生成"受影响实例"表格
2. 查找已有截图
3. PDF 页面截图
4. 生成标准化漏洞页面（Markdown + YAML frontmatter）
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# 添加 vlWiki scripts 目录到路径（支持脚本内独立运行）
skill_dir = Path(__file__).parent.parent
sys.path.insert(0, str(skill_dir))

from utils import escape_yaml_string


def generate_instances_section(instances: List[Dict], vuln_type: Dict = None) -> str:
    """
    生成"受影响实例"章节的Markdown内容（表格形式）
    
    Args:
        instances: 漏洞实例列表
        vuln_type: 漏洞类型信息（可选），用于回退读取被提升到types层级的字段
    
    Returns:
        格式化的Markdown字符串
    
    结构：
      类型通用信息（严重性/CVSS/CVE/原因/修订建议）→ 表格（index + url）
    """
    if not instances:
        return ""
    
    section = "## 受影响实例\n\n"
    
    # ===== 第一部分：类型层级的通用信息（已提升的字段） =====
    if vuln_type:
        # types层级的CVE（所有实例共有的CVE）
        type_cves = vuln_type.get('cve', [])
        if type_cves and isinstance(type_cves, list) and len(type_cves) > 0:
            section += f"- **CVE**: {', '.join(type_cves)}\n"
    
    section += "\n"
    
    # ===== 第二部分：检测是否需要实例级别的额外列 =====
    # 检查是否有实例保留了cvss_score/cve/cause/revision字段（未被提升的情况）
    has_instance_cve = False
    has_instance_cvss = False
    for instance in instances:
        if instance.get('cve') and isinstance(instance.get('cve'), list) and len(instance['cve']) > 0:
            has_instance_cve = True
        if instance.get('cvss_score'):
            has_instance_cvss = True
    
    # ===== 第三部分：构建表格 =====
    # 决定表格列
    headers = ["#", "URL"]
    if has_instance_cve:
        headers.append("CVE")
    if has_instance_cvss:
        headers.append("CVSS")
    
    # 表头
    section += "| " + " | ".join(headers) + " |\n"
    section += "|" + "|".join(["---"] * len(headers)) + "|\n"
    
    # 表体：逐行填充实例数据
    for i, instance in enumerate(instances, 1):
        row = [str(i)]
        
        # URL列：支持多个URL用<br>分隔
        url_val = instance.get('url', '')
        if isinstance(url_val, list):
            # 用HTML <br>在表格单元格中分行（Markdown表格兼容），反引号阻止Obsidian自动链接
            url_str = '<br>'.join(f'`{u}`' for u in url_val) if len(url_val) > 0 else '-'
        else:
            url_str = f'`{url_val}`' if url_val else '-'
        # 转义可能破坏表格的管道符
        url_str = url_str.replace('|', '\\|')
        row.append(url_str)
        
        # CVE列（如果存在实例级别的CVE）
        if has_instance_cve:
            cve_val = instance.get('cve', [])
            if isinstance(cve_val, list) and len(cve_val) > 0:
                row.append(', '.join(cve_val))
            else:
                row.append('-')
        
        # CVSS列（如果存在实例级别的CVSS）
        if has_instance_cvss:
            cvss_val = instance.get('cvss_score', '')
            row.append(str(cvss_val) if cvss_val else '-')
        
        section += "| " + " | ".join(row) + " |\n"
    
    section += "\n"
    return section


def find_screenshots(wiki_dir: str, vl_id: str) -> List[Dict]:
    """查找与漏洞页面关联的PDF页面截图

    截图存放路径：{wiki_dir}/assets/screenshots/
    截图命名规则：{vl_id}_p{页码}.png
    例如：VL-2026-035_p39.png

    Returns:
        列表，每个元素为 {"file": 相对vuln页面的路径, "page": 页码}
    """
    screenshot_dir = Path(wiki_dir) / "assets" / "screenshots"
    if not screenshot_dir.exists():
        return []

    screenshot_pattern = f"{vl_id}_p*.png"
    screenshots = sorted(screenshot_dir.glob(screenshot_pattern))

    result = []
    for img_path in screenshots:
        # 提取页码：VL-2026-035_p39.png -> 39
        page_match = re.search(r'_p(\d+)\.png$', img_path.name)
        page_num = int(page_match.group(1)) if page_match else 0
        result.append({
            'file': f"../assets/screenshots/{img_path.name}",
            'page': page_num
        })
    return result


def screenshot_page(pdf_path: str, page_num: int, output_path: str,
                    crop_top: float = 0.04, crop_bottom: float = 0.04,
                    crop_left: float = 0.03, crop_right: float = 0.03) -> bool:
    """截取PDF指定页面并裁剪边距

    Args:
        pdf_path: PDF文件路径
        page_num: 页码（1-based）
        output_path: 输出图片路径
        crop_top: 顶部裁剪比例（默认4%）
        crop_bottom: 底部裁剪比例（默认4%）
        crop_left: 左侧裁剪比例（默认3%）
        crop_right: 右侧裁剪比例（默认3%）

    Returns:
        是否成功
    """
    try:
        import fitz  # PyMuPDF
        from PIL import Image
        import io
    except ImportError as e:
        print(f"错误: 截图依赖缺失: {e}")
        return False

    try:
        doc = fitz.open(pdf_path)
        if page_num < 1 or page_num > len(doc):
            print(f"错误: 页码越界: {page_num}, PDF共{len(doc)}页")
            doc.close()
            return False

        page = doc[page_num - 1]
        pix = page.get_pixmap(dpi=300)
        img_data = pix.tobytes("png")
        img = Image.open(io.BytesIO(img_data))
        w, h = img.size
        left = int(w * crop_left)
        right = int(w * (1 - crop_right))
        top = int(h * crop_top)
        bottom = int(h * (1 - crop_bottom))
        cropped = img.crop((left, top, right, bottom))

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        cropped.save(output_path, "PNG")
        print(f"截图已保存: {output_path}")
        doc.close()
        return True

    except Exception as e:
        print(f"错误: 截图失败: {e}")
        return False


# severity → severity_order 映射（参考 AppScan 等级：严重>高>中>低>参考）
_SEVERITY_ORDER_MAP = {
    '严重': 5, '紧急': 5,
    '高': 4, '高危': 4,
    '中': 3, '中危': 3,
    '低': 2, '低危': 2,
    '参考': 1, '信息': 1, '提示': 1,
}


def _get_severity_order(severity: str) -> int:
    """根据 severity 字符串返回数值排序值"""
    return _SEVERITY_ORDER_MAP.get(severity, 0)


def generate_vulnerability_page(vuln_type: Dict, output_dir: str, report_date: str,
                                vl_id: str, pdf_path: str = '', wiki_dir: str = '',
                                system_name: str = '未知系统',
                                vuln_category: str = '应用系统漏洞') -> str:
    """生成漏洞页面"""
    # 优先使用 title 字段（新格式），兼容旧格式（只有 type 字段）
    vuln_type_title = vuln_type.get('title', vuln_type.get('type', '未知漏洞类型'))
    vuln_type_name = vuln_type.get('type', '未知漏洞类型')
    severity = vuln_type.get('severity', '中危')
    severity_order = _get_severity_order(severity)

    # 从第一个实例获取起始页码
    instances = vuln_type.get('instances', [])
    start_page = instances[0].get('start_page', 0) if instances else 0

    filename = f"{vl_id}.md"
    filepath = Path(output_dir) / filename

    # 转义YAML字符串
    title_yaml = escape_yaml_string(vuln_type_title)
    type_yaml = escape_yaml_string(vuln_type_name)
    category_yaml = escape_yaml_string(vuln_category)

    # tags - 多行YAML列表格式
    tags_list = [vuln_type_name]
    cve_list = vuln_type.get('cve', [])
    if cve_list and isinstance(cve_list, list):
        for cve in cve_list:
            if cve:
                tags_list.append(cve)
    tags_yaml_lines = '\n'.join([f"  - {escape_yaml_string(tag)}" for tag in tags_list])

    # system - 多行YAML列表格式
    system_yaml_lines = f"  - {escape_yaml_string(system_name)}"

    # 从vuln_type层级读取字段
    cvss_score = vuln_type.get('cvss_score', '')
    # 格式化cve为YAML列表
    if cve_list and isinstance(cve_list, list) and len(cve_list) > 0:
        cve_yaml = json.dumps(cve_list, ensure_ascii=False)
    else:
        cve_yaml = "null"

    # 格式化cwe为YAML多行列表
    cwe_list = vuln_type.get('cwe', [])
    if not isinstance(cwe_list, list):
        cwe_list = [cwe_list] if cwe_list else []
    if cwe_list:
        cwe_yaml = 'cwe:\n' + '\n'.join([f'  - "{c}"' for c in cwe_list])
    else:
        cwe_yaml = 'cwe: null'

    # ===== 获取正文字段 =====
    description = vuln_type.get('description', '')
    revision = vuln_type.get('revision', '')

    # 构建漏洞描述章节
    cause_text = vuln_type.get('cause', '')
    if description:
        desc_section = f"{description}\n"
        if cause_text:
            desc_section += f"\n{cause_text}\n"
    elif cause_text:
        desc_section = f"{cause_text}\n"
    else:
        desc_section = "[详细描述，包括漏洞原理、触发条件、影响范围]\n"
     
    # 构建修复建议章节
    if revision:
        revision_section = f"{revision}\n"
    else:
        revision_section = "[具体可操作的修复方案，包括：\n- 代码层面修复\n- 配置层面修复\n- 架构层面建议]\n"

    # 构建修复方法补充字段（来自修复方法章节）
    remediation_extra = ''
    risk_text = vuln_type.get('risk', '')
    affected_text = vuln_type.get('affected_products', '')
    refs_text = vuln_type.get('references', '')
    if risk_text:
        remediation_extra += f"\n### 风险\n{risk_text}\n"
    if affected_text:
        remediation_extra += f"\n### 受影响产品\n{affected_text}\n"
    if refs_text:
        remediation_extra += f"\n### 外部引用\n{refs_text}\n"

    # 生成Markdown内容
    content = f"""---
title: {title_yaml}
severity: "{severity}"
severity_order: {severity_order}
cvss_score: "{cvss_score}"
date_discovered: "{report_date}"
type: {type_yaml}
status: "待修复"
cve: {cve_yaml}
{cwe_yaml}
tags:
{tags_yaml_lines}
system:
{system_yaml_lines}
vul_category: {category_yaml}
created: "{datetime.now().strftime('%Y-%m-%d %H:%M')}"
---

# {vuln_type_name}

## 原因
{desc_section}
## 修复建议
{revision_section}{remediation_extra}\
"""

    # 生成"受影响实例"章节
    instances_section = generate_instances_section(vuln_type.get('instances', []), vuln_type)

    # ===== 截图生成 =====
    screenshot_path_rel = ''
    if pdf_path and start_page > 0 and Path(pdf_path).exists():
        # 截图存放路径
        screenshots_dir = Path(wiki_dir) / "assets" / "screenshots" if wiki_dir else Path(output_dir) / "assets" / "screenshots"
        screenshot_name = f"{vl_id}_p{start_page}.png"
        screenshot_abs_path = screenshots_dir / screenshot_name

        screenshot_page(pdf_path, start_page, str(screenshot_abs_path))

        if screenshot_abs_path.exists():
            screenshot_path_rel = f"../assets/screenshots/{screenshot_name}"

    # 查找已存在的截图（兼容旧报告已有截图的情况）
    existing_screenshots = find_screenshots(wiki_dir or output_dir, vl_id) if wiki_dir else []

    # ===== 构建"扫描原始数据"章节 =====
    pdf_name = Path(pdf_path).name if pdf_path else '未知报告'

    # 构建原始报告链接（Obsidian 内部链接格式）
    pdf_link = pdf_name
    if pdf_path and wiki_dir:
        pdf_abs = Path(pdf_path).resolve()
        wiki_abs = Path(wiki_dir).resolve()
        # 尝试用 vault 根目录计算相对路径（wiki_dir 可能是 vault 的子目录如 .../wiki）
        vault_abs = wiki_abs.parent if wiki_abs.name == 'wiki' else wiki_abs
        for base in (wiki_abs, vault_abs):
            try:
                pdf_rel = pdf_abs.relative_to(base)
                pdf_rel_str = pdf_rel.as_posix()
                if start_page > 0:
                    pdf_link = f"[[{pdf_rel_str}#page={start_page}|查看报告 (第{start_page}页)]]"
                else:
                    pdf_link = f"[[{pdf_rel_str}]]"
                break
            except ValueError:
                continue
        else:
            print(f"警告: PDF 不在 wiki 目录内: {pdf_path}")
            if start_page > 0:
                pdf_link = f"**原始报告**: {pdf_name} (第{start_page}页)"
            else:
                pdf_link = f"**原始报告**: {pdf_name}"

    raw_section = f"- **原始报告**：{pdf_link}\n"

    # 添加PDF页面截图（Obsidian嵌入语法）
    if screenshot_path_rel:
        raw_section += f"\n**原始报告截图（第{start_page}页）：**\n"
        raw_section += f"![[{screenshot_path_rel}|1200]]\n"
    elif existing_screenshots:
        raw_section += "\n**原始报告截图：**\n"
        for ss in existing_screenshots:
            raw_section += f"![[{ss['file']}|1200]]\n"

    raw_section += "- *此为代表性样本，同类实例仅URL/参数不同*"

    remaining_section = f"""## 扫描原始数据
{raw_section}
## 沟通记录
### 建设方拒绝修复
如建设方拒绝修复，记录：
- 拒绝日期
- 拒绝理由
- 建设方提供的"替代措施"
- 风险评估

### 检测方回复策略
我方针对拒绝的回复策略

## 状态追踪
- [x] {report_date} 初次发现
- [ ] 建设方确认接收
- [ ] 建设方提供修复计划
- [ ] 修复完成
- [ ] 验证通过

## 相关链接
- [[{system_name}]] - 受影响系统
- [[{vuln_type_name}]] - 漏洞类型详解
"""

    content += instances_section + remaining_section

    # 确保输出目录存在
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # 写入文件
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"已生成漏洞页面: {filepath}")
    return str(filepath)
