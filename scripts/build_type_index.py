"""
为 vlWiki 生成漏洞类型页面

功能：
1. 扫描 wiki/vulnerabilities/ 所有 VL 页面
2. 按 type 字段聚合
3. 为每个漏洞类型生成 wiki/vulnerability-types/<类型名>.md（不生成 index.md）

用法：
    python scripts/build_type_index.py [--vuln-dir <路径>] [--output-dir <路径>]
"""

import os
import re
import sys
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List
from datetime import datetime

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from utils import parse_frontmatter, VULN_DIR, TYPE_DIR
else:
    from .utils import parse_frontmatter, VULN_DIR, TYPE_DIR

SEVERITY_RANK = {'紧急': 0, '高危': 1, '中危': 2, '低危': 3, '信息': 4}


def _safe_filename(name: str) -> str:
    """替换文件名中的非法字符为 -"""
    return re.sub(r'[\\/*?:"<>|]', '-', name).strip()


def _normalize_severity(raw: str) -> str:
    if not raw:
        return '中危'
    s = str(raw).strip().strip('"').strip("'")
    return {'严重': '紧急', '高': '高危', '中': '中危', '低': '低危'}.get(s, s)


def _parse_cvss(raw) -> float:
    if not raw or raw == '-':
        return 0.0
    try:
        return float(str(raw).strip().strip('"').strip("'"))
    except (ValueError, TypeError):
        return 0.0


def _extract_section(body: str, heading: str) -> str:
    """从正文中提取指定标题下的内容，直到下一个同级或更高级标题

    支持匹配 ## 标题 和 ### 标题。
    """
    # 匹配 ## 或 ### 级别的标题
    pattern = rf'^(#{{2,3}})\s+{re.escape(heading)}\s*$'
    lines = body.split('\n')
    start = None
    heading_level = None
    for i, line in enumerate(lines):
        m = re.match(pattern, line)
        if m:
            start = i + 1
            heading_level = len(m.group(1))
            break
    if start is None:
        return ''
    section_lines = []
    for i in range(start, len(lines)):
        line = lines[i]
        # 遇到同级或更高级标题则停止
        hm = re.match(r'^(#{2,3})\s+', line)
        if hm and len(hm.group(1)) <= heading_level:
            break
        section_lines.append(line)
    return '\n'.join(section_lines).strip()


def _merge_dedup(texts: List[str]) -> str:
    """合并多段文本并去重：按段落去重，保留首次出现"""
    seen = set()
    result = []
    for text in texts:
        if not text:
            continue
        for para in text.split('\n'):
            stripped = para.strip()
            if not stripped:
                continue
            if stripped not in seen:
                seen.add(stripped)
                result.append(para)
    return '\n'.join(result)


def scan_vulnerabilities(vuln_dir: str) -> List[Dict]:
    """扫描目录中所有 VL 页面，返回 frontmatter 字典列表"""
    vulns = []
    if not os.path.isdir(vuln_dir):
        print(f"[错误] 目录不存在: {vuln_dir}")
        return vulns

    for fname in sorted(os.listdir(vuln_dir)):
        if not (fname.startswith('VL-') and fname.endswith('.md')):
            continue
        fpath = os.path.join(vuln_dir, fname)
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                content = f.read()
            fm, body = parse_frontmatter(content)
            if not fm:
                continue
            vl_id = fname.replace('.md', '')
            vuln_type = str(fm.get('type', '')).strip().strip('"').strip("'") or '未知类型'
            system_raw = fm.get('system', [])
            if isinstance(system_raw, str):
                system_raw = [system_raw] if system_raw else []
            systems = [str(s).strip().strip('"').strip("'") for s in system_raw if s]

            # 提取 cwe 列表
            cwe_raw = fm.get('cwe', [])
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw] if cwe_raw else []
            cwe_list = [str(c).strip().strip('"').strip("'") for c in cwe_raw if c and str(c).strip().lower() != 'null']

            # 提取正文各节
            cause = _extract_section(body, '原因')
            revision = _extract_section(body, '修复建议')
            risk = _extract_section(body, '风险')

            # 提取标题（从正文 # 标题行）
            title_match = re.search(r'^#\s+(.+)$', body, re.MULTILINE)
            vl_title = title_match.group(1).strip() if title_match else vl_id

            vulns.append({
                'vl_id': vl_id,
                'vl_title': vl_title,
                'type': vuln_type,
                'severity': _normalize_severity(fm.get('severity', '')),
                'cvss_score': fm.get('cvss_score', ''),
                'status': str(fm.get('status', '')).strip().strip('"').strip("'") or '待修复',
                'systems': systems,
                'date_discovered': str(fm.get('date_discovered', '')).strip().strip('"').strip("'"),
                'cwe': cwe_list,
                'cause': cause,
                'revision': revision,
                'risk': risk,
            })
        except Exception as e:
            print(f"[警告] 处理 {fname} 失败: {e}")
    return vulns


def group_by_type(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        g[v['type']].append(v)
    return dict(g)


def build_type_page(type_name: str, items: List[Dict], output_dir: str) -> str:
    """生成单个漏洞类型页面，返回输出路径"""
    os.makedirs(output_dir, exist_ok=True)
    safe_name = _safe_filename(type_name)
    out_path = os.path.join(output_dir, f"{safe_name}.md")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_counts = defaultdict(int)
    status_counts = defaultdict(int)
    all_cwe = []
    cvss_scores = []
    for v in items:
        sev_counts[v['severity']] += 1
        status_counts[v['status']] += 1
        for c in v.get('cwe', []):
            if c and c not in all_cwe:
                all_cwe.append(c)
        cvss = _parse_cvss(v.get('cvss_score', ''))
        if cvss > 0:
            cvss_scores.append(cvss)

    sorted_items = sorted(items, key=lambda v: (
        SEVERITY_RANK.get(v['severity'], 99),
        -_parse_cvss(v.get('cvss_score', '')),
    ))

    # 聚合去重各节内容
    cause_merged = _merge_dedup([v.get('cause', '') for v in items])
    revision_merged = _merge_dedup([v.get('revision', '') for v in items])
    risk_merged = _merge_dedup([v.get('risk', '') for v in items])

    lines = []
    # --- frontmatter ---
    lines.append('---')
    lines.append(f'title: "{type_name}"')
    lines.append('owasp: ""')
    if all_cwe:
        lines.append(f'cwe: [{", ".join(all_cwe)}]')
    else:
        lines.append('cwe: ""')
    lines.append(f'created: {now}')
    lines.append('---')
    lines.append('')

    # --- 标题 ---
    lines.append(f'# {type_name}')
    lines.append('')

    # --- 漏洞原因和描述 ---
    lines.append('## 漏洞原因和描述')
    lines.append('')
    if cause_merged:
        lines.append(cause_merged)
    else:
        lines.append('> 暂无描述，可在此处补充该漏洞类型的通用描述。')
    lines.append('')

    # --- 原因 ---
    lines.append('## 原因')
    lines.append('')
    if cause_merged:
        lines.append(cause_merged)
    else:
        lines.append('> 暂无成因分析。')
    lines.append('')

    # --- 风险 ---
    lines.append('## 风险')
    lines.append('')
    if risk_merged:
        lines.append(risk_merged)
    else:
        lines.append('> 暂无风险描述。')
    lines.append('')

    # --- 危害等级 ---
    lines.append('## 危害等级')
    lines.append('')
    sev_parts = [f"共 **{len(items)}** 个漏洞"]
    for sev in ['紧急', '高危', '中危', '低危', '信息']:
        c = sev_counts.get(sev, 0)
        if c > 0:
            sev_parts.append(f"{sev} {c}")
    lines.append(' - '.join(sev_parts))
    if cvss_scores:
        lines.append(f'- CVSS 评分范围：{min(cvss_scores):.1f} ~ {max(cvss_scores):.1f}')
    lines.append('')

    # --- 外部引用 ---
    lines.append('### 外部引用')
    lines.append('')
    if all_cwe:
        for cwe_id in all_cwe:
            lines.append(f'- [CWE-{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id}.html)')
    lines.append('')

    # --- 修复建议 ---
    lines.append('## 修复建议')
    lines.append('')
    if revision_merged:
        lines.append(revision_merged)
    else:
        lines.append('> 暂无修复建议。')
    lines.append('')

    # --- 历史沟通记录 ---
    lines.append('## 历史沟通记录')
    lines.append('')
    lines.append('> 此处记录与建设方就该漏洞类型的沟通历史。')
    lines.append('')

    # --- 本Wiki中相关漏洞实例 ---
    lines.append('## 本Wiki中相关漏洞实例')
    lines.append('')

    # 按系统分组
    system_groups = defaultdict(list)
    for v in sorted_items:
        for s in v['systems']:
            system_groups[s].append(v)
        if not v['systems']:
            system_groups['未知系统'].append(v)

    for sys_name, sys_vulns in sorted(system_groups.items()):
        lines.append(f'### {sys_name}')
        for v in sys_vulns:
            lines.append(f"- [[{v['vl_id']}]] - {v['vl_title']} - {v['severity']}")
        lines.append('')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    return out_path


def main():
    parser = argparse.ArgumentParser(description="生成漏洞类型页面")
    parser.add_argument("--vuln-dir", help="VL页面目录（默认自动检测）")
    parser.add_argument("--output-dir", help="输出目录（默认自动检测）")
    args = parser.parse_args()

    # 默认路径
    vuln_dir = args.vuln_dir or VULN_DIR
    output_dir = args.output_dir or TYPE_DIR

    print(f"VL目录: {vuln_dir}")
    print(f"输出目录: {output_dir}")

    vulns = scan_vulnerabilities(vuln_dir)
    print(f"已扫描 {len(vulns)} 个 VL 页面")

    grouped = group_by_type(vulns)
    print(f"发现 {len(grouped)} 种漏洞类型")

    for type_name, items in sorted(grouped.items()):
        path = build_type_page(type_name, items, output_dir)
        print(f"  [{_safe_filename(type_name)}] → {len(items)} 个实例")

    print("完成。")


if __name__ == '__main__':
    main()
