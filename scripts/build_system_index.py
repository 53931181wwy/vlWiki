"""
为 vlWiki 生成系统页面

功能：
1. 扫描 wiki/vulnerabilities/ 所有 VL 页面
2. 按 system 字段聚合
3. 为每个系统生成 wiki/systems/<系统名>.md（不生成 index.md）

用法：
    python scripts/build_system_index.py [--vuln-dir <路径>] [--output-dir <路径>]
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
    from utils import parse_frontmatter, VULN_DIR, SYSTEM_DIR
else:
    from .utils import parse_frontmatter, VULN_DIR, SYSTEM_DIR

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
            fm, _ = parse_frontmatter(content)
            if not fm:
                continue
            vl_id = fname.replace('.md', '')
            vuln_type = str(fm.get('type', '')).strip().strip('"').strip("'") or '未知类型'
            system_raw = fm.get('system', [])
            if isinstance(system_raw, str):
                system_raw = [system_raw] if system_raw else []
            systems = [str(s).strip().strip('"').strip("'") for s in system_raw if s]

            vulns.append({
                'vl_id': vl_id,
                'type': vuln_type,
                'severity': _normalize_severity(fm.get('severity', '')),
                'cvss_score': fm.get('cvss_score', ''),
                'status': str(fm.get('status', '')).strip().strip('"').strip("'") or '待修复',
                'systems': systems,
                'date_discovered': str(fm.get('date_discovered', '')).strip().strip('"').strip("'"),
            })
        except Exception as e:
            print(f"[警告] 处理 {fname} 失败: {e}")
    return vulns


def group_by_system(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    """按系统名称分组（一个 VL 页面可能属于多个系统）"""
    g = defaultdict(list)
    for v in vulns:
        if not v['systems']:
            g['未知系统'].append(v)
        else:
            for s in v['systems']:
                g[s].append(v)
    return dict(g)


def build_system_page(system_name: str, items: List[Dict], output_dir: str) -> str:
    """生成单个系统页面，返回输出路径"""
    os.makedirs(output_dir, exist_ok=True)
    safe_name = _safe_filename(system_name)
    out_path = os.path.join(output_dir, f"{safe_name}.md")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_counts = defaultdict(int)
    status_counts = defaultdict(int)
    for v in items:
        sev_counts[v['severity']] += 1
        status_counts[v['status']] += 1

    sorted_items = sorted(items, key=lambda v: (
        SEVERITY_RANK.get(v['severity'], 99),
        -_parse_cvss(v.get('cvss_score', '')),
    ))

    lines = []
    lines.append('---')
    lines.append(f"title: {system_name}")
    lines.append('type: system')
    lines.append('tags: [系统]')
    lines.append(f"created: {now}")
    lines.append('---')
    lines.append('')
    lines.append(f"# {system_name}")
    lines.append('')

    summary_parts = [f"共 **{len(items)}** 个漏洞"]
    for sev in ['紧急', '高危', '中危', '低危']:
        c = sev_counts.get(sev, 0)
        if c > 0:
            summary_parts.append(f"{sev} {c}")
    lines.append(f"> {' | '.join(summary_parts)}")
    lines.append('')

    lines.append('## 漏洞列表')
    lines.append('')
    lines.append('| VL编号 | 漏洞类型 | 等级 | CVSS | 状态 | 发现日期 |')
    lines.append('|--------|---------|------|------|------|----------|')

    for v in sorted_items:
        cvss = str(v.get('cvss_score', '')).strip().strip('"').strip("'") or '-'
        date = v.get('date_discovered', '') or '-'
        lines.append(
            f"| [[{v['vl_id']}]] | [[{v['type']}]] | {v['severity']} | {cvss} | {v['status']} | {date} |"
        )

    lines.append('')
    lines.append('## 说明')
    lines.append('')
    lines.append('> 可在此处补充该系统的基本信息、负责人、部署环境等。')
    lines.append('')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    return out_path


def main():
    parser = argparse.ArgumentParser(description="生成系统页面")
    parser.add_argument("--vuln-dir", help="VL页面目录（默认自动检测）")
    parser.add_argument("--output-dir", help="输出目录（默认自动检测）")
    args = parser.parse_args()

    # 默认路径
    vuln_dir = args.vuln_dir or VULN_DIR
    output_dir = args.output_dir or SYSTEM_DIR

    print(f"VL目录: {vuln_dir}")
    print(f"输出目录: {output_dir}")

    vulns = scan_vulnerabilities(vuln_dir)
    print(f"已扫描 {len(vulns)} 个 VL 页面")

    grouped = group_by_system(vulns)
    print(f"发现 {len(grouped)} 个系统")

    for sys_name, items in sorted(grouped.items()):
        path = build_system_page(sys_name, items, output_dir)
        print(f"  [{_safe_filename(sys_name)}] → {len(items)} 个实例")

    print("完成。")


if __name__ == '__main__':
    main()
