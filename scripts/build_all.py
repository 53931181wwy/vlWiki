"""
vlWiki 统一构建脚本
一次扫描，生成所有输出：index.md + 系统页面 + 漏洞类型页面 + log.md

用法：
    python scripts/build_all.py [--dry-run]

原三个独立脚本：
  build_system_index.py  → 生成 wiki/systems/*.md
  build_type_index.py    → 生成 wiki/vulnerability-types/*.md
  update_index.py        → 生成 wiki/index.md + wiki/log.md
"""

import os
import re
import sys
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional
from datetime import datetime

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from utils import parse_frontmatter, VULN_DIR, SYSTEM_DIR, TYPE_DIR
else:
    from .utils import parse_frontmatter, VULN_DIR, SYSTEM_DIR, TYPE_DIR

# ===========================================================================
# 通用工具
# ===========================================================================

SEVERITY_RANK = {'紧急': 0, '高危': 1, '中危': 2, '低危': 3, '信息': 4, '提示': 4, '未知': 5}

SEVERITY_ALIAS = {
    '紧急': '紧急', '严重': '紧急',
    '高危': '高危', '高': '高危',
    '中危': '中危', '中': '中危',
}

def _safe_filename(name: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', '-', name).strip()

def _normalize_severity(raw: str) -> str:
    if not raw:
        return '中危'
    s = str(raw).strip().strip('"').strip("'")
    return SEVERITY_ALIAS.get(s, s)

def _parse_cvss(raw) -> float:
    if not raw or raw == '-':
        return 0.0
    try:
        return float(str(raw).strip().strip('"').strip("'"))
    except (ValueError, TypeError):
        return 0.0

def _parse_severity_order(value) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0

def _extract_section(body: str, heading: str) -> str:
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
        hm = re.match(r'^(#{2,3})\s+', line)
        if hm and len(hm.group(1)) <= heading_level:
            break
        section_lines.append(line)
    return '\n'.join(section_lines).strip()

def _merge_dedup(texts: List[str]) -> str:
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

def _bar(count: int, max_count: int, width: int = 10) -> str:
    filled = round(count / max(max_count, 1) * width)
    return '█' * filled + '░' * (width - filled)

def count_instances_from_body(body: str) -> int:
    in_table = False
    count = 0
    for line in body.split('\n'):
        stripped = line.strip()
        if stripped.startswith('##') and '受影响实例' in stripped:
            in_table = True
            continue
        if in_table:
            if stripped.startswith('##'):
                break
            if re.match(r'^\|[\s\-:|]+\|$', stripped):
                continue
            m = re.match(r'^\|\s*(\d+)', stripped)
            if m:
                count = max(count, int(m.group(1)))
    return max(count, 1)

# ===========================================================================
# 扫描 VL 页面（一次扫描，提取三类脚本所需全部信息）
# ===========================================================================

def scan_all_vulnerabilities(vuln_dir: str) -> List[Dict]:
    """一次扫描，返回完整的漏洞信息列表"""
    vulns = []
    if not os.path.isdir(vuln_dir):
        print(f"[错误] 目录不存在: {vuln_dir}")
        return vulns

    vl_files = sorted(
        f for f in os.listdir(vuln_dir) if f.startswith('VL-') and f.endswith('.md')
    )
    print(f"扫描: {vuln_dir} ({len(vl_files)} 个VL页面)")

    for fname in vl_files:
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

            cwe_raw = fm.get('cwe', [])
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw] if cwe_raw else []
            cwe_list = [str(c).strip().strip('"').strip("'") for c in cwe_raw if c and str(c).strip().lower() != 'null']

            cause = _extract_section(body, '原因')
            revision = _extract_section(body, '修复建议')
            risk = _extract_section(body, '风险')

            title_match = re.search(r'^#\s+(.+)$', body, re.MULTILINE)
            vl_title = title_match.group(1).strip() if title_match else vl_id

            vulns.append({
                'vl_id': vl_id,
                'vl_title': vl_title,
                'filename': fname,
                'filepath': fpath,
                'title': fm.get('title', '未知标题'),
                'type': vuln_type,
                'severity': _normalize_severity(fm.get('severity', '')),
                'severity_order': fm.get('severity_order', 0),
                'cvss_score': fm.get('cvss_score', ''),
                'status': str(fm.get('status', '')).strip().strip('"').strip("'") or '待修复',
                'systems': systems,
                'date_discovered': str(fm.get('date_discovered', '')).strip().strip('"').strip("'"),
                'vul_category': fm.get('vul_category', '应用系统漏洞'),
                'cwe': cwe_list,
                'cause': cause,
                'revision': revision,
                'risk': risk,
                'instance_count': count_instances_from_body(body),
            })
        except Exception as e:
            print(f"  [警告] 处理 {fname} 失败: {e}")
    return vulns

# ===========================================================================
# 分组辅助
# ===========================================================================

def group_by_system(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        if not v['systems']:
            g['未知系统'].append(v)
        else:
            for s in v['systems']:
                g[s].append(v)
    return dict(g)

def group_by_type(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        g[v['type']].append(v)
    return dict(g)

def group_by_category(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        g[v['vul_category']].append(v)
    return dict(g)

def group_by_status(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        g[v['status']].append(v)
    return dict(g)

# ===========================================================================
# 1. 生成系统页面
# ===========================================================================

def build_system_pages(vulns: List[Dict], output_dir: str, dry: bool = False):
    grouped = group_by_system(vulns)
    print(f"\n[1/4] 生成系统页面 → {output_dir}")
    print(f"  发现 {len(grouped)} 个系统")
    if dry:
        for sys_name in sorted(grouped):
            print(f"  [DRY-RUN] {_safe_filename(sys_name)} → {len(grouped[sys_name])} 个实例")
        return

    os.makedirs(output_dir, exist_ok=True)
    for sys_name, items in sorted(grouped.items()):
        safe_name = _safe_filename(sys_name)
        out_path = os.path.join(output_dir, f"{safe_name}.md")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sorted_items = sorted(items, key=lambda v: (
            SEVERITY_RANK.get(v['severity'], 99),
            -_parse_cvss(v.get('cvss_score', '')),
        ))

        sev_counts = defaultdict(int)
        for v in items:
            sev_counts[v['severity']] += 1

        lines = [
            '---',
            f"title: {sys_name}",
            'type: system',
            'tags: [系统]',
            f"created: {now}",
            '---',
            '',
            f"# {sys_name}",
            '',
        ]

        parts = [f"共 **{len(items)}** 个漏洞"]
        for sev in ['紧急', '高危', '中危', '低危']:
            c = sev_counts.get(sev, 0)
            if c > 0:
                parts.append(f"{sev} {c}")
        lines.append(f"> {' | '.join(parts)}")
        lines.extend(['', '## 漏洞列表', '',
            '| VL编号 | 漏洞类型 | 等级 | CVSS | 状态 | 发现日期 |',
            '|--------|---------|------|------|------|----------|'])

        for v in sorted_items:
            cvss = str(v.get('cvss_score', '')).strip().strip('"').strip("'") or '-'
            date = v.get('date_discovered', '') or '-'
            lines.append(f"| [[{v['vl_id']}]] | [[{v['type']}]] | {v['severity']} | {cvss} | {v['status']} | {date} |")

        lines.extend(['', '## 说明', '', '> 可在此处补充该系统的基本信息、负责人、部署环境等。', ''])

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        print(f"  [{safe_name}] → {len(items)} 个实例")

# ===========================================================================
# 2. 生成漏洞类型页面
# ===========================================================================

def build_type_pages(vulns: List[Dict], output_dir: str, dry: bool = False):
    grouped = group_by_type(vulns)
    print(f"\n[2/4] 生成漏洞类型页面 → {output_dir}")
    print(f"  发现 {len(grouped)} 种漏洞类型")
    if dry:
        for type_name in sorted(grouped):
            print(f"  [DRY-RUN] {_safe_filename(type_name)} → {len(grouped[type_name])} 个实例")
        return

    os.makedirs(output_dir, exist_ok=True)
    for type_name, items in sorted(grouped.items()):
        safe_name = _safe_filename(type_name)
        out_path = os.path.join(output_dir, f"{safe_name}.md")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        all_cwe = []
        cvss_scores = []
        sev_counts = defaultdict(int)
        for v in items:
            sev_counts[v['severity']] += 1
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

        cause_merged = _merge_dedup([v.get('cause', '') for v in items])
        revision_merged = _merge_dedup([v.get('revision', '') for v in items])
        risk_merged = _merge_dedup([v.get('risk', '') for v in items])

        lines = [
            '---',
            f'title: "{type_name}"',
            'owasp: ""',
            f'cwe: [{", ".join(all_cwe)}]' if all_cwe else 'cwe: ""',
            f'created: {now}',
            '---',
            '',
            f'# {type_name}',
            '',
            '## 漏洞原因和描述',
            '',
            cause_merged or '> 暂无描述。',
            '',
            '## 原因',
            '',
            cause_merged or '> 暂无成因分析。',
            '',
            '## 风险',
            '',
            risk_merged or '> 暂无风险描述。',
            '',
            '## 危害等级',
            '',
        ]

        sev_parts = [f"共 **{len(items)}** 个漏洞"]
        for sev in ['紧急', '高危', '中危', '低危', '信息']:
            c = sev_counts.get(sev, 0)
            if c > 0:
                sev_parts.append(f"{sev} {c}")
        lines.append(' - '.join(sev_parts))
        if cvss_scores:
            lines.append(f'- CVSS 评分范围：{min(cvss_scores):.1f} ~ {max(cvss_scores):.1f}')
        lines.append('')

        # 外部引用
        lines.append('### 外部引用')
        lines.append('')
        if all_cwe:
            for cwe_id in all_cwe:
                lines.append(f'- [CWE-{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id}.html)')
        lines.append('')

        # 修复建议
        lines.extend(['## 修复建议', '', revision_merged or '> 暂无修复建议。', ''])

        # 历史沟通记录
        lines.extend(['## 历史沟通记录', '', '> 此处记录与建设方就该漏洞类型的沟通历史。', ''])

        # 本Wiki中相关漏洞实例
        lines.extend(['## 本Wiki中相关漏洞实例', ''])

        sg = defaultdict(list)
        for v in sorted_items:
            for s in v['systems']:
                sg[s].append(v)
            if not v['systems']:
                sg['未知系统'].append(v)

        for sys_name, sys_vulns in sorted(sg.items()):
            lines.append(f'### {sys_name}')
            for v in sys_vulns:
                lines.append(f"- [[{v['vl_id']}]] - {v['vl_title']} - {v['severity']}")
            lines.append('')

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        print(f"  [{safe_name}] → {len(items)} 个实例")

# ===========================================================================
# 3. 生成 index.md
# ===========================================================================

def build_index(vulns: List[Dict], output_path: str, dry: bool = False):
    print(f"\n[3/4] 生成索引页面 → {output_path}")
    if dry:
        print(f"  [DRY-RUN] {len(vulns)} 个漏洞")
        return

    now = datetime.now().strftime("%Y-%m-%d")
    now_full = datetime.now().strftime("%Y-%m-%d %H:%M")

    sev_g = group_by_severity(vulns)
    cat_g = group_by_category(vulns)
    sta_g = group_by_status(vulns)
    sys_g = group_by_system(vulns)

    total_raw = len(vulns)
    total_inst = sum(v.get('instance_count', 1) for v in vulns)

    sorted_vulns = sorted(vulns, key=lambda v: (
        -_parse_severity_order(v.get('severity_order', 0)),
        -_parse_cvss(v.get('cvss_score', ''))
    ))

    def _cnt(sev):
        return len(sev_g.get(sev, []))

    sev_order = ['紧急', '高危', '中危']
    max_sev = max((_cnt(s) for s in sev_order), default=1)
    sev_cells = [f"**{s}** {_cnt(s)}  {_bar(_cnt(s), max_sev)}" for s in sev_order]

    status_parts = []
    for st in ['待修复', '修复中', '已修复', '已拒绝']:
        c = len(sta_g.get(st, []))
        status_parts.append(f"**{st}** {c}" if c > 0 else f"_{st}_ 0")

    dashboard = (
        f"> **总览**：{total_raw} 个漏洞类型 · {total_inst} 个实例\n"
        f">\n"
        f"> {' | '.join(sev_cells)}\n"
        f">\n"
        f"> {' · '.join(status_parts)}\n"
        f">\n"
        f"> 涉及 **{len(sys_g)}** 个系统 · 最后更新 {now_full}\n"
        f"本索引提供按类型（按等级排列）、漏洞大类、系统的多维度检索。\n"
        f"---"
    )

    # 完整列表
    table = [
        "## 完整漏洞列表",
        "> 按严重性排序，同类严重性按 CVSS 降序",
        "",
        "| VL编号 | 漏洞类型 | 等级 | CVSS | 大类 | 影响系统 | 实例 | 状态 |",
        "|--------|---------|------|------|------|---------|------|------|",
    ]
    for v in sorted_vulns:
        cvss = v.get('cvss_score', '') or '-'
        sys_str = '、'.join(f"[[{s}]]" for s in v['systems'])
        table.append(f"| [[{v['vl_id']}]] | {v['type']} | {v['severity']} | {cvss} | {v['vul_category']} | {sys_str} | {v.get('instance_count', 1)} | {v['status']} |")
    table.append("")

    # 按类型索引
    type_section = ["## 按类型索引", ""]
    for cat in sorted(cat_g.keys()):
        items = cat_g[cat]
        type_section.append(f"### {cat}（{len(items)}）\n")
        ts = sorted(items, key=lambda v: (-_parse_severity_order(v.get('severity_order', 0)), -_parse_cvss(v.get('cvss_score', ''))))
        type_section.append("| VL编号 | 漏洞类型 | 等级 | CVSS | 影响系统 | 状态 |")
        type_section.append("|--------|---------|------|------|---------|------|")
        for v in ts:
            cvss = v.get('cvss_score', '') or '-'
            sys_str = '、'.join(f"[[{s}]]" for s in v['systems'])
            type_section.append(f"| [[{v['vl_id']}]] | {v['type']} | {v['severity']} | {cvss} | {sys_str} | {v['status']} |")
        type_section.append("")

    # 按系统索引
    system_section = ["## 按系统索引", ""]
    for sn in sorted(sys_g.keys()):
        items = sys_g[sn]
        system_section.append(f"### [[{sn}]] ({len(items)})\n")
        system_section.append("| VL编号 | 漏洞类型 | 等级 | 状态 |")
        system_section.append("|--------|---------|------|------|")
        for v in items:
            system_section.append(f"| [[{v['vl_id']}]] | {v['type']} | {v['severity']} | {v['status']} |")
        system_section.append("")

    fm = (
        "---\n"
        f"title: 安全漏洞Wiki - 多维度索引\n"
        f"type: index\n"
        f"tags: [index, wiki, 漏洞管理]\n"
        f"last_updated: {now}\n"
        "---\n"
    )

    content = (
        fm
        + "# 安全漏洞\n\n"
        + dashboard
        + "\n" + "\n".join(table)
        + "---\n"
        + "\n".join(type_section)
        + "---\n"
        + "\n".join(system_section)
        + f"> **最后更新**：{now_full} · **维护者**：LLM Agent\n"
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  {total_raw} 个漏洞 → {output_path}")

# ===========================================================================
# 4. 更新 log.md
# ===========================================================================

MAX_LOG_LINES = 800
KEEP_LOG_HEADER = 80
KEEP_LOG_RECENT = 500

def update_log(vulns: List[Dict], vuln_dir: str, dry: bool = False):
    wiki_dir = Path(vuln_dir).parent
    log_path = wiki_dir / "log.md"
    print(f"\n[4/4] 更新日志 → {log_path}")
    if dry:
        print(f"  [DRY-RUN] 将记录 {len(vulns)} 条")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    new_lines = [f"\n## 更新记录 {now}\n"]
    for v in sorted(vulns, key=lambda x: x['vl_id']):
        new_lines.append(f"- [[{v['vl_id']}]] - {v['type']} - {v['severity']}\n")

    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(''.join(new_lines))

        with open(log_path, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()

        if len(all_lines) > MAX_LOG_LINES:
            header = all_lines[:KEEP_LOG_HEADER]
            recent = all_lines[-(KEEP_LOG_RECENT - KEEP_LOG_HEADER):]
            with open(log_path, 'w', encoding='utf-8') as f:
                f.writelines(header)
                f.write('\n---\n')
                f.write(f'<!-- 自动轮转于 {now}，保留最近 {KEEP_LOG_RECENT} 行 -->\n')
                f.writelines(recent)
            print(f"  log.md 已轮转（{len(all_lines)} → {KEEP_LOG_RECENT}+ 行）")
        else:
            print(f"  日志已更新")
    except Exception as e:
        print(f"  警告: 写入日志失败: {e}")

def group_by_severity(vulns):
    g = defaultdict(list)
    for v in vulns:
        g[v['severity']].append(v)
    return dict(g)

# ===========================================================================
# 主入口
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="vlWiki 统一构建：一次扫描，全部生成")
    parser.add_argument("--vuln-dir", help="VL页面目录")
    parser.add_argument("--output-dir", help="输出根目录（wiki 目录）")
    parser.add_argument("--dry-run", action="store_true", help="只预览不写入文件")
    parser.add_argument("--skip", nargs="*", choices=["system","type","index","log"],
                        help="跳过指定步骤")
    args = parser.parse_args()

    vuln_dir = args.vuln_dir or VULN_DIR
    wiki_dir = args.output_dir or os.path.dirname(vuln_dir)
    system_dir = os.path.join(wiki_dir, "systems")
    type_dir = os.path.join(wiki_dir, "vulnerability-types")
    index_path = os.path.join(wiki_dir, "index.md")

    dry = args.dry_run
    skip = set(args.skip or [])

    print("=" * 50)
    print("vlWiki 统一构建")
    print("=" * 50)
    print(f"VL目录:   {vuln_dir}")
    print(f"wiki目录: {wiki_dir}")
    if dry:
        print("模式: DRY-RUN（预览，不写入）\n")

    # 扫描
    vulns = scan_all_vulnerabilities(vuln_dir)
    if not vulns:
        print("\n[错误] 没有找到有效的VL页面")
        sys.exit(1)
    print(f"扫描完成: {len(vulns)} 个 VL 页面\n")

    # 生成各类页面
    steps = [
        ("system", "系统页面", lambda: build_system_pages(vulns, system_dir, dry)),
        ("type", "漏洞类型页面", lambda: build_type_pages(vulns, type_dir, dry)),
        ("index", "索引页面", lambda: build_index(vulns, index_path, dry)),
        ("log", "日志更新", lambda: update_log(vulns, vuln_dir, dry)),
    ]

    for key, label, fn in steps:
        if key in skip:
            print(f"[跳过] {label}")
        else:
            fn()

    print(f"\n{'='*50}")
    print("全部完成！")
    print(f"  系统页面:     {system_dir}/")
    print(f"  漏洞类型页面:  {type_dir}/")
    print(f"  索引页面:     {index_path}")
    print(f"  日志文件:     {wiki_dir}/log.md")

if __name__ == '__main__':
    main()
