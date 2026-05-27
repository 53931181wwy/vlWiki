"""
vlWiki 查询脚本 - 遍历 VL 页面，按条件过滤并输出匹配列表。
默认终端表格输出，支持 --output 生成可点击的 Markdown 文件。
"""
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

# 允许直接运行和模块导入两种用法
if __name__ == '__main__':
    # 添加 scripts 目录本身到 sys.path，绕过包 __init__.py 避免循环导入
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from utils import find_vl_files, parse_frontmatter, extract_vl_id, VULN_DIR, WIKI_ROOT
else:
    from .utils import find_vl_files, parse_frontmatter, extract_vl_id, VULN_DIR, WIKI_ROOT


def load_all_vl(vuln_dir: str):
    """加载所有 VL 页面的 frontmatter 数据。

    Returns:
        list[dict]: 每个元素包含 id, filepath, fm 字段
    """
    results = []
    for filepath in find_vl_files(vuln_dir):
        vl_id = extract_vl_id(os.path.basename(filepath))
        if not vl_id:
            continue
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            fm, _ = parse_frontmatter(content)
            results.append({'id': vl_id, 'filepath': filepath, 'fm': fm})
        except Exception as e:
            print(f"[警告] 解析 {filepath} 失败: {e}", file=sys.stderr)
    return results


# ---------------------------------------------------------------------------
# 过滤逻辑
# ---------------------------------------------------------------------------

def filt(items, severity=None, status=None, system=None, vul_type=None,
         cve=None, cve_has=False, date_after=None, date_before=None):
    """按条件过滤 VL 列表，多个条件为 AND 关系。"""
    result = []
    for item in items:
        fm = item['fm']
        if severity and fm.get('severity', '').strip('"\'') != severity:
            continue
        if status and fm.get('status', '').strip('"\'') != status:
            continue
        if system:
            systems = fm.get('system', [])
            if isinstance(systems, str):
                systems = [systems]
            if not any(system.lower() in s.lower() for s in systems):
                continue
        if vul_type:
            t = fm.get('type', '')
            if vul_type.lower() not in t.lower():
                continue
        if cve:
            cve_val = fm.get('cve')
            if not cve_val or cve_val == 'null':
                continue
            if isinstance(cve_val, list):
                if not any(cve.lower() in v.lower() for v in cve_val):
                    continue
            elif cve.lower() not in str(cve_val).lower():
                continue
        if cve_has:
            cve_val = fm.get('cve')
            if not cve_val or cve_val == 'null' or cve_val == []:
                continue
        if date_after or date_before:
            date_str = fm.get('date_discovered', '')
            if not date_str:
                continue
            try:
                dt = datetime.strptime(date_str[:10], '%Y-%m-%d')
                if date_after and dt < date_after:
                    continue
                if date_before and dt > date_before:
                    continue
            except ValueError:
                continue
        result.append(item)
    return result


# ---------------------------------------------------------------------------
# 输出格式化
# ---------------------------------------------------------------------------

SEVERITY_MAP = {'紧急': 4, '高': 3, '中': 2, '低': 1}
SEVERITY_ORDER = ['紧急', '高', '中', '低']


def _sev_sort_key(item):
    sev = item['fm'].get('severity', '').strip('"\'')
    return SEVERITY_MAP.get(sev, 0)


def _format_systems(fm):
    systems = fm.get('system', [])
    if isinstance(systems, str):
        systems = [systems]
    if not systems:
        return '-'
    return ', '.join(s for s in systems if s)


def _format_cve(fm):
    cve_val = fm.get('cve')
    if not cve_val or cve_val == 'null' or cve_val == []:
        return '-'
    if isinstance(cve_val, list):
        return ', '.join(cve_val)
    return str(cve_val)


def _format_date(fm):
    d = fm.get('date_discovered', '')
    if not d:
        return '-'
    return d[:10]


def _build_desc(args):
    """构建查询条件描述文本。"""
    parts = []
    if args.severity:
        parts.append(f"severity={args.severity}")
    if args.status:
        parts.append(f"status={args.status}")
    if args.system:
        parts.append(f"system~={args.system}")
    if args.vul_type:
        parts.append(f"type~={args.vul_type}")
    if args.cve:
        parts.append(f"cve={args.cve}")
    if args.cve_has:
        parts.append("cve-has=true")
    if args.date_after:
        parts.append(f"date-after={args.date_after.strftime('%Y-%m-%d')}")
    if args.date_before:
        parts.append(f"date-before={args.date_before.strftime('%Y-%m-%d')}")
    return ' '.join(parts) if parts else '无过滤条件'


def output_terminal(items):
    """终端表格输出。"""
    if not items:
        print("无匹配结果。")
        return

    # 按等级排序
    items = sorted(items, key=_sev_sort_key, reverse=True)

    header = ['编号', '类型', '等级', 'CVSS', '系统', '状态', '发现日期']
    rows = []
    for item in items:
        fm = item['fm']
        rows.append([
            item['id'],
            fm.get('type', '-'),
            fm.get('severity', '-').strip('"\''),
            fm.get('cvss_score', '-').strip('"\''),
            _format_systems(fm),
            fm.get('status', '-').strip('"\''),
            _format_date(fm),
        ])

    # 计算列宽
    col_widths = [len(h) for h in header]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))
    # 对系统和类型列限宽
    col_widths[1] = min(col_widths[1], 30)
    col_widths[4] = min(col_widths[4], 35)

    # 输出
    sep = '  '
    header_line = sep.join(h.ljust(col_widths[i]) for i, h in enumerate(header))
    print(f"\n查询条件: {_last_query_desc}")
    print(f"共 {len(items)} 条\n")
    print(header_line)
    print('-' * len(header_line))
    for row in rows:
        line = sep.join(
            (val[:col_widths[i]] if len(val) > col_widths[i] else val).ljust(col_widths[i])
            for i, val in enumerate(row)
        )
        print(line)
    print()


def output_markdown(items, output_path, query_desc):
    """输出到 Markdown 文件。"""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    items = sorted(items, key=_sev_sort_key, reverse=True)

    lines = [
        '---',
        f'title: 查询结果',
        f'query: "{query_desc}"',
        f'created: "{datetime.now().strftime("%Y-%m-%d %H:%M")}"',
        '---',
        '',
        f'## 查询结果（共 {len(items)} 条）',
        '',
        '| 编号 | 类型 | 等级 | CVSS | 系统 | 状态 | 发现日期 |',
        '|------|------|------|------|------|------|----------|',
    ]

    for item in items:
        fm = item['fm']
        systems = _format_systems(fm)
        sev = fm.get("severity", "-").strip('"').strip("'")
        cvss = fm.get("cvss_score", "-").strip('"').strip("'")
        st = fm.get("status", "-").strip('"').strip("'")
        lines.append(
            f'| [[{item["id"]}]] '
            f'| {fm.get("type", "-")} '
            f'| {sev} '
            f'| {cvss} '
            f'| {systems} '
            f'| {st} '
            f'| {_format_date(fm)} |'
        )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    print(f"已输出到: {output_path}（{len(items)} 条）")


# ---------------------------------------------------------------------------
# 命令行入口
# ---------------------------------------------------------------------------

_last_query_desc = ''


def _parse_date(s):
    return datetime.strptime(s, '%Y-%m-%d')


def main():
    global _last_query_desc

    parser = argparse.ArgumentParser(description='vlWiki 漏洞查询工具')
    parser.add_argument('--severity', '-s', help='等级过滤（紧急/高/中/低）')
    parser.add_argument('--status', help='状态过滤（待修复/修复中/已修复/已拒绝）')
    parser.add_argument('--system', help='系统名模糊匹配')
    parser.add_argument('--type', dest='vul_type', help='漏洞类型模糊匹配')
    parser.add_argument('--cve', help='CVE 编号匹配')
    parser.add_argument('--cve-has', action='store_true', help='仅列出有 CVE 的漏洞')
    parser.add_argument('--date-after', type=_parse_date, metavar='YYYY-MM-DD',
                        help='发现日期之后')
    parser.add_argument('--date-before', type=_parse_date, metavar='YYYY-MM-DD',
                        help='发现日期之前')
    parser.add_argument('--output', '-o', help='输出到 Markdown 文件')
    parser.add_argument('--dir', default=VULN_DIR,
                        help=f'VL 页面目录（默认: {VULN_DIR}）')

    args = parser.parse_args()
    _last_query_desc = _build_desc(args)

    # 加载
    items = load_all_vl(args.dir)
    if not items:
        print("未找到任何 VL 页面。")
        return

    # 过滤
    matched = filt(
        items,
        severity=args.severity,
        status=args.status,
        system=args.system,
        vul_type=args.vul_type,
        cve=args.cve,
        cve_has=args.cve_has,
        date_after=args.date_after,
        date_before=args.date_before,
    )

    # 输出
    if args.output:
        output_path = args.output
        # 相对路径基于 wiki/ 目录解析，避免受 CWD 影响
        if not os.path.isabs(output_path):
            output_path = os.path.join(WIKI_ROOT, output_path)
        output_markdown(matched, output_path, _last_query_desc)
    else:
        output_terminal(matched)


if __name__ == '__main__':
    main()
