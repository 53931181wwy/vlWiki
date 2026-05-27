"""
更新vlWiki索引文件
功能：
1. 扫描 `wiki/vulnerabilities/` 目录
2. 解析每个页面的YAML frontmatter（支持多行数组格式）
3. 生成 `index.md`：
   - 仪表盘：等级分布+状态概览（置顶）
   - 完整漏洞列表表格（按严重性→CVSS排序，含大类/系统/实例数/状态）
   - 按系统/状态/日期索引（紧凑表格）
   - Dataview 动态查询块（可选）
4. 更新 `log.md`（含自动轮转）
"""

import os
import re
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import datetime

from utils import parse_frontmatter, VULN_DIR


# ---------------------------------------------------------------------------
# 实例数统计
# ---------------------------------------------------------------------------

def count_instances_from_body(body: str) -> int:
    """从页面正文中的 `## 受影响实例` 表格统计实例数"""
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


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------

SEVERITY_RANK = {'紧急': 0, '高危': 1, '中危': 2, '低危': 3, '信息': 4, '提示': 4, '未知': 5}

SEVERITY_ALIAS = {
    '紧急': '紧急', '严重': '紧急',
    '高危': '高危', '高': '高危',
    '中危': '中危', '中': '中危', 
}


def _normalize_severity(severity: str) -> str:
    """标准化 severity，兼容 中/中危 等缩写写法"""
    return SEVERITY_ALIAS.get(severity, severity)


def scan_vulnerabilities(vuln_dir: str) -> List[Dict]:
    """扫描 VL 页面目录，解析所有漏洞信息"""
    vulnerabilities = []
    if not os.path.exists(vuln_dir):
        print(f"错误: 目录不存在: {vuln_dir}")
        return vulnerabilities

    vl_files = sorted(
        f for f in os.listdir(vuln_dir) if f.startswith('VL-') and f.endswith('.md')
    )
    print(f"扫描: {vuln_dir} ({len(vl_files)} 个VL页面)")

    for filename in vl_files:
        filepath = os.path.join(vuln_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            fm, body = parse_frontmatter(content)
            if not fm:
                continue

            system = fm.get('system', [])
            if isinstance(system, str):
                system = [system] if system else []

            vuln_info = {
                'filename': filename,
                'filepath': filepath,
                'vl_id': filename.replace('.md', ''),
                'title': fm.get('title', '未知标题'),
                'date_discovered': fm.get('date_discovered', ''),
                'vul_category': fm.get('vul_category', '应用系统漏洞'),
                'system': system,
                'type': fm.get('type', '未知类型'),
                'severity': _normalize_severity(fm.get('severity', '中')),
                'severity_order': fm.get('severity_order', 0),
                'status': fm.get('status', '待修复'),
                'cve': fm.get('cve', []),
                'cwe': fm.get('cwe', []),
                'cvss_score': fm.get('cvss_score', ''),
                'tags': fm.get('tags', []),
                'instance_count': count_instances_from_body(body),
            }
            vulnerabilities.append(vuln_info)
        except Exception as e:
            print(f"错误：处理 {filename} 失败：{e}")

    return vulnerabilities


# ---------------------------------------------------------------------------
# 分组工具
# ---------------------------------------------------------------------------

def group_by_severity(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        g[v['severity']].append(v)
    return dict(g)


def group_by_category(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        g[v['vul_category']].append(v)
    return dict(g)


def group_by_system(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        for s in v['system']:
            g[s].append(v)
    return dict(g)


def group_by_status(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        g[v['status']].append(v)
    return dict(g)


def _bar(count: int, max_count: int, width: int = 10) -> str:
    """生成简易进度条"""
    filled = round(count / max(max_count, 1) * width)
    return '█' * filled + '░' * (width - filled)


# ---------------------------------------------------------------------------
# 生成索引内容
# ---------------------------------------------------------------------------

def generate_index_content(vulnerabilities: List[Dict]) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d")
    now_full = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    severity_groups = group_by_severity(vulnerabilities)
    cat_g = group_by_category(vulnerabilities)
    sta_g = group_by_status(vulnerabilities)
    sys_g = group_by_system(vulnerabilities)

    total_vulns = len(vulnerabilities)
    total_instances = sum(v['instance_count'] for v in vulnerabilities)

    def _count(sev: str) -> int:
        return len(severity_groups.get(sev, []))

    # ---- 排序：severity_order 降序 → CVSS 降序 ----
    sorted_vulns = sorted(vulnerabilities, key=lambda v: (
        -_parse_severity_order(v.get('severity_order', 0)),
        -_parse_cvss(v.get('cvss_score', ''))
    ))

    # =========================================================================
    # 1. 仪表盘（置顶）
    # =========================================================================
    sev_order = ['紧急', '高危', '中危']
    sev_cells = []
    max_sev = max((_count(s) for s in sev_order), default=1)
    for s in sev_order:
        cnt = _count(s)
        bar = _bar(cnt, max_sev)
        sev_cells.append(f"**{s}** {cnt}  {bar}")

    status_summary = []
    for st in ['待修复', '修复中', '已修复', '已拒绝']:
        cnt = len(sta_g.get(st, []))
        if cnt > 0:
            status_summary.append(f"**{st}** {cnt}")
        else:
            status_summary.append(f"_{st}_ 0")

    dashboard = f"""> **总览**：{total_vulns} 个漏洞类型 · {total_instances} 个实例
>
> {' | '.join(sev_cells)}
>
> {' · '.join(status_summary)}
>
> 涉及 **{len(sys_g)}** 个系统 · 最后更新 {now_full}"""

    # =========================================================================
    # 2. 完整漏洞列表（表格）
    # =========================================================================
    table_lines = [
        "## 完整漏洞列表",
        "> 按严重性排序，同类严重性按 CVSS 降序",
        "",
        "| VL编号 | 漏洞类型 | 等级 | CVSS | 大类 | 影响系统 | 实例 | 状态 |",
        "|--------|---------|------|------|------|---------|------|------|",
    ]
    for v in sorted_vulns:
        cvss = v.get('cvss_score', '') or '-'
        category = v.get('vul_category', '应用系统漏洞')
        sys_str = '、'.join(f"[[{s}]]" for s in v['system'])
        instances = v['instance_count']

        table_lines.append(
            f"| [[{v['vl_id']}]] | {v['type']} | {v['severity']} | {cvss} | {category} | {sys_str} | {instances} | {v['status']} |"
        )
    table_lines.append("")

    # =========================================================================
    # 3. 按类型索引（表格 + CVSS 排序）
    # =========================================================================
    type_section = ["## 按类型索引", ""]
    for cat in sorted(cat_g.keys()):
        items = cat_g[cat]
        type_section.append(f"### {cat}（{len(items)}）")
        type_section.append("")
        sorted_items = sorted(
            items,
            key=lambda v: (-_parse_severity_order(v.get('severity_order', 0)), -_parse_cvss(v.get('cvss_score', '')))
        )
        type_section.append("| VL编号 | 漏洞类型 | 等级 | CVSS | 影响系统 | 状态 |")
        type_section.append("|--------|---------|------|------|---------|------|")
        for v in sorted_items:
            cvss = v.get('cvss_score', '') or '-'
            sys_str = '、'.join(f"[[{s}]]" for s in v['system'])
            type_section.append(
                f"| [[{v['vl_id']}]] | {v['type']} | {v['severity']} | {cvss} | {sys_str} | {v['status']} |"
            )
        type_section.append("")

    # =========================================================================
    # 4. 按系统索引
    # =========================================================================
    system_section = ["## 按系统索引", ""]
    for sys_name in sorted(sys_g.keys()):
        items = sys_g[sys_name]
        system_section.append(f"### [[{sys_name}]] ({len(items)})")
        system_section.append("")
        # 用紧凑表格
        system_section.append("| VL编号 | 漏洞类型 | 等级 | 状态 |")
        system_section.append("|--------|---------|------|------|")
        for v in items:
            system_section.append(
                f"| [[{v['vl_id']}]] | {v['type']} | {v['severity']} | {v['status']} |"
            )
        system_section.append("")

    # =========================================================================
    # 5. Dataview 动态视图（如果用户启用了 Dataview 插件）
    # =========================================================================
    dataview_section = [
        "## 动态视图",
        "",
        "> 如果安装了 [Dataview](https://github.com/blacksmithgu/obsidian-dataview) 插件，以下代码块会自动更新。",
        "",
        "### 高危待修复",
        "",
        "```dataview",
        "TABLE severity, cvss_score, system, date_discovered",
        'FROM "wiki/vulnerabilities"',
        'WHERE severity_order >= 4 AND status = "待修复"',
        "SORT severity_order DESC, cvss_score DESC",
        "```",
        "",
        "### 全部漏洞",
        "",
        "```dataview",
        "TABLE severity, cvss_score, status, date_discovered",
        'FROM "wiki/vulnerabilities"',
        "SORT severity_order DESC, cvss_score DESC",
        "```",
        "",
    ]

    # =========================================================================
    # 组装（统一用 '\n'.join，确保表格每行正确换行）
    # =========================================================================
    def _clean(lines: list) -> list:
        """去掉每个元素末尾多余的换行符，统一由 join 控制"""
        return [l.rstrip('\n') for l in lines]

    frontmatter = (
        "---\n"
        f"title: 安全漏洞Wiki - 多维度索引\n"
        f"type: index\n"
        f"tags: [index, wiki, 漏洞管理]\n"
        f"last_updated: {now}\n"
        "---\n"
    )

    parts = [
        frontmatter,
        "# 安全漏洞",
        "",
        dashboard.rstrip("\n"),
        "本索引提供按类型（按等级排列）、漏洞大类、系统的多维度检索。",
       
        "---",
        "\n".join(_clean(table_lines)),
        "---",
        "\n".join(_clean(type_section)),
        "---",
        "\n".join(_clean(system_section)),
        "---",
        "\n".join(_clean(dataview_section)),
        f"> **最后更新**：{now_full} · **维护者**：LLM Agent",
    ]

    full = "\n".join(parts) + "\n"
    return full


def _parse_severity_order(value) -> int:
    """解析 severity_order 为整数，兼容 YAML 字符串类型"""
    if value is None:
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _parse_cvss(cvss_str: str) -> float:
    """解析 CVSS 字符串为浮点数，用于排序"""
    if not cvss_str:
        return 0.0
    try:
        return float(cvss_str)
    except (ValueError, TypeError):
        return 0.0


# ---------------------------------------------------------------------------
# 更新 log.md
# ---------------------------------------------------------------------------

# log.md 轮转配置
MAX_LOG_LINES = 800       # 超过此行数触发轮转
KEEP_LOG_HEADER = 80      # 保留文件头部行数（标题 + 格式说明 + 分隔符）
KEEP_LOG_RECENT = 500     # 保留最近的条目行数


def update_log(vuln_dir: str, vulnerabilities: List[Dict]) -> None:
    """将本次更新的 VL 列表写入 log.md（追加 + 轮转）"""
    wiki_dir = Path(vuln_dir).parent
    log_path = wiki_dir / "log.md"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    new_lines = [f"\n## 更新记录 {now}\n"]
    for v in vulnerabilities:
        new_lines.append(f"- [[{v['vl_id']}]] - {v['type']} - {v['severity']}\n")

    try:
        # 追加新记录
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(''.join(new_lines))

        # 轮转：超过上限时截断
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
            print(f"  日志已更新: {log_path}")
    except Exception as e:
        print(f"  警告: 写入日志失败: {e}")


# ---------------------------------------------------------------------------
# 公开接口
# ---------------------------------------------------------------------------

def update_index(vuln_dir: str, output_path: Optional[str] = None, skip_log: bool = False) -> bool:
    """更新索引文件

    Args:
        vuln_dir: VL页面目录路径
        output_path: 输出文件路径（默认：自动检测）
        skip_log: 是否跳过更新 log.md
    """
    vulnerabilities = scan_vulnerabilities(vuln_dir)
    if not vulnerabilities:
        print("错误: 没有找到有效的VL页面")
        return False

    index_content = generate_index_content(vulnerabilities)

    if not output_path:
        wiki_dir = Path(vuln_dir).parent
        output_path = wiki_dir / "index.md"

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(index_content)
        print(f"  索引已更新: {output_path}")
    except Exception as e:
        print(f"错误: 写入索引文件失败: {e}")
        return False

    if not skip_log:
        update_log(vuln_dir, vulnerabilities)

    print(f"索引更新完成: {len(vulnerabilities)} 个页面, 输出: {output_path}")
    return True


# ---------------------------------------------------------------------------
# 命令行入口
# ---------------------------------------------------------------------------

def main():
    """命令行主函数"""
    parser = argparse.ArgumentParser(description="更新vlWiki索引文件")
    parser.add_argument("--vuln-dir", help="VL页面目录路径（默认：自动检测）")
    parser.add_argument("--output", help="输出文件路径（默认：自动检测）")
    parser.add_argument("--skip-log", action="store_true", help="跳过更新log.md（默认：False）")

    args = parser.parse_args()

    vuln_dir = args.vuln_dir
    if not vuln_dir:
        if Path(VULN_DIR).exists():
            vuln_dir = VULN_DIR
        else:
            print(f"错误：默认VL页面目录不存在 ({VULN_DIR})，请使用 --vuln-dir 参数指定")
            parser.print_help()
            return

    success = update_index(vuln_dir, args.output, args.skip_log)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
