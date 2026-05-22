"""
更新vlWiki索引文件
功能：
1. 扫描 `wiki/vulnerabilities/` 目录
2. 解析每个页面的YAML frontmatter（支持多行数组格式）
3. 按多维度更新 `index.md`：
   - 按漏洞类型索引（按等级排列）
   - 按漏洞大类索引
   - 按系统索引
   - 按状态索引
   - 按发现日期索引
4. 更新统计信息
5. 更新 `log.md`
"""

import os
import re
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import datetime


# ---------------------------------------------------------------------------
# YAML frontmatter 解析（支持多行列表格式）
# ---------------------------------------------------------------------------

def parse_frontmatter(content: str) -> Tuple[Dict, str]:
    """解析 Markdown 文件的 YAML frontmatter

    Returns:
        (frontmatter_dict, body_text)
    """
    lines = content.split('\n')
    if len(lines) < 3 or lines[0].strip() != '---':
        return {}, content

    # 找 closing ---
    fm_end = -1
    for i in range(1, len(lines)):
        if lines[i].strip() == '---':
            fm_end = i
            break
    if fm_end == -1:
        return {}, content

    fm_dict: Dict = {}
    i = 1
    while i < fm_end:
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            i += 1
            continue
        if ':' in stripped:
            key, rest = stripped.split(':', 1)
            key = key.strip()
            rest = rest.strip()
            # 行内 YAML 数组: ["a", "b"]
            if rest.startswith('[') and rest.endswith(']'):
                inner = rest[1:-1]
                items = [it.strip().strip('"').strip("'") for it in inner.split(',')]
                fm_dict[key] = [it for it in items if it]
                i += 1
                continue
            # 多行列表: 下一行开始以 "- " 开头
            if rest == '' and i + 1 < fm_end:
                next_stripped = lines[i + 1].strip()
                if next_stripped.startswith('- '):
                    lst = []
                    i += 1
                    while i < fm_end:
                        item_line = lines[i].strip()
                        if item_line.startswith('- '):
                            val = item_line[2:].strip().strip('"').strip("'")
                            lst.append(val)
                            i += 1
                        else:
                            break
                    fm_dict[key] = lst
                    continue
            # 普通标量
            fm_dict[key] = rest.strip('"').strip("'")
            i += 1
            continue
        i += 1

    body = '\n'.join(lines[fm_end + 1:])
    return fm_dict, body


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

SEVERITY_RANK = {'紧急': 0, '高': 1, '中': 2, '低': 3, '信息': 4, '提示': 4, '未知': 5}


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
                'vulnerability_category': fm.get('vulnerability_category', '应用系统漏洞'),
                'system': system,
                'type': fm.get('type', '未知类型'),
                'severity': fm.get('severity', '中'),
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
        g[v['vulnerability_category']].append(v)
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


def group_by_date(vulns: List[Dict]) -> Dict[str, List[Dict]]:
    g = defaultdict(list)
    for v in vulns:
        d = v['date_discovered']
        if d:
            key = d[:7] if len(d) >= 7 else d
            g[key].append(v)
    return dict(g)


# ---------------------------------------------------------------------------
# 生成索引内容
# ---------------------------------------------------------------------------

def generate_index_content(vulnerabilities: List[Dict]) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d")
    now_full = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    severity_groups = group_by_severity(vulnerabilities)

    sorted_severities = sorted(
        severity_groups.keys(),
        key=lambda s: SEVERITY_RANK.get(s, 99)
    )

    # ---- 按类型索引 ----
    type_index_lines = []
    for sev in sorted_severities:
        vulns = severity_groups[sev]
        type_index_lines.append(f"### {sev}\n\n")
        type_groups = defaultdict(list)
        for v in vulns:
            type_groups[v['type']].append(v)
        for vuln_type in sorted(type_groups.keys()):
            items = type_groups[vuln_type]
            type_index_lines.append(f"#### {vuln_type}\n")
            for v in items:
                sys_str = '、'.join(f"[[{s}]]" for s in v['system'])
                suffix = f"（{v['instance_count']}个实例）" if v['instance_count'] > 1 else ""
                type_index_lines.append(
                    f"- [[{v['vl_id']}]] - 影响：{sys_str} - {sev}{suffix}\n"
                )
            type_index_lines.append("\n")
        type_index_lines.append("---\n\n")

    # ---- 按大类索引 ----
    category_lines = ["## 按漏洞大类索引\n\n"]
    category_groups = group_by_category(vulnerabilities)
    for cat in ['应用系统漏洞', '主机漏洞', '渗透测试漏洞']:
        items = category_groups.get(cat, [])
        category_lines.append(f"### {cat}\n")
        if not items:
            category_lines.append("- （暂无）\n\n")
            continue
        for v in items:
            category_lines.append(f"- [[{v['vl_id']}]] - {v['type']} - {v['severity']}\n")
        category_lines.append("\n")

    # ---- 按系统索引 ----
    system_lines = ["## 按系统索引\n\n"]
    system_groups = group_by_system(vulnerabilities)
    for sys_name in sorted(system_groups.keys()):
        items = system_groups[sys_name]
        system_lines.append(f"### [[{sys_name}]]\n")
        for v in items:
            system_lines.append(f"- [[{v['vl_id']}]] - {v['type']} - {v['severity']}\n")
        system_lines.append("\n")

    # ---- 按状态索引 ----
    status_lines = ["## 按状态索引\n\n"]
    status_groups = group_by_status(vulnerabilities)
    for st in ['待修复', '修复中', '已修复', '已拒绝']:
        items = status_groups.get(st, [])
        status_lines.append(f"### {st}\n")
        if not items:
            status_lines.append("- （暂无）\n\n")
            continue
        for v in items:
            status_lines.append(f"- [[{v['vl_id']}]] - {v['type']}\n")
        status_lines.append("\n")

    # ---- 按日期索引 ----
    date_lines = ["## 按发现日期索引\n\n"]
    date_groups = group_by_date(vulnerabilities)
    for d in sorted(date_groups.keys()):
        items = date_groups[d]
        date_lines.append(f"### {d} 报告\n")
        for v in items:
            date_lines.append(f"- [[{v['vl_id']}]] - {v['type']}\n")
        date_lines.append("\n")

    # ---- 统计 ----
    total_vulns = len(vulnerabilities)
    total_instances = sum(v['instance_count'] for v in vulnerabilities)

    def _count(sev: str) -> int:
        return len(severity_groups.get(sev, []))

    cat_g = group_by_category(vulnerabilities)
    sta_g = group_by_status(vulnerabilities)
    sys_g = group_by_system(vulnerabilities)

    stats_lines = [
        "## 统计信息\n\n",
        f"- **总漏洞数**：**{total_instances}个实例**（{total_vulns}个VL编号）\n",
        "- **按等级**：\n",
        f"  - 紧急：{_count('紧急')}个\n",
        f"  - 高危：{_count('高')}个\n",
        f"  - 中危：{_count('中')}个\n",
        f"  - 低危：{_count('低')}个\n",
        "- **按漏洞大类**：\n",
        f"  - 应用系统漏洞：{len(cat_g.get('应用系统漏洞', []))}个\n",
        f"  - 主机漏洞：{len(cat_g.get('主机漏洞', []))}个\n",
        f"  - 渗透测试漏洞：{len(cat_g.get('渗透测试漏洞', []))}个\n",
        "- **按状态**：\n",
        f"  - 待修复：{len(sta_g.get('待修复', []))}个\n",
        f"  - 修复中：{len(sta_g.get('修复中', []))}个\n",
        f"  - 已修复：{len(sta_g.get('已修复', []))}个\n",
        f"  - 已拒绝：{len(sta_g.get('已拒绝', []))}个\n",
        "- **按系统**：\n",
    ]
    for sys_name in sorted(sys_g.keys()):
        stats_lines.append(f"  - [[{sys_name}]]：{len(sys_g[sys_name])}个\n")
    stats_lines.append("\n---\n\n")
    stats_lines.append("## 使用说明\n\n")
    stats_lines.append("1. **浏览索引**：点击上述链接查看详细信息\n")
    stats_lines.append("2. **搜索漏洞**：使用Obsidian搜索功能\n")
    stats_lines.append("3. **添加新报告**：运行 `import_report.py`\n")
    stats_lines.append("4. **建设方反馈**：更新对应VL页面的「沟通记录」节\n")
    stats_lines.append("\n---\n\n")
    stats_lines.append(f"**最后更新**：{now_full}\n")
    stats_lines.append("**维护者**：LLM Agent\n")

    frontmatter = (
        "---\n"
        f"title: 安全漏洞Wiki - 多维度索引\n"
        f"type: index\n"
        f"tags: [index, wiki, 漏洞管理]\n"
        f"last_updated: {now}\n"
        "---\n\n"
    )

    full = (
        frontmatter
        + "# 安全漏洞Wiki - 多维度索引\n\n"
        "本索引提供按**类型（按等级排列）、漏洞大类、系统、状态、日期**的多维度检索。\n\n"
        "---\n\n"
        "## 按漏洞类型索引（按等级排列）\n\n"
        + ''.join(type_index_lines)
        + ''.join(category_lines)
        + "---\n\n"
        + ''.join(system_lines)
        + "---\n\n"
        + ''.join(status_lines)
        + "---\n\n"
        + ''.join(date_lines)
        + "---\n\n"
        + ''.join(stats_lines)
    )
    return full


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
        possible_paths = [
            "D:/Users/个人项目/wb/vlWiki/wiki/vulnerabilities",
            str(Path.home() / "vlWiki/wiki/vulnerabilities")
        ]
        for path in possible_paths:
            if Path(path).exists():
                vuln_dir = path
                break
        else:
            print("错误：无法自动检测VL页面目录，请使用 --vuln-dir 参数指定")
            parser.print_help()
            return

    success = update_index(vuln_dir, args.output, args.skip_log)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
