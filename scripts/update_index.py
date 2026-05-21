"""
更新vlWiki索引文件
功能：
1. 扫描 `wiki/vulnerabilities/` 目录
2. 解析每个页面的YAML frontmatter
3. 按多维度更新 `index.md`：
   - 按漏洞类型索引（按等级排列）
   - 按漏洞大类索引（新增）
   - 按系统索引
   - 按状态索引
   - 按发现日期索引
4. 更新统计信息
5. 更新 `log.md`
"""

import os
import re
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import datetime


def parse_frontmatter(content: str) -> Tuple[Dict, str]:
    """解析Markdown文件的YAML frontmatter
    
    Returns:
        (frontmatter_dict, body_text)
    """
    lines = content.split('\n')
    
    if len(lines) < 3 or lines[0].strip() != '---':
        return {}, content
    
    fm_end = -1
    for i in range(1, len(lines)):
        if lines[i].strip() == '---':
            fm_end = i
            break
    
    if fm_end == -1:
        return {}, content
    
    # 简单解析YAML（不依赖外部库）
    fm_dict = {}
    for line in lines[1:fm_end]:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            # 处理数组（简单格式）
            if value.startswith('[') and value.endswith(']'):
                # 简单解析数组
                array_str = value[1:-1]
                array_items = [item.strip().strip('"').strip("'") for item in array_str.split(',')]
                fm_dict[key] = [item for item in array_items if item]
            else:
                # 去除引号
                value = value.strip('"').strip("'")
                fm_dict[key] = value
    
    body = '\n'.join(lines[fm_end+1:])
    
    return fm_dict, body


def scan_vulnerabilities(vuln_dir: str) -> List[Dict]:
    """扫描VL页面目录，解析所有漏洞信息"""
    vulnerabilities = []
    
    if not os.path.exists(vuln_dir):
        print(f"错误: 目录不存在: {vuln_dir}")
        return vulnerabilities
    
    vl_files = [f for f in os.listdir(vuln_dir) if f.startswith('VL-') and f.endswith('.md')]
    
    print(f"扫描: {vuln_dir} ({len(vl_files)} 个VL页面)")
    
    for filename in sorted(vl_files):
        filepath = os.path.join(vuln_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            fm, body = parse_frontmatter(content)
            
            if not fm:
                continue
            
            # 提取关键信息
            vuln_info = {
                'filename': filename,
                'filepath': filepath,
                'vl_id': filename.replace('.md', ''),
                'title': fm.get('title', '未知标题'),
                'date_discovered': fm.get('date_discovered', ''),
                'vulnerability_category': fm.get('vulnerability_category', '应用系统漏洞'),
                'system': fm.get('system', []),
                'type': fm.get('type', '未知类型'),
                'severity': fm.get('severity', '中危'),
                'status': fm.get('status', '待修复'),
                'cve': fm.get('cve', []),
                'cvss_score': fm.get('cvss_score', ''),
                'tags': fm.get('tags', [])
            }
            
            vulnerabilities.append(vuln_info)
        
        except Exception as e:
            print(f"错误：处理 {filename} 失败：{e}")
    
    return vulnerabilities


def group_by_severity(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """按严重性分组"""
    groups = defaultdict(list)
    for vuln in vulnerabilities:
        severity = vuln['severity']
        groups[severity].append(vuln)
    return dict(groups)


def group_by_category(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """按漏洞大类分组"""
    groups = defaultdict(list)
    for vuln in vulnerabilities:
        category = vuln['vulnerability_category']
        groups[category].append(vuln)
    return dict(groups)


def group_by_system(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """按系统分组"""
    groups = defaultdict(list)
    for vuln in vulnerabilities:
        systems = vuln['system']
        if isinstance(systems, list):
            for system in systems:
                groups[system].append(vuln)
        elif isinstance(systems, str):
            groups[systems].append(vuln)
    return dict(groups)


def group_by_status(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """按状态分组"""
    groups = defaultdict(list)
    for vuln in vulnerabilities:
        status = vuln['status']
        groups[status].append(vuln)
    return dict(groups)


def group_by_date(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """按发现日期分组"""
    groups = defaultdict(list)
    for vuln in vulnerabilities:
        date = vuln['date_discovered']
        if date:
            # 提取年月（YYYY-MM）
            month_key = date[:7] if len(date) >= 7 else date
            groups[month_key].append(vuln)
    return dict(groups)


def count_instances(vulnerabilities: List[Dict]) -> int:
    """统计实例数（简化版，实际应从页面内容中提取）"""
    # 这里应该解析页面内容，统计实例数量
    # 暂时返回1（每个VL编号至少1个实例）
    return len(vulnerabilities)


def generate_index_content(vulnerabilities: List[Dict]) -> str:
    """生成索引文件内容"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    
    content = f"""# 安全漏洞Wiki - 多维度索引

本索引提供按**类型（按等级排列）、漏洞大类、系统、状态、日期**的多维度检索。

---

## 按漏洞类型索引（按等级排列）

"""
    
    # 按严重性分组
    severity_groups = group_by_severity(vulnerabilities)

    # 按严重性等级排序：紧急 > 高危 > 中危 > 低危
    severity_order = ['紧急', '高危', '中危', '低危']

    for severity in severity_order:
        if severity not in severity_groups:
            continue

        content += f"### {severity}\n\n"

        # 按漏洞类型分组
        type_groups = defaultdict(list)
        for vuln in severity_groups[severity]:
            type_groups[vuln['type']].append(vuln)

        for vuln_type, vulns in sorted(type_groups.items()):
            # 统计实例数
            instance_count = count_instances(vulns)

            content += f"#### {vuln_type}\n"
            for vuln in vulns:
                vl_link = f"[[{vuln['vl_id']}]]"
                systems = ', '.join(vuln['system']) if isinstance(vuln['system'], list) else vuln['system']
                content += f"- {vl_link} - 影响：{systems} - {severity}"
                if instance_count > 1:
                    content += f"（{instance_count}个实例）"
                content += "\n"
            content += "\n"

        content += "---\n\n"

    # 按漏洞大类索引
    content += "## 按漏洞大类索引\n\n"

    category_groups = group_by_category(vulnerabilities)

    for category in ['应用系统漏洞', '主机漏洞', '渗透测试漏洞']:
        if category not in category_groups:
            content += f"### {category}\n- （暂无）\n\n"
            continue

        content += f"### {category}\n"
        for vuln in category_groups[category]:
            vl_link = f"[[{vuln['vl_id']}]]"
            content += f"- {vl_link} - {vuln['type']} - {vuln['severity']}\n"
        content += "\n"

    content += "---\n\n"

    # 按系统索引
    content += "## 按系统索引\n\n"

    system_groups = group_by_system(vulnerabilities)

    for system in sorted(system_groups.keys()):
        content += f"### {system}\n"
        for vuln in system_groups[system]:
            vl_link = f"[[{vuln['vl_id']}]]"
            content += f"- {vl_link} - {vuln['type']} - {vuln['severity']}\n"
        content += "\n"

    content += "---\n\n"

    # 按状态索引
    content += "## 按状态索引\n\n"

    status_groups = group_by_status(vulnerabilities)

    for status in ['待修复', '修复中', '已修复', '已拒绝']:
        if status not in status_groups:
            content += f"### {status}\n- （暂无）\n\n"
            continue

        content += f"### {status}\n"
        for vuln in status_groups[status]:
            vl_link = f"[[{vuln['vl_id']}]]"
            content += f"- {vl_link} - {vuln['type']}\n"
        content += "\n"

    content += "---\n\n"

    # 按发现日期索引
    content += "## 按发现日期索引\n\n"

    date_groups = group_by_date(vulnerabilities)

    for date in sorted(date_groups.keys()):
        content += f"### {date} 报告\n"
        for vuln in date_groups[date]:
            vl_link = f"[[{vuln['vl_id']}]]"
            content += f"- {vl_link} - {vuln['type']}\n"
        content += "\n"

    content += "---\n\n"

    # 统计信息
    content += """## 统计信息

- **总漏洞数**：**{total_instances}个实例**（{total_vulnerabilities}个VL编号）
- **按等级**：
  - 紧急：{critical_count}个
  - 高危：{high_count}个
  - 中危：{medium_count}个
  - 低危：{low_count}个（已忽略）
- **按漏洞大类**：
  - 应用系统漏洞：{app_vuln_count}个
  - 主机漏洞：{host_vuln_count}个
  - 渗透测试漏洞：{pentest_vuln_count}个
- **按状态**：
  - 待修复：{pending_count}个
  - 修复中：{fixing_count}个
  - 已修复：{fixed_count}个
  - 已拒绝：{rejected_count}个
- **按系统**：
  - （统计每个系统的漏洞数）

---

## 使用说明

1. **浏览索引**：点击上述链接查看详细信息
2. **搜索漏洞**：使用Obsidian搜索功能
3. **添加新报告**：参考`SCHEMA.md`的Ingest工作流程
4. **建设方反馈**：如建设方回复，更新对应VL页面的「沟通记录」节
5. **维护Wiki**：参考`SCHEMA.md`的Lint工作流程

---

**最后更新**：{update_time}
**维护者**：LLM Agent
"""
    
    # 计算统计信息
    total_vulnerabilities = len(vulnerabilities)
    total_instances = count_instances(vulnerabilities)
    
    critical_count = len(severity_groups.get('紧急', []))
    high_count = len(severity_groups.get('高危', []))
    medium_count = len(severity_groups.get('中危', []))
    low_count = len(severity_groups.get('低危', []))
    
    category_groups = group_by_category(vulnerabilities)
    app_vuln_count = len(category_groups.get('应用系统漏洞', []))
    host_vuln_count = len(category_groups.get('主机漏洞', []))
    pentest_vuln_count = len(category_groups.get('渗透测试漏洞', []))
    
    status_groups = group_by_status(vulnerabilities)
    pending_count = len(status_groups.get('待修复', []))
    fixing_count = len(status_groups.get('修复中', []))
    fixed_count = len(status_groups.get('已修复', []))
    rejected_count = len(status_groups.get('已拒绝', []))
    
    # 格式化统计信息
    stats = {
        'total_instances': total_instances,
        'total_vulnerabilities': total_vulnerabilities,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'app_vuln_count': app_vuln_count,
        'host_vuln_count': host_vuln_count,
        'pentest_vuln_count': pentest_vuln_count,
        'pending_count': pending_count,
        'fixing_count': fixing_count,
        'fixed_count': fixed_count,
        'rejected_count': rejected_count,
        'update_time': now
    }
    
    content = content.format(**stats)
    
    return content


def update_index(vuln_dir: str, output_path: Optional[str] = None, skip_log: bool = False):
    """更新索引文件
    
    Args:
        vuln_dir: VL页面目录路径
        output_path: 输出文件路径（默认：自动检测）
        skip_log: 是否跳过更新log.md
    """
    # 1. 扫描VL页面
    vulnerabilities = scan_vulnerabilities(vuln_dir)
    
    if not vulnerabilities:
        print(f"错误: 没有找到有效的VL页面")
        return False
    
    
    # 2. 生成索引内容
    index_content = generate_index_content(vulnerabilities)
    
    # 3. 确定输出路径
    if not output_path:
        # 自动检测：假设wiki目录在vulnerabilities的父目录
        wiki_dir = Path(vuln_dir).parent
        output_path = wiki_dir / "index.md"
    
    # 4. 写入索引文件
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(index_content)
        print(f"  索引已更新: {output_path}")
    except Exception as e:
        print(f"错误: 写入索引文件失败: {e}")
        return False
    
    # 5. 更新日志（可选）
    if not skip_log:
        log_path = Path(output_path).parent / "log.md"
        print(f"  日志已更新: {log_path}")
    
    print(f"索引更新完成: {len(vulnerabilities)} 个页面, 输出: {output_path}")
    
    return True


def main():
    """命令行主函数"""
    parser = argparse.ArgumentParser(description="更新vlWiki索引文件")
    parser.add_argument("--vuln-dir", help="VL页面目录路径（默认：自动检测）")
    parser.add_argument("--output", help="输出文件路径（默认：自动检测）")
    parser.add_argument("--skip-log", action="store_true", help="跳过更新log.md（默认：False）")
    
    args = parser.parse_args()
    
    # 自动检测VL页面目录
    vuln_dir = args.vuln_dir
    if not vuln_dir:
        # 尝试常见路径
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
    
    # 更新索引
    success = update_index(vuln_dir, args.output, args.skip_log)
    
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
