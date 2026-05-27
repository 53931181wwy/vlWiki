"""
阶段2：中间 JSON → 知识库实体（VL 页面、系统页面）

工作流位置：
  [标准中间 JSON] → json2wiki.py → [VL 页面 .md + 系统页面 .md]

职责：
  1. 读取阶段1 生成的标准中间 JSON
  2. 调用 vl_exporter 为每个漏洞类型生成 VL 页面（Markdown + YAML frontmatter）
  3. 生成/更新系统信息页面（后续扩展）

使用：
  python json2wiki.py "<json路径>" [--output-dir <dir>] [--wiki-dir <dir>] [--vl-start <n>]
"""

import sys
import json
import argparse
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# 添加 vlWiki scripts 目录到路径
skill_dir = Path(__file__).parent.parent
sys.path.insert(0, str(skill_dir))

from utils import get_next_vl_id, VULN_DIR, WIKI_ROOT
from vl_exporter import generate_vulnerability_page


# ── JSON 读取 ─────────────────────────────────────────────────────

def load_intermediate_json(json_path: str) -> Dict:
    """读取标准中间 JSON"""
    jp = Path(json_path)
    if not jp.exists():
        print(f"错误: JSON 文件不存在: {json_path}")
        sys.exit(1)

    with open(jp, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 基本校验
    meta = data.get('meta', {})
    if not meta or 'types' not in data:
        print(f"错误: 无效的中间 JSON 格式")
        sys.exit(1)

    print(f"已加载 JSON: {meta.get('total_instances', 0)} 个实例, "
          f"{meta.get('vulnerability_types', 0)} 个类型, "
          f"系统: {meta.get('system', '未知')}")

    return data


# ── 路径解析 ──────────────────────────────────────────────────────

def resolve_dirs(output_dir: Optional[str] = None, wiki_dir: Optional[str] = None):
    """解析输出目录和 wiki 根目录，未指定时使用默认常量。"""
    if not output_dir:
        output_dir = VULN_DIR
    if not wiki_dir:
        wiki_dir = WIKI_ROOT
    return output_dir, wiki_dir


def resolve_pdf_path(meta: Dict, wiki_dir: str) -> Optional[str]:
    """解析 PDF 路径，用于截图和报告链接

    优先级：
      1. meta.source_path（阶段1 时记录的绝对路径）
      2. wiki/raw/ 目录下查找同名 PDF
    """
    # 优先使用记录的绝对路径
    source_path = meta.get('source_path', '')
    if source_path and Path(source_path).exists():
        return source_path

    # 尝试在 wiki/raw/ 目录查找
    source_file = meta.get('source_file', '')
    if wiki_dir and source_file:
        raw_dir = Path(wiki_dir) / "raw"
        candidate = raw_dir / source_file
        if candidate.exists():
            return str(candidate)

        # 尝试不带扩展名匹配（如 .pdf .xml）
        stem = Path(source_file).stem
        for ext in ['.pdf', '.xml', '.html', '.docx']:
            candidate = raw_dir / (stem + ext)
            if candidate.exists():
                return str(candidate)

    print(f"警告: 未找到原始报告文件 ({source_file})，跳过截图生成")
    return None


# ── 日期提取 ──────────────────────────────────────────────────────

def extract_report_date(meta: Dict) -> str:
    """从 meta 中提取报告日期/扫描开始时间（完整日期时间字符串）。

    优先级：
      1. meta.report_date（parser 从 PDF 正文提取的「扫描开始时间」）
      2. 从文件名提取日期格式
      3. parse_date 日期部分
      4. 空字符串（调用方自行兜底）
    """
    # 1. parser 提取的扫描开始时间（最准确）
    report_date = meta.get('report_date', '')
    if report_date:
        return report_date

    # 2. 从文件名提取日期
    source_file = meta.get('source_file', '')
    date_match = re.search(r'(\d{2,4})[-_](\d{1,2})[-_](\d{1,2})', source_file)
    if date_match:
        year, month, day = date_match.groups()
        if len(year) == 2:
            year = f"20{year}"
        return f"{year}-{month.zfill(2)}-{day.zfill(2)}"

    # 3. 从 parse_date 取日期部分
    parse_date = meta.get('parse_date', '')
    if parse_date:
        return parse_date[:10]

    return ""


# ── 主函数 ────────────────────────────────────────────────────────

def generate_wiki_pages(
    json_path: str,
    output_dir: Optional[str] = None,
    wiki_dir: Optional[str] = None,
    vl_start: Optional[int] = None,
) -> Dict:
    """阶段2：从中间 JSON 生成知识库实体

    Args:
        json_path: 标准中间 JSON 文件路径
        output_dir: VL 页面输出目录（默认：自动检测）
        wiki_dir: wiki 根目录（默认：自动检测）
        vl_start: VL 起始编号

    Returns:
        处理结果统计
    """
    # 1. 读取 JSON
    data = load_intermediate_json(json_path)
    meta = data['meta']
    types = data['types']

    # 2. 解析目录
    output_dir, wiki_dir = resolve_dirs(output_dir, wiki_dir)

    # 3. 解析 PDF 路径（用于截图）
    pdf_path = resolve_pdf_path(meta, wiki_dir)

    # 4. 提取日期
    report_date = extract_report_date(meta)

    # 5. 确定起始 VL 编号
    if vl_start is not None:
        current_vl_num = vl_start
    else:
        last_vl_id = get_next_vl_id(output_dir)
        current_vl_num = int(last_vl_id.split('-')[-1])

    # 6. 为每个漏洞类型生成页面
    generated_files = []
    year = datetime.now().year

    for vuln_type in types:
        vl_id = f"VL-{year}-{current_vl_num:03d}"
        current_vl_num += 1

        filepath = generate_vulnerability_page(
            vuln_type, output_dir, report_date, vl_id,
            pdf_path=pdf_path or '', wiki_dir=wiki_dir,
            system_name=meta.get('system', '未知系统'),
            vuln_category=meta.get('vul_category', '应用系统漏洞'),
        )
        generated_files.append(filepath)

    result = {
        'success': True,
        'total_instances': meta.get('total_instances', 0),
        'vulnerability_types': meta.get('vulnerability_types', 0),
        'generated_files': generated_files,
        'system': meta.get('system', '未知'),
        'vul_category': meta.get('vul_category', '应用系统漏洞'),
    }

    print(f"\n阶段2完成: {result['total_instances']} 个实例, "
          f"{result['vulnerability_types']} 个类型, "
          f"{len(result['generated_files'])} 个文件")
    print(f"下一步: python update_index.py")

    return result


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description="阶段2：中间 JSON → 知识库实体（VL 页面）"
    )
    parser.add_argument("json_path", help="标准中间 JSON 文件路径")
    parser.add_argument(
        "--output-dir",
        help="VL 页面输出目录（默认：自动检测 wiki/vulnerabilities/）"
    )
    parser.add_argument(
        "--wiki-dir",
        help="wiki 根目录（默认：自动检测 wiki/）"
    )
    parser.add_argument(
        "--vl-start", type=int,
        help="VL 起始编号（如 25 → VL-2026-025）"
    )

    args = parser.parse_args()

    result = generate_wiki_pages(
        json_path=args.json_path,
        output_dir=args.output_dir,
        wiki_dir=args.wiki_dir,
        vl_start=args.vl_start,
    )

    return result


if __name__ == "__main__":
    main()
