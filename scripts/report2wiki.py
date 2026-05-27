"""
一键转换：AppScan PDF 报告 → 知识库实体

工作流：
  [AppScan PDF 报告] → report2wiki.py → [VL 页面 .md]

内部流程：
  阶段1: appscanpdf2json.py  → 标准中间 JSON
  阶段2: json2wiki.py        → VL 页面 (.md)

使用：
  python report2wiki.py "报告.pdf" [--no-skip-low] [--vl-start <n>]
"""

import sys
import argparse
from pathlib import Path

# 添加 vlWiki scripts 目录到路径
skill_dir = Path(__file__).parent.parent
sys.path.insert(0, str(skill_dir))

from appscanpdf2json import convert_report
from json2wiki import generate_wiki_pages


def convert(file_path: str, skip_low: bool = True, vl_start: int = None) -> dict:
    """一键完成阶段1+2：PDF → VL 页面

    Args:
        file_path: PDF 文件路径
        skip_low: 是否跳过低危
        vl_start: VL 起始编号

    Returns:
        json2wiki 的结果字典
    """
    # 阶段1：PDF → JSON
    print("=" * 50)
    print("阶段1：PDF → 中间 JSON")
    print("=" * 50)
    json_path = convert_report(file_path=file_path, skip_low=skip_low)

    # 阶段2：JSON → VL 页面
    print("\n" + "=" * 50)
    print("阶段2：中间 JSON → VL 页面")
    print("=" * 50)
    result = generate_wiki_pages(json_path=json_path, vl_start=vl_start)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="一键：AppScan PDF → 知识库 VL 页面"
    )
    parser.add_argument("file_path", help="AppScan PDF 报告文件路径")
    parser.add_argument(
        "--skip-low", action="store_true", default=True,
        help="跳过低危漏洞（默认）"
    )
    parser.add_argument(
        "--no-skip-low", action="store_false", dest="skip_low",
        help="包含低危漏洞"
    )
    parser.add_argument(
        "--vl-start", type=int,
        help="VL 起始编号（如 25 → VL-2026-025）"
    )

    args = parser.parse_args()

    result = convert(
        file_path=args.file_path,
        skip_low=args.skip_low,
        vl_start=args.vl_start,
    )

    print(f"\n所有步骤完成: {len(result['generated_files'])} 个 VL 页面已生成")
    return result


if __name__ == "__main__":
    main()
