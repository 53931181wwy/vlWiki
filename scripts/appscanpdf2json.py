"""
阶段1：AppScan PDF 报告 → 中间 JSON

工作流位置：
  [AppScan PDF 报告] → appscanpdf2json.py → [标准中间 JSON]

职责：
  1. 使用 document-reader 提取 PDF 文本 → 输出 fulltxt.txt
  2. 调用 appscan_pdf 解析器
  3. 输出标准中间 JSON 到输入文件所在目录

使用：
  python appscanpdf2json.py "报告.pdf" [--skip-low] [--output-dir <dir>]
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

# 添加 vlWiki scripts 目录到路径
skill_dir = Path(__file__).parent.parent
sys.path.insert(0, str(skill_dir))

# 添加 document-reader 路径（PDF 提取）
doc_reader_scripts = Path.home() / ".codebuddy/skills/document-reader/scripts"
sys.path.insert(0, str(doc_reader_scripts))

from parsers import get_parser

PARSER_KEY = "appscan_pdf"


# ── PDF 文本提取 ─────────────────────────────────────────────────

def extract_pdf_text(file_path: str, save_fulltxt: bool = True) -> str:
    """使用 document-reader 提取 PDF 文本

    Args:
        file_path: PDF 文件路径
        save_fulltxt: 是否保存 fulltxt.txt（用于调试）

    Returns:
        带页码标签的完整文本
    """
    try:
        import pdf_extract
    except ImportError as e:
        print(f"错误: 无法导入 pdf_extract: {e}")
        print("  请确保 document-reader skill 已正确安装")
        sys.exit(1)

    result_pymupdf = pdf_extract.extract_pymupdf(file_path)
    if not result_pymupdf.get('success'):
        print(f"错误: PyMuPDF 提取失败: {result_pymupdf.get('error', '未知')}")
        sys.exit(1)

    pages = result_pymupdf.get('pages', [])
    full_text = "\n\n".join(
        [f"[VLWIKI_PAGE_SEPARATOR:{page['page']}]\n{page['text']}" for page in pages]
    )
    print(f"文本提取完成: {len(pages)} 页")

    # 输出 fulltxt.txt
    if save_fulltxt:
        pdf_dir = Path(file_path).parent
        fulltxt_path = pdf_dir / f"{Path(file_path).stem}_fulltxt.txt"
        fulltxt_path.write_text(full_text, encoding='utf-8')
        print(f"完整文本已输出: {fulltxt_path}")

    return full_text


# ── JSON 输出 ─────────────────────────────────────────────────────

def save_intermediate_json(
    data: Dict,
    source_path: str,
    parser_key: str,
    output_dir: Optional[str] = None
) -> str:
    """保存标准中间 JSON 到输入文件所在目录

    Args:
        data: 解析器返回的字典
        source_path: 原始报告文件路径
        parser_key: 解析器键（如 appscan_pdf）
        output_dir: 输出目录（默认：与输入文件同目录）

    Returns:
        输出文件路径
    """
    if not output_dir:
        output_dir = str(Path(source_path).parent)

    source_name = Path(source_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{source_name}_{parser_key}_{timestamp}.json"
    output_path = Path(output_dir) / output_filename

    # 构建标准 JSON 结构
    output_data = {
        'meta': {
            'source_file': Path(source_path).name,
            'source_path': str(Path(source_path).resolve()),
            'parser': parser_key,
            'parse_date': datetime.now().isoformat(),
            'report_date': data.get('report_date', ''),
            'total_instances': data.get('total_instances', 0),
            'vulnerability_types': data.get('vulnerability_types', 0),
            'system': data.get('system', '未知'),
            'vul_category': data.get('vul_category', '应用系统漏洞'),
        },
        'types': []
    }

    for vuln_type in data.get('types', []):
        type_info = {
            'type': vuln_type.get('type', '未知类型'),
            'title': vuln_type.get('title', ''),
            'severity': vuln_type.get('severity', '未知'),
            'instance_count': len(vuln_type.get('instances', [])),
        }
        for field in ['cvss_score', 'cve', 'cause', 'revision',
                      'description', 'risk', 'affected_products',
                      'cwe', 'references', 'wasc']:
            if field in vuln_type and vuln_type[field] is not None:
                val = vuln_type[field]
                if isinstance(val, (list, str)) and len(val) == 0:
                    continue
                type_info[field] = val

        type_info['instances'] = []
        for i, instance in enumerate(vuln_type.get('instances', [])):
            inst = {'index': i + 1, 'url': instance.get('url', [])}
            for field in ['cvss_score', 'cve', 'cause', 'revision',
                          'start_page', 'wasc']:
                if field in instance and instance[field] is not None:
                    val = instance[field]
                    if isinstance(val, (list, str)) and len(val) == 0:
                        continue
                    inst[field] = val
            type_info['instances'].append(inst)

        output_data['types'].append(type_info)

    # 写入文件
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print(f"中间 JSON 已保存: {output_path}")
    print(f"  {output_data['meta']['total_instances']} 个实例, "
          f"{output_data['meta']['vulnerability_types']} 个类型, "
          f"系统: {output_data['meta']['system']}")

    return str(output_path)


# ── 主函数 ────────────────────────────────────────────────────────

def convert_report(
    file_path: str,
    skip_low: bool = True,
    output_dir: Optional[str] = None,
) -> str:
    """阶段1：将 AppScan PDF 报告转为标准中间 JSON

    Args:
        file_path: PDF 报告文件路径
        skip_low: 是否跳过低危漏洞
        output_dir: JSON 输出目录

    Returns:
        输出的 JSON 文件路径
    """
    report_path = Path(file_path)
    if not report_path.exists():
        print(f"错误: 文件不存在: {file_path}")
        sys.exit(1)

    if report_path.suffix.lower() != '.pdf':
        print(f"错误: 仅支持 PDF 格式，当前文件: {report_path.suffix}")
        sys.exit(1)

    parser_key = PARSER_KEY
    print(f"解析器: {parser_key}")

    # 提取 PDF 文本
    full_text = extract_pdf_text(file_path, save_fulltxt=True)

    # 解析
    print(f"正在解析...")
    try:
        parser = get_parser(parser_key, skip_low=skip_low)
        data = parser.parse(full_text, pdf_path=file_path)
    except Exception as e:
        print(f"错误: 解析失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # 输出 JSON
    output_path = save_intermediate_json(data, file_path, parser_key, output_dir)

    return output_path


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description="阶段1：AppScan PDF 报告 → 标准中间 JSON"
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
        "--output-dir",
        help="JSON 输出目录（默认：与输入文件同目录）"
    )

    args = parser.parse_args()

    output_path = convert_report(
        file_path=args.file_path,
        skip_low=args.skip_low,
        output_dir=args.output_dir,
    )

    print(f"\n阶段1完成: {output_path}")
    print(f"下一步: python json2wiki.py \"{output_path}\" 或 "
          f"python report2wiki.py \"{args.file_path}\"")

    return output_path


if __name__ == "__main__":
    main()
