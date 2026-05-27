"""
vlWiki Skill - 主入口脚本
功能：
1. 接收报告文件路径和类型参数
2. 调用 document-reader 提取文本（如果是PDF/DOCX）
3. 根据报告类型选择对应解析器
4. 解析漏洞实例
5. 生成/更新vlWiki页面
"""


import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional

# 添加vlWiki scripts目录到路径
skill_dir = Path(__file__).parent.parent
sys.path.insert(0, str(skill_dir))

# 添加document-reader的scripts目录到路径
doc_reader_scripts = Path.home() / ".codebuddy/skills/document-reader/scripts"
sys.path.insert(0, str(doc_reader_scripts))

# 导入document-reader的pdf_extract模块
try:
    import pdf_extract
except ImportError as e:
    print(f"错误: 无法导入 pdf_extract: {e}")
    sys.exit(1)

# 导入vlWiki解析器
try:
    from parsers import get_parser
except ImportError as e:
    print(f"错误: 无法导入解析器: {e}")
    sys.exit(1)

# 导入vlWiki工具函数
try:
    from utils import get_next_vl_id
except ImportError as e:
    print(f"错误: 无法导入工具函数: {e}")
    sys.exit(1)

# 导入VL页面导出模块
try:
    from vl_exporter import generate_vulnerability_page
except ImportError as e:
    print(f"错误: 无法导入导出模块: {e}")
    sys.exit(1)

# 导入调试模块（可选）
try:
    from debug_parser import save_parser_output
    DEBUG_MODE = True
except ImportError:
    DEBUG_MODE = False
    save_parser_output = None


def select_best_text(extraction_result: Dict) -> List[Dict]:
    """选择最佳文本（PyMuPDF优先）"""
    if extraction_result.get('pymupdf', {}).get('success'):
        return extraction_result['pymupdf']['pages']
    elif extraction_result.get('ocr', {}).get('success'):
        return extraction_result['ocr']['pages']
    else:
        raise ValueError("PyMuPDF和OCR提取都失败了")


def import_report(file_path: str, report_type: str = 'appscan', 
                skip_low: bool = True, output_dir: Optional[str] = None,
                wiki_dir: Optional[str] = None, vl_start: Optional[int] = None) -> Dict:
    """导入漏扫报告并生成vlWiki页面
    
    Args:
        file_path: 报告文件路径
        report_type: 报告类型（appscan, nessus, openvas, awvs）
        skip_low: 是否跳过低危漏洞
        output_dir: VL页面输出目录（默认：自动检测）
        wiki_dir: vlWiki的wiki目录（默认：自动检测）
        vl_start: VL编号起始数字（如25，则从VL-2026-025开始）
    
    Returns:
        dict: 处理结果统计
    """
    print(f"vlWiki - 导入: {file_path}, 类型: {report_type}, 跳过低危: {skip_low}")
    
    # 验证文件存在
    if not Path(file_path).exists():
        print(f"错误: 文件不存在: {file_path}")
        sys.exit(1)
    
    # 1. 提取文本（使用document-reader）
    
    try:
        result_pymupdf = pdf_extract.extract_pymupdf(file_path)
        if not result_pymupdf.get('success'):
            print(f"  错误: PyMuPDF提取失败: {result_pymupdf.get('error', '未知')}")
        
        # 方案二：暂时跳过RapidOCR
        result_ocr = {'success': False, 'error': '跳过OCR', 'pages': []}
        
        extraction_result = {
            'pymupdf': result_pymupdf,
            'ocr': result_ocr
        }
        
        if not extraction_result:
            print(f"错误: 文本提取失败")
            sys.exit(1)
        
        
    except Exception as e:
        print(f"错误: 调用document-reader失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # 2. 选择最佳文本
    
    try:
        pages = select_best_text(extraction_result)
    except ValueError as e:
        print(f"错误: {e}")
        sys.exit(1)
    
    # 3. 解析漏洞实例
    
    try:
        parser = get_parser(report_type, skip_low=skip_low)
        
        full_text = "\n\n".join([f"[VLWIKI_PAGE_SEPARATOR:{page['page']}]\n{page['text']}" for page in pages])

        # 输出 fulltxt.txt 到 PDF 同目录，便于调试
        pdf_dir = Path(file_path).parent
        fulltxt_path = pdf_dir / f"{Path(file_path).stem}_fulltxt.txt"
        fulltxt_path.write_text(full_text, encoding='utf-8')
        print(f"完整文本已输出: {fulltxt_path}")

        if hasattr(parser, 'parse'):
            vulnerabilities = parser.parse(full_text, pdf_path=file_path)
        else:
            print(f"错误: 解析器没有parse方法")
            sys.exit(1)
        
        
        # 输出调试JSON（如果debug_parser可用）
        if DEBUG_MODE and save_parser_output:
            debug_output_path = str(Path(file_path).parent / f"{Path(file_path).stem}_debug.json")
            try:
                save_parser_output(vulnerabilities, output_path=debug_output_path, report_path=file_path)
            except Exception:
                pass
        
    except Exception as e:
        print(f"错误: 解析漏洞实例失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # 4. 生成/更新vlWiki页面
    
    # 确定输出目录
    if not output_dir:
        possible_paths = [
            "D:/Users/个人项目/wb/vlWiki/wiki/vulnerabilities",
            str(Path.home() / "vlWiki/wiki/vulnerabilities")
        ]
        for path in possible_paths:
            if Path(path).exists():
                output_dir = path
                break
        else:
            output_dir = "."
            # auto-detect output dir failed

    # 确定wiki根目录（用于assets/screenshots/截图路径和原始报告链接）
    if not wiki_dir:
        possible_wiki_paths = [
            "D:/Users/个人项目/wb/vlWiki/wiki",
            str(Path.home() / "vlWiki/wiki")
        ]
        for path in possible_wiki_paths:
            if Path(path).exists():
                wiki_dir = path
                break
        else:
            wiki_dir = "."
            # auto-detect wiki dir failed

    # 提取报告日期（从文件名或文件修改时间）
    from datetime import datetime
    try:
        file_name = Path(file_path).stem
        import re
        date_match = re.search(r'(\d{2,4})[-_](\d{1,2})[-_](\d{1,2})', file_name)
        if date_match:
            year, month, day = date_match.groups()
            if len(year) == 2:
                year = f"20{year}"
            report_date = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
        else:
            mtime = Path(file_path).stat().st_mtime
            report_date = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
    except Exception as e:
        report_date = datetime.now().strftime("%Y-%m-%d")
        # date extraction failed

    # 确定起始VL编号
    if vl_start is not None:
        current_vl_num = vl_start
    else:
        last_vl_id = get_next_vl_id(output_dir)
        current_vl_num = int(last_vl_id.split('-')[-1])



    # 为每个漏洞类型生成页面
    generated_files = []
    for i, vuln_type in enumerate(vulnerabilities.get('types', [])):
        year = datetime.now().year
        vl_id = f"VL-{year}-{current_vl_num:03d}"
        current_vl_num += 1
        
        filepath = generate_vulnerability_page(
            vuln_type, output_dir, report_date, vl_id,
            pdf_path=file_path, wiki_dir=wiki_dir,
            system_name=vulnerabilities.get('system', '未知系统'),
            vuln_category=vulnerabilities.get('vul_category', '应用系统漏洞')
        )
        generated_files.append(filepath)
    
    # 5. 返回处理结果
    result = {
        'success': True,
        'total_instances': vulnerabilities['total_instances'],
        'vulnerability_types': vulnerabilities['vulnerability_types'],
        'generated_files': generated_files,
        'system': vulnerabilities.get('system', '未知'),
        'vul_category': vulnerabilities.get('vul_category', '应用系统漏洞')
    }

    print(f"\n导入完成: {result['total_instances']} 个实例, {result['vulnerability_types']} 个类型, {len(result['generated_files'])} 个文件, 系统: {result['system']}, 大类: {result['vul_category']}")

    return result


def main():
    """命令行主函数"""
    parser = argparse.ArgumentParser(description="vlWiki Skill - 导入漏扫报告")
    parser.add_argument("file_path", help="报告文件路径")
    parser.add_argument("--type", default="appscan", 
                        choices=["appscan"],  # 后续添加：nessus, openvas, awvs
                        help="报告类型（默认：appscan）")
    parser.add_argument("--skip-low", action="store_true", default=True,
                        help="跳过低危漏洞（默认：True）")
    parser.add_argument("--no-skip-low", action="store_false", dest="skip_low",
                        help="不跳过低危漏洞")
    parser.add_argument("--output-dir", help="VL页面输出目录（默认：自动检测）")
    parser.add_argument("--wiki-dir", help="vlWiki的wiki目录（默认：自动检测）")
    parser.add_argument("--vl-start", type=int, help="VL编号起始数字（如25，则从VL-2026-025开始）")
    
    args = parser.parse_args()
    
    result = import_report(
        file_path=args.file_path,
        report_type=args.type,
        skip_low=args.skip_low,
        output_dir=args.output_dir,
        wiki_dir=args.wiki_dir,
        vl_start=args.vl_start
    )
    
    return result


if __name__ == "__main__":
    main()
