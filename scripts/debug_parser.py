"""
调试脚本 - 将解析器返回值输出为JSON文件
功能：
1. 提供 save_parser_output() 函数，被 import_report.py 调用
2. 可以独立运行（从PDF提取+解析），直接输出JSON

使用方式：
  1. 作为模块调用（集成到 import_report.py）：
     from debug_parser import save_parser_output
     save_parser_output(vulnerabilities, report_path="报告.pdf")
  
  2. 独立运行：
     python debug_parser.py "报告.pdf"
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Optional


def save_parser_output(vulnerabilities: Dict, output_path: str = None, report_path: str = None) -> str:
    """
    将解析器输出保存为JSON文件
    
    Args:
        vulnerabilities: 解析器返回的字典（包含types、total_instances等）
        output_path: 输出JSON文件路径（可选，默认自动生成）
        report_path: 原始报告路径（用于生成输出文件名）
    
    Returns:
        输出文件的完整路径
    """
    # 生成输出文件路径
    if not output_path:
        if report_path:
            # 使用报告文件名（同目录，扩展名改为.json）
            report_name = Path(report_path).stem
            output_path = str(Path(report_path).parent / f"{report_name}_debug.json")
        else:
            # 默认文件名（当前目录）
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"parser_debug_{timestamp}.json"
    
    # 构建输出数据（格式化，便于阅读）
    output_data = {
        'meta': {
            'total_instances': vulnerabilities.get('total_instances', 0),
            'vulnerability_types': vulnerabilities.get('vulnerability_types', 0),
            'system': vulnerabilities.get('system', '未知'),
            'vulnerability_category': vulnerabilities.get('vulnerability_category', '应用系统漏洞')
        },
        'types': []
    }
    
    # 处理每个漏洞类型
    for vuln_type in vulnerabilities.get('types', []):
        type_info = {
            'type': vuln_type.get('type', '未知类型'),
            'title': vuln_type.get('title', ''),
            'severity': vuln_type.get('severity', '未知'),
            'instance_count': len(vuln_type.get('instances', [])),
            'instances': []
        }
        
        # 添加从实例层级提升到types层级的字段（智能提升后的字段）
        for field in ['cvss_score', 'cve', 'cause', 'revision']:
            if field in vuln_type and vuln_type[field] is not None:
                type_info[field] = vuln_type[field]
        # 添加修复方法补充字段
        for field in ['risk', 'affected_products', 'cwe', 'references']:
            if field in vuln_type and vuln_type[field] is not None:
                type_info[field] = vuln_type[field]
        
        # 处理每个实例（精简输出：只保留实例特有字段）
        for i, instance in enumerate(vuln_type.get('instances', [])):
            instance_info = {
                'index': i + 1,
                'url': instance.get('url', []),
            }
            # 如果某些字段没有被提升到types层级（实例间有不同），保留它们
            for field in ['cvss_score', 'cve', 'cause', 'revision']:
                if field in instance and instance[field] is not None:
                    val = instance[field]
                    # 跳过空列表和空字符串
                    if isinstance(val, (list, str)) and len(val) == 0:
                        continue
                    instance_info[field] = val
            type_info['instances'].append(instance_info)
        
        output_data['types'].append(type_info)
    
    # 写入JSON文件（格式化，缩进2空格）
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    
    print(f"解析器输出: {output_path} ({output_data['meta']['total_instances']} 个实例, {output_data['meta']['vulnerability_types']} 个类型)")
    
    return output_path


def main():
    """命令行主函数 - 独立运行时从PDF直接解析并输出JSON"""
    import argparse
    
    parser = argparse.ArgumentParser(description="调试解析器输出 - 保存为JSON")
    parser.add_argument("pdf_path", help="PDF报告文件路径")
    parser.add_argument("--type", default="appscan", 
                        choices=["appscan"],
                        help="报告类型（默认：appscan）")
    parser.add_argument("--output", help="输出JSON文件路径（默认：自动生成）")
    
    args = parser.parse_args()
    
    # 验证文件存在
    if not Path(args.pdf_path).exists():
        print(f"错误: 文件不存在: {args.pdf_path}")
        sys.exit(1)
    
    # 动态导入（避免依赖问题）
    try:
        # 添加路径
        skill_dir = Path(__file__).parent.parent
        sys.path.insert(0, str(skill_dir))
        
        # 添加document-reader路径
        doc_reader_scripts = Path.home() / ".workbuddy/skills/document-reader/scripts"
        sys.path.insert(0, str(doc_reader_scripts))
        
        # 导入模块
        import pdf_extract
        from parsers import get_parser
        
        
    except ImportError as e:
        print(f"错误: 模块导入失败: {e}")
        print(f"  请确保document-reader和vlWiki parsers已正确安装")
        sys.exit(1)
    
    # 1. 提取文本
    try:
        result_pymupdf = pdf_extract.extract_pymupdf(args.pdf_path)
        
        if not result_pymupdf.get('success'):
            print(f"错误: PyMuPDF提取失败: {result_pymupdf.get('error', '未知错误')}")
            sys.exit(1)
        
        pages = []
        for page in result_pymupdf.get('pages', []):
            pages.append({'page': page['page'], 'text': page['text']})
        
        
    except Exception as e:
        print(f"错误: 文本提取失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # 2. 解析漏洞
    try:
        parser = get_parser(args.type)
        
        full_text = "\n\n".join([f"[VLWIKI_PAGE_SEPARATOR:{page['page']}]\n{page['text']}" for page in pages])
        
        # 解析
        vulnerabilities = parser.parse(full_text, pdf_path=args.pdf_path)
        
        
    except Exception as e:
        print(f"错误: 解析失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # 3. 输出JSON
    output_path = save_parser_output(vulnerabilities, output_path=args.output, report_path=args.pdf_path)
    
    print(f"\n调试完成: {output_path}")


if __name__ == "__main__":
    main()
