"""
vlWiki Skill - 解析器模块
命名规范：{tool}_{format}_parser.py  类名：{Tool}{Format}Parser
映射键：{tool}_{format}（如 appscan_pdf）
"""

from .appscan_pdf_parser import AppScanPDFParser

# 解析器映射（tool_format → ParserClass）
PARSER_MAP = {
    'appscan_pdf': AppScanPDFParser,
    # 后续添加：
    # 'appscan_xml': AppScanXMLParser,
    # 'nessus_xml':   NessusXMLParser,
    # 'awvs_html':    AWVSHTMLParser,
}


def get_parser(parser_key: str, skip_low: bool = True):
    """
    根据解析器键获取解析器实例

    Args:
        parser_key: 解析器键，格式为 {tool}_{format}（如 'appscan_pdf'）
        skip_low: 是否跳过低危漏洞
    """
    parser_class = PARSER_MAP.get(parser_key)
    if not parser_class:
        raise ValueError(f"不支持的解析器: {parser_key}，可用: {list(PARSER_MAP.keys())}")
    return parser_class(skip_low=skip_low)


__all__ = ['get_parser', 'AppScanPDFParser', 'PARSER_MAP']
