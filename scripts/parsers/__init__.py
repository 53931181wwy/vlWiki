"""
vlWiki Skill - 解析器模块
支持多种漏扫报告格式
"""

from .appscan_parser import AppScanParser

# 解析器映射
PARSER_MAP = {
    'appscan': AppScanParser,
    # 后续添加：
    # 'nessus': NessusParser,
    # 'openvas': OpenVASParser,
    # 'awvs': AWVSParser,
}

def get_parser(report_type, skip_low=True):
    """
    根据报告类型获取对应的解析器实例
    
    Args:
        report_type: 报告类型（appscan, nessus, openvas, awvs）
        skip_low: 是否跳过低危漏洞
    """
    parser_class = PARSER_MAP.get(report_type)
    if not parser_class:
        raise ValueError(f"不支持的报告类型: {report_type}")
    return parser_class(skip_low=skip_low)

__all__ = ['get_parser', 'AppScanParser']
