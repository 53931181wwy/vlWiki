# vlWiki Skill - 模板模块
# 包含漏洞页面、系统页面、漏洞类型页面等模板

from .vulnerability import VULNERABILITY_TEMPLATE
from .system import SYSTEM_TEMPLATE
from .vulnerability_type import VULNERABILITY_TYPE_TEMPLATE
from .report import REPORT_TEMPLATE

__all__ = ['VULNERABILITY_TEMPLATE', 'SYSTEM_TEMPLATE', 'VULNERABILITY_TYPE_TEMPLATE', 'REPORT_TEMPLATE']
