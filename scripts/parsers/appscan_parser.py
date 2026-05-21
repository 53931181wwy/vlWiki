"""
AppScan报告解析器
重构自: C:\\Users\\stc\\WorkBuddy\\Claw\\parse_appscan_fixed_v3.py
主要改进：
1. 封装为类 AppScanParser
2. 支持从 document-reader 输出读取（而不是直接读PDF）
3. 保留现有逻辑：严重性解析、实例提取、系统信息提取
4. 添加 vulnerability_category 字段（默认"应用系统漏洞"）
5. 记录每个漏洞实例的起始页码（用于截图）
6. 移除 request/response 解析（不再需要）
"""

import re
import json
from typing import List, Dict, Optional


class AppScanParser:
    """AppScan报告解析器"""

    def __init__(self, skip_low=True):
        """
        初始化解析器

        Args:
            skip_low: 是否跳过低危漏洞（默认True）
        """
        self.skip_low = skip_low
        self.vulnerability_category = "应用系统漏洞"  # 默认漏洞大类

    def extract_system_info_from_text(self, text: str) -> str:
        """从文本中提取系统名称（扫描文件名称）"""
        try:
            # 查找"扫描文件名称"或"扫描文件"模式
            patterns = [
                r'扫描文件名称[：:]\s*([^\n]+)',
                r'扫描文件[：:]\s*([^\n]+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    system_name = match.group(1).strip()
                    # 清理可能的多余字符（如日期、页码等）
                    system_name = re.sub(r'\d{4}/\d{1,2}/\d{1,2}.*', '', system_name)
                    system_name = system_name.strip()
                    if system_name:
                        return system_name

        except Exception as e:
            print(f"警告: 提取系统信息失败: {e}")

        # 默认返回未知系统
        return "未知系统"

    def parse_vulnerability_instances(self, text: str) -> List[Dict]:
        """解析漏洞实例 - 支持多行格式，正确处理"紧急"严重性"""
        instances = []

        # 使用 finditer 保留分页符中的页码
        page_sep_re = re.compile(
            r'\[VLWIKI_PAGE_SEPARATOR:(\d+)\]\n(.*?)(?=\[VLWIKI_PAGE_SEPARATOR:\d+\]|\Z)',
            re.DOTALL
        )

        current_instance = None
        current_field = None  # 当前正在解析的字段（多行格式）
        expecting_vuln_type = False
        current_page = 0

        for match in page_sep_re.finditer(text):
            current_page = int(match.group(1))
            page_text = match.group(2)

            lines = page_text.strip().split('\n')
            if len(lines) == 0:
                continue

            i = 0
            while i < len(lines):
                line = lines[i].strip()

                # 检测新的漏洞实例（格式：问题   X   /   Y）
                if re.match(r'问题\s+\d+\s+/\s+\d+', line):
                    # 保存上一个实例
                    if current_instance:
                        if self.skip_low:
                            if current_instance.get('severity') not in ['低', '信息', '提示']:
                                instances.append(current_instance)
                        else:
                            instances.append(current_instance)

                    # 开始新实例，记录起始页码
                    current_instance = {
                        'type': None,
                        'severity': None,
                        'cvss_score': None,
                        'url': [],  # 改为列表，支持多个URL
                        'cause': None,
                        'revision': None,
                        'cve': [],  # 改为列表，支持多个CVE
                        'wasc': None,
                        'start_page': current_page,  # 记录该实例所在的PDF页码
                    }
                    current_field = None
                    expecting_vuln_type = True
                    i += 1
                    continue

                # 期望漏洞类型名称（"问题"行的下一非空白行）
                if expecting_vuln_type and line:
                    # 检查是否是日期行（如"2026/3/17"），如果是则跳过
                    if re.match(r'\d{4}/\d{1,2}/\d{1,2}', line):
                        i += 1
                        continue
                    # 检查是否是纯数字行，如果是则跳过
                    if re.match(r'^\d+$', line):
                        i += 1
                        continue
                    # 检查是否是"TOC"（目录），如果是则跳过
                    if line.upper() == 'TOC':
                        i += 1
                        continue
                    # 检查是否是页码行（如"16 页 ---"），如果是则跳过
                    if re.match(r'^\d+\s*页\s*---$', line):
                        i += 1
                        continue
                    # 检查是否包含中文字符或英文字母（漏洞类型名称应该包含这些）
                    if re.search(r'[\u4e00-\u9fff]', line) or re.search(r'[a-zA-Z]', line):
                        current_instance['type'] = line
                        expecting_vuln_type = False
                    else:
                        # 不是漏洞类型名称，跳过
                        i += 1
                        continue
                    i += 1
                    continue

                # 检测字段标签（多行格式：标签在当前行，值在下一行）
                if line.startswith('严重性') or line.startswith('严重性：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'severity'
                    # 检查是否在同一行有值
                    if '：' in line:
                        parts = line.split('：', 1)
                        if len(parts) > 1 and parts[1].strip():
                            value = parts[1].strip()
                            if '紧急' in value:
                                current_instance['severity'] = '紧急'
                            elif '高' in value:
                                current_instance['severity'] = '高'
                            elif '中' in value:
                                current_instance['severity'] = '中'
                            elif '低' in value:
                                current_instance['severity'] = '低'
                            else:
                                current_instance['severity'] = value
                            current_field = None
                            i += 1
                            continue
                    i += 1
                    continue

                elif line.startswith('CVSS 分数') or line.startswith('CVSS 分数：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'cvss_score'
                    if '：' in line:
                        parts = line.split('：', 1)
                        if len(parts) > 1 and parts[1].strip():
                            current_instance['cvss_score'] = parts[1].strip()
                            current_field = None
                            i += 1
                            continue
                    i += 1
                    continue

                elif line.startswith('URL') or line.startswith('URL：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'url'
                    if '：' in line:
                        parts = line.split('：', 1)
                        if len(parts) > 1 and parts[1].strip():
                            # 改为追加到列表，支持多个URL
                            if not isinstance(current_instance['url'], list):
                                current_instance['url'] = []
                            current_instance['url'].append(parts[1].strip())
                            current_field = None
                            i += 1
                            continue
                    i += 1
                    continue

                elif line.startswith('原因') or line.startswith('原因：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'cause'
                    if '：' in line:
                        parts = line.split('：', 1)
                        if len(parts) > 1 and parts[1].strip():
                            current_instance['cause'] = parts[1].strip()
                            current_field = None
                            i += 1
                            continue
                    i += 1
                    continue

                elif line.startswith('固定值') or line.startswith('修订建议') or line.startswith('固定值：') or line.startswith('修订建议：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'revision'
                    if '：' in line:
                        parts = line.split('：', 1)
                        if len(parts) > 1 and parts[1].strip():
                            current_instance['revision'] = parts[1].strip()
                            current_field = None
                            i += 1
                            continue
                    i += 1
                    continue

                # 处理当前字段的值（多行格式的下一行）
                if current_field and line:
                    if current_field == 'severity':
                        if not current_instance:
                            i += 1
                            continue
                        if '紧急' in line:
                            current_instance['severity'] = '紧急'
                        elif '高' in line:
                            current_instance['severity'] = '高'
                        elif '中' in line:
                            current_instance['severity'] = '中'
                        elif '低' in line:
                            current_instance['severity'] = '低'
                        else:
                            current_instance['severity'] = line
                        current_field = None

                    elif current_field == 'cvss_score':
                        if not current_instance:
                            i += 1
                            continue
                        score_match = re.search(r'[\d.]+', line)
                        if score_match:
                            current_instance['cvss_score'] = score_match.group(0)
                        current_field = None

                    elif current_field == 'url':
                        if not current_instance:
                            i += 1
                            continue
                        if line.startswith('http'):
                            if not isinstance(current_instance['url'], list):
                                current_instance['url'] = []
                            current_instance['url'].append(line)
                            current_field = None

                    elif current_field == 'cause':
                        if not current_instance:
                            i += 1
                            continue
                        current_instance['cause'] = line
                        current_field = None

                    elif current_field == 'revision':
                        if not current_instance:
                            i += 1
                            continue
                        current_instance['revision'] = line
                        current_field = None

                    i += 1
                    continue

                # 提取CVE（支持多个CVE）
                if 'CVE-' in line:
                    cve_matches = re.finditer(r'CVE-\d+-\d+', line)
                    for cve_match in cve_matches:
                        if not isinstance(current_instance['cve'], list):
                            current_instance['cve'] = []
                        current_instance['cve'].append(cve_match.group(0))

                # 提取WASC
                if 'WASC-' in line:
                    wasc_match = re.search(r'WASC-\d+', line)
                    if wasc_match:
                        current_instance['wasc'] = wasc_match.group(0)

                i += 1

        # 保存最后一个实例
        if current_instance:
            if self.skip_low:
                if current_instance.get('severity') not in ['低', '信息', '提示']:
                    instances.append(current_instance)
            else:
                instances.append(current_instance)

        return instances

    def _extract_type_details(self, text: str) -> Dict[str, Dict]:
        """从文本中提取每个漏洞类型的描述

        AppScan 报告中，每个漏洞类型章节在实例列表之前包含：
        - 描述/Description: 漏洞原理解释
        """
        type_details = {}
        combined = re.sub(r'\[VLWIKI_PAGE_SEPARATOR:\d+\]', '\n', text)

        # 按"问题 X / Y"分割文本，每段对应一个漏洞类型的信息块
        sections = re.split(r'问题\s+\d+\s+/\s+\d+', combined)

        for section in sections:
            lines = section.strip().split('\n')
            if not lines:
                continue

            # 找类型名：第一个非空、非页码、非TOC、非字段标签的中文行
            type_name = None
            skip_labels = {'严重性', 'CVSS', 'URL', '原因', '固定值', '修订建议',
                           '描述', 'WASC'}
            for line in lines:
                s = line.strip()
                if not s:
                    continue
                if re.match(r'^\d+\s*页\s*-{2,}$', s) or s.upper() == 'TOC':
                    continue
                if any(s.startswith(p) for p in skip_labels):
                    continue
                if re.search(r'[\u4e00-\u9fff]', s):
                    type_name = s
                    break

            if not type_name:
                continue

            # 提取描述
            current_field = None
            field_content = []

            def save_field(field, content):
                if field and content:
                    if type_name not in type_details:
                        type_details[type_name] = {}
                    type_details[type_name][field] = '\n'.join(content).strip()

            for line in lines:
                s = line.strip()
                if not s:
                    continue

                # 检测描述字段开始
                if re.match(r'^描述[：:]', s) or s.upper().startswith('DESCRIPTION'):
                    save_field(current_field, field_content)
                    current_field = 'description'
                    field_content = []
                    rest = re.split(r'[：:]', s, 1)
                    if len(rest) > 1 and rest[1].strip():
                        field_content.append(rest[1].strip())
                    continue

                # 其他字段标签终止当前收集
                if any(s.startswith(p) for p in ['严重性', 'CVSS', 'URL', '原因',
                                                  '固定值', '修订建议',
                                                  '修订建议：', 'WASC']):
                    save_field(current_field, field_content)
                    current_field = None
                    field_content = []
                    continue

                # 积累字段内容
                if current_field:
                    field_content.append(s)

            # 保存最后一个字段
            save_field(current_field, field_content)

        return type_details

    def parse(self, text: str, pdf_path: Optional[str] = None) -> Dict:
        """解析AppScan报告，返回结构化数据"""
        # 提取系统信息
        system_name = self.extract_system_info_from_text(text)
        print(f"系统: {system_name}")

        # 解析漏洞实例
        instances = self.parse_vulnerability_instances(text)
        print(f"找到 {len(instances)} 个实例（已过滤低危）")

        # 按漏洞类型分组
        vuln_types = {}
        for instance in instances:
            vuln_type = instance.get('type', '未知')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = {
                    'type': vuln_type,
                    'severity': instance.get('severity', '未知'),
                    'instances': []
                }
            vuln_types[vuln_type]['instances'].append(instance)

        # 为每个漏洞类型添加 title 字段（格式：类型名 (实例数个零件)）
        for vuln_type_name, vuln_type_data in vuln_types.items():
            instance_count = len(vuln_type_data['instances'])
            vuln_type_data['title'] = f"{vuln_type_name} ({instance_count}个实例)"
            vuln_type_data['instance_count'] = instance_count

        # 智能字段提升：将instances中重复的字段提升到types层级
        # 目的：消除数据冗余，types包含通用信息，instances只保留实例特有信息
        for vuln_type_name, vuln_type_data in vuln_types.items():
            type_instances = vuln_type_data.get('instances', [])
            if not type_instances:
                continue

            # 步骤1：始终删除instances中的type和severity（types层级已包含）
            # 这些字段在所有实例中与types层级完全重复
            for instance in type_instances:
                instance.pop('type', None)
                instance.pop('severity', None)

            # 步骤2：检测哪些字段在所有实例中值完全相同，相同则提升到types
            # cvss_score 和 cve 需要动态检测
            # cause 和 revision 通常是漏洞类型的通用属性（所有实例相同）
            # start_page 是实例特有的，不提升
            fields_to_check = ['cvss_score', 'cve', 'cause', 'revision']

            for field in fields_to_check:
                # 收集所有实例的该字段值（转为JSON字符串以便比较）
                field_values = []
                for instance in type_instances:
                    if field in instance and instance[field] is not None:
                        val = instance[field]
                        # 空列表和空字符串视为相同（空值统一为__EMPTY__）
                        if isinstance(val, (list, str)) and len(val) == 0:
                            field_values.append('__EMPTY__')
                        else:
                            field_values.append(json.dumps(val, sort_keys=True, ensure_ascii=False))
                    else:
                        # 实例中没有该字段，标记为缺失
                        field_values.append('__MISSING__')

                # 如果所有实例都有该字段且值完全相同，则提升到types层级
                unique_values = set(field_values)
                if len(unique_values) == 1:
                    # 提升到types层级（保留第一个实例的值作为代表）
                    vuln_type_data[field] = type_instances[0].get(field)
                    # 从所有实例中删除该字段（消除冗余）
                    for instance in type_instances:
                        instance.pop(field, None)

        # 提取每个漏洞类型的描述
        type_details = self._extract_type_details(text)
        for vuln_type_data in vuln_types.values():
            type_name = vuln_type_data.get('type', '')
            if type_name in type_details:
                vuln_type_data.update(type_details[type_name])

        # 构建输出
        output = {
            'total_instances': len(instances),
            'vulnerability_types': len(vuln_types),
            'system': system_name,
            'vulnerability_category': self.vulnerability_category,
            'types': list(vuln_types.values())
        }

        return output


def main():
    """测试函数"""
    # 测试用例：模拟document-reader输出
    test_text = """
--- 第 9 页 ---
问题 1 / 6
NoSQL 注入
严重性：紧急
CVSS 分数：10.0
URL：http://example.com/login
原因：未过滤用户输入
修订建议：使用参数化查询

--- 第 10 页 ---
问题 2 / 6
NoSQL 注入
严重性：紧急
CVSS 分数：10.0
URL：http://example.com/api
原因：未过滤用户输入
修订建议：使用参数化查询
"""

    parser = AppScanParser(skip_low=True)
    result = parser.parse(test_text)

    print(f"实例数: {result['total_instances']}")
    print(f"类型数: {result['vulnerability_types']}")
    print(f"系统: {result['system']}")
    print(f"大类: {result['vulnerability_category']}")

    for vuln_type in result['types']:
        print(f"  类型: {vuln_type['type']}, 实例数: {len(vuln_type['instances'])}")


if __name__ == '__main__':
    main()
