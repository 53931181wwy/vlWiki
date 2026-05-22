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

                # 检测字段标签（支持同行值和跨行值两种格式）
                if line.startswith('严重性') or line.startswith('严重性：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'severity'
                    # 检查是否在同一行有值（兼容中文冒号 ： 和英文冒号 :）
                    value_extracted = False
                    for sep in ['：', ':']:
                        if sep in line:
                            parts = line.split(sep, 1)
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
                                value_extracted = True
                            break  # 找到冒号就停止尝试
                    if value_extracted:
                        i += 1
                        continue
                    # 同行无值 → current_field 保持为 'severity'
                    # 下一行进入多行收集逻辑（第 234 行起）
                    i += 1
                    continue

                elif line.startswith('CVSS 分数') or line.startswith('CVSS 分数：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'cvss_score'
                    for sep in ['：', ':']:
                        if sep in line:
                            parts = line.split(sep, 1)
                            if len(parts) > 1 and parts[1].strip():
                                current_instance['cvss_score'] = parts[1].strip()
                                current_field = None
                            break
                    i += 1
                    continue

                elif line.startswith('URL') or line.startswith('URL：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'url'
                    for sep in ['：', ':']:
                        if sep in line:
                            parts = line.split(sep, 1)
                            if len(parts) > 1 and parts[1].strip():
                                # 改为追加到列表，支持多个URL
                                if not isinstance(current_instance['url'], list):
                                    current_instance['url'] = []
                                current_instance['url'].append(parts[1].strip())
                                current_field = None
                            break
                    i += 1
                    continue

                elif line.startswith('原因') or line.startswith('原因：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'cause'
                    for sep in ['：', ':']:
                        if sep in line:
                            parts = line.split(sep, 1)
                            if len(parts) > 1 and parts[1].strip():
                                current_instance['cause'] = parts[1].strip()
                                current_field = None
                            break
                    i += 1
                    continue

                elif line.startswith('固定值') or line.startswith('修订建议') or line.startswith('固定值：') or line.startswith('修订建议：'):
                    # 只有在漏洞实例内部才处理字段标签
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'revision'
                    for sep in ['：', ':']:
                        if sep in line:
                            parts = line.split(sep, 1)
                            if len(parts) > 1 and parts[1].strip():
                                current_instance['revision'] = parts[1].strip()
                                current_field = None
                            break
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

    def _extract_remediation_section(self, text: str, type_names: List[str]) -> List[Dict]:
        """提取修复方法章节（计数驱动，通用）

        Args:
            text: 去除分页符后的完整文本
            type_names: 前面章节的漏洞类型名列表（有序，高→低）

        Returns:
            [{cause, risk, affected_products, revision, cwe, references}, ...]
            长度 = len(type_names)，与 type_names 按位置对应
        """
        # 1. 定位修复方法章节：用 rfind 取最后一次出现
        anchor = text.rfind('修复方法')
        if anchor == -1:
            return [{}] * len(type_names)

        remaining = text[anchor:]
        clean = re.sub(r'\[VLWIKI_PAGE_SEPARATOR:\d+\]', '\n', remaining)

        # 2. 按类型名分块
        results = []
        cur_pos = 0
        for idx, name in enumerate(type_names):
            pos = clean.find(name, cur_pos)
            if pos == -1:
                results.append({})
                continue

            if pos < 100 and idx == 0:
                pos2 = clean.find(name, pos + len(name))
                if pos2 != -1:
                    pos = pos2

            after_name = pos + len(name)
            next_pos = len(clean)
            for next_name in type_names[idx + 1:]:
                p = clean.find(next_name, after_name)
                if p != -1 and p < next_pos:
                    next_pos = p

            if next_pos == len(clean):
                for tail in ['应用程序数据', '已访问的 URL', 'cookie', 'JavaScript']:
                    p = clean.find(tail, after_name)
                    if p != -1 and p < next_pos:
                        next_pos = p

            block = clean[after_name:next_pos]
            results.append(self._parse_field_block(block, type_names))
            cur_pos = after_name

        return results

    def _clean_cwe_field(self, text: str) -> List[str]:
        """清洗 CWE 字段：保留有效 CWE 编号，剔除页码等噪声

        可靠策略（不依赖数字大小，避免误删两位数 CWE）：
        1. 在原始文本中检测页脚模式：日期行（\d{4}/\d{1,2}/\d{1,2}）后紧跟的数字行=页码，标记剔除
        2. 其余纯数字行在 CWE 范围（1-1999）内的保留，去重输出

        Returns:
            CWE 编号列表（字符串），如 ["1275", "284", "923"]
        """
        if not text:
            return []

        lines = text.split('\n')

        # Pass 1: 检测页脚模式，标记紧跟日期后的数字为页码
        page_numbers = set()
        prev_was_date = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                prev_was_date = False
                continue
            if re.match(r'^\d{4}/\d{1,2}/\d{1,2}$', stripped):
                prev_was_date = True
                continue
            if prev_was_date and re.match(r'^\d+$', stripped):
                page_numbers.add(stripped)
                prev_was_date = False
                continue
            prev_was_date = False

        # Pass 2: 提取有效 CWE 编号
        cwe_nums = []
        for line in lines:
            stripped = line.strip()
            if not re.match(r'^\d+$', stripped):
                continue
            if stripped in page_numbers:
                continue
            num = int(stripped)
            if 1 <= num <= 1999:
                cwe_nums.append(stripped)

        # 去重后输出（保持原始出现顺序）
        seen = set()
        result = []
        for n in cwe_nums:
            if n not in seen:
                seen.add(n)
                result.append(n)

        return result

    def _parse_field_block(self, block: str, type_names: List[str]) -> Dict:
        """解析修复方法中的一个字段块

        字段标签在 PDF 中严格固定，按出现顺序提取
        type_names: 所有已知类型名，用于剔除尾部混入的下一个类型名
        """
        result = {}
        lines = block.strip().split('\n')

        field_defs = [
            ('cause', ['原因']),
            ('risk', ['风险']),
            ('affected_products', ['受影响产品']),
            ('revision', ['修订建议']),
            ('cwe', ['CWE']),
            ('references', ['外部引用']),
        ]

        current_field = None
        field_content = []

        def save_field():
            if current_field and field_content:
                content = '\n'.join(field_content).strip()
                # CWE 字段：传入原始文本（含日期行），由 _clean_cwe_field 统一处理
                if current_field == 'cwe' and content:
                    content = self._clean_cwe_field(content)
                    # cwe 已转为列表，直接保存后返回（无需后续字符串清理）
                    if content:
                        result[current_field] = content
                    return
                else:
                    # 去 TOC、日期行干扰（用 \n 替换，防止相邻内容粘合）
                    content = re.sub(r'\n?TOC\n?', '\n', content).strip()
                    content = re.sub(r'\n?\d{4}/\d{1,2}/\d{1,2}\n?', '\n', content).strip()
                    # 去尾部孤立的页码（1-999）
                    content = re.sub(r'\n\d{1,3}$', '', content).strip()
                # 去尾部混入的下一个类型名（与已知类型名精确匹配）
                lines = content.split('\n')
                if lines:
                    last = lines[-1].strip()
                    if last in type_names:
                        lines = lines[:-1]
                        content = '\n'.join(lines).strip()
                if content:
                    result[current_field] = content

        section_boundaries = {'应用程序数据', '已访问的 URL', 'cookie', 'JavaScript', '失败的请求', '参数', '注释'}
        for line in lines:
            s = line.strip()
            if not s:
                continue
            if s == 'TOC':
                continue
            # 遇到新章节立即停止
            if s in section_boundaries:
                save_field()
                break
            # 遇到"原因："且已有字段输出 → 新类型开始，停止
            if s.startswith('原因') and current_field and current_field != 'cause':
                save_field()
                break

            # 检测字段标签（必须标签+冒号才算新字段开始）
            matched = False
            for field_name, labels in field_defs:
                for label in labels:
                    if s.startswith(label):
                        rest = s[len(label):].strip()
                        # 标签后紧跟冒号才是字段开始
                        if rest.startswith('：') or rest.startswith(':'):
                            save_field()
                            current_field = field_name
                            field_content = []
                            val = s.split(label, 1)[1].lstrip('：').lstrip(':').strip()
                            if val:
                                field_content.append(val)
                            matched = True
                            break
                if matched:
                    break

            if not matched and current_field:
                field_content.append(s)

        save_field()
        return result

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

            # 确保类型名始终记录（即使无描述，也需要用于尾部剔除匹配）
            if type_name not in type_details:
                type_details[type_name] = {}

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

        # 类型级过滤：跳过低危及以下漏洞类型（双重保险）
        if self.skip_low:
            vuln_types = {
                k: v for k, v in vuln_types.items()
                if v.get('severity') not in ['低', '信息', '提示', None, '未知']
            }
            if vuln_types:
                skipped = len(set(v.get('type') for v in instances if v.get('severity') in ['低', '信息', '提示'])) \
                    if instances else 0
            else:
                skipped = 0

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
                elif field == 'cvss_score' and len(unique_values) > 1:
                    # cvss_score 不统一时，types 层级标记"详情见实例"
                    vuln_type_data['cvss_score'] = '详情见实例'

        # 提取每个漏洞类型的描述
        type_details = self._extract_type_details(text)
        for vuln_type_data in vuln_types.values():
            type_name = vuln_type_data.get('type', '')
            if type_name in type_details:
                vuln_type_data.update(type_details[type_name])

        # 提取修复方法（type_details 含全部类型名，过滤出在修复方法中真实出现的）
        anchor = text.rfind('修复方法')
        clean_remediation = re.sub(r'\[VLWIKI_PAGE_SEPARATOR:\d+\]', '\n', text[anchor:]) if anchor != -1 else ''
        all_type_names = [n for n in type_details if n in clean_remediation]
        remediation_list = self._extract_remediation_section(text, all_type_names)
        for vuln_type_data, remediation in zip(vuln_types.values(), remediation_list):
            if not remediation:
                continue
            # 同名字段拼接
            for field in ['cause', 'revision']:
                if field in remediation:
                    existing = vuln_type_data.get(field, '')
                    if existing:
                        vuln_type_data[field] = existing + '\n' + remediation[field]
                    else:
                        vuln_type_data[field] = remediation[field]
            # 新字段直接写入
            for field in ['risk', 'affected_products', 'cwe', 'references']:
                if field in remediation:
                    vuln_type_data[field] = remediation[field]

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
