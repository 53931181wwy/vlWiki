"""
AppScan PDF 报告解析器
解析 PDF 格式的 AppScan 漏洞报告。

设计说明：
- 解析器命名：{tool}_{format}_parser.py
- 输入：通过 document-reader 提取的带页码标签的纯文本
- 输出：结构化 Python dict（非 JSON 文件）
- JSON 输出由 report2json.py（阶段1）负责
"""

import re
import json
from difflib import SequenceMatcher
from typing import List, Dict, Optional, Set


class AppScanPDFParser:
    """AppScan PDF 格式报告解析器"""

    def __init__(self, skip_low=True):
        """
        Args:
            skip_low: 是否跳过低危漏洞（默认True）
        """
        self.skip_low = skip_low
        self.vul_category = "应用系统漏洞"

    def extract_system_info_from_text(self, text: str) -> str:
        """从文本中提取系统名称（扫描文件名称）"""
        try:
            patterns = [
                r'扫描文件名称[：:]\s*([^\n]+)',
                r'扫描文件[：:]\s*([^\n]+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    system_name = match.group(1).strip()
                    system_name = re.sub(r'\d{4}/\d{1,2}/\d{1,2}.*', '', system_name)
                    system_name = system_name.strip()
                    if system_name:
                        return system_name

        except Exception as e:
            print(f"警告: 提取系统信息失败: {e}")

        return "未知系统"

    def extract_scan_start_time(self, text: str) -> str:
        """从 PDF 第一页提取「扫描开始时间」完整日期+时间字符串。

        典型输入：「扫描开始时间： 2026/3/17 10:11:30」
        返回格式：YYYY-MM-DD HH:MM:SS
        """
        m = re.search(
            r'扫描开始时间[：:]\s*(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})',
            text
        )
        if m:
            return f"{m.group(1)}-{m.group(2).zfill(2)}-{m.group(3).zfill(2)} {m.group(4)}:{m.group(5)}:{m.group(6)}"
        return ""

    def extract_vuln_types_from_toc(self, text: str) -> Set[str]:
        """从目录提取合法漏洞类型名集合。

        目录区段位于「按问题类型分组的问题」到「修复方法」之间（首次出现）。
        每行为「漏洞类型名 + 可选实例数」，提取名称部分去重返回。
        """
        toc_start = text.find('按问题类型分组的问题')
        if toc_start == -1:
            return set()

        toc_end = text.find('修复方法', toc_start)
        if toc_end == -1:
            return set()

        toc_chunk = text[toc_start:toc_end]
        toc_clean = re.sub(r'\[VLWIKI_PAGE_SEPARATOR:\d+\]', '\n', toc_chunk)
        lines = toc_clean.strip().split('\n')

        valid_types: Set[str] = set()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.upper() == 'TOC':
                continue
            if re.match(r'^\d+$', line):
                continue
            if re.match(r'^\d{4}/\d{1,2}/\d{1,2}', line):
                continue
            if line == '按问题类型分组的问题':
                continue
            # 去掉末尾的实例个数
            name = re.sub(r'\s+\d+\s*$', '', line).strip()
            if name and re.search(r'[\u4e00-\u9fff]', name):
                valid_types.add(name)

        return valid_types

    @staticmethod
    def _fuzzy_match_type(candidate: str, valid_types: Set[str], threshold: float = 0.7) -> Optional[str]:
        """候选文本与合法类型名的模糊匹配，返回匹配到的类型名或 None。"""
        if not candidate or not valid_types:
            return None

        # 1. 精确匹配
        if candidate in valid_types:
            return candidate

        # 2. candidate 包含某个合法类型名
        for vt in valid_types:
            if vt in candidate:
                return vt

        # 3. 合法类型名包含 candidate
        for vt in valid_types:
            if candidate in vt:
                return vt

        # 4. 序列相似度匹配
        for vt in valid_types:
            if SequenceMatcher(None, candidate, vt).ratio() >= threshold:
                return vt

        return None

    def parse_vulnerability_instances(self, text: str,
                                       valid_types: Optional[Set[str]] = None) -> List[Dict]:
        """解析漏洞实例。

        Args:
            text: PDF 提取的纯文本
            valid_types: 从目录提取的合法漏洞类型名集合，用于校验 type 字段
        """
        instances = []

        page_sep_re = re.compile(
            r'\[VLWIKI_PAGE_SEPARATOR:(\d+)\]\n(.*?)(?=\[VLWIKI_PAGE_SEPARATOR:\d+\]|\Z)',
            re.DOTALL
        )

        current_instance = None
        current_field = None
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

                if re.match(r'问题\s+\d+\s+/\s+\d+', line):
                    if current_instance:
                        if self.skip_low:
                            if current_instance.get('severity') not in ['低', '信息', '提示']:
                                instances.append(current_instance)
                        else:
                            instances.append(current_instance)

                    current_instance = {
                        'type': None,
                        'severity': None,
                        'cvss_score': None,
                        'url': [],
                        'cause': None,
                        'revision': None,
                        'cve': [],
                        'wasc': None,
                        'start_page': current_page,
                    }
                    current_field = None
                    expecting_vuln_type = True
                    i += 1
                    continue

                if expecting_vuln_type and line:
                    # 跳过噪声行
                    if re.match(r'\d{4}/\d{1,2}/\d{1,2}', line):
                        i += 1
                        continue
                    if re.match(r'^\d+$', line):
                        i += 1
                        continue
                    if line.upper() == 'TOC':
                        i += 1
                        continue
                    if re.match(r'^\d+\s*页\s*---$', line):
                        i += 1
                        continue

                    # 有合法类型列表时，用 TOC 类型做校验
                    if valid_types:
                        matched = self._fuzzy_match_type(line, valid_types)
                        if matched:
                            current_instance['type'] = matched
                            expecting_vuln_type = False
                        else:
                            # 不匹配任何合法类型 → 噪声，继续找
                            i += 1
                            continue
                    else:
                        # 无 TOC 列表时回退到旧启发式
                        if re.search(r'[\u4e00-\u9fff]', line) or re.search(r'[a-zA-Z]', line):
                            current_instance['type'] = line
                            expecting_vuln_type = False
                        else:
                            i += 1
                            continue
                    i += 1
                    continue

                if line.startswith('严重性') or line.startswith('严重性：'):
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'severity'
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
                            break
                    if value_extracted:
                        i += 1
                        continue
                    i += 1
                    continue

                elif line.startswith('CVSS 分数') or line.startswith('CVSS 分数：'):
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
                    if not current_instance:
                        i += 1
                        continue
                    current_field = 'url'
                    for sep in ['：', ':']:
                        if sep in line:
                            parts = line.split(sep, 1)
                            if len(parts) > 1 and parts[1].strip():
                                if not isinstance(current_instance['url'], list):
                                    current_instance['url'] = []
                                current_instance['url'].append(parts[1].strip())
                                current_field = None
                            break
                    i += 1
                    continue

                elif line.startswith('原因') or line.startswith('原因：'):
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

                if 'CVE-' in line:
                    cve_matches = re.finditer(r'CVE-\d+-\d+', line)
                    for cve_match in cve_matches:
                        if not isinstance(current_instance['cve'], list):
                            current_instance['cve'] = []
                        current_instance['cve'].append(cve_match.group(0))

                if 'WASC-' in line:
                    wasc_match = re.search(r'WASC-\d+', line)
                    if wasc_match:
                        current_instance['wasc'] = wasc_match.group(0)

                i += 1

        if current_instance:
            if self.skip_low:
                if current_instance.get('severity') not in ['低', '信息', '提示']:
                    instances.append(current_instance)
            else:
                instances.append(current_instance)

        return instances

    def _extract_remediation_section(self, text: str, type_names: List[str]) -> List[Dict]:
        """提取修复方法章节（计数驱动，通用）"""
        anchor = text.rfind('修复方法')
        if anchor == -1:
            return [{}] * len(type_names)

        remaining = text[anchor:]
        clean = re.sub(r'\[VLWIKI_PAGE_SEPARATOR:\d+\]', '\n', remaining)

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
        """清洗 CWE 字段：保留有效 CWE 编号，剔除页码等噪声"""
        if not text:
            return []

        lines = text.split('\n')

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

        seen = set()
        result = []
        for n in cwe_nums:
            if n not in seen:
                seen.add(n)
                result.append(n)

        return result

    def _parse_field_block(self, block: str, type_names: List[str]) -> Dict:
        """解析修复方法中的一个字段块"""
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
                if current_field == 'cwe' and content:
                    content = self._clean_cwe_field(content)
                    if content:
                        result[current_field] = content
                    return
                else:
                    content = re.sub(r'\n?TOC\n?', '\n', content).strip()
                    content = re.sub(r'\n?\d{4}/\d{1,2}/\d{1,2}\n?', '\n', content).strip()
                    content = re.sub(r'\n\d{1,3}$', '', content).strip()
                lines_ = content.split('\n')
                if lines_:
                    last = lines_[-1].strip()
                    if last in type_names:
                        lines_ = lines_[:-1]
                        content = '\n'.join(lines_).strip()
                if content:
                    result[current_field] = content

        section_boundaries = {'应用程序数据', '已访问的 URL', 'cookie', 'JavaScript', '失败的请求', '参数', '注释'}
        for line in lines:
            s = line.strip()
            if not s:
                continue
            if s == 'TOC':
                continue
            if s in section_boundaries:
                save_field()
                break
            # 匹配 '原因：' 或 'XXX原因：'（下一个漏洞的 cause 字段开始）
            if current_field and re.search(r'原因\s*[：:]', s):
                save_field()
                break
            # 当前行以某个漏洞类型名开头 → 已进入下一个漏洞的修复块，截断
            if current_field and any(s.startswith(t) for t in type_names):
                save_field()
                break

            matched = False
            for field_name, labels in field_defs:
                for label in labels:
                    if s.startswith(label):
                        rest = s[len(label):].strip()
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
        """从文本中提取每个漏洞类型的描述"""
        type_details = {}
        combined = re.sub(r'\[VLWIKI_PAGE_SEPARATOR:\d+\]', '\n', text)

        sections = re.split(r'问题\s+\d+\s+/\s+\d+', combined)

        for section in sections:
            lines = section.strip().split('\n')
            if not lines:
                continue

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

                if re.match(r'^描述[：:]', s) or s.upper().startswith('DESCRIPTION'):
                    save_field(current_field, field_content)
                    current_field = 'description'
                    field_content = []
                    rest = re.split(r'[：:]', s, 1)
                    if len(rest) > 1 and rest[1].strip():
                        field_content.append(rest[1].strip())
                    continue

                if any(s.startswith(p) for p in ['严重性', 'CVSS', 'URL', '原因',
                                                  '固定值', '修订建议',
                                                  '修订建议：', 'WASC']):
                    save_field(current_field, field_content)
                    current_field = None
                    field_content = []
                    continue

                if current_field:
                    field_content.append(s)

            save_field(current_field, field_content)

            if type_name not in type_details:
                type_details[type_name] = {}

        return type_details

    def parse(self, text: str, pdf_path: Optional[str] = None) -> Dict:
        """解析 AppScan PDF 报告，返回结构化数据"""
        system_name = self.extract_system_info_from_text(text)
        print(f"系统: {system_name}")

        report_date = self.extract_scan_start_time(text)
        print(f"扫描开始时间: {report_date or '未识别'}")

        valid_types = self.extract_vuln_types_from_toc(text)
        if valid_types:
            print(f"从目录提取到 {len(valid_types)} 个合法漏洞类型: {valid_types}")

        instances = self.parse_vulnerability_instances(text, valid_types=valid_types)
        print(f"找到 {len(instances)} 个实例（已过滤低危）")

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

        if self.skip_low:
            vuln_types = {
                k: v for k, v in vuln_types.items()
                if v.get('severity') not in ['低', '信息', '提示', None, '未知']
            }

        for vuln_type_name, vuln_type_data in vuln_types.items():
            instance_count = len(vuln_type_data['instances'])
            vuln_type_data['title'] = f"{vuln_type_name} ({instance_count}个实例)"
            vuln_type_data['instance_count'] = instance_count

        for vuln_type_name, vuln_type_data in vuln_types.items():
            type_instances = vuln_type_data.get('instances', [])
            if not type_instances:
                continue

            for instance in type_instances:
                instance.pop('type', None)
                instance.pop('severity', None)

            fields_to_check = ['cvss_score', 'cve', 'cause', 'revision']

            for field in fields_to_check:
                field_values = []
                for instance in type_instances:
                    if field in instance and instance[field] is not None:
                        val = instance[field]
                        if isinstance(val, (list, str)) and len(val) == 0:
                            field_values.append('__EMPTY__')
                        else:
                            field_values.append(json.dumps(val, sort_keys=True, ensure_ascii=False))
                    else:
                        field_values.append('__MISSING__')

                unique_values = set(field_values)
                if len(unique_values) == 1:
                    vuln_type_data[field] = type_instances[0].get(field)
                    for instance in type_instances:
                        instance.pop(field, None)
                elif field == 'cvss_score' and len(unique_values) > 1:
                    vuln_type_data['cvss_score'] = '详情见实例'

        type_details = self._extract_type_details(text)
        for vuln_type_data in vuln_types.values():
            type_name = vuln_type_data.get('type', '')
            if type_name in type_details:
                vuln_type_data.update(type_details[type_name])

        anchor = text.rfind('修复方法')
        clean_remediation = re.sub(r'\[VLWIKI_PAGE_SEPARATOR:\d+\]', '\n', text[anchor:]) if anchor != -1 else ''
        all_type_names = [n for n in type_details if n in clean_remediation]
        remediation_list = self._extract_remediation_section(text, all_type_names)
        for vuln_type_data, remediation in zip(vuln_types.values(), remediation_list):
            if not remediation:
                continue
            for field in ['cause', 'revision']:
                if field in remediation:
                    existing = vuln_type_data.get(field, '')
                    if existing:
                        vuln_type_data[field] = existing + '\n' + remediation[field]
                    else:
                        vuln_type_data[field] = remediation[field]
            for field in ['risk', 'affected_products', 'cwe', 'references']:
                if field in remediation:
                    vuln_type_data[field] = remediation[field]

        output = {
            'total_instances': len(instances),
            'vulnerability_types': len(vuln_types),
            'system': system_name,
            'vul_category': self.vul_category,
            'report_date': report_date,
            'types': list(vuln_types.values())
        }

        return output


def main():
    """测试函数"""
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

    parser = AppScanPDFParser(skip_low=True)
    result = parser.parse(test_text)

    print(f"实例数: {result['total_instances']}")
    print(f"类型数: {result['vulnerability_types']}")
    print(f"系统: {result['system']}")
    print(f"大类: {result['vul_category']}")

    for vuln_type in result['types']:
        print(f"  类型: {vuln_type['type']}, 实例数: {len(vuln_type['instances'])}")


if __name__ == '__main__':
    main()
