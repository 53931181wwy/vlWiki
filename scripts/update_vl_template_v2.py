#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量更新VL Wiki页面，使其符合新模板结构
新顺序: title → severity → cvss_score → vl_id → date_discovered → vulnerability_category → type → status → cve → tags → system

修改内容：
1. 调整YAML字段顺序
2. 删除"## 漏洞证明"章节（如果存在）
3. 删除"## 版本历史"章节（如果存在）
4. 添加"## 扫描原始数据"章节（如果缺失）
5. 添加"## 沟通记录"章节（如果缺失）
6. 更新"## 漏洞描述"章节，确保有子章节（漏洞原理、共同特征、受影响URL清单）
   - 如果"## 漏洞描述"后有实质内容，将其移动到"### 漏洞原理"下
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

def parse_yaml_frontmatter(content: str) -> Tuple[Dict[str, str], str]:
    """
    解析YAML frontmatter
    
    Args:
        content: 文件内容
    
    Returns:
        (yaml_dict, body_content) 元组
    """
    # 匹配YAML frontmatter (--- 之间的内容)
    pattern = r'^---\s*\n(.*?)\n---\s*\n(.*)$'
    match = re.match(pattern, content, re.DOTALL)
    
    if not match:
        return None, content
    
    yaml_str = match.group(1)
    body = match.group(2)
    
    # 解析YAML字段
    yaml_dict = {}
    for line in yaml_str.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 匹配 "key: value" 或 "key: [value]" 或 'key: "value"'
        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip()
            value = value.strip()
            yaml_dict[key] = value
    
    return yaml_dict, body

def reorder_yaml_fields(yaml_dict: Dict[str, str], vl_id: str = None) -> str:
    """
    按新顺序重新生成YAML frontmatter
    
    Args:
        yaml_dict: 原始YAML字段字典
        vl_id: VL编号（从文件名提取）
    
    Returns:
        重新排序后的YAML字符串（包含---包围）
    """
    # 定义新的字段顺序
    field_order = [
        'title',
        'severity',
        'cvss_score',
        'vl_id',
        'date_discovered',
        'vulnerability_category',
        'type',
        'status',
        'cve',
        'tags',
        'system'
    ]
    
    # 构建新的YAML
    yaml_lines = []
    
    for field in field_order:
        if field == 'vl_id':
            # vl_id从文件名获取，如果YAML中没有则添加
            if vl_id:
                yaml_lines.append(f'vl_id: "{vl_id}"')
        elif field in yaml_dict:
            yaml_lines.append(f'{field}: {yaml_dict[field]}')
    
    # 用---包围
    yaml_str = '---\n' + '\n'.join(yaml_lines) + '\n---\n'
    
    return yaml_str

def remove_section(content: str, section_name: str) -> str:
    """
    删除指定的章节（包括所有子章节）
    
    Args:
        content: 文件内容
        section_name: 章节名称（如 "## 漏洞证明"）
    
    Returns:
        删除章节后的内容
    """
    # 匹配章节及其所有内容（直到下一个 ## 或文件结尾）
    pattern = rf'^{re.escape(section_name)}.*?(?=^## |\Z)'
    new_content = re.sub(pattern, '', content, flags=re.MULTILINE | re.DOTALL)
    
    return new_content

def add_missing_sections(content: str, vl_id: str) -> str:
    """
    添加缺失的章节（扫描原始数据、沟通记录）
    
    Args:
        content: 文件内容
        vl_id: VL编号
    
    Returns:
        添加章节后的内容
    """
    # 检查并添加"扫描原始数据"章节
    if '## 扫描原始数据' not in content:
        scan_section = f"""
## 扫描原始数据
- **原始报告**: [[]]
- **原始请求/响应**: [ ](../../raw/scan_data/{vl_id}.txt)
- *此为代表性样本，同类实例仅URL/参数不同*
"""
        # 插入到"## 状态追踪"之前
        content = content.replace('## 状态追踪', scan_section + '\n## 状态追踪')
    
    # 检查并添加"沟通记录"章节
    if '## 沟通记录' not in content:
        comm_section = """
## 沟通记录
### 建设方拒绝修复
[如建设方拒绝修复，记录：
- 拒绝日期
- 拒绝理由
- 建设方提供的"替代措施"
- 风险评估

### 检测方回复策略
[我方针对拒绝的回复策略]
"""
        # 插入到"## 扫描原始数据"之后，"## 状态追踪"之前
        if '## 扫描原始数据' in content:
            content = content.replace('## 状态追踪', comm_section + '\n## 状态追踪')
        else:
            content = content.replace('## 状态追踪', comm_section + '\n## 状态追踪')
    
    return content

def update_vulnerability_description(content: str) -> str:
    """
    更新"## 漏洞描述"章节，添加子章节
    
    Args:
        content: 文件内容
    
    Returns:
        更新后的内容
    """
    # 情况1：已经有子章节（### 漏洞原理）
    if '### 漏洞原理' in content:
        return content  # 已经有子章节，不需要添加
    
    # 情况2："## 漏洞描述"后直接是内容（没有子章节）
    # 需要：
    # 1. 提取"## 漏洞描述"后的内容（直到下一个##）
    # 2. 将内容移动到"### 漏洞原理"下
    # 3. 添加"### 共同特征"和"### 受影响URL清单"占位符
    
    # 匹配"## 漏洞描述"章节的内容
    pattern = r'(## 漏洞描述\s*\n)(.*?)(?=^## |\Z)'
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    
    if match:
        prefix = match.group(1)  # "## 漏洞描述\n"
        existing_content = match.group(2).strip()
        
        # 构建新的漏洞描述章节
        if existing_content and not existing_content.startswith('['):
            # 有实质内容，将其移动到"### 漏洞原理"下
            new_desc = f"""## 漏洞描述
### 漏洞原理
{existing_content}

### 共同特征
（待补充）

### 受影响URL清单
（待补充）

"""
        else:
            # 无实质内容或只有占位符，使用标准模板
            new_desc = """## 漏洞描述
[详细描述，包括漏洞原理、触发条件、影响范围]
### 漏洞原理

### 共同特征
### 受影响URL清单
"""
        
        # 替换原内容
        content = content.replace(match.group(0), new_desc)
    
    return content

def process_vl_file(file_path: Path) -> bool:
    """
    处理单个VL文件
    
    Args:
        file_path: VL文件路径
    
    Returns:
        是否成功处理
    """
    try:
        # 读取文件
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            content = f.read()
        
        # 解析YAML
        yaml_dict, body = parse_yaml_frontmatter(content)
        
        if yaml_dict is None:
            print(f"跳过 {file_path.name}: 无法解析YAML")
            return False
        
        # 提取VL ID（从文件名）
        vl_id = file_path.stem  # 文件名（不含扩展名）
        
        # 1. 重新排序YAML
        new_yaml = reorder_yaml_fields(yaml_dict, vl_id)
        
        # 2. 删除"漏洞证明"章节
        body = remove_section(body, '## 漏洞证明')
        
        # 3. 删除"版本历史"章节
        body = remove_section(body, '## 版本历史')
        
        # 4. 添加缺失的章节
        body = add_missing_sections(body, vl_id)
        
        # 5. 更新"漏洞描述"章节
        body = update_vulnerability_description(body)
        
        # 6. 写回文件
        new_content = new_yaml + body
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"已更新: {file_path.name}")
        return True
    
    except Exception as e:
        print(f"处理失败 {file_path.name}: {e}")
        return False

def main():
    """主函数"""
    # VL Wiki页面目录
    vulnerabilities_dir = Path('D:/Users/个人项目/wb/vlWiki/wiki/vulnerabilities')
    
    if not vulnerabilities_dir.exists():
        print(f"错误: 目录不存在: {vulnerabilities_dir}")
        return
    
    # 查找所有MD文件
    md_files = list(vulnerabilities_dir.glob('VL-*.md'))
    
    print(f"找到 {len(md_files)} 个VL文件")
    print(f"修改内容: 调整YAML顺序, 删除漏洞证明/版本历史, 添加缺失章节, 更新漏洞描述")
    
    # 处理每个文件
    success_count = 0
    for md_file in sorted(md_files):
        if process_vl_file(md_file):
            success_count += 1
    
    print(f"\n完成! 成功更新 {success_count}/{len(md_files)} 个文件")

if __name__ == '__main__':
    main()
