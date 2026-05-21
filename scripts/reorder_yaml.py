#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量调整VL Wiki页面YAML frontmatter的字段顺序
新顺序: title → severity → cvss_score → vl_id → date_discovered → type → status → cve → tags → vulnerability_category → system
"""

import re
from pathlib import Path
from typing import Dict, List

def parse_yaml_frontmatter(content: str) -> tuple[Dict[str, str], str]:
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
        'type',
        'status',
        'cve',
        'tags',
        'vulnerability_category',
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
        else:
            # 字段缺失时使用默认值
            if field in ['cve', 'tags']:
                yaml_lines.append(f'{field}: []')
            elif field == 'status':
                yaml_lines.append(f'{field}: "待修复"')
            elif field == 'cvss_score':
                yaml_lines.append(f'{field}: ""')
            else:
                yaml_lines.append(f'{field}: ""')
    
    # 用---包围
    yaml_str = '---\n' + '\n'.join(yaml_lines) + '\n---\n'
    
    return yaml_str

def process_vl_file(file_path: Path) -> bool:
    """
    处理单个VL文件，调整YAML字段顺序
    
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
        
        # 重新排序YAML
        new_yaml = reorder_yaml_fields(yaml_dict, vl_id)
        
        # 写回文件
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
    print(f"新字段顺序: title → severity → cvss_score → vl_id → date_discovered → type → status → cve → tags → vulnerability_category → system")
    
    # 处理每个文件
    success_count = 0
    for md_file in sorted(md_files):
        if process_vl_file(md_file):
            success_count += 1
    
    print(f"\n完成! 成功更新 {success_count}/{len(md_files)} 个文件")

if __name__ == '__main__':
    main()
