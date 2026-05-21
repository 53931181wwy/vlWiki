"""
vlWiki Skill - 工具函数模块
包含通用工具函数，如文件操作、路径处理、YAML frontmatter解析等。
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional


def parse_frontmatter_simple(content: str) -> Tuple[Dict, str]:
    """简单解析Markdown文件的YAML frontmatter（不依赖外部库）
    
    Args:
        content: Markdown文件内容
        
    Returns:
        (frontmatter_dict, body_text)
    """
    lines = content.split('\n')
    
    if len(lines) < 3 or lines[0].strip() != '---':
        return {}, content
    
    fm_end = -1
    for i in range(1, len(lines)):
        if lines[i].strip() == '---':
            fm_end = i
            break
    
    if fm_end == -1:
        return {}, content
    
    # 简单解析YAML（支持键值对和简单数组）
    fm_dict = {}
    for line in lines[1:fm_end]:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            # 处理数组（简单格式）
            if value.startswith('[') and value.endswith(']'):
                # 简单解析数组
                array_str = value[1:-1]
                array_items = [item.strip().strip('"').strip("'") for item in array_str.split(',')]
                fm_dict[key] = [item for item in array_items if item]
            else:
                # 去除引号
                value = value.strip('"').strip("'")
                fm_dict[key] = value
    
    body = '\n'.join(lines[fm_end+1:])
    
    return fm_dict, body


def write_frontmatter_file(filepath: str, fm_dict: Dict, body: str) -> bool:
    """写入带YAML frontmatter的Markdown文件
    
    Args:
        filepath: 文件路径
        fm_dict: frontmatter字典
        body: 正文内容
        
    Returns:
        是否成功写入
    """
    try:
        # 构建YAML frontmatter
        fm_lines = []
        for key, value in fm_dict.items():
            if isinstance(value, list):
                # 数组格式
                array_str = ', '.join([f'"{item}"' for item in value])
                fm_lines.append(f"{key}: [{array_str}]")
            else:
                # 字符串格式
                fm_lines.append(f'{key}: "{value}"')
        
        # 组合文件内容
        content = '---\n' + '\n'.join(fm_lines) + '\n---\n\n' + body
        
        # 写入文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return True
    
    except Exception as e:
        print(f"错误：写入文件失败：{e}")
        return False


def find_vl_files(directory: str) -> List[str]:
    """查找目录中所有VL页面文件
    
    Args:
        directory: 目录路径
        
    Returns:
        VL页面文件路径列表
    """
    if not os.path.exists(directory):
        return []
    
    vl_files = []
    for filename in os.listdir(directory):
        if filename.startswith('VL-') and filename.endswith('.md'):
            vl_files.append(os.path.join(directory, filename))
    
    return sorted(vl_files)


def extract_vl_id(filename: str) -> Optional[str]:
    """从文件名提取VL编号
    
    Args:
        filename: 文件名（如 VL-2026-001.md）
        
    Returns:
        VL编号（如 VL-2026-001），如果不符合格式则返回None
    """
    if not filename.startswith('VL-') or not filename.endswith('.md'):
        return None
    
    vl_id = filename.replace('.md', '')
    return vl_id


def get_next_vl_id(vuln_dir: str) -> str:
    """获取下一个VL编号
    
    Args:
        vuln_dir: VL页面目录路径
        
    Returns:
        下一个VL编号（如 VL-2026-025）
    """
    vl_files = find_vl_files(vuln_dir)
    
    if not vl_files:
        return "VL-2026-001"
    
    # 提取所有VL编号中的最大序号
    max_seq = 0
    current_year = "2026"  # 当前年份
    
    for filepath in vl_files:
        filename = os.path.basename(filepath)
        vl_id = extract_vl_id(filename)
        
        if vl_id:
            parts = vl_id.split('-')
            if len(parts) == 3:
                year = parts[1]
                seq = int(parts[2])
                
                if year == current_year and seq > max_seq:
                    max_seq = seq
    
    # 生成下一个编号
    next_seq = max_seq + 1
    return f"VL-{current_year}-{next_seq:03d}"


def clean_system_name(system_name: str) -> str:
    """清理系统名称（去除日期、页码等干扰字符）
    
    Args:
        system_name: 原始系统名称
        
    Returns:
        清理后的系统名称
    """
    # 去除日期（如 2026/3/17）
    system_name = re.sub(r'\d{4}/\d{1,2}/\d{1,2}.*', '', system_name)
    
    # 去除页码（如 第X页）
    system_name = re.sub(r'第\d+页.*', '', system_name)
    
    # 去除多余空格
    system_name = system_name.strip()
    
    return system_name


def format_systems_for_wiki(systems: List[str]) -> str:
    """格式化系统列表为Obsidian wiki链接格式
    
    Args:
        systems: 系统名称列表
        
    Returns:
        格式化后的字符串（如 [[系统1]]、[[系统2]]）
    """
    if not systems:
        return "[[未知系统]]"
    
    return '、'.join([f"[[{s}]]" for s in systems])


def should_skip_vulnerability(severity: str, skip_low: bool = True) -> bool:
    """判断是否应该跳过此漏洞
    
    Args:
        severity: 严重性
        skip_low: 是否跳过低危漏洞
        
    Returns:
        是否应该跳过
    """
    if not skip_low:
        return False
    
    low_severities = ['低', '信息', '提示', '低危']
    for low in low_severities:
        if low in severity:
            return True
    
    return False
