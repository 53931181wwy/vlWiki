"""
vlWiki Skill - 工具函数模块
包含 YAML frontmatter 解析、文件操作、路径处理等通用工具。
"""

import os
import re
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ---------------------------------------------------------------------------
# 知识库默认路径
# ---------------------------------------------------------------------------

VAULT_ROOT = r"D:\Users\个人项目\wb\vlWiki"
WIKI_DIR = VAULT_ROOT                         # 知识库根目录
WIKI_ROOT = os.path.join(VAULT_ROOT, "wiki")  # wiki 子目录
VULN_DIR = os.path.join(WIKI_ROOT, "vulnerabilities")
TYPE_DIR = os.path.join(WIKI_ROOT, "vulnerability-types")
SYSTEM_DIR = os.path.join(WIKI_ROOT, "systems")
RAW_DIR = os.path.join(WIKI_ROOT, "raw")


# ---------------------------------------------------------------------------
# YAML frontmatter 解析（支持多行列表格式）
# ---------------------------------------------------------------------------

def parse_frontmatter(content: str) -> Tuple[Dict, str]:
    """解析 Markdown 文件的 YAML frontmatter

    Args:
        content: Markdown 文件内容

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

    fm_dict: Dict = {}
    i = 1
    while i < fm_end:
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            i += 1
            continue
        if ':' in stripped:
            key, rest = stripped.split(':', 1)
            key = key.strip()
            rest = rest.strip()
            if rest.startswith('[') and rest.endswith(']'):
                inner = rest[1:-1]
                items = [it.strip().strip('"').strip("'") for it in inner.split(',')]
                fm_dict[key] = [it for it in items if it]
                i += 1
                continue
            if rest == '' and i + 1 < fm_end:
                next_stripped = lines[i + 1].strip()
                if next_stripped.startswith('- '):
                    lst = []
                    i += 1
                    while i < fm_end:
                        item_line = lines[i].strip()
                        if item_line.startswith('- '):
                            val = item_line[2:].strip().strip('"').strip("'")
                            lst.append(val)
                            i += 1
                        else:
                            break
                    fm_dict[key] = lst
                    continue
            fm_dict[key] = rest.strip('"').strip("'")
            i += 1
            continue
        i += 1

    body = '\n'.join(lines[fm_end + 1:])
    return fm_dict, body


# ---------------------------------------------------------------------------
# YAML 字符串转义
# ---------------------------------------------------------------------------

def escape_yaml_string(s: str) -> str:
    """转义 YAML 字符串 - 使用单引号，内部的单引号转义为两个单引号"""
    escaped = s.replace("'", "''")
    return f"'{escaped}'"


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
    import datetime
    vl_files = find_vl_files(vuln_dir)
    
    if not vl_files:
        current_year = str(datetime.datetime.now().year)
        return f"VL-{current_year}-001"
    
    # 提取所有VL编号中的最大序号
    max_seq = 0
    current_year = str(datetime.datetime.now().year)
    
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
