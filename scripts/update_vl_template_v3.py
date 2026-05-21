#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量更新VL Wiki页面（第二步）

修改内容：
1. 删除所有VL文件的 "## 基本信息" 章节
2. 对 VL-2026-025 之后的文件统一 "## 漏洞描述" 子章节结构
   - 目标结构：### 漏洞原理、### 共同特征、### 受影响URL清单
   - 将现有内容移动到 "### 漏洞原理" 下
"""

import re
from pathlib import Path
from typing import List

def remove_basic_info_section(content: str) -> str:
    """
    删除 "## 基本信息" 章节（包括所有子内容）
    
    Args:
        content: 文件内容
    
    Returns:
        删除章节后的内容
    """
    # 匹配 "## 基本信息" 及其所有内容（直到下一个 ## 或文件结尾）
    pattern = r'^## 基本信息\s*\n.*?(?=^## |\Z)'
    new_content = re.sub(pattern, '', content, flags=re.MULTILINE | re.DOTALL)
    
    return new_content

def unify_vulnerability_description(content: str) -> str:
    """
    统一 "## 漏洞描述" 的子章节结构
    
    Args:
        content: 文件内容
    
    Returns:
        统一后的内容
    """
    # 检查是否已经是目标结构（有 ### 共同特征 或 ### 受影响URL清单）
    if '### 共同特征' in content or '### 受影响URL清单' in content:
        return content  # 已经是目标结构，不需要修改
    
    # 当前结构：### 漏洞位置、### 漏洞原理、### 漏洞风险（或其他变体）
    # 目标结构：### 漏洞原理、### 共同特征、### 受影响URL清单
    
    # 提取 "## 漏洞描述" 章节的所有内容
    pattern = r'(## 漏洞描述\s*\n)(.*?)(?=^## |\Z)'
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    
    if not match:
        return content  # 没有找到 "## 漏洞描述" 章节
    
    prefix = match.group(1)  # "## 漏洞描述\n"
    existing_content = match.group(2).strip()
    
    # 构建新的漏洞描述章节
    # 将现有内容放入 "### 漏洞原理" 下
    new_desc = f"""## 漏洞描述
### 漏洞原理
{existing_content}

### 共同特征
（待补充）

### 受影响URL清单
（待补充）

"""
    
    # 替换原内容
    content = content.replace(match.group(0), new_desc)
    
    return content

def process_vl_file(file_path: Path, unify_desc: bool = False) -> bool:
    """
    处理单个VL文件
    
    Args:
        file_path: VL文件路径
        unify_desc: 是否统一"漏洞描述"子章节
    
    Returns:
        是否成功处理
    """
    try:
        # 读取文件
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            content = f.read()
        
        original_content = content
        
        # 1. 删除 "## 基本信息" 章节
        content = remove_basic_info_section(content)
        
        # 2. 如果需要统一"漏洞描述"子章节
        if unify_desc:
            content = unify_vulnerability_description(content)
        
        # 3. 如果内容有变化，写回文件
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"已更新: {file_path.name}")
            return True
        else:
            print(f"跳过 {file_path.name}: 无需修改")
            return False
    
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
    md_files = sorted(list(vulnerabilities_dir.glob('VL-*.md')))
    
    print(f"找到 {len(md_files)} 个VL文件")
    print(f"修改内容: 删除基本信息章节, 统一漏洞描述子章节")
    
    # 处理每个文件
    success_count = 0
    
    for md_file in md_files:
        # 判断是否需要统一"漏洞描述"子章节
        # 仅对 VL-2026-025 及之后的文件执行
        file_num = int(md_file.stem.split('-')[2])  # 提取编号（如 025）
        unify_desc = file_num >= 25
        
        if process_vl_file(md_file, unify_desc=unify_desc):
            success_count += 1
    
    print(f"\n完成! 成功更新 {success_count}/{len(md_files)} 个文件")

if __name__ == '__main__':
    main()
