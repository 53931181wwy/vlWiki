#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量精简 vlWiki 技能代码中的 print 语句，删除所有 emoji
"""
import re
import os
from pathlib import Path

def remove_emoji(text):
    """删除文本中的所有 emoji"""
    emoji_pattern = re.compile(
        "["
        u"\U0001F600-\U0001F64F"  # emoticons
        u"\U0001F300-\U0001F5FF"  # symbols & pictographs
        u"\U0001F680-\U0001F6FF"  # transport & map
        u"\U0001F1E0-\U0001F1FF"  # flags
        u"\U00002702-\U000027B0"
        u"\U000024C2-\U0001F251"
        u"\U0001F900-\U0001F9FF"
        u"\U0001FA00-\U0001FA6F"
        u"\U0001FA70-\U0001FAFF"
        u"\U00002600-\U000026FF"
        u"\U00002700-\U000027BF"
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub(r'', text)

def simplify_print(content):
    """精简 print 语句"""
    lines = content.split('\n')
    result = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # 删除装饰线 print
        if re.match(r'^\s*print\(f?[\'"]\{\'=\*\d+\}[\'"]\s*\)', line):
            i += 1
            continue
            
        # 删除空的 print
        if re.match(r'^\s*print\(\s*\)', line):
            i += 1
            continue
            
        result.append(line)
        i += 1
    
    return '\n'.join(result)

def process_file(filepath):
    """处理单个文件"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        
        # 1. 删除 emoji
        content = remove_emoji(content)
        
        # 2. 精简 print 语句
        content = simplify_print(content)
        
        # 3. 删除多余的空行
        content = re.sub(r'\n{3,}', '\n\n', content)
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
        
    except Exception as e:
        print(f"处理失败 {filepath}: {e}")
        return False

def main():
    script_dir = Path(__file__).parent
    skill_dir = script_dir.parent
    
    # 查找所有 Python 文件
    py_files = []
    for root, dirs, files in os.walk(skill_dir):
        # 跳过 __pycache__
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            if f.endswith('.py') and f not in ['batch_cleanup.py', 'cleanup_print.py', 'cleanup_print_simple.py']:
                py_files.append(os.path.join(root, f))
    
    print(f"找到 {len(py_files)} 个 Python 文件")
    
    success_count = 0
    for py_file in sorted(py_files):
        if process_file(py_file):
            success_count += 1
            print(f"  已处理: {os.path.relpath(py_file, skill_dir)}")
    
    print(f"\n完成! 成功处理 {success_count}/{len(py_files)} 个文件")

if __name__ == '__main__':
    main()
