#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终清理脚本 - 精简所有Python文件中的print语句，删除emoji
"""
import re
import os
from pathlib import Path

def remove_emoji(text):
    """删除文本中的所有emoji"""
    emoji_pattern = re.compile(
        "["
        u"\U0001F600-\U0001F64F"  # emoticons
        u"\U0001F300-\U0001F5FF"  # symbols & pictographs
        u"\U0001F680-\U0001F6FF"  # transport & map
        u"\U0001F1E0-\U0001F1FF"  # flags
        u"\U00002702-\U000027B0"
        u"\U000024C2-\U0001F251"
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub(r'', text)

def simplify_file(filepath):
    """精简单个文件的print语句"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        new_lines = []
        i = 0
        changed = False
        
        while i < len(lines):
            line = lines[i]
            
            # 删除装饰线 print (print(f"{'='*60}"))
            if re.search(r'print\(f?[\'"]\{[\'"]?=[\'"]?\*?\d+[\'"]?\}[\'"]?\)', line):
                i += 1
                continue
            
            # 删除空的 print ()
            if re.match(r'^\s*print\(\s*\)\s*(#.*)?$', line):
                i += 1
                continue
            
            new_lines.append(line)
            i += 1
        
        new_content = ''.join(new_lines)
        
        # 删除emoji
        new_content = remove_emoji(new_content)
        
        # 删除多余空行
        new_content = re.sub(r'\n{3,}', '\n\n', new_content)
        
        if new_content != ''.join(lines):
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True
        return False
        
    except Exception as e:
        print(f"处理失败 {filepath}: {e}")
        return False

def main():
    script_dir = Path(__file__).parent
    skill_dir = script_dir.parent
    
    # 查找所有Python文件
    py_files = []
    for root, dirs, files in os.walk(skill_dir):
        # 跳过 __pycache__
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            if f.endswith('.py') and f not in ['final_cleanup.py', 'batch_cleanup.py', 'cleanup_print.py', 'cleanup_print_simple.py']:
                py_files.append(os.path.join(root, f))
    
    print(f"找到 {len(py_files)} 个Python文件")
    
    success_count = 0
    for py_file in sorted(py_files):
        if simplify_file(py_file):
            success_count += 1
            print(f"  已处理: {os.path.relpath(py_file, skill_dir)}")
    
    print(f"\n完成! 成功处理 {success_count}/{len(py_files)} 个文件")

if __name__ == '__main__':
    main()
