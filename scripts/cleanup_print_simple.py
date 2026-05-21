#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化版：批量删除 vlWiki 代码中的所有 emoji
"""
import re
import os
from pathlib import Path

def remove_emoji(text):
    """删除文本中的所有 emoji"""
    # 匹配常见 emoji 的 Unicode 范围
    emoji_pattern = re.compile(
        "["
        u"\U0001F600-\U0001F64F"  # emoticons
        u"\U0001F300-\U0001F5FF"  # symbols & pictographs
        u"\U0001F680-\U0001F6FF"  # transport & map
        u"\U0001F1E0-\U0001F1FF"  # flags
        u"\U00002702-\U000027B0"
        u"\U000024C2-\U0001F251"
        u"\U0001F900-\U0001F9FF"
        u"\U00002600-\U000026FF"  # Miscellaneous Symbols
        u"\U00002700-\U000027BF"  # Dingbats
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub(r'', text)

def process_file(filepath):
    """处理单个文件：删除 emoji，精简 print"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        original = content

        # 1. 删除 emoji
        content = remove_emoji(content)

        # 2. 删除装饰线 print
        content = re.sub(r'^\s+print\(f[\"\'\{\\'=.*\}\]\n?', '', content, flags=re.MULTILINE)

        # 3. 删除孤立的空 print
        content = re.sub(r'^\s+print\(\"\"\)\n?', '', content, flags=re.MULTILINE)
        content = re.sub(r'^\s+print\(\'\'\'\)\n?', '', content, flags=re.MULTILINE)

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

    py_files = list(script_dir.glob('*.py'))

    print(f"找到 {len(py_files)} 个 Python 文件 (scripts/ 目录)")

    success_count = 0
    for py_file in sorted(py_files):
        if py_file.name == 'cleanup_print_simple.py':
            continue
        if process_file(str(py_file)):
            success_count += 1
            print(f"  已处理: {py_file.name}")

    print(f"\n完成! 成功处理 {success_count} 个文件")

if __name__ == '__main__':
    main()
