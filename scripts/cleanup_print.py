#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量精简 vlWiki 技能代码中的 print 语句，并删除所有 emoji
用法: python cleanup_print.py
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
        u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
        u"\U00002702-\U000027B0"
        u"\U000024C2-\U0001F251"
        u"\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
        u"\U0001FA00-\U0001FA6F"  # Chess Symbols
        u"\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
        u"\U00002600-\U000026FF"  # Miscellaneous Symbols
        u"\U00002700-\U000027BF"  # Dingbats
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub(r'', text)

def simplify_print_statements(content, filepath):
    """精简 print 语句"""
    lines = content.split('\n')
    new_lines = []
    i = 0
    changed = False

    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()

        # 检查是否是 print 语句
        if 'print(' in line or 'print (' in line:
            # 计算缩进
            indent = len(line) - len(line.lstrip())
            indent_str = ' ' * indent

            # 情况1: 删除空的 print 装饰线 (print(f"{'='*60}"))
            if re.search(r"print\(f[\"']\{\\\'=\\*\\d+\}[\"']\)", line):
                i += 1
                continue

            # 情况2: 合并连续的 print 语句
            # 查找后面是否还有 print 语句可以合并
            if i + 1 < len(lines) and 'print(' in lines[i+1]:
                # 尝试合并
                merged = try_merge_prints(lines, i)
                if merged:
                    new_lines.append(merged)
                    # 跳过已合并的行
                    while i < len(lines) and 'print(' in lines[i]:
                        i += 1
                    continue

        new_lines.append(line)
        i += 1

    return '\n'.join(new_lines), changed

def try_merge_prints(lines, start_idx):
    """尝试合并多个连续的 print 语句"""
    # 收集连续的 print 语句
    prints = []
    i = start_idx
    base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())

    while i < len(lines):
        line = lines[i]
        indent = len(line) - len(line.lstrip())
        # 如果不是 print 或者缩进不对，停止
        if 'print(' not in line or indent != base_indent:
            break
        prints.append(line.rstrip())
        i += 1

    if len(prints) <= 1:
        return None

    # 尝试合并（简单情况：都是简单字符串）
    # 这里先返回 None，表示不合并
    return None

def process_file(filepath):
    """处理单个文件"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        # 1. 删除 emoji
        content = remove_emoji(content)

        # 2. 精简 print 语句 (手动规则)
        # 规则1: 删除 print(f"{'='*60}") 装饰线
        content = re.sub(r'    print\(f"\{\'=\*\d+\}"\)\n?', '', content)
        content = re.sub(r'    print\(f\'\{\"=\*\d+\}\'\)\n?', '', content)

        # 规则2: 合并简单的连续 print
        # 例如:
        #   print(f"找到 {len(md_files)} 个VL文件")
        #   print(f"修改内容: ...")
        # 合并为:
        #   print(f"找到 {len(md_files)} 个VL文件, 修改内容: ...")

        # 3. 删除冗余的空行
        content = re.sub(r'\n\n\n+', '\n\n', content)

        if content != original_content:
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
            if f.endswith('.py'):
                py_files.append(os.path.join(root, f))

    print(f"找到 {len(py_files)} 个 Python 文件")

    success_count = 0
    for py_file in sorted(py_files):
        if process_file(py_file):
            success_count += 1
            print(f"  已处理: {os.path.relpath(py_file, skill_dir)}")

    print(f"\n完成! 成功处理 {success_count} 个文件")

if __name__ == '__main__':
    main()
