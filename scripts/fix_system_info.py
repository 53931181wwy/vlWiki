"""
修复VL页面系统信息不一致问题
优化自: C:\\Users\\stc\\WorkBuddy\\Claw\\fix_vl_system_info_v5.py
主要改进：
1. 支持命令行参数（单文件/批量目录）
2. 添加 dry-run 模式（仅显示将要修改的内容）
3. 支持漏洞大类字段的修复
4. 更友好的进度提示和错误报告
"""

import os
import re
import argparse
from pathlib import Path
from typing import List, Dict, Tuple


def extract_systems_from_line(line: str) -> List[str]:
    """从system:行提取系统列表 - 使用简单字符串操作"""
    start = line.find('[')
    end = line.rfind(']')  # 使用rfind找最后一个]
    if start == -1 or end == -1:
        return None
    
    systems_str = line[start+1:end]
    systems = []
    for s in systems_str.split(','):
        s = s.strip().strip('"').strip("'")
        if s:
            systems.append(s)
    return systems if systems else None


def extract_systems_from_body(lines: List[str], start_idx: int) -> List[str]:
    """从正文中提取[[系统名称]]格式的系统"""
    i = start_idx
    systems = []
    
    while i < len(lines):
        line = lines[i].strip()
        
        # 找到"影响系统"行
        if '影响系统' in line or '**影响系统**' in line:
            # 提取同一行或下一行的[[系统名称]]
            system_line = line
            if '[[' not in line and i+1 < len(lines):
                system_line = lines[i+1].strip()
            
            # 提取所有[[...]]中的内容
            matches = re.findall(r'\[\[([^]]+)\]\]', system_line)
            if matches:
                return matches
        
        i += 1
    
    return systems


def fix_vl_system_info(file_path: str, dry_run: bool = False) -> Tuple[bool, str]:
    """修复VL页面的系统信息不一致问题
    
    Args:
        file_path: VL页面文件路径
        dry_run: 是否仅显示将要修改的内容，不实际修改
        
    Returns:
        (是否修改了文件, 消息)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # 1. 定位frontmatter
        if len(lines) < 3 or lines[0].strip() != '---':
            return False, "无frontmatter"
        
        # 2. 提取frontmatter中的system列表
        fm_end = -1
        fm_systems = None
        for i in range(1, len(lines)):
            if lines[i].strip() == '---':
                fm_end = i
                break
        
        if fm_end == -1:
            return False, "frontmatter格式错误"
        
        # 在frontmatter中查找system:行
        for i in range(1, fm_end):
            if lines[i].strip().startswith('system:'):
                fm_systems = extract_systems_from_line(lines[i])
                break
        
        if not fm_systems:
            return False, "frontmatter中无system字段"
        
        # 3. 查找正文中的"影响系统"行
        body_systems = extract_systems_from_body(lines, fm_end+1)
        
        # 4. 比较并修复
        fm_set = set(fm_systems)
        body_set = set(body_systems) if body_systems else set()
        
        if fm_set == body_set:
            return False, "系统信息一致，无需修复"
        
        # 需要修复：更新正文中的"影响系统"行
        new_body = []
        i = 0
        fixed = False
        
        while i < len(lines):
            line = lines[i]
            
            if '**影响系统**:' in line or '**影响系统**' in line or line.strip().startswith('- **影响系统**'):
                # 替换这一行
                new_line = f"- **影响系统**: {'、'.join(['[[' + s + ']]' for s in fm_systems])}"
                new_body.append(new_line)
                fixed = True
                i += 1
                continue
            
            new_body.append(line)
            i += 1
        
        if not fixed:
            return False, "未找到正文中的影响系统行"
        
        # 5. 写回文件（如果不是dry-run）
        if not dry_run:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(new_body))
            return True, f"已修复：正文系统信息更新为 {fm_systems}"
        else:
            return True, f"[Dry-Run] 将要修复：正文系统信息更新为 {fm_systems}"
    
    except Exception as e:
        return False, f"处理失败: {e}"


def fix_vul_category(file_path: str, category: str = "应用系统漏洞", dry_run: bool = False) -> Tuple[bool, str]:
    """修复VL页面的漏洞大类字段
    
    Args:
        file_path: VL页面文件路径
        category: 漏洞大类（默认："应用系统漏洞"）
        dry_run: 是否仅显示将要修改的内容，不实际修改
        
    Returns:
        (是否修改了文件, 消息)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # 1. 定位frontmatter
        if len(lines) < 3 or lines[0].strip() != '---':
            return False, "无frontmatter"
        
        # 2. 检查是否有vul_category字段
        fm_end = -1
        has_category = False
        for i in range(1, len(lines)):
            if lines[i].strip() == '---':
                fm_end = i
                break
            
            if lines[i].strip().startswith('vul_category:'):
                has_category = True
                # 检查值是否正确
                if category in lines[i]:
                    return False, "漏洞大类字段已正确设置"
                else:
                    # 需要修复
                    if not dry_run:
                        lines[i] = f"vul_category: \"{category}\""
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write('\n'.join(lines))
                        return True, f"已修复：漏洞大类字段更新为 {category}"
                    else:
                        return True, f"[Dry-Run] 将要修复：漏洞大类字段更新为 {category}"
        
        # 3. 如果没有vul_category字段，添加它
        if not has_category and fm_end != -1:
            # 在frontmatter结束前添加
            new_lines = lines[:fm_end] + [f"vul_category: \"{category}\""] + lines[fm_end:]
            
            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(new_lines))
                return True, f"已添加：漏洞大类字段设置为 {category}"
            else:
                return True, f"[Dry-Run] 将要添加：漏洞大类字段设置为 {category}"
        
        return False, "无需修复"
    
    except Exception as e:
        return False, f"处理失败: {e}"


def batch_fix(directory: str, dry_run: bool = False, fix_category: bool = False, category: str = "应用系统漏洞"):
    """批量修复目录下的所有VL页面
    
    Args:
        directory: VL页面目录路径
        dry_run: 是否仅显示将要修改的内容，不实际修改
        fix_category: 是否修复漏洞大类字段
        category: 漏洞大类（默认："应用系统漏洞"）
    """
    if not os.path.exists(directory):
        print(f"错误: 目录不存在: {directory}")
        return
    
    vl_files = [f for f in os.listdir(directory) if f.startswith('VL-') and f.endswith('.md')]
    
    if not vl_files:
        print(f"警告: 目录中没有找到VL页面: {directory}")
        return
    
    fixed_count = 0
    error_count = 0
    
    for filename in sorted(vl_files):
        filepath = os.path.join(directory, filename)
        print(f"  处理: {filename}")
        
        # 修复系统信息
        modified, msg = fix_vl_system_info(filepath, dry_run)
        print(f"    {msg}")
        if modified:
            fixed_count += 1
        
        # 修复漏洞大类字段
        if fix_category:
            modified2, msg2 = fix_vul_category(filepath, category, dry_run)
            print(f"    {msg2}")
            if modified2 and not modified:
                fixed_count += 1
    
    print(f"\n批量修复完成: 处理{len(vl_files)}个文件, 修复{fixed_count}个, 错误{error_count}个")


def main():
    """命令行主函数"""
    parser = argparse.ArgumentParser(description="修复VL页面系统信息不一致问题")
    parser.add_argument("--dir", help="VL页面目录路径")
    parser.add_argument("--file", help="单个VL页面文件路径")
    parser.add_argument("--dry-run", action="store_true", help="仅显示将要修改的内容，不实际修改")
    parser.add_argument("--fix-category", action="store_true", help="修复漏洞大类字段")
    parser.add_argument("--category", default="应用系统漏洞", help="漏洞大类（默认：应用系统漏洞）")
    
    args = parser.parse_args()
    
    if not args.dir and not args.file:
        print("错误：必须指定 --dir 或 --file 参数")
        parser.print_help()
        return
    
    if args.file:
        # 修复单个文件
        if not os.path.exists(args.file):
            print(f"错误: 文件不存在: {args.file}")
            return
        
        print(f"处理文件: {args.file}")
        
        # 修复系统信息
        modified, msg = fix_vl_system_info(args.file, args.dry_run)
        print(f"  {msg}")
        
        # 修复漏洞大类字段
        if args.fix_category:
            modified2, msg2 = fix_vul_category(args.file, args.category, args.dry_run)
            print(f"  {msg2}")
    
    elif args.dir:
        # 批量修复目录
        batch_fix(args.dir, args.dry_run, args.fix_category, args.category)


if __name__ == "__main__":
    main()
