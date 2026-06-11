#!/usr/bin/env python3
"""
vlWiki 简单查看器 - 纯标准库实现
"""

import http.server
import socketserver
import os
import re
import html
import urllib.parse
from pathlib import Path

VAULT_DIR = Path("/home/sistec/.codebuddy/skills/vlWiki/vlWiki/wiki")
PORT = 8080

# 搜索索引：启动时构建，缓存所有页面标题和正文
_search_index = None


def build_search_index():
    """扫描所有 .md 文件，构建搜索索引"""
    index = []
    for md_file in VAULT_DIR.rglob('*.md'):
        try:
            with open(md_file, 'r', encoding='utf-8') as f:
                text = f.read()
            fm, body = parse_frontmatter(text)
            title = fm.get('title', md_file.stem)
            rel = md_file.relative_to(VAULT_DIR).as_posix().replace('.md', '')
            index.append({
                'title': str(title),
                'body': body,
                'rel': rel,
                'severity': str(fm.get('severity', '')),
                'type': str(fm.get('type', '')),
                'system': str(fm.get('system', '')),
            })
        except Exception:
            pass
    return index


def search_pages(query, limit=30):
    """搜索页面，返回匹配结果列表"""
    if not _search_index:
        return []
    q = query.lower().strip()
    if not q:
        return []
    results = []
    for entry in _search_index:
        score = 0
        title_lower = entry['title'].lower()
        body_lower = entry['body'].lower()
        # 标题精确匹配最高优先
        if title_lower == q:
            score = 100
        elif title_lower.startswith(q):
            score = 80
        elif q in title_lower:
            score = 60
        # 正文匹配
        if q in body_lower:
            score += 20 + min(body_lower.count(q) * 2, 20)
        # frontmatter 字段匹配
        if q in entry['severity'].lower() or q in entry['type'].lower() or q in entry['system'].lower():
            score += 30
        if score > 0:
            results.append((score, entry))
    results.sort(key=lambda x: -x[0])
    return results[:limit]


def convert_inline(text):
    text = html.escape(text)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    # 处理图片嵌入 ![[路径|宽度]]
    def _img_repl(m):
        raw = m.group(1)
        if '|' in raw:
            img_path, width = raw.split('|', 1)
        else:
            img_path, width = raw, ''
        # 处理 ../ 相对路径
        while img_path.startswith('../'):
            img_path = img_path[3:]
        img_path = img_path.lstrip('/')
        # 统一为 /assets/ 下的路径
        if not img_path.startswith('assets/'):
            img_path = 'assets/' + img_path
        src = '/' + img_path
        attr = ' width="{0}"'.format(width) if width and width.strip().isdigit() else ''
        return '<img src="{0}" class="wiki-img"{1} onerror="this.style.display=\'none\'">'.format(src, attr)
    text = re.sub(r'!\[\[([^\]]+)\]\]', _img_repl, text)
    # 处理 wikilink [[目标|显示文本]]
    def _wiki_repl(m):
        raw = m.group(1)
        if '|' in raw:
            link_path, label = raw.split('|', 1)
        else:
            link_path, label = raw, raw
        # 去掉 #fragment 用于检测扩展名
        clean_path = link_path.split('#')[0]
        # 检查是否是静态文件链接（有已知扩展名）
        ext = clean_path.rsplit('.', 1)[-1].lower() if '.' in clean_path else ''
        if ext in ('pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg'):
            # 替换 .. 为相对根路径
            while link_path.startswith('../'):
                link_path = link_path[3:]
            link_path = link_path.lstrip('/')
            return '<a href="/{0}" class="wiki-link">{1}</a>'.format(link_path, label)
        else:
            return '<a href="/wiki-link?q={0}" class="wiki-link">{1}</a>'.format(link_path, label)
    text = re.sub(r'\[\[([^\]]+)\]\]', _wiki_repl, text)
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)',
                      r'<a href="\2">\1</a>', text)
    return text


def markdown_to_html(text):
    lines = text.splitlines()
    html_lines = []
    in_code = False
    in_table = False
    table_rows = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('```'):
            if not in_code:
                lang = line[3:].strip()
                html_lines.append('<pre><code>')
                in_code = True
            else:
                html_lines.append('</code></pre>')
                in_code = False
            i += 1
            continue
        if in_code:
            html_lines.append(html.escape(line))
            i += 1
            continue
        if line.startswith('|') and '|' in line[1:]:
            if not in_table:
                in_table = True
                table_rows = []
            table_rows.append(line)
            i += 1
            continue
        else:
            if in_table and table_rows:
                html_lines.append(render_table(table_rows))
                table_rows = []
                in_table = False
        if line.startswith('# '):
            html_lines.append('<h1>' + convert_inline(line[2:]) + '</h1>')
        elif line.startswith('## '):
            html_lines.append('<h2>' + convert_inline(line[3:]) + '</h2>')
        elif line.startswith('### '):
            html_lines.append('<h3>' + convert_inline(line[4:]) + '</h3>')
        elif re.match(r'^---+$', line.strip()):
            html_lines.append('<hr>')
        elif line.startswith('- ') or line.startswith('* '):
            html_lines.append('<li>' + convert_inline(line[2:]) + '</li>')
        elif re.match(r'^\d+\.\s', line):
            content = line.split('.', 1)[1].strip()
            html_lines.append('<li>' + convert_inline(content) + '</li>')
        elif line.startswith('> '):
            html_lines.append('<blockquote>' + convert_inline(line[2:]) + '</blockquote>')
        elif not line.strip():
            html_lines.append('<br>')
        else:
            html_lines.append('<p>' + convert_inline(line) + '</p>')
        i += 1
    if in_table and table_rows:
        html_lines.append(render_table(table_rows))
    return '\n'.join(html_lines)


def render_table(rows):
    html_rows = []
    for idx, row in enumerate(rows):
        cells = [c.strip() for c in row.strip('|').split('|')]
        if idx == 0:
            html_rows.append('<tr>' + ''.join('<th>' + convert_inline(c) + '</th>' for c in cells) + '</tr>')
        elif idx == 1 and all(re.match(r'^[-:]+$', c) for c in cells):
            continue
        else:
            html_rows.append('<tr>' + ''.join('<td>' + convert_inline(c) + '</td>' for c in cells) + '</tr>')
    return '<table class="md-table">\n' + '\n'.join(html_rows) + '\n</table>'


def find_md_file(name):
    # 如果名称已包含 .md 后缀，先去掉
    if name.endswith(".md"):
        name = name[:-3]
    p = VAULT_DIR / f"{name}.md"
    if p.exists():
        return p
    for sub in ["vulnerabilities", "systems", "vulnerability-types", "reports", "knowledge"]:
        p = VAULT_DIR / sub / f"{name}.md"
        if p.exists():
            return p
    return None


def parse_frontmatter(text):
    fm = {}
    body = text
    m = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)', text, re.DOTALL)
    if m:
        fm_text = m.group(1)
        body = m.group(2)
        lines = fm_text.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if ':' in line:
                k, _, v = line.partition(':')
                k = k.strip()
                v = v.strip().strip('"\'')
                # 如果值非空，直接存储
                if v:
                    fm[k] = v
                else:
                    # 空值可能意味着后面有列表项（YAML list）
                    items = []
                    j = i + 1
                    while j < len(lines) and lines[j].strip().startswith('-'):
                        item = lines[j].strip()[1:].strip().strip('"\'')
                        items.append(item)
                        j += 1
                    if items:
                        fm[k] = ', '.join(items)
                    else:
                        fm[k] = v
                    i = j - 1  # 跳过已处理的列表行
            i += 1
    return fm, body


def resolve_page(path):
    """根据路径解析对应的 .md 文件路径，支持子目录"""
    # 先尝试 path.md（如 vulnerability-types/SQL 注入.md）
    p = VAULT_DIR / Path(path).with_suffix('.md')
    if p.exists():
        return p
    # 再尝试 path/index.md
    p = VAULT_DIR / path / "index.md"
    if p.exists():
        return p
    return None


def load_page_content(name):
    md_file = find_md_file(name) or (VAULT_DIR / name)
    if not md_file.exists():
        return {}, ''
    with open(md_file, 'r', encoding='utf-8') as f:
        text = f.read()
    return parse_frontmatter(text)


def build_nav():
    sections = {
        '漏洞 (VL)': sorted(VAULT_DIR.glob('vulnerabilities/VL-*.md')),
        '系统': sorted(VAULT_DIR.glob('systems/*.md')),
        '漏洞类型': sorted(VAULT_DIR.glob('vulnerability-types/*.md')),
        '报告': sorted(VAULT_DIR.glob('reports/*.md')),
        '知识库': sorted(VAULT_DIR.glob('knowledge/*.md')),
        '模板': sorted(VAULT_DIR.glob('templates/*.md')),
    }
    nav_parts = []
    for title, files in sections.items():
        if not files:
            continue
        items = ''
        for f in files:
            name = f.stem
            rel = f.relative_to(VAULT_DIR).as_posix().replace('.md', '')
            href = '/' + urllib.parse.quote(rel, safe='/')
            items += '<li><a href="{0}">{1}</a></li>\n'.format(href, html.escape(name))
        nav_parts.append(
            '<div class="nav-section">'
            '<h3 class="nav-toggle" onclick="toggleNav(this)"><span class="nav-arrow">▶</span> {0} <span class="nav-count">{1}</span></h3>'
            '<ul class="nav-collapsed">\n{2}</ul>'
            '</div>'.format(html.escape(title), len(files), items)
        )
    return '\n'.join(nav_parts)


CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans SC", sans-serif;
    background: #ffffff;
    color: #333333;
    display: flex;
    min-height: 100vh;
}
.sidebar {
    width: 260px;
    background: #f8f9fa;
    border-right: 1px solid #e0e0e0;
    padding: 12px 0;
    overflow-y: auto;
    flex-shrink: 0;
}
.sidebar h2 {
    padding: 8px 16px;
    font-size: 13px;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.search-box {
    padding: 6px 12px;
    border-bottom: 1px solid #e0e0e0;
    margin-bottom: 4px;
}
.search-box input {
    width: 100%;
    padding: 6px 10px;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    font-size: 13px;
    outline: none;
    background: #fff;
}
.search-box input:focus {
    border-color: #1a73e8;
}
.search-results {
    max-height: 300px;
    overflow-y: auto;
    border-bottom: 1px solid #e0e0e0;
}
.search-results a {
    display: block;
    padding: 5px 16px;
    font-size: 12px;
    color: #333;
    text-decoration: none;
    border-left: 3px solid transparent;
}
.search-results a:hover {
    background: #e8f0fe;
    color: #1a73e8;
    border-left-color: #1a73e8;
}
.search-results .sr-title {
    font-weight: 600;
    font-size: 13px;
}
.search-results .sr-context {
    color: #888;
    font-size: 11px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.nav-section h3 {
    padding: 8px 16px 4px;
    font-size: 12px;
    color: #888;
    font-weight: 600;
    cursor: pointer;
    user-select: none;
    display: flex;
    align-items: center;
    gap: 4px;
}
.nav-section h3:hover {
    color: #333;
}
.nav-arrow {
    font-size: 10px;
    transition: transform 0.15s;
    display: inline-block;
}
.nav-arrow.open {
    transform: rotate(90deg);
}
.nav-count {
    margin-left: auto;
    font-size: 11px;
    color: #aaa;
    font-weight: 400;
}
.nav-collapsed {
    display: none;
    list-style: none;
    padding: 0;
}
.nav-collapsed.open {
    display: block;
}
.nav-section ul { list-style: none; padding: 0; }
.nav-section li a {
    display: block;
    padding: 4px 16px 4px 24px;
    color: #333333;
    text-decoration: none;
    font-size: 13px;
    border-left: 3px solid transparent;
}
.nav-section li a:hover {
    background: #e8f0fe;
    color: #1a73e8;
    border-left-color: #1a73e8;
}
.nav-section li a.active {
    background: #1a73e8;
    color: #fff;
    border-left-color: #1a73e8;
    font-weight: 600;
}
.main {
    flex: 1;
    padding: 24px 32px;
    overflow-y: auto;
    max-width: 1100px;
    overflow-x: auto;
    background: #ffffff;
}
h1 { font-size: 28px; margin-bottom: 16px; color: #1a1a1a; }
h2 { font-size: 22px; margin: 20px 0 10px; color: #1a1a1a; border-bottom: 1px solid #e0e0e0; padding-bottom: 6px; }
h3 { font-size: 18px; margin: 16px 0 8px; color: #333; }
p { margin: 8px 0; line-height: 1.7; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }
.wiki-link { color: #0066cc; }
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    margin-left: 8px;
}
.badge-紧急 { background: #ff0040; color: #fff; }
.badge-高 { background: #ff4242; color: #fff; }
.badge-中 { background: #ff8c00; color: #fff; }
.badge-低 { background: #4ec9b0; color: #000; }
.badge-信息 { background: #888; color: #fff; }
.frontmatter {
    background: #f0f4ff;
    border: 1px solid #c8d8f0;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 20px;
    font-size: 13px;
}
.fm-item { padding: 2px 0; }
.fm-key { color: #888; min-width: 120px; display: inline-block; }
.fm-val { color: #0066cc; }
pre {
    background: #f5f5f5;
    border: 1px solid #ddd;
    border-radius: 6px;
    padding: 14px 18px;
    overflow-x: auto;
    margin: 12px 0;
    font-size: 13px;
}
pre code { color: #333; font-family: "Cascadia Code", "Fira Code", monospace; }
code {
    background: #e8e8e8;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 13px;
    color: #c7254e;
}
.md-table {
    border-collapse: collapse;
    width: 100%;
    margin: 12px 0;
    font-size: 13px;
}
.md-table th, .md-table td {
    border: 1px solid #ddd;
    padding: 6px 12px;
    text-align: left;
}
.md-table th { background: #f0f0f0; color: #333; font-weight: 600; }
li { margin: 4px 0 4px 20px; line-height: 1.7; }
blockquote {
    border-left: 3px solid #1a73e8;
    padding: 8px 16px;
    margin: 12px 0;
    background: #f9f9f9;
    color: #666;
}
hr { border: none; border-top: 1px solid #e0e0e0; margin: 20px 0; }
.wiki-img { border-radius: 6px; margin: 12px 0; }
/* 搜索关键词高亮 */
.highlight { background: #fff176; padding: 0 2px; border-radius: 2px; color: #333; }
/* 返回顶部按钮 */
.back-to-top {
    position: fixed;
    bottom: 30px;
    left: 30px;
    width: 42px;
    height: 42px;
    background: #1a73e8;
    color: #fff;
    border: none;
    border-radius: 50%;
    font-size: 20px;
    cursor: pointer;
    opacity: 0;
    transition: opacity 0.3s;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    z-index: 999;
}
.back-to-top.visible { opacity: 0.85; }
.back-to-top:hover { opacity: 1; }
/* 侧边栏切换按钮 */
.sidebar-toggle {
    display: block;
    position: fixed;
    top: 10px;
    left: 274px;
    z-index: 999;
    background: #f8f9fa;
    color: #1a73e8;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 14px;
    cursor: pointer;
    transition: left 0.3s;
}
.sidebar-toggle.collapsed { left: 10px; }
/* 宽屏时侧边栏收起 */
body.sidebar-collapsed .sidebar { width: 0; overflow: hidden; padding: 0; border: none; }
body.sidebar-collapsed .sidebar-toggle { left: 10px; }
body.sidebar-collapsed .main { max-width: 100%; }
/* 响应式布局 */
@media (max-width: 768px) {
    .sidebar {
        position: fixed;
        left: -280px;
        top: 0;
        bottom: 0;
        width: 280px;
        z-index: 998;
        transition: left 0.3s;
    }
    .sidebar.mobile-open { left: 0; }
    .sidebar-toggle { left: 10px; }
    .main {
        max-width: 100%;
        padding: 40px 16px 24px;
    }
    .md-table { font-size: 11px; }
    .md-table th, .md-table td { padding: 4px 6px; }
    .wiki-img { max-width: 100%; }
    .back-to-top { left: 16px; bottom: 20px; }
}
"""


def wrap_template(title, content, nav):
    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{0} - vlWiki</title>
<style>{1}</style>
</head>
<body>
    <button class="sidebar-toggle" onclick="toggleSidebar()">☰ 导航</button>
    <div class="sidebar" id="sidebar">
    <h2><a href="/" style="color:inherit;text-decoration:none;">📚 vlWiki</a></h2>
    <div class="search-box">
        <input type="text" id="searchInput" placeholder="搜索漏洞..." oninput="doSearch(this.value)" onfocus="showResults()" />
        <div class="search-results" id="searchResults" style="display:none"></div>
    </div>
    {2}
  </div>
  <div class="main" id="mainContent">
    {3}
  </div>
  <button class="back-to-top" id="backToTop" onclick="scrollToTop()" title="返回顶部">↑</button>
</body>
<script>
// ===== 侧边栏折叠/展开记忆 =====
function toggleNav(el) {{
    var ul = el.nextElementSibling;
    var arrow = el.querySelector('.nav-arrow');
    var section = el.textContent.trim().replace(/^[▶▷]\\s*/, '').split(' ')[0];
    if (ul.classList.contains('open')) {{
        ul.classList.remove('open');
        arrow.classList.remove('open');
        saveNavState(section, false);
    }} else {{
        ul.classList.add('open');
        arrow.classList.add('open');
        saveNavState(section, true);
    }}
}}
function saveNavState(section, open) {{
    var state = JSON.parse(localStorage.getItem('navState') || '{{}}');
    state[section] = open;
    localStorage.setItem('navState', JSON.stringify(state));
}}
function restoreNavState() {{
    var state = JSON.parse(localStorage.getItem('navState') || '{{}}');
    document.querySelectorAll('.nav-toggle').forEach(function(el) {{
        var section = el.textContent.trim().replace(/^[▶▷]\\s*/, '').split(' ')[0];
        if (state[section] === true) {{
            var ul = el.nextElementSibling;
            var arrow = el.querySelector('.nav-arrow');
            ul.classList.add('open');
            arrow.classList.add('open');
        }}
    }});
}}

// ===== 当前页面高亮 =====
function highlightCurrentPage() {{
    var href = window.location.pathname;
    var links = document.querySelectorAll('.nav-section li a');
    var best = null;
    var bestLen = 0;
    links.forEach(function(a) {{
        var ahref = a.getAttribute('href') || '';
        // 精确匹配优先，其次最长前缀匹配
        if (decodeURIComponent(ahref) === decodeURIComponent(href)) {{
            best = a; bestLen = 999;
        }} else if (decodeURIComponent(href).indexOf(decodeURIComponent(ahref)) === 0 && ahref.length > bestLen) {{
            best = a; bestLen = ahref.length;
        }}
    }});
    if (best) {{
        best.classList.add('active');
        // 展开所在分类
        var section = best.closest('.nav-section');
        if (section) {{
            var ul = section.querySelector('ul');
            var arrow = section.querySelector('.nav-arrow');
            if (ul && arrow) {{
                ul.classList.add('open');
                arrow.classList.add('open');
            }}
        }}
    }}
}}

// ===== 侧边栏响应式切换 =====
function toggleSidebar() {{
    var body = document.body;
    var sidebar = document.getElementById('sidebar');
    var toggle = document.querySelector('.sidebar-toggle');
    var isNarrow = window.innerWidth <= 768;
    if (isNarrow) {{
        // 窄屏：overlay模式
        sidebar.classList.toggle('mobile-open');
    }} else {{
        // 宽屏：折叠模式
        body.classList.toggle('sidebar-collapsed');
        toggle.classList.toggle('collapsed');
        var state = body.classList.contains('sidebar-collapsed') ? 'collapsed' : 'expanded';
        localStorage.setItem('sidebarState', state);
    }}
}}

// 宽屏时恢复侧边栏折叠状态
(function() {{
    if (window.innerWidth > 768) {{
        var state = localStorage.getItem('sidebarState');
        if (state === 'collapsed') {{
            document.body.classList.add('sidebar-collapsed');
            document.querySelector('.sidebar-toggle').classList.add('collapsed');
        }}
    }}
}})();

// ===== 返回顶部 =====
var backToTop = document.getElementById('backToTop');
var mainContent = document.getElementById('mainContent');
function updateBackToTop() {{
    var scrollTop = mainContent.scrollTop || window.pageYOffset || document.documentElement.scrollTop || 0;
    if (scrollTop > 300) {{
        backToTop.classList.add('visible');
    }} else {{
        backToTop.classList.remove('visible');
    }}
}}
mainContent.addEventListener('scroll', updateBackToTop);
window.addEventListener('scroll', updateBackToTop);
// 初始化时也检查一次
updateBackToTop();
function scrollToTop() {{
    mainContent.scrollTo({{ top: 0, behavior: 'smooth' }});
    window.scrollTo({{ top: 0, behavior: 'smooth' }});
}}

// ===== 搜索关键词高亮 =====
function highlightSearchTerm() {{
    var params = new URLSearchParams(window.location.search);
    var q = params.get('hl');
    if (!q) {{
        // 也检查 referrer 是否来自搜索
        if (document.referrer.indexOf('/search?q=') === -1) return;
        var m = document.referrer.match(/[?&]q=([^&]*)/);
        if (!m) return;
        q = decodeURIComponent(m[1]);
    }}
    if (!q || q.length < 2) return;
    var words = q.split(/\\s+/).filter(function(w) {{ return w.length >= 2; }});
    if (!words.length) return;
    var main = document.getElementById('mainContent');
    var walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT, null, false);
    var textNodes = [];
    while (walker.nextNode()) textNodes.push(walker.currentNode);
    var html = main.innerHTML;
    words.forEach(function(word) {{
        var re = new RegExp('(' + word.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&') + ')', 'gi');
        html = html.replace(re, '<mark class="highlight">$1</mark>');
    }});
    // 避免在高亮标签内嵌套
    html = html.replace(/<mark class="highlight">([^<]*<mark[^>]*>[^<]*)<\\/mark><\\/mark>/gi, '<mark class="highlight">$1</mark>');
    if (html !== main.innerHTML) {{
        main.innerHTML = html;
    }}
}}

// ===== 页面初始化 =====
restoreNavState();
highlightCurrentPage();
highlightSearchTerm();

// ===== 搜索功能（保持原有） =====
var searchTimer = null;
function doSearch(val) {{
    clearTimeout(searchTimer);
    var container = document.getElementById('searchResults');
    if (!val.trim()) {{
        container.style.display = 'none';
        container.innerHTML = '';
        return;
    }}
    searchTimer = setTimeout(function() {{
        fetch('/search?q=' + encodeURIComponent(val))
            .then(function(r) {{ return r.text(); }})
            .then(function(html) {{
                container.innerHTML = html || '<div style="padding:8px 16px;color:#888;font-size:12px;">无结果</div>';
                container.style.display = 'block';
            }});
    }}, 300);
}}
function showResults() {{
    var container = document.getElementById('searchResults');
    if (container.innerHTML) container.style.display = 'block';
}}
document.addEventListener('click', function(e) {{
    var box = document.querySelector('.search-box');
    var container = document.getElementById('searchResults');
    if (!box.contains(e.target)) {{
        container.style.display = 'none';
    }}
}});
document.addEventListener('keydown', function(e) {{
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {{
        e.preventDefault();
        document.getElementById('searchInput').focus();
    }}
}});
// 窄屏点击内容区关闭侧边栏
document.getElementById('mainContent').addEventListener('click', function() {{
    if (window.innerWidth <= 768) {{
        document.getElementById('sidebar').classList.remove('mobile-open');
    }}
}});
</script>
</html>""".format(html.escape(title), CSS, nav, content)


class WikiHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(parsed.path)
        query = urllib.parse.parse_qs(parsed.query)

        if path == '/' or path == '/index.html':
            self.serve_index()
        elif path.startswith('/assets/') or path.startswith('/raw/'):
            self.serve_asset(path)
        elif path.startswith('/wiki-link'):
            q = query.get('q', [''])[0]
            self.serve_wiki_link(q)
        elif path.startswith('/search'):
            q = query.get('q', [''])[0]
            self.serve_search(q)
        else:
            self.serve_page(path.strip('/'))

    def serve_index(self):
        import traceback, sys
        try:
            fm, body = load_page_content("index.md")
            page_html = markdown_to_html(body)
            nav = build_nav()
            html_page = wrap_template("vlWiki 知识库", page_html, nav)
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html_page.encode('utf-8'))
        except Exception as e:
            err = traceback.format_exc()
            with open("/tmp/vlwiki_error.log", "w") as f:
                f.write(str(err))
            self.send_error(500, str(e))

    def serve_page(self, path):
        import traceback as _tb
        try:
            md_file = resolve_page(path)
            if not md_file or not md_file.exists():
                self.send_error(404, "Page not found: {0}".format(path))
                return
            with open(md_file, 'r', encoding='utf-8') as f:
                text = f.read()
            fm, body = parse_frontmatter(text)
            title = fm.get('title', path)
            body_stripped = body.lstrip()
            if body_stripped.startswith('# '):
                first_line = body_stripped.split('\n')[0]
                h1_title = first_line[2:].strip()
                if h1_title == title:
                    body = body_stripped[len(first_line):].lstrip('\n')
            page_html = markdown_to_html(body)
            severity = fm.get('severity', '')
            severity_badge = ''
            if severity:
                cls = 'badge-' + severity.replace('危', '')
                severity_badge = '<span class="badge {0}">{1}</span>'.format(cls, severity)
            fm_html = ''
            if fm:
                fm_items = ''.join(
                    '<div class="fm-item"><span class="fm-key">{0}</span>: <span class="fm-val">{1}</span></div>'.format(k, v)
                    for k, v in fm.items()
                )
                fm_html = '<div class="frontmatter">{0}</div>'.format(fm_items)
            vl_id = md_file.stem
            if vl_id.startswith('VL-'):
                heading = '{0} {1}'.format(html.escape(vl_id), html.escape(title))
            else:
                heading = html.escape(title)
            content = '{0}\n<h1>{1} {2}</h1>\n{3}'.format(fm_html, heading, severity_badge, page_html)
            nav = build_nav()
            html_page = wrap_template(title, content, nav)
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html_page.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write("ERROR: {0}\n{1}".format(e, _tb.format_exc()).encode())

    def serve_asset(self, path):
        asset_path = VAULT_DIR / path[len('/'):].replace('/', os.sep)
        if not asset_path.exists():
            self.send_error(404)
            return
        ext = asset_path.suffix.lower()[1:]
        mime = {
            'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
            'gif': 'image/gif', 'svg': 'image/svg+xml',
            'pdf': 'application/pdf',
        }.get(ext, 'application/octet-stream')
        with open(asset_path, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-type', mime)
        if ext == 'pdf':
            # RFC 5987 编码中文文件名，避免 latin-1 错误
            encoded_name = urllib.parse.quote(asset_path.name)
            self.send_header('Content-Disposition', "inline; filename*=UTF-8''{0}".format(encoded_name))
        self.end_headers()
        self.wfile.write(data)

    def serve_wiki_link(self, q):
        md_file = find_md_file(q)
        if md_file:
            rel = md_file.relative_to(VAULT_DIR).as_posix().replace('.md', '')
            location = '/' + urllib.parse.quote(rel, safe='/')
            self.send_response(302)
            self.send_header('Location', location)
            self.end_headers()
        else:
            self.send_error(404, "Page not found: {0}".format(q))

    def serve_search(self, q):
        results = search_pages(q)
        items = []
        for score, entry in results:
            href = '/' + urllib.parse.quote(entry['rel'], safe='/')
            href += '?hl=' + urllib.parse.quote(q, safe='')
            title = html.escape(entry['title'])
            # 提取匹配上下文
            q_lower = q.lower()
            body_lower = entry['body'].lower()
            pos = body_lower.find(q_lower)
            context = ''
            if pos >= 0:
                start = max(0, pos - 20)
                end = min(len(entry['body']), pos + len(q) + 40)
                context = html.escape(entry['body'][start:end].replace('\n', ' '))
                if start > 0:
                    context = '...' + context
                if end < len(entry['body']):
                    context = context + '...'
            items.append('<a href="{0}"><div class="sr-title">{1}</div><div class="sr-context">{2}</div></a>'.format(href, title, context))
        json_resp = '\n'.join(items)
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(json_resp.encode('utf-8'))

    def log_message(self, format, *args):
        pass


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    global _search_index
    _search_index = build_search_index()
    print("搜索索引已构建: {0} 个页面".format(len(_search_index)))
    os.chdir(VAULT_DIR.parent)
    server = ThreadedServer(("0.0.0.0", PORT), WikiHTTPRequestHandler)
    print("vlWiki 查看器已启动")
    print("访问地址: http://localhost:{0}".format(PORT))
    print("知识库目录: {0}".format(VAULT_DIR))
    print("按 Ctrl+C 停止服务器")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("服务器已停止")


if __name__ == '__main__':
    main()
