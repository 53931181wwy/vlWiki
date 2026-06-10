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

VAULT_DIR = Path(__file__).parent.resolve() / "vlWiki" / "wiki"
PORT = 8080


def convert_inline(text):
    text = html.escape(text)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    text = re.sub(r'!\[\[([^\]]+)\]\]',
                      r'<img src="/assets/screenshots/\1" class="wiki-img" onerror="this.style.display=\'none\'">', text)
    text = re.sub(r'\[\[([^\]]+)\]\]',
                      r'<a href="/wiki-link?q=\1" class="wiki-link">\1</a>', text)
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
    for sub in ["vulnerabilities", "systems", "vulnerability-types", "reports"]:
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
        for line in fm_text.splitlines():
            if ':' in line:
                k, _, v = line.partition(':')
                fm[k.strip()] = v.strip().strip('"\'')
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
.main {
    flex: 1;
    padding: 24px 32px;
    overflow-y: auto;
    max-width: 900px;
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
.wiki-img { max-width: 100%; border-radius: 6px; margin: 12px 0; }
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
    <div class="sidebar">
    <h2><a href="/" style="color:inherit;text-decoration:none;">📚 vlWiki</a></h2>
    {2}
  </div>
  <div class="main">
    {3}
  </div>
</body>
<script>
function toggleNav(el) {{
    var ul = el.nextElementSibling;
    var arrow = el.querySelector('.nav-arrow');
    if (ul.classList.contains('open')) {{
        ul.classList.remove('open');
        arrow.classList.remove('open');
    }} else {{
        ul.classList.add('open');
        arrow.classList.add('open');
    }}
}}
document.querySelectorAll('.nav-toggle').forEach(function(el) {{
    var href = window.location.pathname;
    var ul = el.nextElementSibling;
    var links = ul.querySelectorAll('a');
    links.forEach(function(a) {{
        if (a.getAttribute('href') === href || decodeURIComponent(a.getAttribute('href')) === decodeURIComponent(href)) {{
            ul.classList.add('open');
            el.querySelector('.nav-arrow').classList.add('open');
        }}
    }});
}});
</script>
</html>""".format(html.escape(title), CSS, nav, content)


class WikiHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(parsed.path)  # 解码百分号编码的中文
        query = urllib.parse.parse_qs(parsed.query)

        if path == '/' or path == '/index.html':
            self.serve_index()
        elif path.startswith('/assets/'):
            self.serve_asset(path)
        elif path.startswith('/wiki-link'):
            q = query.get('q', [''])[0]
            self.serve_wiki_link(q)
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
        md_file = resolve_page(path)
        if not md_file or not md_file.exists():
            self.send_error(404, "Page not found: {0}".format(path))
            return
        with open(md_file, 'r', encoding='utf-8') as f:
            text = f.read()
        fm, body = parse_frontmatter(text)
        page_html = markdown_to_html(body)
        title = fm.get('title', path)
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
        content = '{0}\n<h1>{1} {2}</h1>\n{3}'.format(fm_html, html.escape(title), severity_badge, page_html)
        nav = build_nav()
        html_page = wrap_template(title, content, nav)
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_page.encode('utf-8'))

    def serve_asset(self, path):
        asset_path = VAULT_DIR / path[len('/'):].replace('/', os.sep)
        if not asset_path.exists():
            self.send_error(404)
            return
        ext = asset_path.suffix.lower()
        mime = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'gif': 'image/gif', 'svg': 'image/svg+xml'}.get(ext, 'application/octet-stream')
        with open(asset_path, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-type', mime)
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

    def log_message(self, format, *args):
        pass


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
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
