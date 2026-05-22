import json, sys
sys.path.insert(0, r'C:\Users\stc\.codebuddy\skills\document-reader\scripts')
import pdf_extract

# 1. Show debug JSON types
json_path = r'D:\Users\个人项目\wb\vlWiki\wiki\assets\pdfs\26-3-3 安全报告_debug.json'
d = json.load(open(json_path, encoding='utf-8'))
print('=== Debug JSON ===')
print(f'Types: {d["meta"]["vulnerability_types"]}, Instances: {d["meta"]["total_instances"]}')
for t in d['types']:
    print(f'  [{t["severity"]}] {t["type"]} ({t["instance_count"]} inst)')

# 2. Extract PDF text and show types from the front section
print('\n=== PDF Front Section Types ===')
r = pdf_extract.extract_pymupdf(r'D:\Users\个人项目\wb\vlWiki\wiki\assets\pdfs\26-3-3 安全报告.pdf')
text = '\n'.join([p['text'] for p in r['pages']])
import re
# Find "按问题类型分组的问题" section
anchor = text.find('按问题类型分组的问题')
if anchor != -1:
    section = text[anchor:2000]
    # Find all "问题 X / Y" patterns and the type after them
    for m in re.finditer(r'问题\s+\d+\s+/\s+\d+\n(.*?)\n', section):
        print(f'  {m.group(1).strip()}')
