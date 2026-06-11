#!/bin/bash
# vlWiki 查看器启动脚本
cd /home/sistec/.codebuddy/skills/vlWiki
pkill -f "vlwiki_viewer.py" 2>/dev/null
sleep 1
nohup python3 /home/sistec/.codebuddy/skills/vlWiki/vlwiki_viewer.py > /tmp/vlwiki.log 2>&1 &
disown
sleep 2
if ps aux | grep -v grep | grep "vlwiki_viewer.py" > /dev/null; then
    echo "vlWiki 查看器启动成功"
    echo "   访问地址: http://localhost:8080"
    ps aux | grep -v grep | grep "vlwiki_viewer.py"
else
    echo "启动失败，查看日志:"
    cat /tmp/vlwiki.log
fi
