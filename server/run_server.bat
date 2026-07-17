@echo off
REM 启动 32759 端口 V2 聊天服务器 (Signal-style 安全栈, uvicorn + ASGI)
chcp 65001 >nul
cd /d "%~dp0"

python -m pip install -r requirements.txt --quiet 2>NUL
python server_v2.py
pause
