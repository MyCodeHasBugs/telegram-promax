@echo off
REM 启动 E2E 加密聊天客户端
chcp 65001 >nul
cd /d "%~dp0"

REM 服务端位置: 默认本地 127.0.0.1:32759 (V2 服务器端口)
E2EChatClient\bin\Debug\net10.0-windows\E2EChatClient.exe
pause
