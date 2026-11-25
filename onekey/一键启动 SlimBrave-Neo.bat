@echo off
setlocal EnableExtensions
chcp 65001 >nul
title 一键启动 SlimBrave-Neo 中文版
color 0A

:: 1. 自动请求管理员权限（使用 PowerShell 提权，兼容 Win11 24H2+ 无 VBScript 与带空格路径）
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在请求管理员权限，请在弹出的 UAC 窗口中点击“是”...
    powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: 切换到脚本所在目录
cd /d "%~dp0"

set "TARGET=SlimBrave-zh.ps1"
set "TMPFILE=SlimBrave-zh.ps1.tmp"
set "URL_MIRROR=https://gh-proxy.org/https://raw.githubusercontent.com/sleel/SlimBrave-Neo-ZH/main/dist/SlimBrave-zh.ps1"
set "URL_DIRECT=https://raw.githubusercontent.com/sleel/SlimBrave-Neo-ZH/main/dist/SlimBrave-zh.ps1"

echo 正在获取最新版 SlimBrave-Neo 中文版，请稍候...

:: 2. 安全下载（先镜像、失败回退 GitHub 直连；校验内容防止代理返回错误网页覆盖本地文件）
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ProgressPreference = 'SilentlyContinue';" ^
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" ^
    "$urls = @('%URL_MIRROR%', '%URL_DIRECT%');" ^
    "$ok = $false;" ^
    "foreach ($u in $urls) {" ^
    "  try {" ^
    "    Invoke-WebRequest -Uri $u -OutFile '%TMPFILE%' -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop;" ^
    "    $raw = [System.IO.File]::ReadAllText((Resolve-Path '%TMPFILE%'), [System.Text.Encoding]::UTF8);" ^
    "    if ($raw -match 'SLIMBRAVE-NEO-ZH') {" ^
    "      Move-Item -Path '%TMPFILE%' -Destination '%TARGET%' -Force;" ^
    "      Write-Host ('已更新为最新版本 (' + $u + ')');" ^
    "      $ok = $true; break" ^
    "    }" ^
    "  } catch {}" ^
    "  if (Test-Path '%TMPFILE%') { Remove-Item '%TMPFILE%' -Force -ErrorAction SilentlyContinue }" ^
    "}" ^
    "if (-not $ok) { exit 1 }"

if %errorlevel% neq 0 (
    if exist "%TARGET%" (
        echo [提示] 在线更新失败，将使用本地已缓存的 %TARGET% 启动...
    ) else (
        echo [错误] 下载失败且本地无可用缓存，请检查网络连接后重试。
        pause
        exit /b 1
    )
)

:: 3. 启动中文版 GUI
echo 正在启动 %TARGET% ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0%TARGET%"
if %errorlevel% neq 0 (
    echo [错误] 脚本异常退出（退出码 %errorlevel%）。
    pause
    exit /b %errorlevel%
)

endlocal
exit /b 0
