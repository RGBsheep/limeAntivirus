@echo off
chcp 65001 >nul
title 青柠杀毒启动器

cd /d "%~dp0"

echo ========================================
echo    青柠杀毒 LS - 正在启动...
echo ========================================
echo.

:: 检查Python
python --version >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未找到Python！
    echo 请从 https://python.org 下载安装
    echo 安装时勾选 "Add Python to PATH"
    pause
    exit /b 1
)

:: 安装依赖
echo [信息] 检查依赖...
pip install psutil pywin32 -q 2>nul

:: 启动程序
echo [信息] 正在启动青柠杀毒...
start /b pythonw main.py

echo [信息] 程序已在后台运行
echo [信息] 关闭此窗口不影响程序运行
echo.

timeout /t 2 /nobreak >nul
exit