@echo off
chcp 65001 >nul
:: ============================================================
:: 欲蓝财务魔方 APP —— 以管理员身份启动
:: 双击本文件即可「以管理员身份」运行（UAC 会弹窗确认）。
:: 使用单个 exe（yulan_cube_app.exe），不需要安装 Python 或任何环境。
:: 长期运行更推荐用「计划任务（最高权限）」或 NSSM 注册为 Windows 服务，
:: 这样其他（非管理员）用户登录后完全看不到本程序及其日志。
:: ============================================================
setlocal
set "HERE=%~dp0"

:: 检查管理员权限，不足则自动提权
fltmc >nul 2>&1 || (
  echo 需要管理员权限，正在请求提权……
  powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo 正在启动欲蓝财务魔方 APP（管理员模式）……
"%HERE%yulan_cube_app.exe" --config "%HERE%yulan_cube_config.json"
pause
