@echo off
rem ===========================================================================
rem  SKZI agent uninstaller launcher (team Red Flag).
rem  Usage: uninstall-agent.cmd [/quiet]
rem ===========================================================================
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall-agent.ps1" %*
exit /b %errorlevel%
