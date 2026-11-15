@echo off
rem ===========================================================================
rem  SKZI control panel installer launcher (team Red Flag).
rem  Installs for the current user, administrator rights are not required.
rem  Usage: install.cmd [/quiet]
rem ===========================================================================
setlocal
cd /d "%~dp0"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-panel.ps1" %*
exit /b %errorlevel%
