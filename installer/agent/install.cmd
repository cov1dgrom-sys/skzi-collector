@echo off
rem ===========================================================================
rem  SKZI agent installer launcher (team Red Flag).
rem  Runs from the folder the self-extracting installer unpacked to and starts
rem  install-agent.ps1 in 64-bit PowerShell when the OS is 64-bit.
rem  Usage: install.cmd [/quiet] [/resetconfig]
rem ===========================================================================
setlocal
cd /d "%~dp0"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-agent.ps1" %*
exit /b %errorlevel%
