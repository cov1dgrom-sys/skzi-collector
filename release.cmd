@echo off
rem ===========================================================================
rem  SKZI data collection module (case #03, GRChTs) - team Red Flag
rem  Release build: compiles, runs tests and puts installers, portable ZIP
rem  and SHA-256 checksums into dist\v<version>\.
rem
rem  release.cmd              build + tests + release
rem  release.cmd -SkipTests   build + release without tests
rem ===========================================================================
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\make-release.ps1" %*
exit /b %errorlevel%
