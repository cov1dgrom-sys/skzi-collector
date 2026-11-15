@echo off
rem ===========================================================================
rem  SKZI data collection module (case #03, GRChTs) - team Red Flag
rem  Build script. Uses the C# compiler shipped with .NET Framework 4.x,
rem  Visual Studio is NOT required.
rem
rem  build.cmd          build bin\SkziAgent.exe, bin\SkziControlPanel.exe, bin\SkziTests.exe
rem  build.cmd test     build and run automated tests
rem  build.cmd clean    delete bin\*.exe
rem
rem  Strict .NET 4.5 API check (optional): set SKZI_NET45_REFS to a folder with
rem  .NET 4.5 reference assemblies (NuGet package Microsoft.NETFramework.ReferenceAssemblies.net45,
rem  folder build\.NETFramework\v4.5).
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

if /i "%~1"=="clean" (
	del /q bin\*.exe 2>nul
	echo Cleaned.
	exit /b 0
)

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
	echo ERROR: C# compiler of .NET Framework 4.x not found.
	exit /b 1
)

if not exist bin mkdir bin

set "OPTIONS=/nologo /langversion:5 /codepage:65001 /utf8output /optimize+ /platform:anycpu /warn:4 /win32icon:src\Assets\skzi.ico /win32manifest:src\Assets\app.manifest"
set "P="
if defined SKZI_NET45_REFS (
	echo Strict build against .NET 4.5 reference assemblies: %SKZI_NET45_REFS%
	set "P=%SKZI_NET45_REFS%\"
	set "OPTIONS=%OPTIONS% /nostdlib /noconfig /r:"%SKZI_NET45_REFS%\mscorlib.dll""
)
set "REFS=/r:"%P%System.dll" /r:"%P%System.Core.dll" /r:"%P%System.Data.dll" /r:"%P%System.Xml.dll" /r:"%P%System.Security.dll" /r:"%P%System.ServiceProcess.dll""
set "WINREFS=/r:"%P%System.Windows.Forms.dll" /r:"%P%System.Drawing.dll""

echo [1/3] SkziAgent.exe
"%CSC%" %OPTIONS% %REFS% /target:exe /out:bin\SkziAgent.exe /recurse:src\Common\*.cs src\SkziAgent\*.cs src\SkziAgent\Properties\AssemblyInfo.cs
if errorlevel 1 goto :failed

echo [2/3] SkziControlPanel.exe
"%CSC%" %OPTIONS% %REFS% %WINREFS% /resource:src\Assets\grfc-logo-white.png,Skzi.ControlPanel.GrfcLogo.png /target:winexe /out:bin\SkziControlPanel.exe /recurse:src\Common\*.cs src\SkziControlPanel\*.cs src\SkziControlPanel\Properties\AssemblyInfo.cs
if errorlevel 1 goto :failed

echo [3/3] SkziTests.exe
"%CSC%" %OPTIONS% %REFS% %WINREFS% /target:exe /main:Skzi.Tests.TestProgram /out:bin\SkziTests.exe /recurse:src\Common\*.cs src\SkziAgent\*.cs src\SkziControlPanel\*.cs tests\SkziTests\*.cs
if errorlevel 1 goto :failed

if not exist bin\agent.config.xml copy /y config\agent.config.xml bin\ >nul
if not exist bin\panel.config.xml copy /y config\panel.config.xml bin\ >nul

echo.
echo Build OK: %CD%\bin
if /i "%~1"=="test" (
	echo.
	bin\SkziTests.exe samples\certs
	exit /b %errorlevel%
)
exit /b 0

:failed
echo.
echo BUILD FAILED
exit /b 1
