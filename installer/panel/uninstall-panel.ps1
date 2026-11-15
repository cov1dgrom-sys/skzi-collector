# ===========================================================================
#  Удаление панели управления сбором данных о СКЗИ (команда Red Flag) для текущего пользователя.
#  Удаляет программу, ярлыки и запись в «Установленных приложениях». Агенты на ПК сети и база данных не затрагиваются.
#  Параметры: /quiet — без вопросов и окон.
# ===========================================================================

$ErrorActionPreference = 'Stop'
$Quiet = $false
foreach ($argument in $args) { if ($argument -match '^[/-](q|quiet)$') { $Quiet = $true } }
$Title = 'Модуль сбора данных о СКЗИ — панель управления'
$ShortcutName = 'СКЗИ — панель управления.lnk'
Add-Type -AssemblyName System.Windows.Forms

$panelDirectory = Split-Path -Parent $PSCommandPath
if (-not $Quiet) {
	$answer = [System.Windows.Forms.MessageBox]::Show(
		"Удалить панель управления из папки`n$panelDirectory ?`n`nНастройки и журналы панели тоже будут удалены. Агенты на ПК сети и база данных останутся.",
		$Title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
	if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { exit 1 }
}

try {
	$running = Get-Process -Name 'SkziControlPanel' -ErrorAction SilentlyContinue |
		Where-Object { $_.Path -and ($_.Path -ieq (Join-Path $panelDirectory 'SkziControlPanel.exe')) }
	if ($running) {
		if (-not $Quiet) { [void][System.Windows.Forms.MessageBox]::Show('Сначала закройте панель управления.', $Title) }
		exit 2
	}
	foreach ($folder in @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('Desktop'))) {
		Remove-Item -Path (Join-Path $folder $ShortcutName) -Force -ErrorAction SilentlyContinue
	}
	Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SkziControlPanel' -Recurse -Force -ErrorAction SilentlyContinue
	# Папку удаляем после завершения этого сценария (он сам лежит в ней).
	Set-Location -Path $env:SystemRoot
	Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -WindowStyle Hidden `
		-ArgumentList ('/c ping -n 3 127.0.0.1 >nul & rmdir /s /q "' + $panelDirectory + '"')
	if (-not $Quiet) { [void][System.Windows.Forms.MessageBox]::Show('Панель управления удалена.', $Title) }
	exit 0
}
catch {
	if (-not $Quiet) { [void][System.Windows.Forms.MessageBox]::Show("Удаление не удалось:`n" + $_.Exception.Message, $Title) }
	exit 1
}
