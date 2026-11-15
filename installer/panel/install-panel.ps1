# ===========================================================================
#  Установка панели управления сбором данных о СКЗИ (команда Red Flag).
#  Ставится для текущего пользователя в %LOCALAPPDATA%\Programs\SkziControlPanel — права администратора не нужны:
#  панель хранит конфигурацию и журналы рядом с exe, а пароли — под DPAPI этого пользователя.
#  Рядом кладётся SkziAgent.exe: из него панель устанавливает агенты на ПК сети.
#  Повторный запуск обновляет программу; panel.config.xml (настройки, список ПК, пароли) сохраняется.
#
#  Параметры: /quiet — без окон. Коды выхода: 0 — успех, 2 — панель запущена, остальные — ошибка.
# ===========================================================================

$ErrorActionPreference = 'Stop'
$ProductVersion = '@VERSION@'
$DisplayName = 'Модуль сбора данных о СКЗИ — панель управления'
$ShortcutName = 'СКЗИ — панель управления.lnk'
$Quiet = $false
foreach ($argument in $args) { if ($argument -match '^[/-](q|quiet)$') { $Quiet = $true } }

Add-Type -AssemblyName System.Windows.Forms

# Показывает сообщение (в тихом режиме ничего не показывает); возвращает нажатую кнопку.
function Show-Message([string]$Text, [string]$Icon = 'Information', [string]$Buttons = 'OK') {
	if ($Quiet) { return 'None' }
	return [System.Windows.Forms.MessageBox]::Show($Text, $DisplayName + ' ' + $ProductVersion,
		[System.Windows.Forms.MessageBoxButtons]::$Buttons, [System.Windows.Forms.MessageBoxIcon]::$Icon).ToString()
}

# Создаёт ярлык Windows (.lnk) на программу.
function New-Shortcut([string]$Path, [string]$Target, [string]$WorkingDirectory, [string]$Description) {
	$shell = New-Object -ComObject WScript.Shell
	$shortcut = $shell.CreateShortcut($Path)
	$shortcut.TargetPath = $Target
	$shortcut.WorkingDirectory = $WorkingDirectory
	$shortcut.Description = $Description
	$shortcut.IconLocation = $Target + ',0'
	$shortcut.Save()
}

$sourceDirectory = Split-Path -Parent $PSCommandPath
$targetDirectory = Join-Path $env:LOCALAPPDATA 'Programs\SkziControlPanel'
$targetExecutable = Join-Path $targetDirectory 'SkziControlPanel.exe'

try {
	# 1. Панель из этой папки не должна быть запущена — иначе exe не заменить.
	$running = Get-Process -Name 'SkziControlPanel' -ErrorAction SilentlyContinue |
		Where-Object { $_.Path -and ($_.Path -ieq $targetExecutable) }
	if ($running) {
		Show-Message 'Панель управления сейчас запущена. Закройте её и запустите установку ещё раз.' 'Warning' | Out-Null
		exit 2
	}

	# 2. Файлы программы; настройки пользователя не перезаписываются.
	New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
	foreach ($name in @('SkziControlPanel.exe', 'SkziAgent.exe', 'uninstall-panel.ps1')) {
		Copy-Item -Path (Join-Path $sourceDirectory $name) -Destination (Join-Path $targetDirectory $name) -Force
	}
	$targetConfig = Join-Path $targetDirectory 'panel.config.xml'
	if (-not (Test-Path $targetConfig)) {
		Copy-Item -Path (Join-Path $sourceDirectory 'panel.config.xml') -Destination $targetConfig
	}

	# 3. Ярлыки в меню «Пуск» и на рабочем столе.
	$description = 'Сканирование ПК сети: личные сертификаты и КриптоПро CSP → MSSQL'
	New-Shortcut (Join-Path ([Environment]::GetFolderPath('Programs')) $ShortcutName) $targetExecutable $targetDirectory $description
	New-Shortcut (Join-Path ([Environment]::GetFolderPath('Desktop')) $ShortcutName) $targetExecutable $targetDirectory $description

	# 4. Запись в «Установленных приложениях» текущего пользователя — для штатного удаления.
	$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SkziControlPanel'
	New-Item -Path $uninstallKey -Force | Out-Null
	$powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
	$sizeKb = [int]((Get-ChildItem $targetDirectory -File | Measure-Object -Property Length -Sum).Sum / 1KB)
	$values = @{
		DisplayName = $DisplayName; DisplayVersion = $ProductVersion; Publisher = 'Команда Red Flag'
		DisplayIcon = $targetExecutable; InstallLocation = $targetDirectory
		UninstallString = '"' + $powerShellPath + '" -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $targetDirectory 'uninstall-panel.ps1') + '"'
		QuietUninstallString = '"' + $powerShellPath + '" -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $targetDirectory 'uninstall-panel.ps1') + '" /quiet'
	}
	foreach ($entry in $values.GetEnumerator()) { Set-ItemProperty -Path $uninstallKey -Name $entry.Key -Value $entry.Value }
	Set-ItemProperty -Path $uninstallKey -Name 'NoModify' -Value 1 -Type DWord
	Set-ItemProperty -Path $uninstallKey -Name 'NoRepair' -Value 1 -Type DWord
	Set-ItemProperty -Path $uninstallKey -Name 'EstimatedSize' -Value $sizeKb -Type DWord

	$answer = Show-Message ("Панель управления установлена.`n`nПапка: $targetDirectory`n" +
		"Ярлык «СКЗИ — панель управления» — в меню «Пуск» и на рабочем столе.`n`nЗапустить панель сейчас?") 'Information' 'YesNo'
	if ($answer -eq 'Yes') { Start-Process -FilePath $targetExecutable -WorkingDirectory $targetDirectory }
	exit 0
}
catch {
	Show-Message ("Установка панели не удалась:`n" + $_.Exception.Message) 'Error' | Out-Null
	exit 1
}
