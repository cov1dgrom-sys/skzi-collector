# ===========================================================================
#  Установка агента сбора данных о СКЗИ (команда Red Flag).
#  Копирует SkziAgent.exe в «Program Files\SkziAgent», регистрирует службу Windows
#  (автозапуск, без окон, скрыта от обычных пользователей), открывает порт и запускает её.
#  Повторный запуск обновляет агент; конфигурация agent.config.xml сохраняется.
#
#  Параметры: /quiet        — без окон (для GPO, SCCM, сценариев запуска);
#             /resetconfig  — заменить agent.config.xml на конфигурацию из установщика.
#  Коды выхода install.cmd: 0 — успех, 1223 — отказ в правах администратора, остальные — ошибка.
#  Самораспаковывающийся установщик (IExpress) код не передаёт, поэтому итог каждой установки
#  дописывается в «Program Files\SkziAgent\logs\setup.log» (для GPO/SCCM).
# ===========================================================================

$ErrorActionPreference = 'Stop'
$ProductVersion = '@VERSION@'
$ServiceName = 'SkziAgent'
$Quiet = $false
$ResetConfig = $false
foreach ($argument in $args) {
	switch -regex ($argument) {
		'^[/-](q|quiet)$' { $Quiet = $true }
		'^[/-]resetconfig$' { $ResetConfig = $true }
	}
}

# Показывает сообщение пользователю (в тихом режиме ничего не показывает).
function Show-Message([string]$Text, [string]$Icon = 'Information') {
	if ($Quiet) { return }
	Add-Type -AssemblyName System.Windows.Forms
	[void][System.Windows.Forms.MessageBox]::Show($Text, 'Агент сбора данных о СКЗИ ' + $ProductVersion,
		[System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::$Icon)
}

# Дописывает итог установки в logs\setup.log в папке агента (формат как в журнале программы).
function Write-SetupLog([string]$Level, [string]$Text) {
	try {
		$logDirectory = Join-Path $targetDirectory 'logs'
		New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
		$line = (Get-Date).ToString('dd.MM.yy HH:mm:ss.fff') + ' - [' + $Level + '] ' + $Text + ' (установщик ' + $ProductVersion + ', ' + $env:COMPUTERNAME + ')'
		Add-Content -Path (Join-Path $logDirectory 'setup.log') -Value $line -Encoding UTF8
	}
	catch {
	}
}

# Проверяет, запущен ли сценарий с правами администратора.
function Test-Administrator {
	$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
	# Перезапуск с запросом прав (UAC). Ждём завершения, чтобы распакованные файлы не удалились раньше времени.
	$argumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', ('"' + $PSCommandPath + '"')) + $args
	try {
		$process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argumentList -Verb RunAs -Wait -PassThru
		exit $process.ExitCode
	}
	catch {
		Show-Message 'Для установки агента нужны права администратора. Установка отменена.' 'Warning'
		exit 1223
	}
}

$sourceDirectory = Split-Path -Parent $PSCommandPath
$programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$targetDirectory = Join-Path $programFiles 'SkziAgent'
$targetExecutable = Join-Path $targetDirectory 'SkziAgent.exe'

try {
	# 1. Останавливаем уже установленную службу, чтобы заменить exe.
	$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
	if ($service -and $service.Status -ne 'Stopped') {
		Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
		$service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
	}

	# 2. Копируем файлы (несколько попыток: после остановки службы файл освобождается не сразу).
	New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
	for ($attempt = 1; $attempt -le 10; $attempt++) {
		try { Copy-Item -Path (Join-Path $sourceDirectory 'SkziAgent.exe') -Destination $targetExecutable -Force; break }
		catch { if ($attempt -eq 10) { throw }; Start-Sleep -Milliseconds 700 }
	}
	$targetConfig = Join-Path $targetDirectory 'agent.config.xml'
	if ($ResetConfig -or -not (Test-Path $targetConfig)) {
		Copy-Item -Path (Join-Path $sourceDirectory 'agent.config.xml') -Destination $targetConfig -Force
	}
	foreach ($name in @('uninstall-agent.cmd', 'uninstall-agent.ps1')) {
		Copy-Item -Path (Join-Path $sourceDirectory $name) -Destination (Join-Path $targetDirectory $name) -Force
	}

	# 3. Регистрируем и запускаем службу штатной командой агента (служба, скрытие, брандмауэр, запуск).
	$process = Start-Process -FilePath $targetExecutable -ArgumentList '--install' -WorkingDirectory $targetDirectory -WindowStyle Hidden -Wait -PassThru
	if ($process.ExitCode -ne 0) {
		Write-SetupLog 'ERROR' ('Служба не установлена, код ' + $process.ExitCode + '; подробности в журнале агента')
		Show-Message ("Агент скопирован, но служба не установлена (код " + $process.ExitCode + ").`n`nПодробности в журнале: " + (Join-Path $targetDirectory 'logs')) 'Error'
		exit $process.ExitCode
	}

	Write-SetupLog 'INFO' ('Агент установлен и запущен: ' + $targetExecutable)
	Show-Message ("Агент установлен и работает в фоне как служба Windows.`n`n" +
		"Папка: $targetDirectory`n" +
		"Окон и значков нет; обычные пользователи службу не видят.`n" +
		"Проверить: SkziAgent.exe --status`n" +
		"Удалить: uninstall-agent.cmd в папке агента (от администратора).`n`n" +
		"Ключ агента должен совпадать с ключом в панели управления: обновите агент из панели («Агент на ПК» → «Установить / обновить»).")
	exit 0
}
catch {
	Write-SetupLog 'ERROR' ('Установка не удалась: ' + $_.Exception.Message)
	Show-Message ("Установка агента не удалась:`n" + $_.Exception.Message) 'Error'
	exit 1
}
