# ===========================================================================
#  Удаление агента сбора данных о СКЗИ (команда Red Flag).
#  Останавливает и удаляет службу, правило брандмауэра и папку агента вместе с журналами.
#  Параметры: /quiet — без окон. Коды выхода: 0 — успех, 1223 — отказ в правах администратора.
# ===========================================================================

$ErrorActionPreference = 'Stop'
$Quiet = $false
foreach ($argument in $args) { if ($argument -match '^[/-](q|quiet)$') { $Quiet = $true } }

# Показывает сообщение пользователю (в тихом режиме ничего не показывает).
function Show-Message([string]$Text, [string]$Icon = 'Information') {
	if ($Quiet) { return }
	Add-Type -AssemblyName System.Windows.Forms
	[void][System.Windows.Forms.MessageBox]::Show($Text, 'Агент сбора данных о СКЗИ',
		[System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::$Icon)
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$argumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', ('"' + $PSCommandPath + '"')) + $args
	try {
		$process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argumentList -Verb RunAs -Wait -PassThru
		exit $process.ExitCode
	}
	catch {
		Show-Message 'Для удаления агента нужны права администратора.' 'Warning'
		exit 1223
	}
}

$agentDirectory = Split-Path -Parent $PSCommandPath
$agentExecutable = Join-Path $agentDirectory 'SkziAgent.exe'
try {
	if (Test-Path $agentExecutable) {
		# Штатное удаление: остановка службы, удаление службы и правила брандмауэра.
		Start-Process -FilePath $agentExecutable -ArgumentList '--uninstall' -WorkingDirectory $agentDirectory -WindowStyle Hidden -Wait | Out-Null
	}
	else {
		& sc.exe stop SkziAgent | Out-Null
		& sc.exe delete SkziAgent | Out-Null
	}
	# Папку удаляем после завершения этого сценария (он сам лежит в ней).
	Set-Location -Path $env:SystemRoot
	Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -WindowStyle Hidden `
		-ArgumentList ('/c ping -n 3 127.0.0.1 >nul & rmdir /s /q "' + $agentDirectory + '"')
	Show-Message 'Агент удалён: служба, правило брандмауэра и папка агента.'
	exit 0
}
catch {
	Show-Message ("Удаление агента не удалось:`n" + $_.Exception.Message) 'Error'
	exit 1
}
