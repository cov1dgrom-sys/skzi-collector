# ===========================================================================
#  Сборка релиза модуля сбора данных о СКЗИ (команда Red Flag).
#  Запуск: release.cmd [-SkipTests]   (из корня проекта)
#
#  Результат в dist\v<версия>\:
#    SkziAgent-Setup-<версия>.exe          установщик агента (служба Windows, запрашивает права администратора)
#    SkziControlPanel-Setup-<версия>.exe   установщик панели для текущего пользователя (без прав администратора)
#    SkziModule-<версия>-portable.zip      оба exe, примеры конфигураций, SQL-скрипт, документация — без установки
#    SHA256SUMS.txt                        контрольные суммы файлов релиза
#    RELEASE_NOTES.md                      описание выпуска (из CHANGELOG.md) — текст для страницы релиза GitHub
#
#  Самораспаковывающиеся установщики собираются штатным IExpress Windows, сторонние программы не нужны.
#  В установщики попадают ПРИМЕРЫ конфигураций из config\, а не рабочие файлы из bin\ (там могут быть ваши
#  пароли и список ПК). Чтобы агенты сразу получили свой ключ, задайте SharedKey в config\agent.config.xml
#  и config\panel.config.xml до сборки.
# ===========================================================================

param([switch]$SkipTests)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$utf8Bom = New-Object System.Text.UTF8Encoding $true

# Читает версию продукта из AssemblyInfo панели управления (1.0.0.0 → 1.0.0).
function Get-ProductVersion {
	$assemblyInfo = Get-Content -Path (Join-Path $projectRoot 'src\SkziControlPanel\Properties\AssemblyInfo.cs') -Raw -Encoding UTF8
	$match = [regex]::Match($assemblyInfo, 'AssemblyVersion\("(\d+)\.(\d+)\.(\d+)')
	if (-not $match.Success) { throw 'Не удалось прочитать AssemblyVersion' }
	return $match.Groups[1].Value + '.' + $match.Groups[2].Value + '.' + $match.Groups[3].Value
}

# Копирует сценарий установки: подставляет версию и сохраняет с BOM (Windows PowerShell 5.1 иначе портит кириллицу),
# а .cmd — с окончаниями строк CRLF.
function Copy-InstallerScript([string]$Source, [string]$Destination, [string]$Version) {
	$text = [IO.File]::ReadAllText($Source, [Text.Encoding]::UTF8).Replace('@VERSION@', $Version)
	$text = ($text -replace "`r`n", "`n") -replace "`n", "`r`n"
	if ($Source -like '*.cmd') { [IO.File]::WriteAllText($Destination, $text, [Text.Encoding]::ASCII) }
	else { [IO.File]::WriteAllText($Destination, $text, $utf8Bom) }
}

# Собирает самораспаковывающийся установщик штатным IExpress: распаковка во временную папку и запуск install.cmd.
function New-IExpressPackage([string]$PayloadDirectory, [string]$TargetFile, [string]$FriendlyName) {
	$iexpress = Join-Path $env:SystemRoot 'SysWOW64\iexpress.exe'
	if (-not (Test-Path $iexpress)) { $iexpress = Join-Path $env:SystemRoot 'System32\iexpress.exe' }
	$files = @(Get-ChildItem -Path $PayloadDirectory -File | Sort-Object Name)
	$sed = New-Object System.Text.StringBuilder
	[void]$sed.AppendLine('[Version]')
	[void]$sed.AppendLine('Class=IEXPRESS')
	[void]$sed.AppendLine('SEDVersion=3')
	[void]$sed.AppendLine('[Options]')
	[void]$sed.AppendLine('PackagePurpose=InstallApp')
	[void]$sed.AppendLine('ShowInstallProgramWindow=1')
	[void]$sed.AppendLine('HideExtractAnimation=1')
	[void]$sed.AppendLine('UseLongFileName=1')
	[void]$sed.AppendLine('InsideCompressed=0')
	[void]$sed.AppendLine('CAB_FixedSize=0')
	[void]$sed.AppendLine('CAB_ResvCodeSigning=0')
	[void]$sed.AppendLine('RebootMode=N')
	[void]$sed.AppendLine('InstallPrompt=%InstallPrompt%')
	[void]$sed.AppendLine('DisplayLicense=%DisplayLicense%')
	[void]$sed.AppendLine('FinishMessage=%FinishMessage%')
	[void]$sed.AppendLine('TargetName=%TargetName%')
	[void]$sed.AppendLine('FriendlyName=%FriendlyName%')
	[void]$sed.AppendLine('AppLaunched=%AppLaunched%')
	[void]$sed.AppendLine('PostInstallCmd=%PostInstallCmd%')
	[void]$sed.AppendLine('AdminQuietInstCmd=%AdminQuietInstCmd%')
	[void]$sed.AppendLine('UserQuietInstCmd=%UserQuietInstCmd%')
	[void]$sed.AppendLine('SourceFiles=SourceFiles')
	[void]$sed.AppendLine('[Strings]')
	[void]$sed.AppendLine('InstallPrompt=')
	[void]$sed.AppendLine('DisplayLicense=')
	[void]$sed.AppendLine('FinishMessage=')
	[void]$sed.AppendLine('TargetName=' + $TargetFile)
	[void]$sed.AppendLine('FriendlyName=' + $FriendlyName)
	# Команда — сам install.cmd: wextract запускает её из папки, куда распаковал файлы
	# (для «cmd.exe /c …» рабочей папкой стала бы System32, и install.cmd не нашёлся бы).
	# Код выхода сценария wextract наружу не передаёт — результат пишет сам сценарий установки.
	[void]$sed.AppendLine('AppLaunched=install.cmd')
	[void]$sed.AppendLine('PostInstallCmd=<None>')
	[void]$sed.AppendLine('AdminQuietInstCmd=install.cmd /quiet')
	[void]$sed.AppendLine('UserQuietInstCmd=install.cmd /quiet')
	for ($index = 0; $index -lt $files.Count; $index++) { [void]$sed.AppendLine('FILE' + $index + '="' + $files[$index].Name + '"') }
	[void]$sed.AppendLine('[SourceFiles]')
	[void]$sed.AppendLine('SourceFiles0=' + $PayloadDirectory.TrimEnd('\') + '\')
	[void]$sed.AppendLine('[SourceFiles0]')
	for ($index = 0; $index -lt $files.Count; $index++) { [void]$sed.AppendLine('%FILE' + $index + '%=') }
	$sedPath = $PayloadDirectory.TrimEnd('\') + '.sed'
	[IO.File]::WriteAllText($sedPath, $sed.ToString(), [Text.Encoding]::Default)
	if (Test-Path $TargetFile) { Remove-Item $TargetFile -Force }
	# IExpress не понимает путь к SED в кавычках, поэтому рабочая папка — без пробелов и кириллицы (см. Get-SafeDirectory).
	$process = Start-Process -FilePath $iexpress -ArgumentList @('/N', '/Q', $sedPath) -Wait -PassThru -WindowStyle Hidden
	if (-not (Test-Path $TargetFile)) { throw "IExpress не создал $TargetFile (код $($process.ExitCode))" }
}

# Возвращает путь к папке без пробелов и не-ASCII символов (короткое имя 8.3), пригодный для IExpress.
function Get-SafeDirectory([string]$Path) {
	if ($Path -notmatch '[\s]' -and $Path -cmatch '^[\x21-\x7E]+$') { return $Path }
	$shortPath = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($Path).ShortPath
	if ($shortPath -match '[\s]' -or $shortPath -cnotmatch '^[\x21-\x7E]+$') {
		throw "Путь временной папки содержит пробелы или кириллицу, а короткие имена 8.3 отключены: $Path. Задайте переменную TEMP с простым путём, например C:\Temp"
	}
	return $shortPath
}

# Упаковывает папку в ZIP с именами файлов в UTF-8 (кириллица в путях документации сохраняется).
function New-ZipArchive([string]$SourceDirectory, [string]$TargetFile) {
	# Записи добавляются по одной с разделителем «/»: ZipFile.CreateFromDirectory в .NET Framework пишет «\»,
	# и такие архивы неверно распаковываются вне Windows.
	Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
	if (Test-Path $TargetFile) { Remove-Item $TargetFile -Force }
	$baseDirectory = Split-Path -Parent $SourceDirectory.TrimEnd('\')
	$archive = [IO.Compression.ZipFile]::Open($TargetFile, [IO.Compression.ZipArchiveMode]::Create, [Text.Encoding]::UTF8)
	try {
		foreach ($file in Get-ChildItem -Path $SourceDirectory -Recurse -File) {
			$entryName = $file.FullName.Substring($baseDirectory.Length + 1).Replace('\', '/')
			[void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entryName, [IO.Compression.CompressionLevel]::Optimal)
		}
	}
	finally {
		$archive.Dispose()
	}
}

$version = Get-ProductVersion
Write-Host "== Релиз $version =="

# 1. Сборка (и автотесты, если не отключены). Для тестов MSSQL задайте SKZI_TEST_SQL.
$buildArguments = if ($SkipTests) { '' } else { ' test' }
& cmd.exe /c ('"' + (Join-Path $projectRoot 'build.cmd') + '"' + $buildArguments)
if ($LASTEXITCODE -ne 0) { throw "Сборка или тесты завершились с ошибкой (код $LASTEXITCODE)" }

$binDirectory = Join-Path $projectRoot 'bin'
$distDirectory = Join-Path $projectRoot ('dist\v' + $version)
if (Test-Path $distDirectory) { Remove-Item $distDirectory -Recurse -Force }
New-Item -ItemType Directory -Force -Path $distDirectory | Out-Null

# Рабочая папка с ASCII-путём: IExpress не понимает кириллицу в путях.
$stagingDirectory = Join-Path ([IO.Path]::GetTempPath()) ('skzi-release-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $stagingDirectory | Out-Null
$stagingDirectory = Get-SafeDirectory $stagingDirectory

try {
	# 2. Установщик агента.
	$agentPayload = Join-Path $stagingDirectory 'agent'
	New-Item -ItemType Directory -Force -Path $agentPayload | Out-Null
	Copy-Item (Join-Path $binDirectory 'SkziAgent.exe') $agentPayload
	Copy-Item (Join-Path $projectRoot 'config\agent.config.xml') $agentPayload
	foreach ($name in @('install.cmd', 'install-agent.ps1', 'uninstall-agent.cmd', 'uninstall-agent.ps1')) {
		Copy-InstallerScript (Join-Path $PSScriptRoot ('agent\' + $name)) (Join-Path $agentPayload $name) $version
	}
	$agentSetup = Join-Path $stagingDirectory ('SkziAgent-Setup-' + $version + '.exe')
	New-IExpressPackage $agentPayload $agentSetup ('SKZI Agent ' + $version + ' - Red Flag')
	Copy-Item $agentSetup $distDirectory
	Write-Host "[ok] SkziAgent-Setup-$version.exe"

	# 3. Установщик панели (вместе с SkziAgent.exe — из него панель ставит агенты по сети).
	$panelPayload = Join-Path $stagingDirectory 'panel'
	New-Item -ItemType Directory -Force -Path $panelPayload | Out-Null
	Copy-Item (Join-Path $binDirectory 'SkziControlPanel.exe') $panelPayload
	Copy-Item (Join-Path $binDirectory 'SkziAgent.exe') $panelPayload
	Copy-Item (Join-Path $projectRoot 'config\panel.config.xml') $panelPayload
	foreach ($name in @('install.cmd', 'install-panel.ps1', 'uninstall-panel.ps1')) {
		Copy-InstallerScript (Join-Path $PSScriptRoot ('panel\' + $name)) (Join-Path $panelPayload $name) $version
	}
	$panelSetup = Join-Path $stagingDirectory ('SkziControlPanel-Setup-' + $version + '.exe')
	New-IExpressPackage $panelPayload $panelSetup ('SKZI Control Panel ' + $version + ' - Red Flag')
	Copy-Item $panelSetup $distDirectory
	Write-Host "[ok] SkziControlPanel-Setup-$version.exe"

	# 4. Портативный архив: запуск без установки.
	$portableName = 'SkziModule-' + $version + '-portable'
	$portableDirectory = Join-Path $stagingDirectory $portableName
	New-Item -ItemType Directory -Force -Path $portableDirectory | Out-Null
	Copy-Item (Join-Path $binDirectory 'SkziControlPanel.exe') $portableDirectory
	Copy-Item (Join-Path $binDirectory 'SkziAgent.exe') $portableDirectory
	Copy-Item (Join-Path $projectRoot 'config\panel.config.xml') $portableDirectory
	Copy-Item (Join-Path $projectRoot 'config\agent.config.xml') $portableDirectory
	Copy-Item (Join-Path $projectRoot 'README.md') $portableDirectory
	Copy-Item (Join-Path $projectRoot 'CHANGELOG.md') $portableDirectory
	New-Item -ItemType Directory -Force -Path (Join-Path $portableDirectory 'sql') | Out-Null
	Copy-Item (Join-Path $projectRoot 'sql\create_table.sql') (Join-Path $portableDirectory 'sql')
	Copy-Item (Join-Path $projectRoot 'docs') $portableDirectory -Recurse
	$portableZip = Join-Path $distDirectory ($portableName + '.zip')
	New-ZipArchive $portableDirectory $portableZip
	Write-Host "[ok] $portableName.zip"
}
finally {
	Remove-Item $stagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

# 5. Описание выпуска — раздел этой версии из CHANGELOG.md.
$changelog = [IO.File]::ReadAllText((Join-Path $projectRoot 'CHANGELOG.md'), [Text.Encoding]::UTF8)
$section = [regex]::Match($changelog, '(?ms)^## \[' + [regex]::Escape($version) + '\].*?(?=^## \[|\z)')
$notes = if ($section.Success) { $section.Value.Trim() } else { "## [$version]" }
[IO.File]::WriteAllText((Join-Path $distDirectory 'RELEASE_NOTES.md'), $notes + "`r`n", (New-Object System.Text.UTF8Encoding $false))

# 6. Контрольные суммы.
$sums = Get-ChildItem -Path $distDirectory -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' -and $_.Name -ne 'RELEASE_NOTES.md' } | Sort-Object Name |
	ForEach-Object { (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name }
[IO.File]::WriteAllLines((Join-Path $distDirectory 'SHA256SUMS.txt'), [string[]]$sums, [Text.Encoding]::ASCII)

Write-Host ''
Write-Host "Релиз готов: $distDirectory"
Get-ChildItem $distDirectory | ForEach-Object { Write-Host ('  {0,-42} {1,10:N0} байт' -f $_.Name, $_.Length) }
