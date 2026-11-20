#Requires -Version 5.1
[CmdletBinding()]
param([string]$LinuxRoot='C:\linux')
$ErrorActionPreference='Stop'
$helper = @'
function Initialize-VgUsbPartitionTable([int]$DiskNumber, [string]$ExpectedSerial) {
    $current = Get-Disk -Number $DiskNumber
    if (-not $current.SerialNumber -or $current.SerialNumber.Trim() -cne $ExpectedSerial.Trim() -or $current.IsBoot -or $current.IsSystem -or $current.BusType -ne 'USB') {
        throw 'USB-диск изменился после очистки; подготовка остановлена'
    }
    if (@(Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue).Count -gt 0) {
        throw 'На USB остались разделы; изменение таблицы разделов остановлено'
    }
    switch ([string]$current.PartitionStyle) {
        'RAW' { Initialize-Disk -Number $DiskNumber -PartitionStyle GPT | Out-Null }
        'MBR' { Set-Disk -Number $DiskNumber -PartitionStyle GPT | Out-Null }
        'GPT' { } # Clear-Disk may keep an already initialized GPT disk.
        default { throw "Неизвестный стиль разделов USB: $($current.PartitionStyle)" }
    }
    $verified = Get-Disk -Number $DiskNumber
    if (-not $verified.SerialNumber -or $verified.SerialNumber.Trim() -cne $ExpectedSerial.Trim() -or $verified.PartitionStyle -ne 'GPT' -or $verified.IsBoot -or $verified.IsSystem -or $verified.BusType -ne 'USB') {
        throw 'Не удалось подтвердить GPT на выбранной флешке'
    }
}
'@
$old = '    Initialize-Disk -Number $UsbDiskNumber -PartitionStyle GPT'
$new = '    Initialize-VgUsbPartitionTable -DiskNumber $UsbDiskNumber -ExpectedSerial $EraseUsbSerial'
$patched=0
foreach ($relative in @('deploy\Prepare-Usb.ps1','deploy\output\usb-kit\Prepare-Usb.ps1')) {
    $path=Join-Path $LinuxRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $text=Get-Content -LiteralPath $path -Raw -Encoding UTF8
    if ($text.Contains('function Initialize-VgUsbPartitionTable')) { Write-Host "Уже исправлен: $path"; $patched++; continue }
    if (-not $text.Contains($old)) { throw "Неожиданная версия скрипта: $path. Файл не изменён." }
    $updated=$text.Replace($old,$new).Replace('{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}','{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}')
    $anchor='$bundle = (Resolve-Path -LiteralPath $BundlePath).Path'
    if (-not $updated.Contains($anchor)) { throw "Не найдена точка исправления: $path" }
    $updated=$updated.Replace($anchor,$helper+[Environment]::NewLine+$anchor)
    $tokens=$null; $errors=$null
    [void][System.Management.Automation.Language.Parser]::ParseInput($updated,[ref]$tokens,[ref]$errors)
    if ($errors) { throw 'Исправление не прошло проверку синтаксиса; файл не изменён' }
    $backup=$path+'.before-usb-fix-'+(Get-Date -Format 'yyyyMMdd-HHmmssfff')
    Copy-Item -LiteralPath $path -Destination $backup
    [IO.File]::WriteAllText($path,$updated,(New-Object Text.UTF8Encoding($true)))
    Write-Host "Исправлен: $path"
    $patched++
}
if (-not $patched) { throw "В $LinuxRoot не найдены файлы подготовки USB" }
Write-Host 'Готово. Можно повторить WRITE-USB.cmd. Этот ремонт не форматировал диски и не менял загрузку ПК.'
