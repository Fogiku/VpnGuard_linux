#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([ValidatePattern('^[A-Za-z]$')][string]$DriveLetter='E', [string]$LinuxRoot='C:\linux')
$ErrorActionPreference='Stop'
function Invoke-VgDiskPart([string[]]$Commands) {
    $file=[IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllLines($file,$Commands,[Text.Encoding]::ASCII)
        & "$env:SystemRoot\System32\diskpart.exe" /s $file | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "diskpart завершился с кодом $LASTEXITCODE" }
    } finally { Remove-Item -LiteralPath $file -Force }
}
function Repair-VgUsbAccess([string]$Letter) {
    $part=Get-Partition -DriveLetter $Letter
    $disk=Get-Disk -Number $part.DiskNumber
    $volume=Get-Volume -DriveLetter $Letter
    if ($disk.BusType -ne 'USB' -or $disk.IsBoot -or $disk.IsSystem -or $disk.PartitionStyle -ne 'GPT') {
        throw 'Остановлено: выбран не USB-диск GPT либо системный диск'
    }
    if ($volume.FileSystem -ne 'FAT32') { throw "Остановлено: ожидалась FAT32, обнаружена $($volume.FileSystem). Форматирование не выполнялось." }
    $efi='c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
    $data='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
    $kind=([string]$part.GptType).Trim('{}').ToLowerInvariant()
    if ($kind -ne $efi -and $kind -ne $data) { throw "Неожиданный тип раздела $($part.GptType); изменений нет" }
    if ($kind -eq $efi) {
        $again=Get-Disk -Number $part.DiskNumber
        if ($again.BusType -ne 'USB' -or $again.IsBoot -or $again.IsSystem -or $again.UniqueId -ne $disk.UniqueId) { throw 'Выбранный USB-диск изменился' }
        Write-Host "Меняю только GPT-тип раздела $($part.PartitionNumber) на USB-диске $($part.DiskNumber), $($disk.FriendlyName). Файлы не удаляются."
        Invoke-VgDiskPart @(
            "select disk $([uint32]$part.DiskNumber)"
            "select partition $([uint32]$part.PartitionNumber)"
            "set id=$data override"
            'exit'
        )
    }
    $check=Get-Partition -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber
    if (([string]$check.GptType).Trim('{}').ToLowerInvariant() -ne $data -or $check.Guid -ne $part.Guid -or $check.Offset -ne $part.Offset -or $check.Size -ne $part.Size) {
        throw 'Не удалось подтвердить тип и прежние границы USB-раздела'
    }
    # These attributes can only be changed after this is confirmed to be a data partition.
    if ($check.NoDefaultDriveLetter -or $check.IsHidden) {
        Set-Partition -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -NoDefaultDriveLetter:$false -IsHidden:$false -Confirm:$false
    }
    if ([string]$check.DriveLetter -ne $Letter) {
        if (Get-Partition -DriveLetter $Letter -ErrorAction SilentlyContinue) { throw "Буква $Letter уже занята; ничего не переназначено" }
        Add-PartitionAccessPath -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -AccessPath ($Letter+':\')
    }
    Write-Host "Готово. Закройте и снова откройте $($Letter): в Проводнике."
}
Repair-VgUsbAccess $DriveLetter

foreach ($relative in @('deploy\Prepare-Usb.ps1','deploy\output\usb-kit\Prepare-Usb.ps1')) {
    $file=Join-Path $LinuxRoot $relative
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
    $text=Get-Content -LiteralPath $file -Raw -Encoding UTF8
    $old="-GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'"
    $new="-GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'"
    if ($text.Contains($old)) {
        Copy-Item -LiteralPath $file -Destination ($file+'.before-access-fix-'+(Get-Date -Format 'yyyyMMdd-HHmmssfff'))
        [IO.File]::WriteAllText($file,$text.Replace($old,$new),(New-Object Text.UTF8Encoding($true)))
        Write-Host "Подготовка USB также исправлена: $file"
    }
}
