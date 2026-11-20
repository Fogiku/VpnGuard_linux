#Requires -Version 5.1
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Prepare-Usb.ps1'),[ref]$tokens,[ref]$errors)
if ($errors) { throw 'Prepare-Usb.ps1 parse failed' }
$fn=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Initialize-VgUsbPartitionTable'},$true)
if (-not $fn) { throw 'Partition table helper not found' }
. ([scriptblock]::Create($fn.Extent.Text))
function Get-Disk {
    param($Number)
    [pscustomobject]@{SerialNumber=$script:Serial;PartitionStyle=$script:Style;IsBoot=$script:SystemDisk;IsSystem=$script:SystemDisk;BusType='USB'}
}
function Get-Partition {
    [CmdletBinding()]param($DiskNumber)
    if ($script:HasPartitions) { [pscustomobject]@{PartitionNumber=1} }
}
function Initialize-Disk { param($Number,$PartitionStyle) $script:InitCalls++; $script:Style='GPT' }
function Set-Disk { param($Number,$PartitionStyle) $script:SetCalls++; $script:Style='GPT' }
foreach ($initial in @('RAW','MBR','GPT')) {
    $script:Serial='USB-TEST';$script:Style=$initial;$script:SystemDisk=$false;$script:HasPartitions=$false;$script:InitCalls=0;$script:SetCalls=0
    Initialize-VgUsbPartitionTable -DiskNumber 123 -ExpectedSerial 'USB-TEST'
    if ($script:Style -ne 'GPT') { throw 'Expected GPT' }
    if ($initial -eq 'GPT' -and ($script:InitCalls -ne 0 -or $script:SetCalls -ne 0)) { throw 'Existing GPT must not be initialized again' }
    if ($initial -eq 'RAW' -and $script:InitCalls -ne 1) { throw 'RAW must be initialized' }
    if ($initial -eq 'MBR' -and $script:SetCalls -ne 1) { throw 'Empty MBR must be converted' }
}
foreach ($scenario in @('serial','system','partitions')) {
    $script:Serial='USB-TEST';$script:Style='RAW';$script:SystemDisk=$false;$script:HasPartitions=$false;$script:InitCalls=0;$script:SetCalls=0
    if ($scenario -eq 'serial') { $script:Serial='CHANGED' }
    if ($scenario -eq 'system') { $script:SystemDisk=$true }
    if ($scenario -eq 'partitions') { $script:HasPartitions=$true }
    $rejected=$false
    try { Initialize-VgUsbPartitionTable -DiskNumber 123 -ExpectedSerial 'USB-TEST' } catch { $rejected=$true }
    if (-not $rejected -or $script:InitCalls -or $script:SetCalls) { throw "Unsafe scenario was not rejected: $scenario" }
}
Write-Output '6 USB state tests passed with mocked storage commands; no disks modified.'
