#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')][string]$Gateway,
    [ValidatePattern('^[a-zA-Z_][a-zA-Z0-9_-]*$')][string]$User = 'vpnadmin',
    [ValidateRange(1,65535)][int]$Port = 22,
    [string]$IdentityFile,
    [string]$KnownHostsFile,
    [ValidatePattern('^\d+\.\d+(\.\d+)?$')][string]$Version
)

$ErrorActionPreference = 'Stop'
$repository = 'https://raw.githubusercontent.com/Fogiku/VpnGuard_linux'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Invoke-Tool([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed (exit $LASTEXITCODE)."
    }
}

foreach ($tool in 'ssh', 'scp') {
    Get-Command $tool -CommandType Application -ErrorAction Stop | Out-Null
}
$common = @('-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10', '-o', 'ControlPath=none')
# Reuse access files if the script is next to an extracted previous distribution.
$roots = @($PSScriptRoot, (Get-Location).Path, (Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop'))
foreach ($root in $roots) {
    foreach ($prefix in '.', '1', '1/1') {
        $folder = Join-Path $root $prefix
        if (-not $IdentityFile) {
            foreach ($relative in 'SSH-PRIVATE-KEY', 'deploy/output/support/verified-install-access/SSH-PRIVATE-KEY', 'deploy/output/retry-access/SSH-PRIVATE-KEY') {
                $file = Join-Path $folder $relative
                if (Test-Path -LiteralPath $file -PathType Leaf) { $IdentityFile = $file; break }
            }
        }
        if (-not $KnownHostsFile) {
            $file = Join-Path $folder 'deploy/output/repair-access/TARGET-KNOWN-HOSTS'
            if (Test-Path -LiteralPath $file -PathType Leaf) { $KnownHostsFile = $file }
        }
    }
}
if ($KnownHostsFile) {
    $known = (Resolve-Path -LiteralPath $KnownHostsFile).Path.Replace('\','/')
    $common += @('-o', ('UserKnownHostsFile="' + $known + '"'))
}
if ($IdentityFile) {
    $common += @('-i', (Resolve-Path -LiteralPath $IdentityFile).Path, '-o', 'IdentitiesOnly=yes')
}
$dest = "$User@$Gateway"
$sshArgs = $common + @('-p', "$Port", $dest)
function Invoke-Gateway([string]$Command) {
    Invoke-Tool ssh ($sshArgs + $Command)
}

$channel = if ($Version) { "bin-v$Version" } else { "releases" }
$release = Invoke-RestMethod -Uri "$repository/$channel/manifest.json" -TimeoutSec 30
$number = [string]$release.version
if ($number -notmatch '^\d+\.\d+(\.\d+)?$' -or ($Version -and $number -ne $Version) -or $release.source -cnotmatch '^[a-f0-9]{40}$') {
    throw 'Unexpected repository release manifest.'
}

$current = (Invoke-Gateway '/usr/local/bin/vpnguard --version').Trim()
if ($current -notmatch '^\d+\.\d+(\.\d+)?$') { throw "Unrecognized installed version: $current" }
if ([version]$number -lt [version]$current) { throw "Refusing downgrade from $current to $number." }
if ($current -eq $number) {
    Write-Host "Version $number is already on disk. See Updates on the gateway for confirmation status."
    return
}
$machine = (Invoke-Gateway 'uname -m').Trim()
switch ($machine) {
    'x86_64'  { $targetArch = 'amd64' }
    'aarch64' { $targetArch = 'arm64' }
    default   { throw "Unsupported gateway architecture: $machine" }
}
Invoke-Gateway 'sudo -n true'
Write-Host "Preparing VpnGuard $number ($machine) for $dest, currently $current."
$temp = Join-Path ([IO.Path]::GetTempPath()) ('vpnguard-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$stage = $null
Push-Location -LiteralPath $temp
try {
    $sha = [string]$release.sha256.$targetArch
    if ($sha -cnotmatch '^[a-f0-9]{64}$') { throw "No release checksum for $targetArch." }
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 120 -Uri "$repository/bin-v$number/vpnguard-linux-$targetArch" -OutFile vpnguard
    if ((Get-FileHash vpnguard -Algorithm SHA256).Hash -ne $sha) { throw 'Downloaded binary SHA256 mismatch.' }
    foreach ($helper in 'guarded_update.py', 'route_guard.py') {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri "$repository/$($release.source)/deploy/$helper" -OutFile $helper
        if ((Get-FileHash $helper -Algorithm SHA256).Hash -ne $release.helpers.$helper) { throw "Unexpected checksum for $helper." }
    }
    $remoteDir = (Invoke-Gateway 'mktemp -d /tmp/vpnguard-upload.XXXXXXXXXX').Trim()
    if ($remoteDir -cnotmatch '^/tmp/vpnguard-upload\.[a-zA-Z0-9]{10}$') { throw 'Unexpected staging directory.' }
    $stage = $remoteDir
    Invoke-Tool scp ($common + @('-P',"$Port",'vpnguard','guarded_update.py','route_guard.py',"${dest}:$stage/"))

    # Run only root-owned copies. The guard copies its timer/rollback files before replacing the agent.
    $prepare = @'
set -eu
private=$(sudo -n mktemp -d /var/backups/vpnguard-release.XXXXXXXXXX)
trap 'sudo -n rm -rf -- "$private"' EXIT
sudo -n install -m 700 __STAGE__/vpnguard "$private/vpnguard"
sudo -n install -m 600 __STAGE__/guarded_update.py __STAGE__/route_guard.py "$private/"
sudo -n python3 -I "$private/guarded_update.py" prepare "$private/vpnguard" --version __VERSION__ --sha256 __SHA__
'@
    $prepare = $prepare.Replace('__STAGE__',$stage).Replace('__VERSION__',$number).Replace('__SHA__',$sha).Replace("`r",'')
    # Feed the multi-line script on stdin so Windows native argument quoting cannot alter shell quotes.
    $reply = $prepare | & ssh @sshArgs 'tr -d ''\015'' | sh'
    if ($LASTEXITCODE -ne 0) { throw 'Preparation failed. Check the SSH output and the gateway update history.' }
    $job = (($reply -join "`n") | ConvertFrom-Json).job
    if ($job -cnotmatch '^/var/backups/vpnguard/updates/[0-9]{8}-[0-9]{6}-[0-9]{6}$') { throw 'Invalid update receipt.' }
    Write-Host 'Agent restarted. Checking the new version and VPN through a fresh SSH connection...'
    $deadline = [datetime]::UtcNow.AddSeconds(150)
    do {
        Start-Sleep -Seconds 4
        # Confirm runs the complete health check under the updater lock before cancelling its timer.
        $result = & ssh @sshArgs "sudo -n python3 -I $job/guard.py confirm $job"
        if ($LASTEXITCODE -eq 0) {
            $receipt = ($result -join "`n") | ConvertFrom-Json
            if ($receipt.status -eq 'confirmed' -and $receipt.version -eq $number -and $receipt.health -eq 'ok') {
                Write-Host "VpnGuard $number confirmed on $Gateway."
                return
            }
            throw 'Unexpected confirmation receipt. Check the update history.'
        }
    } while ([datetime]::UtcNow -lt $deadline)
    throw 'Confirmation unavailable. The gateway timer rolls back unconfirmed updates. Check the update history after four minutes.'
} finally {
    if ($stage) { & ssh @sshArgs "rm -rf -- $stage" | Out-Null }
    Pop-Location
    Remove-Item -LiteralPath $temp -Recurse -Force
}
