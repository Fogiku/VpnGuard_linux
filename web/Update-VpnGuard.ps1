#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')][string]$Gateway,
    [ValidatePattern('^[a-zA-Z_][a-zA-Z0-9_-]*$')][string]$User = 'vpnadmin',
    [ValidateRange(1,65535)][int]$Port = 22,
    [string]$IdentityFile,
    [ValidatePattern('^\d+\.\d+(\.\d+)?$')][string]$Version
)

$ErrorActionPreference = 'Stop'
$repository = 'https://github.com/Fogiku/VpnGuard_linux.git'

function Invoke-Tool([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed (exit $LASTEXITCODE)."
    }
}

foreach ($tool in 'git', 'go', 'ssh', 'scp') {
    Get-Command $tool -CommandType Application -ErrorAction Stop | Out-Null
}
$common = @('-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10', '-o', 'ControlPath=none')
if ($IdentityFile) {
    $common += @('-i', (Resolve-Path -LiteralPath $IdentityFile).Path, '-o', 'IdentitiesOnly=yes')
}
$dest = "$User@$Gateway"
$sshArgs = $common + @('-p', "$Port", $dest)
function Invoke-Gateway([string]$Command) {
    Invoke-Tool ssh ($sshArgs + $Command)
}

# Resolve a numbered release tag once. Verify the fetched tag object before building.
$releases = @(foreach ($ref in (Invoke-Tool git @('ls-remote', '--refs', '--tags', $repository, 'refs/tags/v*'))) {
    if ($ref -cmatch '^([a-f0-9]{40})\s+refs/tags/v(\d+\.\d+(?:\.\d+)?)$') {
        [pscustomobject]@{ObjectId=$Matches[1]; Number=$Matches[2]; Order=[version]$Matches[2]}
    }
})
if ($Version) {
    $release = $releases | Where-Object Number -eq $Version | Select-Object -First 1
} else {
    $release = $releases | Sort-Object Order -Descending | Select-Object -First 1
}
if (-not $release) { throw "No matching VpnGuard release tag in $repository." }
$number = $release.Number
$tag = "v$number"

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
    Invoke-Tool git @('-c','core.autocrlf=false','clone','--quiet','--depth','1','--branch',$tag,$repository,'source')
    $fetched = (Invoke-Tool git @('-C','source','rev-parse',"refs/tags/$tag")).Trim()
    if ($fetched -cne $release.ObjectId) { throw "Release tag changed during download. Retry." }
    $commit = (Invoke-Tool git @('-C','source','rev-parse',"refs/tags/${tag}^{commit}")).Trim()
    if ($commit -cne (Invoke-Tool git @('-C','source','rev-parse','HEAD')).Trim()) { throw 'Unexpected checkout.' }
    Write-Host "Building tag $tag at $commit"
    $buildEnv = @{ GOOS='linux'; GOARCH=$targetArch; CGO_ENABLED='0'; GOWORK='off'; GOFLAGS=''; GOTOOLCHAIN='local' }
    $saved = @{}
    Push-Location source
    try {
        foreach ($key in $buildEnv.Keys) {
            $saved[$key] = [Environment]::GetEnvironmentVariable($key)
            [Environment]::SetEnvironmentVariable($key, $buildEnv[$key])
        }
        Invoke-Tool go @('build','-mod=readonly','-trimpath','-o','../vpnguard','.')
    } finally {
        foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key]) }
        Pop-Location
    }
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath vpnguard).Hash.ToLowerInvariant()
    $remoteDir = (Invoke-Gateway 'mktemp -d /tmp/vpnguard-upload.XXXXXXXXXX').Trim()
    if ($remoteDir -cnotmatch '^/tmp/vpnguard-upload\.[a-zA-Z0-9]{10}$') { throw 'Unexpected staging directory.' }
    $stage = $remoteDir
    Invoke-Tool scp ($common + @('-P',"$Port",'vpnguard','source/deploy/guarded_update.py','source/deploy/route_guard.py',"${dest}:$stage/"))

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
