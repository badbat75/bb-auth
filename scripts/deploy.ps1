<#
.SYNOPSIS
    Stage and deploy bb-auth to a remote host over SSH (run from Windows).

.DESCRIPTION
    Orchestrates a zero-downtime (re)deploy of bb-auth to a Linux host:
      1. (with -Build) cross-build the aarch64 binary in WSL
      2. verify the local artifacts exist
      3. verify SSH access, passwordless sudo, and an aarch64 target
      4. stage binary + service unit + env placeholder + deploy.sh on the remote
      5. run deploy.sh on the remote as root (it installs, restarts, self-verifies)
      6. final liveness ping, then clean up the remote staging directory

    Lockout-safe by construction:
      - By default NOTHING is staged for allowed_emails, so deploy.sh keeps the
        existing /opt/bb-auth/allowed_emails untouched. Use -AllowlistFile for a
        first install or to replace the list.
      - deploy.sh preserves an existing /opt/bb-auth/bb-auth.env, so the HMAC key
        (and therefore all existing session cookies) stays valid across redeploys.

.PARAMETER Target
    SSH target as user@host, e.g. emiliano@rpi-01.bombicci.local.

.PARAMETER AllowlistFile
    Local allowlist file to stage instead of preserving the remote one. Required
    for a first install (where /opt/bb-auth/allowed_emails does not exist yet).

.PARAMETER Build
    Cross-build the aarch64 binary in WSL before staging.

.PARAMETER WslDistro
    WSL distribution to use with -Build. Default: FedoraLinux-44.

.EXAMPLE
    ./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -Build
    Cross-build in WSL, then redeploy to rpi-01 (allowlist + HMAC key kept).

.EXAMPLE
    ./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -AllowlistFile .\deploy\emails.txt
    Deploy and replace the allowlist with the given file.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,

    [string]$AllowlistFile,

    [switch]$Build,

    [string]$WslDistro = 'FedoraLinux-44'
)

$ErrorActionPreference = 'Stop'
# Keep native-command (ssh/scp/wsl) exit codes under our own control instead of
# letting them auto-throw, so we can report the failing step clearly.
$PSNativeCommandUseErrorActionPreference = $false

$Repo           = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BinPath        = Join-Path $Repo 'dist\bb-auth'
$ServiceUnit    = Join-Path $Repo 'deploy\bb-auth.service'
$EnvPlaceholder = Join-Path $Repo 'deploy\bb-auth.env'
$DeploySh       = Join-Path $Repo 'scripts\deploy.sh'
$RemoteStage    = 'bb-auth-stage'

function Assert-Native([string]$What) {
    if ($LASTEXITCODE -ne 0) {
        throw "FAILED (exit $LASTEXITCODE): $What"
    }
}

function ConvertTo-WslPath([string]$WinPath) {
    $p = (Resolve-Path $WinPath).Path -replace '\\', '/'
    $drive = $p.Substring(0, 1).ToLower()
    return "/mnt/$drive" + $p.Substring(2)
}

# --- 1. optional build -------------------------------------------------------
if ($Build) {
    Write-Host "==> cross-building aarch64 binary in WSL ($WslDistro)" -ForegroundColor Cyan
    $wslRepo = ConvertTo-WslPath $Repo
    wsl -d $WslDistro -- bash -lc "cd `"$wslRepo`" && bash scripts/build.sh"
    Assert-Native "WSL build (scripts/build.sh)"
}

# --- 2. local artifacts ------------------------------------------------------
if (-not (Test-Path -LiteralPath $BinPath)) {
    throw "Binary not found: $BinPath. Re-run with -Build, or build first in WSL (bash scripts/build.sh)."
}
foreach ($f in @($ServiceUnit, $EnvPlaceholder, $DeploySh)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Missing required file: $f" }
}
if ($AllowlistFile -and -not (Test-Path -LiteralPath $AllowlistFile)) {
    throw "AllowlistFile not found: $AllowlistFile"
}

# --- 3. verify remote access -------------------------------------------------
Write-Host "==> verifying SSH access, sudo, and arch on $Target" -ForegroundColor Cyan
# SSH first-connect can be flaky (slow DNS/ARP, an idle Pi waking up), so retry
# once. Merge stderr so a benign SSH warning or the failure reason is visible.
$probeOk = $false
$probe = $null
foreach ($attempt in 1..2) {
    $probe = ssh -o BatchMode=yes -o ConnectTimeout=10 $Target 'echo "USER=$(whoami)"; echo "ARCH=$(uname -m)"; sudo -n true 2>/dev/null && echo "SUDO=ok" || echo "SUDO=needs-password"' 2>&1
    if ($LASTEXITCODE -eq 0 -and $probe -match 'SUDO=ok' -and $probe -match 'ARCH=') {
        $probeOk = $true
        break
    }
    if ($attempt -lt 2) {
        Write-Host "    probe inconclusive (exit $LASTEXITCODE), retrying..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}
if (-not $probeOk) {
    Write-Host "    probe output:`n$probe" -ForegroundColor Yellow
    if ($probe -and $probe -notmatch 'SUDO=ok') {
        throw "Passwordless sudo is unavailable on $Target - deploy.sh must run as root."
    }
    throw "SSH probe to $Target failed (key auth / host reachable? see output above)."
}
$lines = $probe -split "`n"
$remoteUser = ($lines | Where-Object { $_ -match '^USER=' }) -replace '^USER=', ''
$arch       = ($lines | Where-Object { $_ -match '^ARCH=' }) -replace '^ARCH=', ''
if ($arch.Trim() -ne 'aarch64') {
    throw "Target architecture is '$($arch.Trim())', but the binary is built for aarch64. Refusing to deploy."
}
Write-Host "    connected as $($remoteUser.Trim()) on $($arch.Trim())"

# --- 4. stage on remote ------------------------------------------------------
Write-Host "==> staging artifacts on $Target (~/$RemoteStage)" -ForegroundColor Cyan
ssh -o BatchMode=yes $Target "rm -rf ~/$RemoteStage && mkdir -p ~/$RemoteStage"
Assert-Native "create staging dir on $Target"

$staged = @(
    @{ src = $BinPath;        dst = 'bb-auth' }
    @{ src = $ServiceUnit;    dst = 'bb-auth.service' }
    @{ src = $EnvPlaceholder; dst = 'bb-auth.env' }
    @{ src = $DeploySh;       dst = 'deploy.sh' }
)
if ($AllowlistFile) { $staged += @{ src = $AllowlistFile; dst = 'allowed_emails' } }

foreach ($a in $staged) {
    scp -o BatchMode=yes $a.src "${Target}:~/$RemoteStage/$($a.dst)"
    Assert-Native "scp $($a.dst) -> $Target"
}
$allowlistMode = if ($AllowlistFile) { 'replaced' } else { 'preserved (none staged)' }
Write-Host "    staged $($staged.Count) file(s); allowlist will be $allowlistMode"

# --- 5. run deploy.sh as root (installs + restarts + self-verifies) ----------
Write-Host "==> running deploy.sh as root on $Target" -ForegroundColor Cyan
ssh -o BatchMode=yes $Target "sudo bash ~/$RemoteStage/deploy.sh ~/$RemoteStage"
Assert-Native "remote deploy.sh (one or more verification checks failed)"

# --- 6. final liveness ping --------------------------------------------------
Write-Host "==> final liveness check" -ForegroundColor Cyan
$hz = ssh -o BatchMode=yes $Target 'L=$(sudo grep -E "^[[:space:]]*BB_AUTH_LISTEN=" /opt/bb-auth/bb-auth.env | tail -1 | cut -d= -f2-); curl -fsS --max-time 3 "http://${L:-127.0.0.1:4181}/auth/healthz"'
Assert-Native "post-deploy healthz"
Write-Host "    healthz: $hz" -ForegroundColor Green

# --- 7. cleanup staging ------------------------------------------------------
Write-Host "==> cleaning up ~/$RemoteStage on $Target" -ForegroundColor Cyan
ssh -o BatchMode=yes $Target "rm -rf ~/$RemoteStage"
Assert-Native "cleanup staging dir"

Write-Host ""
Write-Host "DEPLOY COMPLETE — bb-auth deployed to $Target" -ForegroundColor Green
