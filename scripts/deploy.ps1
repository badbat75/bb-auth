<#
.SYNOPSIS
    Build the .deb packages and deploy them to a remote host over SSH (run from Windows).

.DESCRIPTION
    Orchestrates a (re)deploy of bb-auth to a Linux host, through dpkg:
      1. build the packages in WSL (scripts/package.sh, which builds through
         scripts/build.sh, so dist/ stays current for everything else too)
      2. probe the target BEFORE copying anything: SSH access, passwordless sudo, the
         architecture, and which package manager it has. A `.deb` host (Debian, Ubuntu,
         Raspberry Pi OS, Mint) is the only supported family; an RPM host (Fedora, RHEL,
         Rocky, openSUSE) is refused with a plain "not supported yet", because
         scripts/package.sh builds with cargo-deb and there is no RPM to ship
      3. ship the .deb files, scripts/deploy.sh and scripts/verify.sh to a staging
         directory on the remote
      4. run deploy.sh there as root, then clean the staging directory up

    deploy.sh is the host side and does what a package cannot: validate a staged access
    file with the gate's own parser BEFORE anything is installed, `dpkg -i` in one
    transaction, keep the packages it replaced so there is something to roll back to,
    install the staged access file, and run verify.sh. It is staged rather than inlined here so the
    logic that touches a live gate is reviewable in the repo, not quoted through
    PowerShell into ssh into a remote shell.

    The install itself, and everything that must survive it, is the packages' business:
    see [package.metadata.deb] in Cargo.toml and deploy/debian/*/postinst. In short, no
    state is packaged, so an upgrade cannot touch either of the two things that must
    never change by accident:

      - etc/bb-auth.env, which carries the HMAC key. It is created once, on a first
        install, and preserved forever after, so existing session cookies keep
        verifying and nobody is logged out by a redeploy.
      - var/lib/access.json, the live access file. A redeploy leaves it exactly as it
        is. -AccessFile is the only thing here that replaces it, and it validates the
        file with `bb-auth --check-access` before anything is overwritten.

    `dpkg -i` rather than `apt install`, deliberately: apt would decline to reinstall a
    version equal to the one already there, so a rebuilt 1.1.0-1 would silently not
    deploy. dpkg always unpacks and re-configures, which is what a redeploy means here.

.PARAMETER Target
    SSH target as user@host, e.g. emiliano@rpi-01.bombicci.local.

.PARAMETER Packages
    Which packages to install. Default: all three. The two admin tools are optional by
    design (the gate never calls either), so `-Packages bb-auth` is a gate-only host.
    NOTE installing bb-auth-web is what hands the access file to the bb-auth-web user;
    a deploy without it changes no ownership at all.

.PARAMETER AccessFile
    Local access.json to install over the remote one. Required only for a first install
    on a host where you want a roster immediately: the package creates an EMPTY access
    file (nobody authorized) and never touches it again. Validated as JSON locally, then
    by the freshly-installed binary on the host, before it replaces the live file.
    Check it locally first: cargo run -- --check-access .\deploy\access.json

.PARAMETER Arch
    Debian architecture to build and deploy. Default: arm64 (the Pi).

.PARAMETER Revision
    The Debian revision: 1.1.0-<Revision>. Bump it to rebuild the same crate version
    with a packaging change, exactly as `package.sh --revision` does. It was documented
    there and unreachable through this script, which is the supported entry point.

.PARAMETER AllowDirty
    Package an uncommitted working tree. package.sh refuses one by default: a .deb
    version reads the same whether it came from a tag or from a half-finished edit, and
    the build string baked into the binaries (`bb-auth --version`) is the only thing that
    would say otherwise.

.PARAMETER NoBuild
    Skip the compile and package whatever binaries are already in dist/. The packages
    are still rebuilt, which takes seconds.

.PARAMETER WslDistro
    WSL distribution used for the build. Default: FedoraLinux-44.

.EXAMPLE
    ./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local
    Build the arm64 packages and deploy all three (access.json + HMAC key kept).

.EXAMPLE
    ./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -NoBuild -Packages bb-auth
    Repackage the current dist/ and install the gate only.

.EXAMPLE
    ./scripts/deploy.ps1 emiliano@rpi-01.bombicci.local -AccessFile .\deploy\access.json
    Deploy, then replace the access file with the given one.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,

    [ValidateSet('bb-auth', 'bb-auth-adm', 'bb-auth-web')]
    [string[]]$Packages = @('bb-auth', 'bb-auth-adm', 'bb-auth-web'),

    [string]$AccessFile,

    [ValidateSet('arm64', 'amd64', 'armhf')]
    [string]$Arch = 'arm64',

    [ValidateRange(1, 99)]
    [int]$Revision = 1,

    [switch]$NoBuild,

    [switch]$AllowDirty,

    [string]$WslDistro = 'FedoraLinux-44'
)

$ErrorActionPreference = 'Stop'
# Keep native-command (ssh/scp/wsl) exit codes under our own control instead of
# letting them auto-throw, so we can report the failing step clearly.
$PSNativeCommandUseErrorActionPreference = $false

$Repo        = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$DistDir     = Join-Path $Repo 'dist'
# The host side of the deploy: dpkg -i, the access file, and the checks. It runs as root
# on the target and is staged with the packages, so the logic that touches a live gate is
# in the repo and not in a quoted string.
$DeploySh    = Join-Path $Repo 'scripts\deploy.sh'
$VerifySh    = Join-Path $Repo 'scripts\verify.sh'
$RemoteStage = 'bb-auth-stage'

# The gate is not optional, and it must be configured before the two admin packages,
# which Depends: bb-auth (= <version>). dpkg sorts one transaction out by itself, but
# the order also decides which postinst prints what, so keep it deliberate.
if ($Packages -notcontains 'bb-auth') {
    throw "-Packages must include bb-auth: the other two Depends: bb-auth (= <version>)."
}
$Packages = @('bb-auth', 'bb-auth-adm', 'bb-auth-web') | Where-Object { $Packages -contains $_ }

# uname -m on the target, per Debian architecture. A mismatch here is a package apt
# would install and the kernel could not exec.
$UnameFor = @{ arm64 = 'aarch64'; amd64 = 'x86_64'; armhf = 'armv7l' }

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

# --- 1. build the packages ---------------------------------------------------
$pkgArgs = "--arch $Arch --revision $Revision"
if ($NoBuild)    { $pkgArgs += ' --no-build' }
if ($AllowDirty) { $pkgArgs += ' --allow-dirty' }

# WHICH COMMIT THESE BYTES ARE, worked out HERE and passed in. The build runs inside WSL,
# where the checkout is a /mnt/c mount and `git` may not be installed at all: asking there
# answered "unknown" for every release built the supported way, which is the one path where
# the answer matters. It also silently disarmed package.sh's refusal to package an
# uncommitted tree, since a tree it cannot read is never dirty.
# The commit, not `git describe`: a release candidate is never tagged, so describe would
# open with the version of a tag several releases back. See the note in scripts/build.sh.
$Build = (git -C $Repo rev-parse --short=7 HEAD 2>$null | Select-Object -First 1)
if ($Build) {
    git -C $Repo diff-index --quiet HEAD -- 2>$null
    if ($LASTEXITCODE -ne 0) { $Build = "$Build-dirty" }
    $Build = "g$Build"
} else {
    $Build = 'unknown'
}
Write-Host "==> building the $Arch packages in WSL ($WslDistro), from $Build" -ForegroundColor Cyan
$wslRepo = ConvertTo-WslPath $Repo
wsl -d $WslDistro -- bash -lc "cd `"$wslRepo`" && BB_AUTH_BUILD='$Build' bash scripts/package.sh $pkgArgs"
Assert-Native "WSL package build (scripts/package.sh $pkgArgs)"

# --- 2. the artifacts --------------------------------------------------------
# The version comes from Cargo.toml, and the revision is package.sh's default. Matching
# on the exact filename rather than a glob is what stops a stale .deb from an older
# version being shipped when this build produced nothing.
$Version = (Select-String -Path (Join-Path $Repo 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"' |
            Select-Object -First 1).Matches[0].Groups[1].Value
$DebVersion = "$Version-$Revision"

$debs = foreach ($p in $Packages) {
    $f = Join-Path $DistDir "${p}_${DebVersion}_${Arch}.deb"
    if (-not (Test-Path -LiteralPath $f)) {
        throw "Package not found: $f. scripts/package.sh should have produced it."
    }
    $f
}
foreach ($f in @($DeploySh, $VerifySh)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Missing required file: $f" }
}
if ($AccessFile) {
    if (-not (Test-Path -LiteralPath $AccessFile)) { throw "AccessFile not found: $AccessFile" }
    # Cheap local sanity checks, so a typo costs a second instead of a round trip. The
    # authoritative check is the gate's own parser, which now runs on the host BEFORE
    # anything is installed (scripts/deploy.sh).
    try { $doc = Get-Content -Raw -LiteralPath $AccessFile | ConvertFrom-Json }
    catch { throw "AccessFile is not valid JSON: $AccessFile" }
    # The version is the one thing a JSON parse cannot tell you and the gate refuses
    # outright: a file in a pre-1.0 format parses perfectly and compiles to a completely
    # different set of grants, which is why the gate makes it a fatal, explanatory error
    # rather than a type mismatch three levels down.
    if ($doc.version -ne 1) {
        throw ("AccessFile declares version '{0}', not 1: {1}. The gate would refuse it. " +
               "Run: cargo run --bin bb-auth -- --check-access '{1}'") -f $doc.version, $AccessFile
    }
}
Write-Host "    $($debs.Count) package(s) for $Arch at $DebVersion"

# --- 3. verify the remote BEFORE anything is copied --------------------------
# Three questions, and all three must be answered before the first scp: who we are,
# what machine this is, and what it installs software with. A wrong architecture or a
# host that speaks RPM cannot be discovered halfway through a transfer.
Write-Host "==> probing $Target (sudo, architecture, package manager)" -ForegroundColor Cyan
# SSH first-connect can be flaky (slow DNS/ARP, an idle Pi waking up), so retry
# once. Merge stderr so a benign SSH warning or the failure reason is visible.
$probeCmd = 'echo "USER=$(whoami)"; echo "ARCH=$(uname -m)"; ' +
            '. /etc/os-release 2>/dev/null || true; echo "OS=${PRETTY_NAME:-unknown}"; ' +
            'if command -v dpkg >/dev/null 2>&1; then echo "PKG=deb"; ' +
            'elif command -v rpm >/dev/null 2>&1; then echo "PKG=rpm"; ' +
            'else echo "PKG=unknown"; fi; ' +
            'sudo -n true 2>/dev/null && echo "SUDO=ok" || echo "SUDO=needs-password"'
$probeOk = $false
$probe = $null
foreach ($attempt in 1..2) {
    $probe = ssh -o BatchMode=yes -o ConnectTimeout=10 $Target $probeCmd 2>&1
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
    # Only claim a sudo problem when sudo actually answered: an unresolvable host or a
    # refused key produces no SUDO= line at all, and blaming sudo for that sends the
    # operator to the wrong file.
    if ($probe -match 'SUDO=needs-password') {
        throw "Passwordless sudo is unavailable on $Target - the install must run as root."
    }
    throw "SSH probe to $Target failed (key auth / host reachable? see output above)."
}
$lines = $probe -split "`n"
function Get-ProbeValue([string]$Key) {
    $v = $lines | Where-Object { $_ -match "^$Key=" } | Select-Object -First 1
    if ($null -eq $v) { return '' }
    return ($v -replace "^$Key=", '').Trim()
}
# NOT $arch: PowerShell variable names are case-insensitive, so that would silently be
# the -Arch parameter and the comparison below would compare the host against itself.
$remoteUser = Get-ProbeValue 'USER'
$remoteArch = Get-ProbeValue 'ARCH'
$osName     = Get-ProbeValue 'OS'
$pkgKind    = Get-ProbeValue 'PKG'
Write-Host "    $remoteUser@$($Target.Split('@')[-1]): $osName, $remoteArch, package manager: $pkgKind"

# The package manager decides whether this deploy is possible at all. RPM hosts are a
# real target family (Fedora, RHEL, Rocky, openSUSE) and nothing here builds for them
# yet: cargo-deb produces .deb only, so say that plainly instead of failing later with
# "dpkg: command not found".
switch ($pkgKind) {
    'deb' { }
    'rpm' {
        throw ("$Target is RPM-based ($osName). This deploy ships .deb packages and " +
               "RPM packaging is NOT SUPPORTED yet: scripts/package.sh builds with " +
               "cargo-deb, which produces .deb only. Nothing was copied.")
    }
    default {
        throw ("Cannot tell what $Target installs software with (neither dpkg nor rpm " +
               "answered; it reports '$osName'). Only Debian-family hosts are supported. " +
               "Nothing was copied.")
    }
}

if ($remoteArch -ne $UnameFor[$Arch]) {
    $suggest = ($UnameFor.GetEnumerator() | Where-Object { $_.Value -eq $remoteArch } |
                Select-Object -First 1).Key
    $hint = if ($suggest) { "Re-run with -Arch $suggest." }
            else { "No -Arch value here maps to '$remoteArch'." }
    throw "$Target is $remoteArch, but these packages are $Arch (which expects $($UnameFor[$Arch])). $hint Nothing was copied."
}

# --- 4. stage on remote ------------------------------------------------------
Write-Host "==> staging on $Target (~/$RemoteStage)" -ForegroundColor Cyan
ssh -o BatchMode=yes $Target "rm -rf ~/$RemoteStage && mkdir -p ~/$RemoteStage"
Assert-Native "create staging dir on $Target"

$staged = @()
foreach ($f in $debs) { $staged += @{ src = $f; dst = (Split-Path -Leaf $f) } }
$staged += @{ src = $DeploySh; dst = 'deploy.sh' }
$staged += @{ src = $VerifySh; dst = 'verify.sh' }
if ($AccessFile) { $staged += @{ src = $AccessFile; dst = 'access.json' } }

foreach ($a in $staged) {
    scp -o BatchMode=yes $a.src "${Target}:~/$RemoteStage/$($a.dst)"
    Assert-Native "scp $($a.dst) -> $Target"
}
Write-Host "    staged $($staged.Count) file(s): $($Packages -join ', ')"

# --- 5. run deploy.sh as root (dpkg -i + access file + verify) ----------------
# Everything that touches the live host is in that script, staged alongside the
# packages, rather than in a string quoted through PowerShell into ssh into a remote
# shell. A postinst that fails its preflight makes dpkg exit non-zero and this step
# fails with the gate still serving on the inode it holds, which is the point.
Write-Host "==> running deploy.sh as root on $Target" -ForegroundColor Cyan
ssh -o BatchMode=yes $Target "sudo bash ~/$RemoteStage/deploy.sh ~/$RemoteStage"
Assert-Native "remote deploy.sh (install or verification failed)"

# --- 6. cleanup staging ------------------------------------------------------
Write-Host "==> cleaning up ~/$RemoteStage on $Target" -ForegroundColor Cyan
ssh -o BatchMode=yes $Target "rm -rf ~/$RemoteStage"
Assert-Native "cleanup staging dir"

Write-Host ""
Write-Host "DEPLOY COMPLETE: $($Packages -join ', ') $DebVersion ($Arch) on $Target" -ForegroundColor Green
if (-not $AccessFile) {
    Write-Host "The access file and the HMAC key were left untouched." -ForegroundColor Green
}
