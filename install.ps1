# Ghostfork gf installer for Windows.
#
#   irm https://ghostfork.io/install.ps1 | iex
#
# Downloads the signed-off gf setup program from GitHub Releases, verifies it
# against the release's SHA256SUMS, and runs it silently. The setup program
# does the actual work — it installs gf.exe and git-remote-gf.exe under
# %LOCALAPPDATA%\Programs\ghostfork, adds that to the per-user PATH, and
# registers an Add/Remove Programs entry. Everything is per-user: no
# administrator rights, no UAC prompt.
#
# Re-running upgrades in place — that is the supported upgrade path, since
# there is no `gf upgrade` command. Uninstall through Settings > Apps, or by
# running the setup program with --uninstall.
#
# Environment overrides:
#   GF_VERSION    release tag to install (default: the latest release)
#   GF_BASE_URL   base URL to fetch assets from (default: GitHub Releases)
#
# Note there is no param() block: `irm | iex` runs this text in the caller's
# scope, where parameters cannot be bound. Configuration is by environment
# variable only.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo = 'ghostfork-io/ghostfork'
$Asset = 'gf-setup-windows-amd64.exe'

# Windows PowerShell 5.1 still negotiates TLS 1.0 by default on some machines,
# which GitHub refuses outright. Opt into TLS 1.2 before any download.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # PowerShell 7+ on .NET Core manages this itself and may not expose the property.
}

# Invoke-WebRequest's progress bar makes downloads dramatically slower in 5.1.
$ProgressPreference = 'SilentlyContinue'

function Fail($Message) {
    Write-Host ''
    Write-Host "gf install: $Message" -ForegroundColor Red
    exit 1
}

# Only amd64 is published today. ARM64 Windows can run it under x64 emulation,
# but that should be the user's explicit choice rather than something the
# installer does behind their back.
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq 'ARM64') {
    Fail @"
Windows on ARM64 is not published yet.

Windows 11 can run the x64 build under emulation. To do that deliberately:
  `$env:PROCESSOR_ARCHITECTURE='AMD64'; irm https://ghostfork.io/install.ps1 | iex

Or build from source: https://github.com/$Repo#readme
"@
} elseif ($arch -ne 'AMD64') {
    Fail "unsupported architecture: $arch (gf ships for x64 on Windows)"
}

$version = $env:GF_VERSION
if ($env:GF_BASE_URL) {
    $base = $env:GF_BASE_URL
} elseif ($version) {
    $base = "https://github.com/$Repo/releases/download/$version"
} else {
    # GitHub's own "latest" redirect, so the installer never touches the API
    # and never shares its 60-requests-per-hour unauthenticated limit.
    $base = "https://github.com/$Repo/releases/latest/download"
}

Write-Host 'Ghostfork gf installer'
Write-Host "  platform:  Windows $arch"
if ($version) { Write-Host "  release:   $version" } else { Write-Host '  release:   latest' }
Write-Host ''

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("gf-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    $setup = Join-Path $tmp $Asset
    $sums = Join-Path $tmp 'SHA256SUMS'

    Write-Host "downloading $Asset..."
    try {
        Invoke-WebRequest -Uri "$base/$Asset" -OutFile $setup -UseBasicParsing
        Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing
    } catch {
        Fail "could not download from $base`n  $($_.Exception.Message)"
    }

    # Verify before running anything. SHA256SUMS covers every asset in the
    # release; we check only the one we fetched.
    $line = Get-Content $sums | Where-Object { $_ -match "\s$([regex]::Escape($Asset))$" } | Select-Object -First 1
    if (-not $line) { Fail "$Asset is not listed in SHA256SUMS for this release" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Path $setup -Algorithm SHA256).Hash.ToLower()

    if ($expected -ne $actual) {
        Fail @"
checksum mismatch for $Asset
  expected $expected
  actual   $actual
Nothing was installed. Retry, and if it persists please report it.
"@
    }
    Write-Host "checksum verified (sha256 $($actual.Substring(0,8))...)"
    Write-Host ''

    # The setup program is built for the GUI subsystem (-H=windowsgui), so it
    # detaches immediately unless we wait on it explicitly.
    Write-Host 'installing...'
    $proc = Start-Process -FilePath $setup -ArgumentList '--silent' -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Fail "the installer exited with code $($proc.ExitCode) — gf was not installed"
    }

    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\ghostfork'
    $gf = Join-Path $installDir 'gf.exe'
    if (-not (Test-Path $gf)) {
        Fail "the installer reported success but $gf is missing"
    }

    $reported = & $gf --version 2>$null
    Write-Host ''
    Write-Host "installed: $reported"
    Write-Host "           $gf"
    Write-Host "           $(Join-Path $installDir 'git-remote-gf.exe')"
    Write-Host ''
    Write-Host "$installDir was added to your PATH."
    Write-Host 'Open a new terminal for it to take effect.'
    Write-Host ''
    Write-Host 'Next:  gf login --server <url> --username <name>'
    Write-Host "Docs:  https://github.com/$Repo#readme"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
