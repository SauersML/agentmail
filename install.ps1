# Islandmail installer for Windows: the node binary and the client into ~\.local\bin, no admin rights, no Rust.
#
#   irm https://raw.githubusercontent.com/SauersML/islandmail/main/install.ps1 | iex
#
# Saved as a file: install.ps1 [-Tag TAG] [-From DIR]
#   -Tag TAG   install that release (default: the latest release with node binaries; prereleases count when no
#              full release has them)
#   -From DIR  install from a directory holding the release files (CI's own build); no GitHub lookups
# Re-running upgrades in place. macOS and Linux: install.sh.
param([string]$Tag = "", [string]$From = "")

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Windows PowerShell's progress bar slows downloads many times over
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = "SauersML/islandmail"
$BinDir = Join-Path $HOME ".local\bin"
$Share = Join-Path $HOME ".local\share\islandmail"
$NodeAsset = "islandmail-node-x86_64-windows.exe"  # Windows on Arm runs it under x64 emulation
$Files = @($NodeAsset, "islandmail.py", "requirements.txt", "SHA256SUMS")

function Die([string]$msg) { Write-Host "islandmail install: $msg" -ForegroundColor Red; throw "islandmail install: $msg" }
# A native command's exit code, its output dropped. Windows PowerShell turns native stderr into errors, which
# "Stop" would throw on, so this runs with "Continue".
function Quiet([string]$exe, [string[]]$rest) {
    $eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { & $exe @rest *> $null } finally { $ErrorActionPreference = $eap }
    $LASTEXITCODE
}

$headers = @{ "Accept" = "application/vnd.github+json"; "User-Agent" = "islandmail-install" }
$token = if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $env:GH_TOKEN }
if ($token) { $headers["Authorization"] = "Bearer $token" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("islandmail-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    if ($From) {
        foreach ($f in $Files) {
            if (-not (Test-Path (Join-Path $From $f))) { Die "$From has no $f" }
            Copy-Item (Join-Path $From $f) (Join-Path $tmp $f)
        }
        Write-Host "Installing islandmail (x86_64-windows) from $From"
    } else {
        if (-not $Tag) {
            # The latest full release if it has the Windows binary, else the newest release (prereleases included).
            $rels = @()
            try { $rels += Invoke-RestMethod -Headers $headers -TimeoutSec 20 "https://api.github.com/repos/$Repo/releases/latest" } catch {}
            if (-not ($rels | Where-Object { $_.assets.name -contains $NodeAsset })) {
                # Parenthesised and piped: Windows PowerShell returns a JSON array as one object.
                try { $rels = (Invoke-RestMethod -Headers $headers -TimeoutSec 20 "https://api.github.com/repos/$Repo/releases?per_page=30") | ForEach-Object { $_ } } catch {}
            }
            $rel = $rels | Where-Object { $_.assets.name -contains $NodeAsset } | Select-Object -First 1
            if (-not $rel) { Die "found no release with $NodeAsset (GitHub API unreachable or rate limited? set GITHUB_TOKEN, or pass -Tag)" }
            $Tag = $rel.tag_name
        }
        Write-Host "Installing islandmail $Tag (x86_64-windows)"
        foreach ($f in $Files) {
            Invoke-WebRequest -UseBasicParsing -TimeoutSec 300 "https://github.com/$Repo/releases/download/$Tag/$f" -OutFile (Join-Path $tmp $f)
        }
    }

    # Every file against SHA256SUMS.
    $sums = @{}
    foreach ($line in Get-Content (Join-Path $tmp "SHA256SUMS")) {
        $parts = $line -split '\s+\*?', 2
        if ($parts.Count -eq 2) { $sums[$parts[1].Trim()] = $parts[0].ToLower() }
    }
    foreach ($f in @($NodeAsset, "islandmail.py", "requirements.txt")) {
        if (-not $sums.ContainsKey($f)) { Die "SHA256SUMS has no line for $f" }
        $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $f)).Hash.ToLower()
        if ($got -ne $sums[$f]) { Die "checksum mismatch for ${f}: refusing to install" }
    }
    Write-Host "  checksums match SHA256SUMS"

    New-Item -ItemType Directory -Force -Path $BinDir, $Share | Out-Null
    # A running exe cannot be overwritten but can be renamed: move the old one aside first.
    $node = Join-Path $BinDir "islandmail-node.exe"
    $old = "$node.old"
    if (Test-Path $old) { Remove-Item -Force $old -ErrorAction SilentlyContinue }
    if (Test-Path $node) { Move-Item -Force $node $old }
    Copy-Item (Join-Path $tmp $NodeAsset) $node
    Copy-Item (Join-Path $tmp "islandmail.py"), (Join-Path $tmp "requirements.txt") $Share -Force

    # The client's private Python environment (uv when present: much faster than venv + pip).
    $venv = Join-Path $Share "venv"
    $vpy = Join-Path $venv "Scripts\python.exe"
    $req = Join-Path $Share "requirements.txt"
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        if (-not (Test-Path $vpy) -and (Quiet uv @("venv", "-q", $venv)) -ne 0) { Die "uv venv $venv failed" }
        if ((Quiet uv @("pip", "install", "-q", "--python", $vpy, "-r", $req)) -ne 0) { Die "uv pip install failed" }
    } else {
        if (-not (Test-Path $vpy)) {
            # python.exe may be the Microsoft Store stub, which runs nothing: try each candidate.
            $made = $false
            foreach ($cand in @(@("py", "-3"), @("python"), @("python3"))) {
                if (-not (Get-Command $cand[0] -ErrorAction SilentlyContinue)) { continue }
                $pargs = @($cand | Select-Object -Skip 1)
                if ((Quiet $cand[0] ($pargs + @("-c", "import sys; sys.exit(sys.version_info < (3, 9))"))) -ne 0) { continue }
                if ((Quiet $cand[0] ($pargs + @("-m", "venv", $venv))) -eq 0) { $made = $true; break }
            }
            if (-not $made) { Die "the client needs Python 3.9+ (python.org or: winget install Python.Python.3.12) or uv" }
        }
        if ((Quiet $vpy @("-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", $req)) -ne 0) { Die "pip install failed" }
    }

    $wrapper = "@echo off`r`nrem Islandmail client, installed by install.ps1: its own Python environment, the node binary beside it on PATH.`r`n" +
        "set `"PATH=%~dp0;%PATH%`"`r`n`"$vpy`" `"$(Join-Path $Share 'islandmail.py')`" %*`r`n"
    [IO.File]::WriteAllText((Join-Path $BinDir "islandmail.cmd"), $wrapper)

    & $node --version
    if ($LASTEXITCODE -ne 0) { Die "the installed islandmail-node does not run" }
    if ((Quiet (Join-Path $BinDir "islandmail.cmd") @("--help")) -ne 0) { Die "the installed islandmail client does not run" }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not (($userPath -split ';') -contains $BinDir)) {
        [Environment]::SetEnvironmentVariable("Path", ($(if ($userPath) { "$userPath;" } else { "" }) + $BinDir), "User")
        Write-Host "added $BinDir to your user PATH (new terminals)"
    }
    if (-not (($env:Path -split ';') -contains $BinDir)) { $env:Path = "$BinDir;$env:Path" }

    Write-Host ""
    Write-Host "Installed islandmail-node and islandmail in $BinDir. Next, with the invite line (im1...) you were sent:"
    Write-Host ""
    Write-Host "  islandmail join im1..."
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
