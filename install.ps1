[CmdletBinding()]
param(
    [string]$ServerName = "windbg",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path $PSScriptRoot).Path
$manifest = Join-Path $root "Cargo.toml"
$binary = Join-Path $root "target\release\windbg-mcp.exe"

if (-not $SkipBuild) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Rust/Cargo is required. Install the MSVC Rust toolchain, then run this installer again."
    }
    Write-Host "Building WinDbg MCP..."
    & cargo build --release --locked --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Release binary not found at '$binary'. Run without -SkipBuild."
}

function Invoke-ClientCommand {
    param(
        [Parameter(Mandatory = $true)] [string]$Client,
        [Parameter(Mandatory = $true)] [string[]]$Arguments
    )

    Write-Host ("Registering with {0}..." -f $Client)
    & $Client @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Client failed with exit code $LASTEXITCODE"
    }
}

$codex = Get-Command codex -ErrorAction SilentlyContinue
if ($null -ne $codex) {
    & $codex.Source mcp remove $ServerName 2>$null
    Invoke-ClientCommand $codex.Source @("mcp", "add", $ServerName, "--", $binary)
} else {
    Write-Warning "Codex CLI was not found; skipped Codex registration."
}

$claude = Get-Command claude -ErrorAction SilentlyContinue
if ($null -ne $claude) {
    & $claude.Source mcp remove --scope user $ServerName 2>$null
    Invoke-ClientCommand $claude.Source @("mcp", "add", "--scope", "user", $ServerName, "--", $binary)
} else {
    Write-Warning "Claude Code CLI was not found; skipped Claude registration."
}

Write-Host "WinDbg MCP installed as '$ServerName'. Restart Codex and Claude Code to load it."
