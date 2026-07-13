# DnsBlackhole release script: build signed installers and generate latest.json.
# Usage: run .\scripts\release.ps1 from the project root.
# Prerequisite: updater private key at %USERPROFILE%\.tauri\dnsblackhole.key.

$ErrorActionPreference = "Stop"

# 外部构建命令执行前保存仓库根目录，避免后续工作目录或自动变量不可用
$projectRoot = (Get-Location).Path
if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $projectRoot = Split-Path -Parent $PSScriptRoot
}

$keyPath = "$env:USERPROFILE\.tauri\dnsblackhole.key"
if (-not (Test-Path $keyPath)) {
    throw "Updater signing private key not found: $keyPath"
}

# The Tauri CLI reliably accepts the private key content through this env var.
$env:TAURI_SIGNING_PRIVATE_KEY = (Get-Content $keyPath -Raw -Encoding UTF8).Trim()
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ""

pnpm.cmd tauri build --ci
if ($LASTEXITCODE -ne 0) {
    throw "Build failed"
}

$conf = Get-Content "src-tauri/tauri.conf.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$version = $conf.version
$bundleDir = "src-tauri/target/release/bundle"
$setupName = "DnsBlackhole_${version}_x64-setup.exe"
$sigPath = "$bundleDir/nsis/$setupName.sig"

if (-not (Test-Path $sigPath)) {
    throw "Signature file not found: $sigPath. Check createUpdaterArtifacts in tauri.conf.json."
}

$latest = [ordered]@{
    version   = $version
    notes     = "See the GitHub Release page for details."
    pub_date  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    platforms = @{
        "windows-x86_64" = [ordered]@{
            signature = (Get-Content $sigPath -Raw -Encoding UTF8).Trim()
            url       = "https://github.com/wanwan-doudou/DnsBlackhole/releases/download/v$version/$setupName"
        }
    }
}

# 使用脚本启动时保存的仓库根目录，避免外部命令改变工作目录
$latestPath = Join-Path $projectRoot "$bundleDir/latest.json"
$latestJson = $latest | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText(
    [string]$latestPath,
    [string]$latestJson,
    [Text.UTF8Encoding]::new($false)
)

Write-Host ""
Write-Host "Build finished for v$version. Upload these files to GitHub Release tag v${version}:"
Write-Host "  $bundleDir/nsis/$setupName"
Write-Host "  $bundleDir/msi/DnsBlackhole_${version}_x64_en-US.msi"
Write-Host "  $latestPath   <- updater manifest, required"
