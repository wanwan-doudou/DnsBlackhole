# DnsBlackhole release script: build signed installers and generate latest.json.
# Usage: run .\scripts\release.ps1 from the project root.
# Prerequisite: updater private key at %USERPROFILE%\.tauri\dnsblackhole.key.

$ErrorActionPreference = "Stop"

# 外部构建命令执行前保存仓库根目录，避免后续工作目录或自动变量不可用
$projectRoot = (Get-Location).Path
if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $projectRoot = Split-Path -Parent $PSScriptRoot
}
Set-Location $projectRoot

$packageVersion = (Get-Content "package.json" -Raw -Encoding UTF8 | ConvertFrom-Json).version
$conf = Get-Content "src-tauri/tauri.conf.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$cargoToml = Get-Content "src-tauri/Cargo.toml" -Raw -Encoding UTF8
$cargoLock = Get-Content "src-tauri/Cargo.lock" -Raw -Encoding UTF8
$cargoTomlMatch = [regex]::Match($cargoToml, '(?ms)^\[package\]\s*.*?^version\s*=\s*"([^"]+)"')
$cargoLockMatch = [regex]::Match($cargoLock, '(?ms)^\[\[package\]\]\s*name\s*=\s*"dnsblackhole"\s*version\s*=\s*"([^"]+)"')
if (-not $cargoTomlMatch.Success -or -not $cargoLockMatch.Success) {
    throw "Unable to read project version from Cargo.toml or Cargo.lock"
}

$versions = [ordered]@{
    "package.json"             = [string]$packageVersion
    "src-tauri/tauri.conf.json" = [string]$conf.version
    "src-tauri/Cargo.toml"     = $cargoTomlMatch.Groups[1].Value
    "src-tauri/Cargo.lock"     = $cargoLockMatch.Groups[1].Value
}
$uniqueVersions = @($versions.Values | Sort-Object -Unique)
if ($uniqueVersions.Count -ne 1) {
    $details = ($versions.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
    throw "Project versions are inconsistent: $details"
}
$version = $uniqueVersions[0]

$keyPath = "$env:USERPROFILE\.tauri\dnsblackhole.key"
if (-not (Test-Path $keyPath)) {
    throw "Updater signing private key not found: $keyPath"
}

try {
    # The Tauri CLI reliably accepts the private key content through this env var.
    $env:TAURI_SIGNING_PRIVATE_KEY = (Get-Content $keyPath -Raw -Encoding UTF8).Trim()
    $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ""

    pnpm.cmd tauri build --ci
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

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
}
finally {
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
}
