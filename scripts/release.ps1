# DnsBlackhole release script: build signed installers and generate latest.json.
# Usage: run .\scripts\release.ps1 from the project root.
# Prerequisite: updater private key at %USERPROFILE%\.tauri\dnsblackhole.key.

$ErrorActionPreference = "Stop"

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

$latestPath = "$bundleDir/latest.json"
$latestJson = $latest | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText(
    [IO.Path]::GetFullPath($latestPath),
    $latestJson,
    [Text.UTF8Encoding]::new($false)
)

Write-Host ""
Write-Host "Build finished for v$version. Upload these files to GitHub Release tag v${version}:"
Write-Host "  $bundleDir/nsis/$setupName"
Write-Host "  $bundleDir/msi/DnsBlackhole_${version}_x64_en-US.msi"
Write-Host "  $latestPath   <- updater manifest, required"
