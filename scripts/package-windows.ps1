param(
  [switch]$SkipValidation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$configPath = Join-Path $repoRoot "src-tauri\tauri.conf.json"
$targetDirectory = Join-Path $repoRoot "src-tauri\target\package-stage"
$previousTargetDirectory = $env:CARGO_TARGET_DIR

Push-Location $repoRoot
try {
  $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
  if ($config.bundle.windows.nsis.installMode -ne "currentUser") {
    throw "The Windows NSIS package must use current-user installation."
  }
  if ($config.bundle.windows.webviewInstallMode.type -ne "offlineInstaller") {
    throw "The Windows package must embed the offline WebView2 installer."
  }
  if (-not $config.bundle.targets.Contains("nsis")) {
    throw "The Windows package must include the NSIS target."
  }

  if (-not $SkipValidation) {
    & npm run validate
    if ($LASTEXITCODE -ne 0) {
      throw "npm run validate failed with exit code $LASTEXITCODE."
    }
  }

  $env:CARGO_TARGET_DIR = $targetDirectory
  & npm exec -- tauri build --bundles nsis
  if ($LASTEXITCODE -ne 0) {
    throw "The isolated Windows package build failed with exit code $LASTEXITCODE."
  }

  $releaseDirectory = Join-Path $targetDirectory "release"
  $appPath = Join-Path $releaseDirectory "daemoncore.exe"
  $bundleDirectory = Join-Path $releaseDirectory "bundle\nsis"
  $setupFiles = @(Get-ChildItem -LiteralPath $bundleDirectory -Filter "*-setup.exe" -File)
  if (-not (Test-Path -LiteralPath $appPath -PathType Leaf)) {
    throw "The isolated build did not produce daemoncore.exe."
  }
  if ($setupFiles.Count -ne 1) {
    throw "Expected one NSIS setup executable in $bundleDirectory; found $($setupFiles.Count)."
  }

  $setupPath = $setupFiles[0].FullName
  $appHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $appPath).Hash.ToLowerInvariant()
  $setupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $setupPath).Hash.ToLowerInvariant()
  $relativeSetupPath = (Join-Path "bundle\nsis" $setupFiles[0].Name) -replace "\\", "/"
  $checksumManifest = Join-Path $releaseDirectory "SHA256SUMS.txt"
  $manifest = "{0} *daemoncore.exe`n{1} *{2}`n" -f $appHash, $setupHash, $relativeSetupPath
  [System.IO.File]::WriteAllText(
    $checksumManifest,
    $manifest,
    [System.Text.UTF8Encoding]::new($false)
  )

  $artifacts = @(
    [pscustomobject]@{
      path = $appPath
      bytes = (Get-Item -LiteralPath $appPath).Length
      sha256 = $appHash
      authenticode = (Get-AuthenticodeSignature -LiteralPath $appPath).Status.ToString()
    },
    [pscustomobject]@{
      path = $setupPath
      bytes = (Get-Item -LiteralPath $setupPath).Length
      sha256 = $setupHash
      authenticode = (Get-AuthenticodeSignature -LiteralPath $setupPath).Status.ToString()
    }
  )
  [pscustomobject]@{
    output = $releaseDirectory
    checksumManifest = $checksumManifest
    artifacts = $artifacts
    installed = $false
  } | ConvertTo-Json -Depth 4
}
finally {
  if ([string]::IsNullOrEmpty($previousTargetDirectory)) {
    Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
  } else {
    $env:CARGO_TARGET_DIR = $previousTargetDirectory
  }
  Pop-Location
}
