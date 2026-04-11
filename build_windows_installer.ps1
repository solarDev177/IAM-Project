param(
    [switch]$SkipBundleBuild
)

$ErrorActionPreference = "Stop"

# Resolve the repo root so the script works no matter where it is launched from.
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$specPath = Join-Path $projectRoot "CloudflareIAMExplorer.spec"
$installerScriptPath = Join-Path $projectRoot "CloudflareIAMExplorerInstaller.iss"
$distRoot = Join-Path $projectRoot "dist\CloudflareIAMExplorer"
$appExePath = Join-Path $distRoot "CloudflareIAMExplorer.exe"
$metadataPath = Join-Path $projectRoot "app_metadata.py"

function Get-AppVersion {
    # Read the application version directly from the shared metadata file.
    $metadataContent = Get-Content -LiteralPath $metadataPath -Raw
    $versionMatch = [regex]::Match($metadataContent, 'APP_VERSION\s*=\s*"([^"]+)"')
    if (-not $versionMatch.Success) {
        throw "Unable to read APP_VERSION from $metadataPath."
    }

    return $versionMatch.Groups[1].Value
}

function Find-InnoSetupCompiler {
    # Locate the Inno Setup compiler in the common Windows install paths.
    $candidatePaths = @(
        $env:INNO_SETUP_COMPILER,
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    ) | Where-Object { $_ }

    foreach ($candidate in $candidatePaths) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Build-AppBundle {
    # Rebuild the packaged onedir application before compiling the installer.
    $pyInstallerCommand = Get-Command pyinstaller -ErrorAction SilentlyContinue
    if (-not $pyInstallerCommand) {
        throw "PyInstaller is not installed. Install it with 'pip install pyinstaller' and rerun this script."
    }

    & $pyInstallerCommand.Source --noconfirm $specPath

    if (-not (Test-Path -LiteralPath $appExePath)) {
        throw "PyInstaller finished without creating $appExePath."
    }
}

function Build-Installer {
    # Compile the Inno Setup installer with the current application version.
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $isccPath = Find-InnoSetupCompiler
    if (-not $isccPath) {
        throw "Inno Setup 6 was not found. Install it, or set INNO_SETUP_COMPILER to ISCC.exe."
    }

    & $isccPath "/DMyAppVersion=$Version" $installerScriptPath
}

$appVersion = Get-AppVersion

if (-not $SkipBundleBuild) {
    Build-AppBundle
}

if (-not (Test-Path -LiteralPath $appExePath)) {
    throw "The app bundle is missing at $appExePath. Build the onedir package first or rerun without -SkipBundleBuild."
}

Build-Installer -Version $appVersion

Write-Host ""
Write-Host "Installer build complete." -ForegroundColor Green
Write-Host "Bundle:" -NoNewline
Write-Host " $appExePath"
Write-Host "Installer output:" -NoNewline
Write-Host " $(Join-Path $projectRoot 'installer-output')"
