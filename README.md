# Cloudflare IAM Explorer

[![Latest Release](https://img.shields.io/github/v/release/solarDev177/IAM-Project?display_name=tag&label=Latest%20Release)](https://github.com/solarDev177/IAM-Project/releases)
[![Windows Installer](https://img.shields.io/badge/Download-Windows%20Installer-orange)](https://github.com/solarDev177/IAM-Project/releases)

Cloudflare IAM Explorer is a Windows desktop application for reviewing Cloudflare IAM accounts, user groups, permissions, and vulnerability scan results in a more accessible interface.

## Download For Windows

If you just want to use the app, download it from the GitHub Releases page:

- Open [GitHub Releases](https://github.com/solarDev177/IAM-Project/releases)
- Download `CloudflareIAMExplorer-Setup-<version>.exe`
- Double-click the installer
- Follow the setup steps
- Launch `Cloudflare IAM Explorer`

Important:

- Most users should use the installer from `Releases`
- Do not download the `Source code (zip)` file unless you plan to build the app yourself
- You do not need Python, PowerShell, or Visual Studio to use the installer build

## Quick Start

After installing:

1. Open `Cloudflare IAM Explorer`
2. Enter your Cloudflare Account ID on the login screen
3. Enter your local PIN if one is configured
4. Manage tokens, accounts, members, and scans from the dashboard

## What The Installer Includes

- The desktop application
- Start Menu shortcut
- Optional desktop shortcut
- Local install under your Windows user profile

## For Developers

If you are building from source instead of using the installer:

1. Install Python 3.13 on Windows
2. Install dependencies from [requirements-windows-build.txt](C:/Users/tyson/PycharmProjects/IAM-Project/requirements-windows-build.txt)
3. Build the app and installer with [build_windows_installer.ps1](C:/Users/tyson/PycharmProjects/IAM-Project/build_windows_installer.ps1)

Example:

```powershell
pip install -r requirements-windows-build.txt
powershell -ExecutionPolicy Bypass -File .\build_windows_installer.ps1
```

## Releases

The GitHub release pipeline now builds:

- A Windows installer: `CloudflareIAMExplorer-Setup-<version>.exe`
- A portable package: `CloudflareIAMExplorer-Portable-<version>.zip`

The portable zip is mainly useful for testing and updater compatibility. The installer is the recommended option for most users.

## Code Signing Setup

The Windows release workflow can also digitally sign the packaged app and installer with a traditional Windows code-signing certificate through `signtool`.

The signing step is optional. If the certificate settings are missing, the workflow still builds the release artifacts, but they remain unsigned.

To enable code signing in GitHub Actions:

1. Export your OV or EV code-signing certificate as a `.pfx` file.
2. Convert that `.pfx` file to Base64 text.
3. Add these GitHub repository secrets:
   - `WINDOWS_CODESIGN_CERT_BASE64`
   - `WINDOWS_CODESIGN_CERT_PASSWORD`
4. Optionally add this GitHub repository variable:
   - `WINDOWS_CODESIGN_TIMESTAMP_URL`

Recommended timestamp value:

- `WINDOWS_CODESIGN_TIMESTAMP_URL`: `http://timestamp.digicert.com`

Once those are configured, the Windows release workflow in [.github/workflows/windows-installer.yml](C:/Users/tyson/PycharmProjects/IAM-Project/.github/workflows/windows-installer.yml) will:

- build the app and installer
- decode the `.pfx` certificate on the GitHub Actions runner
- sign the packaged app output in `dist\CloudflareIAMExplorer`
- sign the generated installer in `installer-output`
- upload the signed artifacts to the workflow run and release

To generate the Base64 certificate string locally in PowerShell:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\to\codesign-certificate.pfx"))
```

## License

This project is licensed under the MIT License. See [LICENSE](C:/Users/tyson/PycharmProjects/IAM-Project/LICENSE).
