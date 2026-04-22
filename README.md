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

## Unsigned Installer Note

The current Windows installer build is unsigned.

That means Windows Defender SmartScreen may show a warning when the installer is downloaded or launched. For this project, that is expected behavior and not a sign that the repository or release pipeline is broken.

If you are evaluating the app:

- Download the installer from [GitHub Releases](https://github.com/solarDev177/IAM-Project/releases)
- If SmartScreen appears, click `More info`
- Then click `Run anyway`

## License

This project is licensed under the MIT License. See [LICENSE](C:/Users/tyson/PycharmProjects/IAM-Project/LICENSE).
