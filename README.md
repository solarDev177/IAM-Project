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

## Trusted Signing Setup

The Windows release workflow can also digitally sign the packaged app and installer with Microsoft Trusted Signing.

The signing step is optional. If the signing settings are missing, the workflow still builds the release artifacts, but they remain unsigned.

To enable Trusted Signing in GitHub Actions:

1. Create a Trusted Signing account and certificate profile in Azure Artifact Signing.
2. Create an Azure app registration that can access that certificate profile.
3. Add a federated credential for your GitHub repository so Actions can use OpenID Connect instead of a stored client secret.
4. Grant that app registration the `Trusted Signing Certificate Profile Signer` role for the certificate profile.
5. Add these GitHub repository secrets:
   - `AZURE_TENANT_ID`
   - `AZURE_CLIENT_ID`
6. Add these GitHub repository variables:
   - `TRUSTED_SIGNING_ENDPOINT`
   - `TRUSTED_SIGNING_ACCOUNT_NAME`
   - `TRUSTED_SIGNING_CERTIFICATE_PROFILE_NAME`

Example values:

- `TRUSTED_SIGNING_ENDPOINT`: `https://eus.codesigning.azure.net/`
- `TRUSTED_SIGNING_ACCOUNT_NAME`: your Trusted Signing account name
- `TRUSTED_SIGNING_CERTIFICATE_PROFILE_NAME`: your certificate profile name

Once those are configured, the Windows release workflow in [.github/workflows/windows-installer.yml](C:/Users/tyson/PycharmProjects/IAM-Project/.github/workflows/windows-installer.yml) will:

- build the app and installer
- sign the packaged app output in `dist\CloudflareIAMExplorer`
- sign the generated installer in `installer-output`
- upload the signed artifacts to the workflow run and release

## License

This project is licensed under the MIT License. See [LICENSE](C:/Users/tyson/PycharmProjects/IAM-Project/LICENSE).
