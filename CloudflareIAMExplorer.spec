"""PyInstaller spec for the Windows onedir build."""

from pathlib import Path


project_root = Path(SPECPATH)
assets_dir = project_root / "assets"
icon_path = assets_dir / "cloudflare_app.ico"

datas = []
if assets_dir.exists():
    datas.append((str(assets_dir), "assets"))


a = Analysis(
    ["Driver.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CloudflareIAMExplorer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path) if icon_path.exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="CloudflareIAMExplorer",
)
