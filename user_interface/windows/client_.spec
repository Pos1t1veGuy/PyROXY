# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import site

site_packages = Path(site.getsitepackages()[1])
lib = Path(site.getsitepackages()[0]) / 'Lib'

a = Analysis(
    ['client.py'],
    pathex=[],
    binaries=[
        (str(lib / 'pyroxy' / 'tunnel' / 'tun2socks.exe'), '.'),
        (str(lib / 'pyroxy' / 'tunnel' / 'wintun.dll'), '.'),
    ],
    datas=[
        (str(site_packages / 'fake_useragent' / 'data' / '*'), 'fake_useragent/data'),
        (str(lib / 'pyroxy' / 'wrappers' / '*'), 'pyroxy/wrappers'),
    ],
    hiddenimports=['pyroxy'],
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
    a.binaries,
    a.datas,
    [],
    name='client',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)