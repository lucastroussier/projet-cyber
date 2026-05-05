# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\prog\\projet cyber\\src\\cyberaudit\\agent_exe.py'],
    pathex=['C:\\prog\\projet cyber\\src'],
    binaries=[],
    datas=[('C:\\prog\\projet cyber\\src\\cyberaudit\\templates', 'cyberaudit/templates'), ('C:\\prog\\projet cyber\\src\\cyberaudit\\static', 'cyberaudit/static')],
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
    a.binaries,
    a.datas,
    [],
    name='cyberaudit-agent',
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
