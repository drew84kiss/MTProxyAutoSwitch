# -*- mode: python ; coding: utf-8 -*-
import os

datas = [
    ('img/icon.ico', 'img'),
    ('mtproxy_seed.json', '.'),
]
if os.path.isdir('bin'):
    datas.append(('bin', 'bin'))

a = Analysis(
    ['mtproxy_gui.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=(
        [
            'PySide6',
            'PySide6.QtCore',
            'PySide6.QtGui',
            'PySide6.QtWidgets',
            'telethon',
            'cryptography',
            'mtproxy_tg_ws',
            'mtproxy_tg_ws.tg_ws_proxy',
            'mtproxy_tg_ws.raw_websocket',
            'mtproxy_tg_ws.fake_tls',
            'mtproxy_tg_ws.bridge',
            'PIL',
            'PIL.Image',
            'win32crypt',
        ]
    ),
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
    name='MTProxyAutoSwitch',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='img/icon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='MTProxyAutoSwitch',
)
