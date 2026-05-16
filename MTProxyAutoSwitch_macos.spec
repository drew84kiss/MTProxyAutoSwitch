# -*- mode: python ; coding: utf-8 -*-
import platform
import os


def _resolve_target_arch() -> str | None:
    forced_arch = os.environ.get('MTPROXY_TARGET_ARCH', '').strip().lower()
    if forced_arch in {'x86_64', 'arm64', 'universal2'}:
        return forced_arch
    machine = platform.machine().strip().lower()
    if machine in {'arm64', 'aarch64'}:
        return 'arm64'
    if machine in {'x86_64', 'amd64'}:
        return 'x86_64'
    return None


target_arch = _resolve_target_arch()
datas = [
    ('img/icon.ico', 'img'),
    ('mtproxy_seed.json', '.'),
    ('telegram_proxy_collector_seed.txt', '.'),
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
            'objc',
            'Foundation',
            'AppKit',
            'Quartz',
        ]
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['win32crypt'],
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
    target_arch=target_arch,
    codesign_identity=None,
    entitlements_file=None,
    icon=[],
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

app = BUNDLE(
    coll,
    name='MTProxyAutoSwitch.app',
    icon=None,
    bundle_identifier='com.mtproxyautoswitch',
    info_plist={
        'CFBundleName': 'MTProxy AutoSwitch',
        'CFBundleDisplayName': 'MTProxy AutoSwitch',
        'CFBundleShortVersionString': '1.3.5',
        'CFBundleVersion': '1.3.5',
        'LSMinimumSystemVersion': '10.15',
        'NSHighResolutionCapable': True,
        'NSAppleEventsUsageDescription':
            'MTProxy AutoSwitch may open Telegram proxy links in the Telegram app.',
    },
)
