# -*- mode: python ; coding: utf-8 -*-
import os
import sys

# Get the absolute path to the project directory
project_dir = SPECPATH

# Platform-specific ADB binary
if sys.platform.startswith('win32'):
    adb_binary_path = os.path.join(project_dir, 'adb_binary', 'windows')
    adb_data = [(os.path.join(adb_binary_path, 'adb.exe'), 'adb_binary'),
                (os.path.join(adb_binary_path, 'AdbWinApi.dll'), 'adb_binary'),
                (os.path.join(adb_binary_path, 'AdbWinUsbApi.dll'), 'adb_binary')]
elif sys.platform.startswith('linux'):
    adb_binary_path = os.path.join(project_dir, 'adb_binary', 'linux')
    adb_data = [(os.path.join(adb_binary_path, 'adbl'), 'adb_binary')]
elif sys.platform.startswith('darwin'):
    adb_binary_path = os.path.join(project_dir, 'adb_binary', 'macos')
    adb_data = [(os.path.join(adb_binary_path, 'adb'), 'adb_binary')]
else:
    raise RuntimeError(f"Unsupported platform: {sys.platform}")

block_cipher = None

a = Analysis(
    ['adb.py'],
    pathex=[project_dir],
    binaries=[],
    datas=[
        ('ui/icon.png', 'ui'),
        ('ui/icons/fluent', 'ui/icons/fluent'),
    ] + adb_data,
    hiddenimports=[
        'PyQt6.QtSvg',
        'adb_manager',
        'adb_manager.adb_actions',
        'adb_manager.adb_thread',
        'adb_manager.interactive_shell_thread',
        'ui',
        'ui.main_window',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='adb',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to False if you don't want a console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(project_dir, 'ui', 'icon.png'),
)

if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='adb.app',
        icon=os.path.join(project_dir, 'ui', 'icon.png'),
        bundle_identifier=None,
    )