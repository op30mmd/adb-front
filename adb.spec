# -*- mode: python ; coding: utf-8 -*-
import os
import sys

# Get the absolute path to the project directory
project_dir = os.path.abspath(SPECPATH)

block_cipher = None

a = Analysis(
    ['adb.py'],
    pathex=[project_dir],
    binaries=[],
    datas=[
        ('ui/icon.png', 'ui'),  # Include the icon file
    ],
    hiddenimports=[
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
    console=True,  # Set to False if you don't want a console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)