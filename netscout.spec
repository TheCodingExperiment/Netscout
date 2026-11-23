# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for NetScout. Same file works on Windows, macOS and Linux -
# PyInstaller reads it on whichever OS you run it on and builds the right kind of
# program for that OS automatically. It never cross-compiles: run it ONCE ON EACH
# operating system you need a copy for (see BUILD_README.txt).
#
# Usage (after "pip install pyinstaller bleak"):
#   pyinstaller --noconfirm netscout.spec
# Result: dist/NetScout(.exe), plus dist/NetScout.app on macOS.

import os
import sys

# NETSCOUT_ONEDIR=1 builds the "folder" version (dist/NetScout-Folder/NetScout.exe + its files) instead of
# the single .exe. The single file unpacks itself into %TEMP% on every launch; on locked-down or
# antivirus-heavy PCs that unpacking is sometimes blocked, which shows up as "Failed to load Python DLL" -
# a message that makes people think they need Python. The folder version never unpacks anything, so it
# runs on those machines too. build_windows.bat builds BOTH.
ONEDIR = os.environ.get('NETSCOUT_ONEDIR') == '1'

# Each OS wants its own icon format, and Linux doesn't embed one in the binary at all - there the
# build script installs netscout.png and points a .desktop entry at it instead.
if sys.platform == 'win32':
    ICON = 'netscout.ico'
elif sys.platform == 'darwin':
    ICON = 'netscout.icns'
else:
    ICON = None

block_cipher = None

a = Analysis(
    ['netscout_gui.py'],
    pathex=[],
    binaries=[],
    # the .ico also ships INSIDE the app on Windows: the running window loads it for a native,
    # multi-size taskbar / title-bar icon (see _set_app_icon in netscout_gui.py)
    datas=[('netscout.ico', '.')] if sys.platform == 'win32' else [],
    # netscout_gui.py only imports bleak lazily, inside try/except, when Bluetooth is
    # actually used - PyInstaller's static scan still finds that import statement and
    # would normally bundle bleak correctly on its own. Listed here explicitly too, as
    # a safety net, in case a future bleak/PyInstaller version combination needs the
    # nudge. A missing bleak is only a warning, never a failed build: the app handles
    # being packaged without it (ensure_bleak() says so at runtime and carries on).
    # If Bluetooth scanning doesn't work in the built app, the fix is:
    #   pip install pyinstaller-hooks-contrib
    # and rebuild - that package carries bleak's own PyInstaller hook for its
    # platform-specific backends (WinRT / CoreBluetooth / BlueZ).
    # tkinter / _tkinter are listed explicitly so PyInstaller's Tcl/Tk hook ALWAYS fires and copies the
    # Tcl/Tk DLLs and script library (tcl86t.dll, tk86t.dll, tcl/ and tk/ folders) into the build. If
    # that hook is skipped - which happens with some Python installs - the .exe only works on machines
    # that happen to have Python installed (it borrows THEIR Tcl/Tk), which is exactly the
    # "it still needs Python on some PCs" problem. build_windows.bat verifies the result afterwards.
    hiddenimports=['bleak', 'PIL.Image', 'tkinter', 'tkinter.ttk', 'tkinter.font', 'tkinter.filedialog',
                   'tkinter.messagebox', 'tkinter.simpledialog', '_tkinter'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

if ONEDIR:
    _exe_parts = (pyz, a.scripts, [])
else:
    _exe_parts = (pyz, a.scripts, a.binaries, a.datas, [])

exe = EXE(
    *_exe_parts,
    exclude_binaries=ONEDIR,
    name='NetScout',
    icon=ICON,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # upx=False on purpose, and worth leaving alone. UPX squeezes the executable smaller, but it does it
    # by rewriting the DLLs bundled inside - and it is well known to corrupt exactly the ones a Tkinter
    # app cannot start without (tcl86t.dll / tk86t.dll, python3x.dll, vcruntime140.dll). The failure it
    # produces is the nastiest kind: the build succeeds, and the finished .exe then dies instantly on
    # launch with no window and no error, because the damage is inside a DLL that never loads. A few MB
    # of file size is not worth an app that silently refuses to open.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    # No black console/terminal window behind the GUI (Windows/macOS; no effect on Linux, which draws no
    # such distinction). This was temporarily True while chasing a build that launched with no window and
    # no error - with console=False such a failure can be completely silent, since PyInstaller's
    # windowed-mode traceback dialog isn't guaranteed to appear for every kind of startup crash, whereas
    # a console window always shows whatever Python/Tcl/Tk printed. That turned out to be upx (see below)
    # and the app starts cleanly now, so it's back off. If a future build ever dies silently on launch,
    # flip this to True, run it once, and the reason will be sitting in the console window.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if ONEDIR:
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, upx_exclude=[],
                   name='NetScout-Folder')

# macOS only: wrap the executable in a real .app bundle, so it behaves like an application (own icon in
# Finder and the Dock, double-click to run) instead of a bare unix binary that opens a Terminal window.
# BUNDLE is a no-op concept on Windows/Linux, hence the platform guard.
if sys.platform == 'darwin' and not ONEDIR:
    app = BUNDLE(
        exe,
        name='NetScout.app',
        icon=ICON,
        bundle_identifier='com.netscout.netscout',
        info_plist={
            'NSHighResolutionCapable': True,
            # macOS kills an app on the spot if it touches Bluetooth or scans the local network without
            # a stated reason in Info.plist. Both are core to what this tool does, so both are declared.
            'NSBluetoothAlwaysUsageDescription':
                'NetScout lists nearby Bluetooth devices. It only listens - it never connects to or '
                'changes anything on them.',
            'NSLocalNetworkUsageDescription':
                'NetScout scans your own local network to list the devices on it.',
        },
    )
