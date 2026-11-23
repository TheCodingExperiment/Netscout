#!/usr/bin/env bash
# Builds NetScout from the Python source. Run this ONCE on a Mac that HAS Python installed.
# The result (dist/NetScout) will NOT need Python on any Mac you copy it to afterwards.
set -e

echo "============================================================"
echo " NetScout - macOS Build"
echo "============================================================"
echo
echo "This step needs Python only on THIS Mac, right now, to build the app."
echo "The finished NetScout will NOT need Python on the Macs it is copied to."
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 was not found on this Mac."
    echo
    echo "Install it either with Homebrew:"
    echo "    brew install python3"
    echo "or with the official installer from:"
    echo "    https://www.python.org/downloads/"
    echo
    echo "Then run this script again."
    exit 1
fi

echo "Using Python:"
python3 --version
echo

# A Python without working Tcl/Tk (the window library) would produce a program with no window at all.
if ! python3 -c "import tkinter; tkinter.Tcl().eval('info patchlevel')" >/dev/null 2>&1; then
    echo "ERROR: this Python has no working Tcl/Tk (tkinter), which draws NetScout's window."
    echo "    sudo apt install python3-tk     (Debian/Ubuntu)"
    echo "    sudo dnf install python3-tkinter (Fedora)"
    echo "    sudo pacman -S tk                (Arch)"
    echo "    macOS: install Python from https://www.python.org/downloads/macos/ (includes Tcl/Tk)"
    echo "Then run this script again."
    exit 1
fi

echo "Installing/upgrading PyInstaller (required, one-time, needs internet)..."
python3 -m pip install --upgrade --only-binary=:all: pyinstaller --break-system-packages 2>/dev/null \
    || python3 -m pip install --upgrade --only-binary=:all: pyinstaller

echo
echo "Installing bleak (optional - adds Bluetooth scanning to the built app)..."
# --only-binary=:all: refuses to fall back to compiling a dependency from source when no ready-made
# package matches this exact Python build/platform - quicker and clearer than a compiler failing deep
# inside a source build (this is what actually broke a build once already, on Windows, for a Python
# version odd enough that no prebuilt package existed for it yet). This step is run SEPARATELY from
# PyInstaller above and is allowed to fail: Bluetooth is optional, and the built app already handles
# running without bleak bundled - see ensure_bleak() in netscout.py.
if ! { python3 -m pip install --upgrade --only-binary=:all: bleak --break-system-packages 2>/dev/null \
    || python3 -m pip install --upgrade --only-binary=:all: bleak; }; then
    echo "WARNING: Could not install bleak - continuing WITHOUT Bluetooth support in this build."
    echo "This usually means no ready-made bleak package exists yet for this exact Python build."
fi
echo "Installing Pillow (optional - shows the live picture in IP CAMERA)..."
if ! { python3 -m pip install --upgrade --only-binary=:all: Pillow --break-system-packages 2>/dev/null \
    || python3 -m pip install --upgrade --only-binary=:all: Pillow; }; then
    echo "WARNING: Could not install Pillow - IP CAMERA will steer cameras but show no picture in this build."
fi

echo
echo "Building NetScout ..."
rm -rf build dist
python3 -m PyInstaller --noconfirm --clean netscout.spec
chmod +x dist/NetScout 2>/dev/null || true

# Prove the result runs WITHOUT Python: start it with an empty environment (no PATH to Python, no
# PYTHONHOME/TCL_LIBRARY), so it can't borrow anything from this machine's Python install.
echo
echo "Checking that the built program runs WITHOUT Python ..."
if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && [ "$(uname)" != "Darwin" ]; then
    echo "  (skipped - no screen available in this session; run it once by hand to check)"
elif env -i HOME="$HOME" DISPLAY="${DISPLAY:-}" WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" XAUTHORITY="${XAUTHORITY:-}" PATH=/usr/bin:/bin "dist/NetScout" --selftest; then
    echo "  OK - it starts on its own."
else
    echo "  ERROR: the built program did NOT start without Python - don't hand this copy out."
    echo "  Set console=True in netscout.spec, rebuild, and run it from a terminal to see why."
    exit 1
fi
rm -rf build   # half-built intermediate files - never hand those out

# netscout.spec wraps the binary in a real .app bundle on macOS (BUNDLE(...)), which is what gives it an
# icon in Finder and the Dock and makes it double-clickable like any other application. Dropping it into
# /Applications is what actually makes it "installed" rather than a folder you have to go find.
HERE="$(cd "$(dirname "$0")" && pwd)"

# ---- Build a branded .dmg: the drag-to-Applications installer you hand out ----------------------
# A .dmg is what a Mac user expects to download: double-click, a window opens showing the app and an
# Applications folder with an arrow between them, you drag one onto the other. We build that window with
# your reaper background. Every step is best-effort - if Finder styling isn't available (e.g. a headless
# build box), we still always produce a working, if plainer, .dmg.
if [ -d "dist/NetScout.app" ]; then
    echo
    echo "Building the disk image (NetScout.dmg) ..."
    STAGE="$(mktemp -d)"
    cp -R "dist/NetScout.app" "$STAGE/"
    ln -s /Applications "$STAGE/Applications"
    if [ -f "$HERE/installer/dmg_background.png" ]; then
        mkdir -p "$STAGE/.background"
        cp "$HERE/installer/dmg_background.png" "$STAGE/.background/bg.png"
    fi
    rm -f "dist/NetScout.dmg"
    RW="$(mktemp -u).dmg"
    if hdiutil create -srcfolder "$STAGE" -volname "NetScout" -fs HFS+ -format UDRW -ov "$RW" >/dev/null 2>&1; then
        MNT="$(hdiutil attach -readwrite -noverify -noautoopen "$RW" 2>/dev/null | grep -o '/Volumes/.*' | head -1)"
        if [ -n "$MNT" ]; then
            # Position the icons and set the background; harmless if Finder scripting is unavailable.
            osascript >/dev/null 2>&1 <<OSA || true
tell application "Finder"
  tell disk "NetScout"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set bounds of container window to {200, 120, 860, 520}
    set theView to the icon view options of container window
    set arrangement of theView to not arranged
    set icon size of theView to 96
    try
      set background picture of theView to file ".background:bg.png"
    end try
    set position of item "NetScout.app" of container window to {168, 250}
    set position of item "Applications" of container window to {492, 250}
    update without registering applications
    delay 1
    close
  end tell
end tell
OSA
            sync
            hdiutil detach "$MNT" >/dev/null 2>&1 || true
        fi
        # Compress to the final, read-only image people download.
        hdiutil convert "$RW" -format UDZO -imagekey zlib-level=9 -o "dist/NetScout.dmg" >/dev/null 2>&1 || true
        rm -f "$RW"
    fi
    # Guaranteed fallback: if anything above failed, make a plain (unstyled) but fully working dmg.
    if [ ! -f "dist/NetScout.dmg" ]; then
        hdiutil create -srcfolder "$STAGE" -volname "NetScout" -format UDZO -ov "dist/NetScout.dmg" >/dev/null 2>&1 || true
    fi
    rm -rf "$STAGE"
    if [ -f "dist/NetScout.dmg" ]; then
        echo "  Built: dist/NetScout.dmg  <- hand THIS out (drag-to-Applications installer with your logo)."
    else
        echo "  NOTE: could not build the .dmg here; dist/NetScout.app still works - drag it to Applications."
    fi

    echo
    printf "Also copy NetScout.app into /Applications on THIS Mac now? [y/N] "
    read -r REPLY </dev/tty 2>/dev/null || REPLY=""
    case "$REPLY" in
        [yY]*)
            if cp -R "dist/NetScout.app" /Applications/ 2>/dev/null; then
                echo "Installed: /Applications/NetScout.app"
            else
                echo "Could not copy automatically (permissions?). Drag dist/NetScout.app into Applications in Finder."
            fi
            ;;
        *) echo "Left in place. Share dist/NetScout.dmg, or drag the app to Applications when you want it." ;;
    esac
fi

echo
echo "============================================================"
echo " DONE: dist/NetScout"
echo " Copy this one file to other Macs with the SAME KIND OF CHIP"
echo " (Apple Silicon/M-series and Intel are not interchangeable -"
echo " when in doubt, build once on each). None of them will need"
echo " Python installed."
echo
echo " Note: the very first time it runs, macOS Gatekeeper will warn"
echo " about an \"unverified developer\"."
echo " -> Right-click NetScout -> Open -> confirm once more"
echo "    (only needed the very first time)."
echo "============================================================"
