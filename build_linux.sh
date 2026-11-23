#!/usr/bin/env bash
# Builds NetScout from the Python source. Run this ONCE on a Linux machine that HAS Python installed.
# The result (dist/NetScout) will NOT need Python on any machine you copy it to afterwards.
set -e

echo "============================================================"
echo " NetScout - Linux Build"
echo "============================================================"
echo
echo "This step needs Python only on THIS machine, right now, to build the app."
echo "The finished NetScout will NOT need Python on the machines it is copied to."
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 was not found on this machine."
    echo
    echo "Install it with your distribution's package manager, for example:"
    echo "    sudo apt install python3 python3-pip      (Debian/Ubuntu)"
    echo "    sudo dnf install python3 python3-pip      (Fedora)"
    echo "    sudo pacman -S python python-pip          (Arch)"
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
chmod +x dist/NetScout 2>/dev/null || true

# A Linux binary carries no embedded icon the way a Windows .exe does - what gives an app its name, icon
# and menu entry here is a .desktop file. Writing one (plus installing the icon where the desktop
# environment looks for it) is what turns dist/NetScout from "a file you run" into something that shows
# up in the applications menu and can be pinned, which is the whole point of this step.
HERE="$(cd "$(dirname "$0")" && pwd)"
ICON_SRC="$HERE/netscout.png"
if [ -f "$ICON_SRC" ]; then
    ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
    mkdir -p "$ICON_DIR" && cp -f "$ICON_SRC" "$ICON_DIR/netscout.png" || true
    ICON_PATH="$ICON_DIR/netscout.png"
else
    ICON_PATH=""   # no icon shipped alongside: the entry still works, it just gets a generic icon
fi

APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR" || true
DESKTOP_FILE="$APPS_DIR/netscout.desktop"
if cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Type=Application
Name=NetScout
GenericName=Network Scanner
Comment=Scan your own network: devices, ports, WiFi, Bluetooth
Exec=$HERE/dist/NetScout
Icon=$ICON_PATH
Path=$HERE/dist
Terminal=false
Categories=Network;System;Monitor;
EOF
then
    chmod +x "$DESKTOP_FILE" 2>/dev/null || true
    # harmless if absent (not every distro ships it); only refreshes the menu cache sooner
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" 2>/dev/null || true
    # a copy on the Desktop itself, for people who expect an icon there rather than only in the menu
    if [ -d "$HOME/Desktop" ]; then
        cp -f "$DESKTOP_FILE" "$HOME/Desktop/netscout.desktop" 2>/dev/null || true
        chmod +x "$HOME/Desktop/netscout.desktop" 2>/dev/null || true
    fi
    echo
    echo "Menu entry created: $DESKTOP_FILE"
    echo "NetScout should now appear in your applications menu."
    echo "On GNOME, a Desktop icon may need a one-time right-click -> \"Allow Launching\"."
else
    echo
    echo "WARNING: Could not write the .desktop entry - dist/NetScout still runs directly."
fi

echo
echo "============================================================"
echo " DONE: dist/NetScout"
echo " Copy this one file to other Linux machines - none of them will"
echo " need Python installed. Most reliable on machines with a distro"
echo " release as new as this one, or OLDER (newer is almost always"
echo " compatible, much older sometimes isn't)."
echo "============================================================"
