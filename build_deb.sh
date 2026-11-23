#!/usr/bin/env bash
# Builds a proper Debian/Ubuntu installer package: netscout_<version>_<arch>.deb
#
# A .deb is the Linux equivalent of a nice installer: your users double-click it (it opens in their
# Software Center / "Install" button), it drops NetScout into /opt, puts it in the applications menu with
# your reaper icon, and adds a `netscout` command - and it uninstalls cleanly with `sudo apt remove netscout`.
#
# Run build_linux.sh FIRST (it produces the actual program in dist/). Then run this.
# Needs only `dpkg-deb`, which is already on every Debian/Ubuntu/Mint machine.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

VERSION="${NETSCOUT_VERSION:-1.5.0}"

# --- find the program that build_linux.sh produced -------------------------------------------------
# PyInstaller makes either a single file (dist/NetScout) or, in onedir mode, a folder
# (dist/NetScout-Folder/NetScout + its libraries). We package whichever exists.
if [ -d "dist/NetScout-Folder" ] && [ -x "dist/NetScout-Folder/NetScout" ]; then
    SRC_KIND="folder"; SRC="dist/NetScout-Folder"
elif [ -x "dist/NetScout" ]; then
    SRC_KIND="single"; SRC="dist/NetScout"
else
    echo "ERROR: no built program found in dist/."
    echo "Run ./build_linux.sh first - it produces dist/NetScout (or dist/NetScout-Folder)."
    exit 1
fi

# --- Debian architecture name for THIS machine -----------------------------------------------------
if command -v dpkg >/dev/null 2>&1; then
    ARCH="$(dpkg --print-architecture)"
else
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        armv7l|armhf) ARCH=armhf ;;
        *) ARCH="$(uname -m)" ;;
    esac
fi

echo "Packaging NetScout $VERSION ($ARCH, $SRC_KIND build) into a .deb ..."

PKG="$(mktemp -d)"
trap 'rm -rf "$PKG"' EXIT

# --- lay out the files exactly where they belong on the target system ------------------------------
install -d "$PKG/opt/netscout" "$PKG/usr/bin" "$PKG/usr/share/applications" \
           "$PKG/usr/share/doc/netscout" "$PKG/DEBIAN"

if [ "$SRC_KIND" = "folder" ]; then
    cp -R "$SRC"/. "$PKG/opt/netscout/"
else
    cp "$SRC" "$PKG/opt/netscout/NetScout"
fi
chmod 0755 "$PKG/opt/netscout/NetScout"

# a `netscout` command on PATH
ln -sf /opt/netscout/NetScout "$PKG/usr/bin/netscout"

# the license travels with the install
[ -f LICENSE ] && cp LICENSE "$PKG/usr/share/doc/netscout/copyright"

# icons, every size we have, where the desktop looks for them
for s in 256 128 64 48 32; do
    ic="installer/netscout_${s}.png"
    [ -f "$ic" ] || ic="netscout.png"
    if [ -f "$ic" ]; then
        install -d "$PKG/usr/share/icons/hicolor/${s}x${s}/apps"
        cp "$ic" "$PKG/usr/share/icons/hicolor/${s}x${s}/apps/netscout.png"
    fi
done

# the menu entry
cat > "$PKG/usr/share/applications/netscout.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetScout
GenericName=Network Scanner
Comment=Scan your own network: devices, ports, WiFi, Bluetooth, security audit
Exec=/opt/netscout/NetScout
Icon=netscout
Terminal=false
Categories=Network;System;Monitor;Security;
Keywords=network;scan;wifi;bluetooth;ports;security;audit;
EOF

# --- package metadata ------------------------------------------------------------------------------
INSTALLED_KB="$(du -sk "$PKG/opt" "$PKG/usr" 2>/dev/null | awk '{s+=$1} END{print s+0}')"
cat > "$PKG/DEBIAN/control" <<EOF
Package: netscout
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: TheCodingExperiment <noreply@localhost>
Installed-Size: $INSTALLED_KB
Depends: libc6
Description: NetScout - cross-platform network scanner & defensive security toolkit
 Find every device on your network, scan ports, analyse WiFi and Bluetooth, and
 run a one-click A-F security audit with plain-English fixes. Self-contained: it
 does not need Python installed on this machine.
 .
 NetScout by TheCodingExperiment. Free software under the GNU AGPL v3 - keep it open.
EOF

# refresh the menu + icon caches after install / removal (best-effort - never fail the package on it)
cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -f /usr/share/icons/hicolor || true
exit 0
EOF
cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/postrm"

# --- build it ---------------------------------------------------------------------------------------
chmod 0755 "$PKG"            # mktemp makes the staging root 0700; the packaged tree must be world-readable
OUT="netscout_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG" "$OUT" >/dev/null
echo
echo "============================================================"
echo " Built: $OUT"
echo
echo " Your users install it by double-clicking it, or with:"
echo "     sudo apt install ./$OUT          (Debian/Ubuntu/Mint)"
echo " and remove it with:"
echo "     sudo apt remove netscout"
echo " After installing, 'NetScout' is in the applications menu, and"
echo " the 'netscout' command works in a terminal."
echo "============================================================"
