#!/usr/bin/env bash
# Builds a ready-to-install Linux package straight from the Python source - NO PyInstaller needed.
#
# NetScout is pure Python + Tkinter, so on Linux the cleanest "installer" is a .deb that installs the
# source and lets the system's own Python run it. apt pulls in python3 + python3-tk automatically, so your
# user still just double-clicks the .deb (or `sudo apt install ./netscout_*.deb`) and it works - menu
# entry, icon, a `netscout` command - and `sudo apt remove netscout` uninstalls it cleanly.
#
# Architecture is "all" (pure Python): one .deb works on every CPU - amd64, arm64, a Raspberry Pi, anything.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
VERSION="${NETSCOUT_VERSION:-1.5.0}"

for f in netscout.py netscout_gui.py; do
    [ -f "$f" ] || { echo "ERROR: $f not found next to this script."; exit 1; }
done

echo "Packaging NetScout $VERSION (source / Architecture: all) into a .deb ..."
PKG="$(mktemp -d)"
trap 'rm -rf "$PKG"' EXIT

install -d "$PKG/opt/netscout" "$PKG/usr/bin" "$PKG/usr/share/applications" \
           "$PKG/usr/share/doc/netscout" "$PKG/DEBIAN"

# the program itself (engine + GUI must sit together so `import netscout` resolves)
install -m 0644 netscout.py netscout_gui.py "$PKG/opt/netscout/"

# a launcher on PATH
cat > "$PKG/usr/bin/netscout" <<'EOF'
#!/bin/sh
# NetScout launcher - runs the GUI with the system Python.
exec python3 /opt/netscout/netscout_gui.py "$@"
EOF
chmod 0755 "$PKG/usr/bin/netscout"

[ -f LICENSE ] && install -m 0644 LICENSE "$PKG/usr/share/doc/netscout/copyright"

for s in 256 128 64 48 32; do
    ic="installer/netscout_${s}.png"; [ -f "$ic" ] || ic="netscout.png"
    if [ -f "$ic" ]; then
        install -d "$PKG/usr/share/icons/hicolor/${s}x${s}/apps"
        install -m 0644 "$ic" "$PKG/usr/share/icons/hicolor/${s}x${s}/apps/netscout.png"
    fi
done

cat > "$PKG/usr/share/applications/netscout.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetScout
GenericName=Network Scanner
Comment=Scan your own network: devices, ports, WiFi, Bluetooth, security audit
Exec=netscout
Icon=netscout
Terminal=false
Categories=Network;System;Monitor;Security;
Keywords=network;scan;wifi;bluetooth;ports;security;audit;
EOF
chmod 0644 "$PKG/usr/share/applications/netscout.desktop"

INSTALLED_KB="$(du -sk "$PKG/opt" "$PKG/usr" 2>/dev/null | awk '{s+=$1} END{print s+0}')"
cat > "$PKG/DEBIAN/control" <<EOF
Package: netscout
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Maintainer: TheCodingExperiment <noreply@localhost>
Installed-Size: $INSTALLED_KB
Depends: python3 (>= 3.8), python3-tk
Recommends: python3-pil
Suggests: python3-bleak
Description: NetScout - cross-platform network scanner & defensive security toolkit
 Find every device on your network, scan ports, analyse WiFi and Bluetooth, and
 run a one-click A-F security audit with plain-English fixes. Runs on the system
 Python (python3 + python3-tk, installed automatically).
 .
 NetScout by TheCodingExperiment. Free software under the GNU AGPL v3 - keep it open.
EOF

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

chmod 0755 "$PKG"
OUT="netscout_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$PKG" "$OUT" >/dev/null
echo
echo "============================================================"
echo " Built: $OUT   (works on every Debian/Ubuntu/Mint/Raspberry Pi)"
echo
echo "   Install:  sudo apt install ./$OUT"
echo "   Remove :  sudo apt remove netscout"
echo " Then 'NetScout' is in the applications menu and 'netscout' runs it."
echo "============================================================"
