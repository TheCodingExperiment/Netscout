# NetScout v1.1.0

Second release — a noticeably smarter engine, a real security report, branded installers for
Windows / macOS / Linux, and a new license.

## New
- **Much better device recognition** — tells a laptop from a desktop and names the actual model
  (ASUS TUF, Dell XPS, Lenovo ThinkPad, HP EliteBook, MacBook, Surface, Galaxy Book…) across all
  the major brands, even from a bare model code like `FX506`. It reports the **computer's** maker,
  not its Wi-Fi card's.
- **Computers nearby (Bluetooth)** — finds laptops and desktop PCs physically around you from the
  Windows "Connected Devices" beacon, whether or not they're on your network.
- **Smarter Security Audit** — now also warns about devices that may still have their **factory
  password** (cameras, routers, NAS, server BMCs — advice only, it never tries a login) and spots
  **network conflicts**: one MAC answering on several IPs (a sign of ARP spoofing) and more than one
  gateway. Plus ~20 more risky services flagged, each with a plain-English fix.
- **Active ARP discovery (Linux)** — finds devices that stay silent to ping and every other probe.
- **Faster scans** — the per-port timeout adapts to the network's measured speed.
- **Remote power** — a server's BMC can now power it **on** or hard-**cycle** it over IPMI, not just
  off/restart (credentialed only — no forced power-off of devices you don't control).

## Installers (new)
- **Windows** — one-click `NetScout-Setup.exe`: branded wizard, no admin needed, Start-Menu &
  Desktop shortcuts, clean uninstaller.
- **macOS** — drag-to-Applications `NetScout.dmg`.
- **Linux** — `netscout_1.1.0_all.deb`: `sudo apt install ./netscout_1.1.0_all.deb` (works on every
  CPU, including Raspberry Pi).

## Fixes
- Laptops no longer show their Wi-Fi chip maker as the brand ("Intel TUF" → "ASUS TUF").
- A Samsung Galaxy Book is no longer mislabelled a phone.
- Hardened against malformed/odd device data (no more crash on unusual Bluetooth names).

## License change
NetScout is **no longer MIT**. It is now proprietary: **free to download and use**, but you may
**not** sell it, republish it as your own, claim authorship, or remove the author's name. See `LICENSE`.

## Downloads
| Platform | File |
|---|---|
| Windows | `NetScout-Setup.exe` (build it with `build_windows.bat` + Inno Setup) |
| macOS | `NetScout.dmg` (build it with `build_macos.sh`) |
| Linux | `netscout_1.1.0_all.deb` (ready to install) |
