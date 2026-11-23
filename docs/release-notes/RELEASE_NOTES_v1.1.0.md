# NetScout v1.1.0

Second release — a noticeably smarter **and faster** engine, a live device search, per-device
priority scoring, a real security report, branded installers for Windows / macOS / Linux, and a
move to a proper open-source license (**GNU AGPL v3**).

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
- **Faster scans on every network** — a quick first ping pass, with the full wait kept only for the
  addresses that stay silent, plus a single **parallel probe sweep** across every remaining address
  and port at once (in place of the old one-address-at-a-time check), the per-port timeout tuned to
  the network's measured speed. Ping-silent, firewalled devices now turn up in a fraction of the
  time — **faster *and* more thorough**, together.
- **Live device search** — a search box above the list filters the table as you type (name, brand,
  type, IP address, even a risk word like "high"), with a live match count; **Ctrl + F** jumps to
  it. Built for big office networks with dozens of devices.
- **Priority ranking** — every device gets a 0–100 **PRIORITY** threat score (its risk, any
  known-vulnerable software, default-password hints, and whether it's brand-new on the network), and
  the table is sorted **worst-first**, so the device that needs attention is already at the top.
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

## License — now open source (GNU AGPL v3)
NetScout is **free and open source** under the **GNU Affero General Public License v3** (see
`LICENSE`). Use it, study it, share it, modify it — the one condition is that if you distribute it,
**or run a modified version as a network service**, you keep it open: publish your source under the
same AGPL-3.0 licence and leave the author's copyright notice intact. This is the license that keeps
NetScout open for everyone and stops anyone closing it up and reselling it as their own product.

## Downloads
| Platform | File |
|---|---|
| Windows | `NetScout-Setup.exe` (build it with `build_windows.bat` + Inno Setup) |
| macOS | `NetScout.dmg` (build it with `build_macos.sh`) |
| Linux | `netscout_1.1.0_all.deb` (ready to install) |
