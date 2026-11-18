# NetScout v1.2.0 — the 24/7 Guardian

The headline of this release turns NetScout from a tool you *run* into one you *leave running*.
**BACKGROUND WATCH is now the 24/7 Guardian**: it watches your network over time, tells you in plain
language what changed, learns what "normal" looks like, and reaches you even when the app is closed.

## New — the 24/7 Guardian
- **A "what changed" feed.** Every pass is compared to the one before it and turned into a readable,
  severity-tagged feed instead of a bare device list:
  - **new device joined** / **device left**
  - **a new open port** (risky ports — RDP, Telnet, SMB… — are flagged louder)
  - **risk rose** on a device (e.g. `LOW → HIGH`)
  - **vendor changed on the same hardware address** (a classic spoofing tell)
  Each line is colour-coded **ALERT / WARN / INFO**.
- **Alerts that leave the app.** At a severity you choose, changes are pushed to:
  - **desktop** notifications,
  - a **Slack / Teams / Discord webhook** (just paste the incoming-webhook URL into the new **ALERT
    WEBHOOK** box), and
  - **e-mail** (SMTP; details live in `~/.netscout_guardian.json`).
  So you find out the moment something changes, even with NetScout closed.
- **A golden baseline.** Approve the current network as known-good (**Export ▾ ▸ _Approve current
  devices as Guardian baseline_**) and Guardian flags anything that **drifts** from it — a device that
  shouldn't be there, or an approved device that opened a new port.
- **A live trend** of device and risk counts over time, drawn as an inline sparkline each pass.
- **No crying wolf.** Devices you've marked approved are filtered out of the alerts, so a network where
  phones come and go doesn't bury the one change that matters.

It's all **pure Python standard library** (`sqlite`-free: it builds on the scan history NetScout already
keeps; `smtplib` + `urllib` for e-mail and webhooks), so it adds no dependency and runs anywhere NetScout
already does.

## Under the hood
- Scan snapshots now record each device's **risk level**, so "risk rose/fell" can be detected across scans
  (older snapshots are handled gracefully — no false "risk changed" on the first comparison).
- New, fully-tested engine functions: `guardian_changes`, `guardian_timeline`, `guardian_trends`,
  `guardian_baseline_save/load/clear/drift`, `notify_email`, `notify_webhook`, `guardian_dispatch`,
  `guardian_record`.
- **57 test files** now (two new suites cover the Guardian engine and its GUI wiring); the undefined-method
  check is clean.

## Still open source
NetScout remains free and open source under the **GNU AGPL v3** — see `LICENSE`.

## Downloads
| Platform | File |
|---|---|
| Windows | `NetScout-Setup.exe` (build with `build_windows.bat` + Inno Setup) |
| macOS | `NetScout.dmg` (build with `build_macos.sh`) |
| Linux | `netscout_1.2.0_all.deb` (ready to install) |
