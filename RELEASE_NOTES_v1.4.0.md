# NetScout v1.4.0 — Power Management

This release is about **saving power across a fleet** — the real-world problem of machines left on overnight
— done the right way: everything is **credentialed, reversible, and shows you the exact command before it
runs**. It also brings a big round of **engine polish** (faster, smarter, more robust) and a reaper that now
**reacts to the tool you're using**.

## New — Power Policy
POWER CONTROL already shuts a machine down *now*. **POWER POLICY** pushes a **lasting** policy to a machine
you administer, so it saves power on its own, every day, without NetScout having to be there. It travels the
**same credentialed channel** as a shutdown — **WinRM** into a Windows PC, **SSH** into Linux/Mac, or applied
to the machine NetScout runs on — so the target still authenticates every change. Pick a device, and:

- **Sleep when idle** — the display and the PC sleep after N minutes (on battery *and* plugged in).
- **Shut down after hours** — a daily scheduled shutdown at a time you set (as SYSTEM, so it works with
  nobody logged in), with the standard save-your-work warning; cancellable.
- **Allow IT management (the root-cause fix)** — the honest fix for laptops on the Windows **Public** firewall
  profile, which blocks WinRM/RDP/SMB so IT can't reach them. Instead of weakening the firewall, NetScout adds
  **one scoped inbound allow for your IT-management subnet only**. Nothing else on any network gains anything.

Every action **shows you the exact command first** (a dry-run preview in the confirm dialog), and every "set"
has a matching "clear" — nothing here is a one-way door.

## New — Power Saver + the deployment pack
**POWER SAVER** scans, then estimates the **energy and money wasted** by machines left on after hours — worst
offenders first, using your own idle-watt and price-per-kWh assumptions, clearly labelled as an estimate.

And **Save Deployment Pack** writes the ready-to-roll-out fleet scripts so you can set the policy **everywhere
at once** instead of device by device:

- `NetScout-PowerPolicy.ps1` — one idempotent, **reversible** (`-Undo`) Windows script: sleep + nightly
  shutdown + the scoped IT-management allow.
- `netscout-nightly-off.sh` — the Linux equivalent (`--undo`).
- `GPO-rollout.md` — deploy it to the whole fleet with **Group Policy** (the power plan, a scheduled task,
  and a startup script).
- `ROOT-CAUSE-public-profile.md` — a plain-English explanation of **why** idle laptops don't answer IT, and
  the two fixes (recommended scoped allow, or setting the network profile).

## New — the reaper reacts to what you're doing
The mascot now has a **motion personality per tool**, all drawn from its *own* parts — the scythe, the free
hand, the eye-embers, the float — never anything bolted on:

- **Hunting** (Threat Monitor, Packet Inspector, Vuln Scan, Audit, WiFi Audit) — fast hot eyes, quick darting
  glances, a brisk full-reach sway.
- **Sweeping** (Device/Network/Port/Server scans, Topology, Survey…) — a steady, methodical sweep.
- **Strike** (Power Control, **Power Policy**, **Power Saver**, Firewall…) — the scythe raised and tense, the
  hottest, steadiest eyes: the reaper about to act.
- **Signalling** (DNS, Website Health, Subnet, WiFi Password, Bluetooth) — lighter, inquisitive glances.
- **Watching** (Live Monitor, Background Watch, Ping, Info…) — calm, vigilant.

## Engine polish — faster, smarter, tougher
- **Reverse-DNS is now cached for the session.** Live Monitor and Background Watch rescan constantly, and
  every cycle used to re-query the resolver for *every* device — including the many LAN devices that have no
  PTR record, each costing a full NXDOMAIN round-trip. Repeat lookups are now instant (0 resolver calls).
- **`which` lookups are memoised** — tools that probe for the same binaries (nmcli, iwctl, iptables…) no
  longer hit the filesystem again and again.
- **Sharper scan timing.** The adaptive connect-timeout now keys off a **high percentile (p90)** of the
  measured round-trips instead of the median, so a host slower than the rest no longer has its open ports
  quietly missed — while a uniformly fast LAN is still just as quick. It never waits longer than the old
  fixed cap.
- **Hardened against junk.** Every parser was fuzzed with empty, truncated, garbage, over-long and non-ASCII
  input; the wire/packet decoders (Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS, the SNMP forwarding table) and
  every command-output parser degrade to "nothing found" rather than ever crashing.

## Under the hood
- New engine: `power_policy_script` / `power_policy_transport` / `apply_power_policy` (build the exact command,
  then run it over WinRM/SSH/local — with a `dry_run` that changes nothing), `deployment_pack`,
  `power_saver_report`. All credential-gated, all reversible, all offline-tested.
- **34 tools** now (POWER POLICY + POWER SAVER added); the window's tool count is computed live, never
  hard-coded.
- **Bug sweep:** the full suite (now **62 test files**) and the undefined-reference check are green, and a
  sweep for the usual defect patterns (bare excepts, mutable default arguments, identity-vs-equality mix-ups,
  `shell=True`, unbounded subprocess timeouts) came back clean.
- **Still defensive-only.** There is no uncredentialed or forced power-off, and nothing here works against a
  machine you don't administer — the target authenticates every command, and every change is reversible.

## Still open source
NetScout remains free and open source under the **GNU AGPL v3** — see `LICENSE`.

## Downloads
| Platform | File |
|---|---|
| Windows | `Windows - NetScout Build v1.4.0.zip` (build with `build_windows.bat` + Inno Setup) |
| macOS | `macOS - NetScout Build v1.4.0.zip` (build with `build_macos.sh`) |
| Linux | `Linux - NetScout Build v1.4.0.zip` — includes the ready-to-install `netscout_1.4.0_all.deb` |
