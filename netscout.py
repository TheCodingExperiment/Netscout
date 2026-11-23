#!/usr/bin/env python3
"""
NetScout - cross-platform network tool (Windows / Linux / macOS), stdlib only.

Copyright (C) 2026 TheCodingExperiment.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
Affero General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. NetScout is distributed WITHOUT ANY WARRANTY; see the
GNU Affero General Public License (the LICENSE file, or https://www.gnu.org/licenses/agpl-3.0.html).

Usage:
  python netscout.py                      interactive menu
  python netscout.py info                 IP, subnet mask, gateway, DHCP, DNS
  python netscout.py scan                 find all devices on your network
  python netscout.py scan --type camera   camera | laptop | desktop | phone | router | printer | media | other | all
  python netscout.py scan --save scan.txt
  python netscout.py ports --ports 22,80,443  port scan of your own network (--target IP|CIDR)
  python netscout.py nearby --passes 3    WiFi networks + hotspots in range (--hotspots = only hotspots)
  python netscout.py bluetooth --seconds 10   nearby Bluetooth devices ('bleak' installs itself on first use)
  python netscout.py ping 192.168.1.1 -c 4
  python netscout.py wifi                 show saved password of the current WiFi
  python netscout.py wifi --ssid MyWifi --save wifi.txt
  python netscout.py interfaces           every network interface on this machine - MAC, IPv4, IPv6
  Saved txt files are readable by everyone by default; add --private for owner-only.
  Tip: save to a shared folder, e.g. --save "\\\\server\\share\\wifi.txt"

Only use this on networks you own or administer.
"""
import argparse
import concurrent.futures as cf
import csv
import datetime
import getpass
import glob
import html
import http.client
import asyncio
import io
import ipaddress
import json
import math
import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import base64
import hashlib

OS = platform.system()  # "Windows", "Linux", "Darwin"


def _workers(n, lo=16, hi=256):
    """Thread-pool size that scales with the job instead of a fixed guess: enough concurrency for a
    big sweep, no wasted threads for a small one."""
    return max(lo, min(hi, n or lo))
IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
IPV6 = r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"
MACRE = r"[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}"
NOWIN = {"creationflags": 0x08000000} if OS == "Windows" else {}
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_FILE = os.path.join(os.path.expanduser("~"), ".netscout_oui.txt")
NOTES_FILE = os.path.join(os.path.expanduser("~"), ".netscout_notes.json")
HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".netscout_history")
HISTORY_MAX = 30  # oldest snapshots beyond this count are pruned automatically
# 24/7 Guardian: continuous-monitoring config and the approved "golden" baseline.
GUARDIAN_FILE = os.path.join(os.path.expanduser("~"), ".netscout_guardian.json")
BASELINE_FILE = os.path.join(os.path.expanduser("~"), ".netscout_baseline.json")
# Action audit log: an append-only who/when/what-command record of every state-changing action.
AUDIT_FILE = os.path.join(os.path.expanduser("~"), ".netscout_audit.log")
AUDIT_MAX_BYTES = 2_000_000       # rotate (keep the recent half) once the log grows past this
# Saved multi-subnet scan profiles (name -> {networks, ports, type}).
PROFILES_FILE = os.path.join(os.path.expanduser("~"), ".netscout_profiles.json")
_DEV_RISK_RANK = {"": 0, "NONE": 0, "OK": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _dev_risk_rank(level):
    """A device's risk level as a number, so risk can be compared and ordered (NONE<LOW<MEDIUM<HIGH)."""
    return _DEV_RISK_RANK.get((level or "").upper(), 0)


# ----------------------------------------------------------------- helpers
def run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, **NOWIN)
        return p.stdout.decode(errors="ignore")
    except Exception:
        return ""


def mask_from_prefix(n):
    return str(ipaddress.IPv4Network(f"0.0.0.0/{n}").netmask)


def norm_mac(mac):
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", mac)).lower()


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # UDP connect: sends no packet
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None
    finally:
        s.close()


# ------------------------------------------------------- network information
def info_linux(ip):
    d = {}
    out = run(["ip", "route", "show", "default"])
    m = re.search(rf"default via ({IPV4}) dev (\S+)", out)
    if m:
        d["gateway"], d["iface"] = m.groups()
    iface = d.get("iface")
    if iface:
        out = run(["ip", "-o", "-4", "addr", "show", "dev", iface])
        m = re.search(rf"inet ({IPV4})/(\d+)", out)
        if m:
            d["ip"], d["mask"] = m.group(1), mask_from_prefix(int(m.group(2)))
        nm = run(["nmcli", "-t", "dev", "show", iface])
        m = re.search(rf"dhcp_server_identifier\s*=\s*({IPV4})", nm)
        if m:
            d["dhcp"] = m.group(1)
        dns = re.findall(rf"IP4\.DNS\[\d+\]:({IPV4})", nm)
        if dns:
            d["dns"] = ", ".join(dns)
    if "dhcp" not in d:
        files = (glob.glob("/run/systemd/netif/leases/*") + glob.glob("/var/lib/dhcp/*.leases")
                 + glob.glob("/var/lib/NetworkManager/*.lease"))
        for f in files:
            try:
                txt = open(f, errors="ignore").read()
            except OSError:
                continue
            m = (re.search(rf"SERVER_ADDRESS=({IPV4})", txt)
                 or re.search(rf"dhcp-server-identifier ({IPV4})", txt))
            if m:
                d["dhcp"] = m.group(1)
                break
    if "dns" not in d:
        try:
            d["dns"] = ", ".join(re.findall(rf"^nameserver\s+({IPV4})", open("/etc/resolv.conf").read(), re.M))
        except OSError:
            pass
    return d


def info_windows(ip):
    d = {}
    # gateway via routing table (independent of the Windows display language)
    best = None
    for line in run(["route", "print", "-4", "0.0.0.0"]).splitlines():
        m = re.match(rf"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+({IPV4})\s+({IPV4})\s+(\d+)", line)
        if m:
            gw, ifc, metric = m.group(1), m.group(2), int(m.group(3))
            key = (ifc != ip, metric)
            if best is None or key < best[0]:
                best = (key, gw)
    if best:
        d["gateway"] = best[1]
    out = run(["ipconfig", "/all"])
    for block in re.split(r"\r?\n(?=\S)", out):
        if not ip or not re.search(rf"(?<!\d){re.escape(ip)}(?!\d)", block):
            continue
        lines = block.splitlines()
        seen_ip = False
        for i, line in enumerate(lines):
            vals = re.findall(IPV4, line)
            if not vals:
                continue
            if vals[0] == ip:
                seen_ip = True
            elif seen_ip and "mask" not in d and vals[0].startswith("255."):
                d["mask"] = vals[0]
            if "dhcp" in line.lower() and "dhcp" not in d:
                d["dhcp"] = vals[0]
            if "dns" in line.lower() and "dns" not in d:
                dns = [vals[0]]
                for nxt in lines[i + 1:]:
                    s = nxt.strip()
                    if re.fullmatch(IPV4, s):
                        dns.append(s)
                        continue
                    if re.fullmatch(rf"{IPV6}(?:%\S+)?", s):
                        continue        # an IPv6 DNS server interleaved in the list - skip, keep looking for IPv4
                    break
                d["dns"] = ", ".join(dns)
        break
    return d


def info_mac(ip):
    d = {}
    out = run(["route", "-n", "get", "default"])
    m = re.search(rf"gateway:\s*({IPV4})", out)
    if m:
        d["gateway"] = m.group(1)
    m = re.search(r"interface:\s*(\S+)", out)
    if m:
        d["iface"] = m.group(1)
    iface = d.get("iface")
    if iface:
        out = run(["ifconfig", iface])
        m = re.search(rf"inet ({IPV4}) netmask (0x[0-9a-fA-F]+)", out)
        if m:
            d["ip"] = m.group(1)
            d["mask"] = socket.inet_ntoa(int(m.group(2), 16).to_bytes(4, "big"))
        out = run(["ipconfig", "getpacket", iface])
        m = re.search(rf"server_identifier \(ip\):\s*({IPV4})", out)
        if m:
            d["dhcp"] = m.group(1)
    dns = []
    for x in re.findall(rf"nameserver\[\d+\]\s*:\s*({IPV4})", run(["scutil", "--dns"])):
        if x not in dns:
            dns.append(x)
    if dns:
        d["dns"] = ", ".join(dns)
    return d


def ipv6_addrs(iface=None):
    """This machine's own IPv6 addresses: (global_or_unique_local_list, link_local_list)."""
    glob_, link = [], []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            addr = sockaddr[0].split("%")[0]
            try:
                a = ipaddress.ip_address(addr)
            except ValueError:
                continue
            (link if a.is_link_local else glob_).append(str(a))
    except socket.gaierror:
        pass
    if OS == "Linux":
        out = run(["ip", "-6", "-o", "addr", "show"] + (["dev", iface] if iface else []))
        for m in re.finditer(rf"inet6 ({IPV6})/\d+.*?scope (\S+)", out):
            addr, scope = m.groups()
            (glob_ if scope == "global" else link if scope == "link" else glob_).append(addr)
    elif OS == "Darwin":
        out = run(["ifconfig"] + ([iface] if iface else []))
        for m in re.finditer(rf"inet6 ({IPV6})(?:%\S+)?\s+prefixlen", out):
            a = m.group(1)
            (link if a.lower().startswith("fe80") else glob_).append(a)
    elif OS == "Windows":
        out = run(["ipconfig", "/all"])
        for m in re.finditer(rf"IPv6[^:\n]*:\s*({IPV6})", out):
            a = m.group(1)
            (link if a.lower().startswith("fe80") else glob_).append(a)
    seen = set()
    uniq = lambda xs: [x for x in xs if not (x in seen or seen.add(x))]
    return uniq(glob_), uniq(link)


# ------------------------------------------------------------ all network interfaces on this machine
def _ifaces_linux():
    ifaces = {}
    for line in run(["ip", "-o", "link", "show"]).splitlines():
        m = re.match(r"^\d+:\s+([^:@]+)(?:@\S+)?:\s+<([^>]*)>.*?link/\S+\s+([0-9a-fA-F:]{17})", line)
        if m:
            name, flags, mac = m.groups()
            ifaces[name] = {"name": name, "mac": norm_mac(mac), "up": "UP" in flags.split(","),
                            "ipv4": [], "ipv6": []}
    for line in run(["ip", "-o", "addr", "show"]).splitlines():
        m = re.match(r"^\d+:\s+([^\s@]+)(?:@\S+)?\s+(inet6?)\s+(\S+)/\d+", line)
        if m:
            name, fam, addr = m.groups()
            d = ifaces.setdefault(name, {"name": name, "mac": "", "up": True, "ipv4": [], "ipv6": []})
            d["ipv4" if fam == "inet" else "ipv6"].append(addr)
    return list(ifaces.values())


def _ifaces_mac():
    ifaces, cur = {}, None
    for line in run(["ifconfig", "-a"]).splitlines():
        m = re.match(r"^(\S+):\s+flags=\d+<([^>]*)>", line)
        if m:
            name, flags = m.groups()
            cur = ifaces.setdefault(name, {"name": name, "mac": "", "up": "UP" in flags.split(","),
                                           "ipv4": [], "ipv6": []})
            continue
        if cur is None:
            continue
        m = re.match(r"^\s*ether\s+([0-9a-fA-F:]{17})", line)
        if m:
            cur["mac"] = norm_mac(m.group(1))
            continue
        m = re.match(rf"^\s*inet\s+({IPV4})\s", line)
        if m:
            cur["ipv4"].append(m.group(1))
            continue
        m = re.match(rf"^\s*inet6\s+({IPV6})(?:%\S+)?\s", line)
        if m:
            cur["ipv6"].append(m.group(1))
    return list(ifaces.values())


def _ifaces_windows():
    """English + German ipconfig /all (other locales: the adapter still appears with its MAC; addresses may
    not be picked up since the field labels are matched by text, not position)."""
    ifaces = []
    for block in re.split(r"\r?\n(?=\S)", run(["ipconfig", "/all"])):
        lines = block.splitlines()
        if not lines:
            continue
        mac_m = re.search(rf"({MACRE})", block)
        if not mac_m:
            continue                  # the leading "Windows IP Configuration" block has no MAC - not an adapter
        ipv4, ipv6, link6 = [], [], []
        for line in lines:
            s = line.strip()
            m = (re.match(r"(?i)^link-local ipv6[- ]address\s*[.\s]*:\s*(" + IPV6 + ")", s) or
                 re.match(r"(?i)^link-lokale ipv6-adresse\s*[.\s]*:\s*(" + IPV6 + ")", s))
            if m:
                link6.append(m.group(1))
                continue
            m = (re.match(r"(?i)^ipv6[- ]address\s*[.\s]*:\s*(" + IPV6 + ")", s) or
                 re.match(r"(?i)^ipv6-adresse\s*[.\s]*:\s*(" + IPV6 + ")", s))
            if m:
                ipv6.append(m.group(1))
                continue
            m = (re.match(r"(?i)^ipv4[- ]address\s*[.\s]*:\s*(" + IPV4 + ")", s) or
                 re.match(r"(?i)^ipv4-adresse\s*[.\s]*:\s*(" + IPV4 + ")", s))
            if m:
                ipv4.append(m.group(1))
        # Windows only prints IPv4/IPv6 Address lines once an adapter actually has a connection, so "has
        # any address" is a language-independent stand-in for the (translatable) media-state text
        ifaces.append({"name": lines[0].strip().rstrip(":"), "mac": norm_mac(mac_m.group(1)),
                       "up": bool(ipv4 or ipv6 or link6), "ipv4": ipv4, "ipv6": ipv6 + link6})
    return ifaces


def list_interfaces():
    """Every network interface on this machine - name, MAC, up/down, and every IPv4 / IPv6 address on it.
    Virtual, disabled and loopback adapters are included too; nothing is filtered out here."""
    try:
        return {"Linux": _ifaces_linux, "Darwin": _ifaces_mac, "Windows": _ifaces_windows}.get(OS, list)()
    except Exception:
        return []


def iface_lines(ifaces):
    lines = [f"{'INTERFACE':<30}{'STATUS':<8}{'MAC ADDRESS':<20}{'IPV4 ADDRESS(ES)':<34}{'IPV6 ADDRESS(ES)'}",
             "-" * 140]
    for f in ifaces:
        lines.append(f"{f['name'][:28]:<30}{('UP' if f['up'] else 'DOWN'):<8}{f['mac'] or '-':<20}"
                     f"{(', '.join(f['ipv4']) or '-')[:32]:<34}{', '.join(f['ipv6']) or '-'}")
    lines.append(f"\n{len(ifaces)} interface(s) found.")
    return lines


def ipv6_neighbors():
    """MAC (lowercase, colon form) -> set of IPv6 addresses seen for it, from this host's neighbor cache.
    Needs no administrator / root rights; a device only appears once it has exchanged IPv6 traffic with you."""
    table = {}

    def add(addr, mac):
        mac = norm_mac(mac)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            table.setdefault(mac, set()).add(addr)
    if OS == "Linux":
        for line in run(["ip", "-6", "neigh"]).splitlines():
            m = re.match(rf"({IPV6})\s+dev\s+\S+\s+lladdr\s+({MACRE})", line)
            if m:
                add(*m.groups())
    elif OS == "Darwin":
        for line in run(["ndp", "-an"]).splitlines():
            m = re.match(rf"({IPV6})(?:%\S+)?\s+({MACRE})", line)
            if m:
                add(*m.groups())
    elif OS == "Windows":
        for line in run(["netsh", "interface", "ipv6", "show", "neighbors"]).splitlines():
            m = re.search(rf"({IPV6})\s+({MACRE})", line)
            if m:
                add(*m.groups())
    return table


def net_info():
    ip = local_ip()
    d = {"windows": info_windows, "linux": info_linux, "darwin": info_mac}.get(OS.lower(), lambda i: {})(ip)
    d.setdefault("ip", ip)
    if d.get("ip") and d.get("mask"):
        net = ipaddress.ip_network(f"{d['ip']}/{d['mask']}", strict=False)
        d["network"] = str(net)
        d["broadcast"] = str(net.broadcast_address)
    glob6, link6 = ipv6_addrs(d.get("iface"))
    d["ipv6"] = ", ".join(glob6) or (", ".join(link6[:1]) if link6 else "")
    d["ipv6_all"] = glob6 + link6
    return d


def info_lines(d):
    rows = [("Interface", d.get("iface")), ("Your IP", d.get("ip")), ("Subnet mask", d.get("mask")),
            ("Network", d.get("network")), ("Broadcast", d.get("broadcast")), ("Gateway", d.get("gateway")),
            ("DHCP server", d.get("dhcp")), ("DNS servers", d.get("dns")),
            ("IPv6", ", ".join(d.get("ipv6_all") or []) or None), ("Hostname", socket.gethostname())]
    return [f"{k:<12}: {v or 'not found'}" for k, v in rows]


# ---------------------------------------------------------------------- ping
def ping_rtt(ip, wait_ms=700):
    """One ping packet. Returns (alive, ttl, rtt_ms). TTL hints at the OS (64 Unix-like, 128 Windows, 255 gear).
    `wait_ms` is how long to wait for the reply. A live host answers in milliseconds, so the sweep uses a
    short first pass and only re-checks the silent addresses with the full wait - fast everywhere, and no
    slow host is dropped (the retry still gives it the full time)."""
    wait_ms = max(100, int(wait_ms))
    if OS == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(wait_ms), ip]
    elif OS == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(wait_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(wait_ms / 1000.0))), ip]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=max(2.5, wait_ms / 1000.0 + 1.5), **NOWIN)
    except Exception:
        return False, None, None
    out = p.stdout.decode(errors="ignore")
    m = re.search(r"ttl[=:\s]*(\d+)", out, re.I)
    # Windows exits 0 even for "destination unreachable" - a real reply always contains a TTL
    alive = p.returncode == 0 and (m is not None or OS != "Windows")
    t = re.search(r"(?:time|zeit)\s*([=<])\s*([\d.,]+)\s*ms", out, re.I)
    ms = None
    if alive and t:
        ms = float(t.group(2).replace(",", "."))
        if t.group(1) == "<":
            ms = max(0.1, ms / 2)
    return alive, (int(m.group(1)) if m else None), ms


def ping_probe(ip):
    """Like ping_rtt, without the latency: (alive, ttl)."""
    alive, ttl, _ = ping_rtt(ip)
    return alive, ttl


def is_alive(ip):
    return ping_probe(ip)[0]


def ping_host(host, count=4):
    flag = "-n" if OS == "Windows" else "-c"
    try:
        subprocess.call(["ping", flag, str(count), host])
    except FileNotFoundError:
        print("ping command not found on this system.")


# ------------------------------------------------------------------ scanning
OUI_MAX_AGE_DAYS = 30
_OUI_CACHE = {"mtime": None, "table": None}  # avoids re-parsing a multi-MB vendor file on every call

# A small built-in MAC-prefix table so the most common devices are still NAMED before (or without) the
# full IEEE registry download - handy on an air-gapped first run, or on a company network that blocks the
# download. The downloaded IEEE file OVERLAYS this (load_oui), so it is only ever a fallback and an online
# scan is unchanged. Kept deliberately to prefixes that reliably identify a device on sight.
OUI_BUILTIN = {
    # Raspberry Pi (B827EB = the original Foundation prefix; the rest are Raspberry Pi Trading)
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading", "E45F01": "Raspberry Pi Trading",
    "28CDC1": "Raspberry Pi Trading", "2CCF67": "Raspberry Pi Trading", "D83ADD": "Raspberry Pi Trading",
    # Espressif (ESP8266 / ESP32 - the guts of countless DIY and smart-home gadgets; 5CCF7F is the classic)
    "5CCF7F": "Espressif Inc.", "240AC4": "Espressif Inc.", "246F28": "Espressif Inc.", "30AEA4": "Espressif Inc.",
    "3C71BF": "Espressif Inc.", "84F3EB": "Espressif Inc.", "8CAAB5": "Espressif Inc.", "A020A6": "Espressif Inc.",
    "A4CF12": "Espressif Inc.", "AC67B2": "Espressif Inc.", "B4E62D": "Espressif Inc.", "BCDDC2": "Espressif Inc.",
    "CC50E3": "Espressif Inc.", "D8A01D": "Espressif Inc.", "DC4F22": "Espressif Inc.", "ECFABC": "Espressif Inc.",
}


def load_oui(download=True, log=print):
    had_file = os.path.exists(OUI_FILE)
    stale = had_file and (time.time() - os.path.getmtime(OUI_FILE)) > OUI_MAX_AGE_DAYS * 86400
    if (not had_file or stale) and download:
        try:
            log("Downloading MAC vendor list..." if not had_file else
                f"MAC vendor list is over {OUI_MAX_AGE_DAYS} days old - refreshing...")
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = r.read()
            if not data:
                raise OSError("empty response")
            # write to a temp file and replace atomically - a download that fails partway must never
            # truncate a cache file that was already good (os.replace is an all-or-nothing rename).
            # The name includes pid + thread id so two concurrent refreshes (two tabs/processes both
            # deciding the cache is stale at once) never both write the same temp file.
            tmp = f"{OUI_FILE}.{os.getpid()}.{threading.get_ident()}.tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, OUI_FILE)
            had_file = True
        except Exception:
            if had_file:
                log("Could not refresh the MAC vendor list - using the cached copy.")
            else:
                log("Vendor list unavailable - using the built-in common-device list for now.")
                return dict(OUI_BUILTIN)
    # the file is 30000+ lines and does not change between scans in the same run (at most once a day,
    # and only via the refresh above, which always writes a new mtime) - re-parsing it from scratch on
    # every single scan/live-monitor tick was pure repeated work for the same result, so the parsed
    # table is kept in memory and only rebuilt when the file's mtime actually moves.
    try:
        mtime = os.path.getmtime(OUI_FILE)
    except OSError:
        mtime = None
    if mtime is not None and mtime == _OUI_CACHE["mtime"] and _OUI_CACHE["table"] is not None:
        return _OUI_CACHE["table"]
    table = dict(OUI_BUILTIN)     # the IEEE file overlays (and so corrects/extends) the built-in fallback
    try:
        for line in open(OUI_FILE, errors="ignore"):
            if "(hex)" in line:
                left, _, right = line.partition("(hex)")
                table[left.strip().replace("-", "").upper()] = right.strip()
    except OSError:
        pass
    _OUI_CACHE["mtime"], _OUI_CACHE["table"] = mtime, table
    return table


# The IEEE lists these as the registered HOLDER of a sub-divided block (an MA-M / MA-S parent), not the
# device maker, so a 24-bit hit of one of them is not a real vendor - treat it as unknown so a misleading
# name never shows and other signals (mDNS, hostname, ports) decide instead.
OUI_GENERIC = {"ieee registration authority", "private"}


def vendor_of(mac, oui):
    """The device vendor for a MAC, read from the OUI table. Returns "" for an empty/short MAC, for a
    generic registration-authority placeholder, and when nothing matches. If the table carries longer
    28-bit (MA-M) or 36-bit (MA-S) keys, the more specific one is preferred over the 24-bit one - so this
    is a strict improvement over a bare 24-bit `oui.get`, and the single place every caller resolves a
    vendor."""
    if not mac:
        return ""
    h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(h) < 6:
        return ""
    for n in (9, 7, 6):                       # MA-S (36-bit) -> MA-M (28-bit) -> MA-L (24-bit)
        if len(h) >= n:
            v = oui.get(h[:n])
            if v and v.strip().lower() not in OUI_GENERIC:
                return v
    return ""


def arp_table():
    entries = {}
    outs = [run(["arp", "-a"])]
    if OS == "Linux":
        outs.append(run(["ip", "neigh"]))
    for out in outs:
        for line in out.splitlines():
            m = re.search(rf"({IPV4}).*?({MACRE})", line)
            if m:
                mac = norm_mac(m.group(2))
                if mac != "ff:ff:ff:ff:ff:ff":
                    entries[m.group(1)] = mac
    return entries


# Neighbour-cache states that settle the question "is this address really still there?"
NEIGH_GONE = {"FAILED", "INCOMPLETE", "UNREACHABLE"}
NEIGH_PENDING = {"STALE", "DELAY", "PROBE"}


def parse_ip_neigh(text):
    """`ip -4 neigh show` -> {ip: STATE}. Lines look like '192.168.1.5 dev wlan0 lladdr aa:.. REACHABLE'
    or '192.168.1.9 dev wlan0  FAILED' - the state is always the last word."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(IPV4, parts[0]) and parts[-1].isalpha():
            out[parts[0]] = parts[-1].upper()
    return out


def parse_netneighbor_csv(text):
    """PowerShell `Get-NetNeighbor ... | ConvertTo-Csv` -> {ip: STATE}. The State values are enum names
    (Reachable, Stale, Unreachable, ...), never translated - this works on a German Windows too."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(rf'^\s*"?({IPV4})"?\s*,\s*"?([A-Za-z]+)"?\s*$', line)
        if m:
            out[m.group(1)] = m.group(2).upper()
    return out


def neighbor_states():
    """{ip: state} from the OS neighbour (ARP) cache, where the OS reports states; {} where it doesn't."""
    if OS == "Linux":
        return parse_ip_neigh(run(["ip", "-4", "neigh", "show"]))
    if OS == "Windows":
        return parse_netneighbor_csv(run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,State | ConvertTo-Csv -NoTypeInformation"],
            timeout=12))
    return {}


def drop_arp_ghosts(candidates, since, log=print, cancel=None, settle=8.5, states_fn=None, sleep=time.sleep):
    """Of the addresses that are ONLY in the ARP cache (no ping, no TCP, no mDNS/WS-Discovery answer),
    return the ones that turned out to be gone.

    A device that left the network keeps its cache entry for minutes to hours, so it used to be listed as
    present-but-silent. Our ping sweep made the OS re-check every such entry: a device that is still there
    answers the OS's own ARP probe (REACHABLE), one that left ends FAILED / UNREACHABLE within ~8 seconds
    of the sweep. This waits only while something is still being re-checked, and only up to that limit.
    An address the OS gives no state for is kept - unknown is not gone."""
    states_fn = states_fn or neighbor_states
    cand = set(candidates)
    if not cand:
        return set()
    states = states_fn()
    if not states:
        return set()
    while any(states.get(ip) in NEIGH_PENDING for ip in cand) and time.time() - since < settle:
        if cancel is not None and cancel.is_set():
            break
        sleep(0.5)
        states = states_fn() or states
    gone = {ip for ip in cand if states.get(ip) in NEIGH_GONE}
    if gone:
        log(f"{len(gone)} address(es) were only left over in the ARP cache (the device has gone) - not listed.")
    return gone


PORTS = [21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1400, 3389, 5000, 5900, 7000,
         8000, 8008, 8009, 8080, 8443, 8554, 9100, 37777, 62078]


def probe(ip, port, timeout=0.4):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return ip, port
    except Exception:
        return None


def adaptive_timeout(rtt_ms, floor=0.25, cap=0.4, k=8):
    """A TCP-connect timeout tuned to how fast this network actually is. A port's SYN-ACK comes back at
    roughly the ICMP round-trip time, so on a LAN that pings in a few ms we don't need to wait the full
    fixed timeout on every silent (firewalled) port - we scale the wait to the measured RTT instead.

    It keys off a HIGH PERCENTILE (p90) of the samples, not the median: with the median, half the hosts are
    slower than the budget, so a host slower than median x k could have its open ports time out and be
    missed. p90 sizes the wait to the slower hosts too, so it is the safer statistic for not missing a port,
    while still shortening the wait on a uniformly fast LAN (there p90 ~ median). It never waits longer than
    `cap` (today's fixed value) nor shorter than `floor`; with no RTT samples it returns `cap`, i.e. exactly
    the old behaviour."""
    vals = sorted(v for v in rtt_ms if isinstance(v, (int, float)) and v > 0)
    if not vals:
        return cap
    p90 = vals[min(len(vals) - 1, int(len(vals) * 0.9))]
    return max(floor, min(cap, p90 / 1000.0 * k))


_RDNS_CACHE = {}
_RDNS_CACHE_MAX = 4096
_RDNS_MISS = object()


def hostname_of(ip):
    """Reverse-DNS name for an IP, cached for the session. Names are stable within a run, and the tools
    that rescan constantly (LIVE MONITOR, BACKGROUND WATCH) used to re-query the resolver for every device
    every single cycle - including the many LAN devices that have no PTR record at all, each costing a full
    NXDOMAIN round-trip. Caching both hits AND misses turns every repeat into a dict lookup. Empty string
    when there is no name."""
    cached = _RDNS_CACHE.get(ip, _RDNS_MISS)
    if cached is not _RDNS_MISS:
        return cached
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ""
    if len(_RDNS_CACHE) >= _RDNS_CACHE_MAX:   # bounded: a long-running watch never grows it without limit
        _RDNS_CACHE.clear()
    _RDNS_CACHE[ip] = name
    return name


_WHICH_CACHE = {}


def _which(name):
    """shutil.which, memoised: the set of installed programs doesn't change during a run, yet several tools
    probe for the same binaries (nmcli, iwctl, iptables, ...) repeatedly within a single invocation."""
    if name not in _WHICH_CACHE:
        _WHICH_CACHE[name] = shutil.which(name)
    return _WHICH_CACHE[name]


# ------------------------------------------------------------ fingerprinting
def _dns_name(data, off):
    """Read a DNS name (with compression pointers). Returns (name, next_offset)."""
    labels, end = [], None
    for _ in range(40):
        if off >= len(data):
            break
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            continue
        labels.append(data[off + 1:off + 1 + n].decode(errors="ignore"))
        off += 1 + n
    return ".".join(labels), (end if end is not None else off)


def _udp_ask(ip, port, payload, timeout=0.8):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (ip, port))
        return s.recvfrom(2048)[0]
    except Exception:
        return b""
    finally:
        s.close()


# The NetBIOS "node status" (NBSTAT) wildcard query - asks a host for its whole name table. "CKAA...A"
# is the first-level encoding of the single-character name "*", padded to 16 bytes with nulls.
NBSTAT_QUERY = (b"\x81\x62\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
                + b"\x00\x21\x00\x01")


def parse_nbstat(d):
    """A NBSTAT reply -> {"name", "mac", "names"}. The name table is 18 bytes per entry (15-char name,
    1-byte suffix, 2-byte flags); the 6-byte hardware address follows the table. The machine name is the
    first unique (not group) entry whose suffix is 0x00."""
    out = {"name": "", "mac": "", "names": []}
    try:
        if len(d) <= 57:
            return out
        n = d[56]
        for i in range(n):
            e = d[57 + i * 18: 57 + i * 18 + 18]
            if len(e) != 18:
                break
            nm = e[:15].decode("ascii", "ignore").strip("\x00 ").strip()
            group = bool(e[16] & 0x80)
            out["names"].append((nm, e[15], group))
            if not out["name"] and e[15] == 0 and not group and nm:
                out["name"] = nm
        mac_off = 57 + n * 18
        mac = d[mac_off:mac_off + 6]
        if len(mac) == 6 and mac != b"\x00" * 6:
            out["mac"] = ":".join(f"{b:02x}" for b in mac)
    except Exception:
        pass
    return out


def netbios_name(ip):
    """Windows / Samba machine name via NetBIOS (UDP 137)."""
    return parse_nbstat(_udp_ask(ip, 137, NBSTAT_QUERY)).get("name", "")


def nbns_broadcast(bcast_ip, bind_ip=None, wait=1.5, cancel=None, port=137):
    """One NBSTAT query to the subnet broadcast - every Windows / Samba host answers at once with its
    name and hardware address. Returns {ip: {"name","mac","names"}}.

    This is the efficient way to find the machines a ping sweep misses: Windows blocks ICMP by default
    but still answers NetBIOS, and one broadcast packet reaches the whole subnet instead of 254 separate
    probes. Purely a question every Windows network answers for file-sharing discovery; nothing is sent
    to any host individually and nothing is changed."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        if bind_ip:
            try:
                s.bind((bind_ip, 0))
            except OSError:
                pass
        s.settimeout(0.3)
        for _ in range(2):              # two sends: one UDP packet is easily lost, and hosts answer each
            try:
                s.sendto(NBSTAT_QUERY, (bcast_ip, port))
            except OSError:
                break
        t0 = time.time()
        while time.time() - t0 < wait:
            if cancel is not None and cancel.is_set():
                break
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            rec = parse_nbstat(data)
            if rec["name"] or rec["mac"]:
                found.setdefault(addr[0], rec)
    except OSError:
        pass
    finally:
        s.close()
    return found


def mdns_name(ip):
    """Bonjour/mDNS name (Apple, Android, Chromecast, printers...) via a unicast reverse lookup."""
    q = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in (".".join(reversed(ip.split("."))) + ".in-addr.arpa").split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00\x00\x0c\x80\x01"
    d = _udp_ask(ip, 5353, q)
    try:
        if len(d) > 12:
            qd, an, off = int.from_bytes(d[4:6], "big"), int.from_bytes(d[6:8], "big"), 12
            for _ in range(qd):
                off = _dns_name(d, off)[1] + 4
            for _ in range(an):
                _, off = _dns_name(d, off)
                rtype, rdlen = int.from_bytes(d[off:off + 2], "big"), int.from_bytes(d[off + 8:off + 10], "big")
                if rtype == 12:
                    name = _dns_name(d, off + 10)[0]
                    return re.sub(r"\.local\.?$", "", name)
                off += 10 + rdlen
    except Exception:
        pass
    return ""


def ssdp_discover(bind_ip=None, wait=2.5):
    """One UPnP/SSDP multicast search. Returns {ip: {"location":..., "server":...}}."""
    found = {}
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
           'MX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if bind_ip:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
        s.settimeout(0.5)
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            txt = data.decode(errors="ignore")
            rec = found.setdefault(addr[0], {})
            m = re.search(r"(?im)^location:\s*(\S+)", txt)
            if m:
                rec.setdefault("location", m.group(1))
            m = re.search(r"(?im)^server:\s*(.+)$", txt)
            if m:
                rec.setdefault("server", m.group(1).strip())
    except OSError:
        pass
    finally:
        s.close()
    return found


# --- WS-Discovery: the Windows / printer / ONVIF-camera counterpart of SSDP and Bonjour ----------------------
# A Probe to 239.255.255.250:3702 is what Windows Explorer's "Network" view sends; every device that takes
# part answers with what it IS (its Types) and where its service lives (XAddrs). It reaches devices that
# drop ping (most IP cameras, many printers, Windows PCs with network discovery on) and tells them apart
# without opening a single port on them.
WSD_GROUP = ("239.255.255.250", 3702)
# local name of a WS-Discovery type -> (device type, what to call it)
WSD_KIND = {"NetworkVideoTransmitter": ("Camera", "IP Camera"), "PrintDeviceType": ("Printer", "Printer"),
            "ScanDeviceType": ("Printer", "Scanner / MFP"), "Computer": ("Computer", "Computer")}


def _wsd_probe(types=""):
    mid = "urn:uuid:" + str(uuid.uuid4())
    tline = (f'<wsd:Types xmlns:dn="http://www.onvif.org/ver10/network/wsdl">{types}</wsd:Types>' if types else "")
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            '<soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
            '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
            f'<wsa:MessageID>{mid}</wsa:MessageID></soap:Header>'
            f'<soap:Body><wsd:Probe>{tline}</wsd:Probe></soap:Body></soap:Envelope>').encode()


def parse_wsd(xml_text):
    """One ProbeMatches answer -> {"types": [...local names], "xaddrs": [...], "name", "model", "kind", "word"}.
    Namespace prefixes differ between vendors (wsd:, d:, ns2: ...), so elements are matched by local name."""
    def elem(tag):
        m = re.search(rf"<(?:[\w.-]+:)?{tag}\b[^>]*>(.*?)</(?:[\w.-]+:)?{tag}>", xml_text, re.S)
        return m.group(1).strip() if m else ""
    types = [t.split(":")[-1] for t in elem("Types").split() if t]
    xaddrs = [x for x in elem("XAddrs").split() if x.startswith("http")]
    scopes = elem("Scopes").split()
    name = model = ""
    for sc in scopes:            # ONVIF cameras state their name and hardware model in their scopes
        m = re.match(r"(?i)onvif://www\.onvif\.org/(name|hardware)/(.+)$", sc)
        if m:
            val = urllib.parse.unquote(m.group(2)).replace("_", " ").strip()
            if m.group(1).lower() == "name":
                name = name or val
            else:
                model = model or val
        if re.match(r"(?i)onvif://www\.onvif\.org/type/(video_encoder|NetworkVideoTransmitter)", sc) \
                and "NetworkVideoTransmitter" not in types:
            types.append("NetworkVideoTransmitter")
    kind = word = ""
    for t in ("NetworkVideoTransmitter", "PrintDeviceType", "ScanDeviceType", "Computer"):
        if t in types:
            kind, word = WSD_KIND[t]
            break
    return {"types": types, "xaddrs": xaddrs, "name": name, "model": model, "kind": kind, "word": word}


def wsd_browse(bind_ip=None, wait=2.5, cancel=None):
    """WS-Discovery Probe (plain, plus one asking specifically for ONVIF cameras - some only answer that).
    Returns {ip: parse_wsd(...) merged}. Read-only: a Probe asks devices to describe themselves."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        if bind_ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
            except OSError:
                pass
        s.settimeout(0.25)
        probes = [_wsd_probe(), _wsd_probe("dn:NetworkVideoTransmitter")]
        for p in probes:
            s.sendto(p, WSD_GROUP)
        resent, t0 = False, time.time()
        while time.time() - t0 < wait:
            if cancel is not None and cancel.is_set():
                break
            if not resent and time.time() - t0 > wait / 2:        # UDP: one repeat catches a lost datagram
                for p in probes:
                    s.sendto(p, WSD_GROUP)
                resent = True
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            txt = data.decode("utf-8", errors="ignore")
            if "ProbeMatch" not in txt:
                continue
            rec = parse_wsd(txt)
            ips = {addr[0]}
            for x in rec["xaddrs"]:               # a device can answer from one address for another
                m = re.match(rf"https?://({IPV4})[:/]", x)
                if m:
                    ips.add(m.group(1))
            for ip in ips:
                cur = found.setdefault(ip, {"types": [], "xaddrs": [], "name": "", "model": "", "kind": "", "word": ""})
                cur["types"] = sorted(set(cur["types"]) | set(rec["types"]))
                cur["xaddrs"] = sorted(set(cur["xaddrs"]) | set(rec["xaddrs"]))
                for k in ("name", "model", "kind", "word"):
                    cur[k] = cur[k] or rec[k]
    except OSError:
        pass
    finally:
        s.close()
    return found


# --- IP camera control (ONVIF, authenticated) -----------------------------------------------------------
# View and steer the cameras YOU run. Every request carries the camera's own login (ONVIF WS-Security - the
# same token the manufacturer's app sends) and the camera checks it, so this reaches a camera only when you
# hold its username and password. There is no "view any camera" path: a camera you have no login for
# refuses every call here, as it should. Running NetScout as administrator changes nothing about that -
# admin is a right on YOUR computer; a separate camera answers to its OWN password, not to how the program
# talking to it was launched.
ONVIF_DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"
ONVIF_MEDIA_NS = "http://www.onvif.org/ver10/media/wsdl"
ONVIF_PTZ_NS = "http://www.onvif.org/ver20/ptz/wsdl"
# keyboard -> (pan x, tilt y, zoom) velocity. w/s tilt, a/d pan, e/q zoom in/out. Half speed: a full-speed
# nudge on many PTZ heads overshoots; half is steerable by hand.
PTZ_KEYS = {"w": (0.0, 0.5, 0.0), "s": (0.0, -0.5, 0.0), "a": (-0.5, 0.0, 0.0), "d": (0.5, 0.0, 0.0),
            "e": (0.0, 0.0, 0.5), "q": (0.0, 0.0, -0.5)}


def _xml_escape(s):
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def ws_security_header(user, password, now=None, nonce=None):
    """ONVIF WS-UsernameToken header. PasswordDigest = base64(sha1(nonce + created + password)), so the
    password itself never crosses the wire. `now`/`nonce` are injectable to make the digest testable."""
    raw_nonce = nonce if nonce is not None else os.urandom(16)
    created = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest = base64.b64encode(hashlib.sha1(raw_nonce + created.encode() + (password or "").encode()).digest()).decode()
    return ('<s:Header><Security s:mustUnderstand="1" '
            'xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
            f'<UsernameToken><Username>{_xml_escape(user)}</Username>'
            '<Password Type="http://docs.oasis-open.org/wss/2004/01/'
            f'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</Password>'
            '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/'
            f'oasis-200401-wss-soap-message-security-1.0#Base64Binary">{base64.b64encode(raw_nonce).decode()}</Nonce>'
            '<Created xmlns="http://docs.oasis-open.org/wss/2004/01/'
            f'oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>'
            '</UsernameToken></Security></s:Header>')


def onvif_envelope(body, user=None, password=None):
    header = ws_security_header(user, password) if user else ""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:tt="http://www.onvif.org/ver10/schema">'
            f'{header}<s:Body>{body}</s:Body></s:Envelope>')


def _auth_opener(user, password):
    """urllib opener for the LAN (no proxy) that also answers HTTP Basic/Digest challenges - some cameras
    want WS-Security, some HTTP auth, many both, so every request is ready for either."""
    handlers = [urllib.request.ProxyHandler({})]
    if user:
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, "", user, password or "")
        handlers += [urllib.request.HTTPDigestAuthHandler(mgr), urllib.request.HTTPBasicAuthHandler(mgr)]
    return urllib.request.build_opener(*handlers)


def onvif_post(url, body, user, password, timeout=6):
    """One authenticated ONVIF SOAP call. Returns (xml_text, error)."""
    data = onvif_envelope(body, user, password).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/soap+xml; charset=utf-8"})
    try:
        with _auth_opener(user, password).open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "ignore"), ""
    except urllib.error.HTTPError as e:
        txt = ""
        try:
            txt = e.read().decode("utf-8", "ignore")
        except Exception:
            pass
        if e.code in (401, 403) or "NotAuthorized" in txt:
            return txt, "The camera refused the login - check its ONVIF user name and password."
        return txt, f"The camera returned an error (HTTP {e.code})."
    except (urllib.error.URLError, OSError, ValueError) as e:
        return "", f"Could not reach the camera: {getattr(e, 'reason', e)}"


def _onvif_tag(xml, local):
    m = re.search(rf"<(?:[\w.-]+:)?{local}\b[^>]*>(.*?)</(?:[\w.-]+:)?{local}>", xml or "", re.S)
    return m.group(1).strip() if m else ""


def onvif_service_urls(xml):
    """GetServices -> (media_url, ptz_url) from each <Service>'s Namespace + XAddr ("" if not offered)."""
    media = ptz = ""
    for m in re.finditer(r"<(?:[\w.-]+:)?Service\b[^>]*>(.*?)</(?:[\w.-]+:)?Service>", xml or "", re.S):
        ns, addr = _onvif_tag(m.group(1), "Namespace"), _onvif_tag(m.group(1), "XAddr")
        if "/media/" in ns and not media:
            media = addr
        elif "/ptz/" in ns and not ptz:
            ptz = addr
    return media, ptz


def onvif_profiles(xml):
    """GetProfiles -> [{token, name, ptz}]. The token is an attribute on each <Profiles>; a profile that
    carries a PTZConfiguration can be steered."""
    out = []
    for m in re.finditer(r"<(?:[\w.-]+:)?Profiles\b([^>]*)>(.*?)</(?:[\w.-]+:)?Profiles>", xml or "", re.S):
        tok = re.search(r'\btoken="([^"]+)"', m.group(1))
        if tok:
            out.append({"token": tok.group(1), "name": _onvif_tag(m.group(2), "Name"),
                        "ptz": "PTZConfiguration" in m.group(2)})
    return out


def _valid_host(h):
    h = (h or "").strip()
    if "//" in h:
        h = h.split("//", 1)[1]
    h = h.split("/")[0].split(":")[0]
    return bool(re.fullmatch(r"[A-Za-z0-9._\-]{1,253}", h))


def camera_connect(ip, user, password, timeout=6):
    """Log in to a camera you administer and gather what's needed to view and steer it.

    Returns {ok, error, ...}; on success it holds the profile token, snapshot / RTSP stream URLs, whether it
    can pan/tilt/zoom, and the service URLs - plus the login (kept in memory for this session only, so each
    later frame / move can re-authenticate). The camera refuses all of it without the right login."""
    if not _valid_host(ip):
        return {"ok": False, "error": "Enter the camera's IP address or host name."}
    if not (user or "").strip():
        return {"ok": False, "error": "Enter the camera's ONVIF user name (its own login, not this PC's)."}
    base = ip if ip.startswith("http") else f"http://{ip}"
    device_url = base.rstrip("/") + "/onvif/device_service"
    sxml, serr = onvif_post(device_url, f'<tds:GetServices xmlns:tds="{ONVIF_DEVICE_NS}">'
                            '<tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>',
                            user, password, timeout)
    if serr and "refused the login" in serr:
        return {"ok": False, "error": serr}
    media_url, ptz_url = onvif_service_urls(sxml) if not serr else ("", "")
    media_url = media_url or base.rstrip("/") + "/onvif/Media"
    ptz_url = ptz_url or base.rstrip("/") + "/onvif/PTZ"
    gp = f'<trt:GetProfiles xmlns:trt="{ONVIF_MEDIA_NS}"/>'
    pxml, perr = onvif_post(media_url, gp, user, password, timeout)
    if perr and media_url != device_url:
        pxml2, perr2 = onvif_post(device_url, gp, user, password, timeout)   # some serve media at the device URL
        if not perr2:
            pxml, perr, media_url = pxml2, "", device_url
    if perr:
        return {"ok": False, "error": perr}
    profiles = onvif_profiles(pxml)
    if not profiles:
        return {"ok": False, "error": "The camera answered but offers no video profile over ONVIF."}
    prof = next((p for p in profiles if p["ptz"]), profiles[0])
    tok = _xml_escape(prof["token"])
    snap, _ = onvif_post(media_url, f'<trt:GetSnapshotUri xmlns:trt="{ONVIF_MEDIA_NS}">'
                         f'<trt:ProfileToken>{tok}</trt:ProfileToken></trt:GetSnapshotUri>', user, password, timeout)
    stream, _ = onvif_post(media_url, f'<trt:GetStreamUri xmlns:trt="{ONVIF_MEDIA_NS}"><trt:StreamSetup>'
                           '<tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol>'
                           f'</tt:Transport></trt:StreamSetup><trt:ProfileToken>{tok}</trt:ProfileToken>'
                           '</trt:GetStreamUri>', user, password, timeout)
    return {"ok": True, "error": "", "ip": ip, "user": user, "password": password,
            "device_url": device_url, "media_url": media_url, "ptz_url": ptz_url, "token": prof["token"],
            "ptz": prof["ptz"], "name": prof["name"], "profiles": profiles,
            "snapshot_uri": _onvif_tag(snap, "Uri"), "stream_uri": _onvif_tag(stream, "Uri")}


def camera_snapshot(cam, timeout=6):
    """One JPEG frame (the live view polls this a few times a second). Returns (jpeg_bytes, error)."""
    uri = cam.get("snapshot_uri")
    if not uri:
        return b"", "This camera exposes no snapshot URL over ONVIF - open the RTSP stream in VLC instead."
    try:
        with _auth_opener(cam.get("user"), cam.get("password")).open(urllib.request.Request(uri), timeout=timeout) as r:
            return r.read(), ""
    except urllib.error.HTTPError as e:
        return b"", ("The camera refused the snapshot login." if e.code in (401, 403)
                     else f"Snapshot failed (HTTP {e.code}).")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return b"", f"Could not fetch a frame: {getattr(e, 'reason', e)}"


def ptz_move_body(token, x, y, z=0.0):
    v = ""
    if x or y:
        v += f'<tt:PanTilt x="{float(x):.2f}" y="{float(y):.2f}"/>'
    if z:
        v += f'<tt:Zoom x="{float(z):.2f}"/>'
    return (f'<tptz:ContinuousMove xmlns:tptz="{ONVIF_PTZ_NS}"><tptz:ProfileToken>{_xml_escape(token)}'
            f'</tptz:ProfileToken><tptz:Velocity>{v}</tptz:Velocity></tptz:ContinuousMove>')


def ptz_stop_body(token):
    return (f'<tptz:Stop xmlns:tptz="{ONVIF_PTZ_NS}"><tptz:ProfileToken>{_xml_escape(token)}</tptz:ProfileToken>'
            '<tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>')


def camera_move(cam, x, y, z=0.0, timeout=5):
    """Start the camera turning (it keeps moving until camera_stop). Returns (ok, error)."""
    if not cam.get("ptz"):
        return False, "This camera has no pan / tilt / zoom - it's a fixed camera."
    _, err = onvif_post(cam["ptz_url"], ptz_move_body(cam["token"], x, y, z), cam.get("user"), cam.get("password"), timeout)
    return (not err), err


def camera_stop(cam, timeout=5):
    if not cam.get("ptz"):
        return True, ""
    _, err = onvif_post(cam["ptz_url"], ptz_stop_body(cam["token"]), cam.get("user"), cam.get("password"), timeout)
    return (not err), err


def ensure_pillow(log=print):
    """Pillow decodes the camera's JPEG frames for display (Tk itself can't). Installed on first use, the
    same way bleak is for Bluetooth. Pan/tilt/zoom works without it - only the picture needs it."""
    try:
        import PIL.Image  # noqa: F401
        return True
    except ImportError:
        pass
    if getattr(sys, "frozen", False):
        log("This packaged copy was built without Pillow, so the camera picture can't be shown in it - "
            "pan / tilt / zoom still works. Rebuild with 'pip install Pillow' first to include it.")
        return False
    log("Installing the 'Pillow' package (needed to show camera pictures) - once...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--only-binary=:all:", "Pillow"],
                       capture_output=True, timeout=240, **NOWIN)
    except Exception as e:
        log(f"Automatic install failed ({e}). Install it yourself:  pip install Pillow")
    try:
        import PIL.Image  # noqa: F401
        return True
    except ImportError:
        return False


def upnp_details(ip, location):
    """Friendly name / brand / model from the device's own UPnP description (same host only)."""
    try:
        if urllib.parse.urlparse(location).hostname != ip:
            return {}
        req = urllib.request.Request(location, headers={"User-Agent": "NetScout"})
        xml = urllib.request.urlopen(req, timeout=1.5).read(60000).decode(errors="ignore")
    except Exception:
        return {}
    out = {}
    for key, tag in (("name", "friendlyName"), ("brand", "manufacturer"), ("model", "modelName"),
                     ("desc", "modelDescription")):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.S)
        if m:
            out[key] = re.sub(r"\s+", " ", m.group(1)).strip()[:60]
    return out


def http_banner(ip, port):
    """Page title / Server header / login realm of a device's web interface."""
    # (http.client.HTTPConnection does NOT support "with" - unlike socket objects, it has no __enter__/
    # __exit__ - so cleanup here needs an explicit finally, not a context manager.)
    c = None
    try:
        c = http.client.HTTPConnection(ip, port, timeout=1.2)
        c.request("GET", "/", headers={"User-Agent": "NetScout", "Connection": "close"})
        r = c.getresponse()
        body = r.read(4096).decode(errors="ignore")
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        realm = re.search(r'realm="?([^",]+)', r.getheader("WWW-Authenticate", "") or "")
        return {"title": re.sub(r"\s+", " ", m.group(1)).strip()[:60] if m else "",
                "server": (r.getheader("Server", "") or "").split(" ")[0][:40],
                "realm": realm.group(1).strip()[:40] if realm else ""}
    except Exception:
        return {}
    finally:
        # the old code only called c.close() on the success path, so a slow or malformed device's web
        # server raising partway through (request()/getresponse()/read()) could leak a socket on every
        # failed attempt - this runs on every host with an open web port, so it adds up across a scan.
        if c is not None:
            c.close()


def fingerprint(ip, open_ports, ssdp_rec):
    out = {"netbios": netbios_name(ip), "mdns": mdns_name(ip), "upnp": {}, "http": {}, "snmp": {}, "tls": {}}
    if ssdp_rec and ssdp_rec.get("location"):
        out["upnp"] = upnp_details(ip, ssdp_rec["location"])
    for p in (80, 8080, 8000):
        if p in open_ports:
            out["http"] = http_banner(ip, p)
            if out["http"]:
                break
    # SNMP is asked of every host, not only ones with 161 in open_ports: that list comes from the TCP
    # sweep, and SNMP is UDP, so it would never appear there. One short datagram per host, and silence
    # is the normal answer - see snmp_get.
    out["snmp"] = snmp_get(ip)
    # The first TLS port that actually completes a handshake. Most hosts have none and cost one refused
    # connection; the ones that do hand back their certificate's expiry, which nothing else reports.
    for p in TLS_PORTS:
        if p in open_ports:
            out["tls"] = tls_cert(ip, p)
            if out["tls"]:
                break
    return out


# brand detection: regex on vendor + names + banners  ->  clean brand name
BRANDS = [
    (r"apple", "Apple"), (r"samsung", "Samsung"), (r"huawei|\bhonor\b", "Huawei"), (r"xiaomi|redmi|\bpoco\b", "Xiaomi"),
    (r"oneplus", "OnePlus"), (r"oppo", "OPPO"), (r"\bvivo\b", "vivo"), (r"realme", "realme"), (r"motorola", "Motorola"),
    (r"fairphone", "Fairphone"), (r"google|nest labs|chromecast|pixel", "Google"), (r"amazon|\becho\b|fire ?tv|kindle", "Amazon"),
    (r"sonos", "Sonos"), (r"roku", "Roku"), (r"vizio", "Vizio"), (r"\btcl\b", "TCL"), (r"hisense", "Hisense"),
    (r"lg elec|webos|\blg\b", "LG"), (r"sony", "Sony"), (r"nintendo", "Nintendo"), (r"playstation", "Sony PlayStation"),
    (r"xbox", "Microsoft Xbox"), (r"bose", "Bose"), (r"hewlett packard enterprise|\bhpe\b|\baruba\b", "HPE"),
    (r"hewlett|\bhp\b|laserjet|officejet|deskjet", "HP"),
    (r"canon|pixma", "Canon"), (r"epson|ecotank", "Epson"), (r"brother|\bmfc-", "Brother"), (r"xerox", "Xerox"),
    (r"ricoh", "Ricoh"), (r"kyocera", "Kyocera"), (r"lexmark", "Lexmark"), (r"konica", "Konica Minolta"),
    (r"tapo|tp-?link", "TP-Link"), (r"netgear", "Netgear"), (r"\bavm\b|fritz", "AVM FRITZ!"), (r"ubiquiti|unifi", "Ubiquiti"),
    (r"mikrotik|routerboard", "MikroTik"), (r"asustek|\basus\b", "ASUS"), (r"d-link|dlink", "D-Link"), (r"linksys", "Linksys"),
    (r"zyxel", "Zyxel"), (r"cisco|meraki", "Cisco"), (r"aruba|hewlett packard enterprise", "Aruba"), (r"ruckus", "Ruckus"),
    (r"juniper", "Juniper"), (r"\beero\b", "eero"), (r"draytek", "DrayTek"), (r"teltonika", "Teltonika"),
    (r"swisscom", "Swisscom"), (r"sunrise", "Sunrise"), (r"technicolor", "Technicolor"), (r"sagemcom", "Sagemcom"),
    (r"arcadyan", "Arcadyan"), (r"askey", "Askey"), (r"sercomm", "Sercomm"), (r"\bzte\b", "ZTE"), (r"arris", "ARRIS"),
    (r"compal", "Compal"), (r"hitron", "Hitron"), (r"dell", "Dell"), (r"lenovo", "Lenovo"), (r"microsoft", "Microsoft"),
    (r"intel", "Intel"), (r"raspberry", "Raspberry Pi"), (r"espressif", "Espressif"), (r"tuya", "Tuya"),
    (r"shelly|allterco", "Shelly"), (r"signify|philips lighting|\bhue\b", "Philips Hue"), (r"ecobee", "ecobee"),
    (r"hikvision", "Hikvision"), (r"dahua", "Dahua"), (r"reolink", "Reolink"), (r"axis comm", "Axis"),
    (r"amcrest", "Amcrest"), (r"foscam", "Foscam"), (r"wyze", "Wyze"), (r"\barlo\b", "Arlo"), (r"eufy|anker", "eufy"),
    (r"ezviz", "EZVIZ"), (r"uniview", "Uniview"), (r"vivotek", "Vivotek"), (r"hanwha", "Hanwha"), (r"lorex", "Lorex"),
    (r"annke", "Annke"), (r"swann", "Swann"), (r"imou", "Imou"), (r"\bring\b", "Ring"), (r"mobotix", "Mobotix"),
    (r"geovision", "GeoVision"), (r"synology", "Synology"), (r"qnap", "QNAP"), (r"western digital", "Western Digital"),
    (r"vmware", "VMware"), (r"pcs systemtechnik|virtualbox", "VirtualBox"), (r"supermicro", "Supermicro"),
    (r"acer", "Acer"), (r"gigabyte", "Gigabyte"), (r"msi\b|micro-star", "MSI"), (r"realtek", "Realtek"),
    (r"liteon|lite-on|azurewave|foxconn|hon hai", "Wi-Fi/PC module"),
    # --- extended coverage -----------------------------------------------------------------------
    # This table's job is not to list every manufacturer on earth - brand_of() already falls back to
    # the IEEE OUI registry, which carries some 35,000 of them, so an unlisted vendor still gets named.
    # What these entries add is a CLEAN, consistent name for the messy strings that registry actually
    # contains ("Hewlett Packard Enterprise", "HP Inc.", "Hewlett-Packard Company" are one brand), plus
    # recognition from a hostname or banner when there is no useful OUI at all.
    # phones, tablets, wearables
    (r"\bnokia\b|hmd global", "Nokia"), (r"\bzte\b", "ZTE"), (r"\blenovo\b", "Lenovo"),
    (r"\bhtc\b", "HTC"), (r"asus", "ASUS"), (r"\bsharp\b", "Sharp"), (r"\btecno\b", "TECNO"),
    (r"infinix", "Infinix"), (r"\bitel\b", "itel"), (r"ulefone", "Ulefone"), (r"doogee", "DOOGEE"),
    (r"cat phones|bullitt", "CAT"), (r"\bgarmin\b", "Garmin"), (r"fitbit", "Fitbit"),
    (r"withings", "Withings"), (r"polar electro", "Polar"), (r"\bwhoop\b", "WHOOP"),
    # computers and workstations
    (r"dell\b", "Dell"), (r"hewlett packard enterprise|\bhpe\b", "HPE"), (r"framework computer", "Framework"),
    (r"system76", "System76"), (r"tuxedo computers", "TUXEDO"), (r"clevo", "Clevo"),
    (r"intel corp", "Intel"), (r"amd\b|advanced micro", "AMD"), (r"nvidia", "NVIDIA"),
    (r"raspberry pi", "Raspberry Pi"), (r"beagleboard", "BeagleBoard"), (r"hardkernel|odroid", "ODROID"),
    (r"pine64", "PINE64"), (r"\bminisforum\b", "MINISFORUM"), (r"\bzotac\b", "ZOTAC"),
    # printers and scanners
    (r"zebra tech", "Zebra"), (r"\bsato\b", "SATO"), (r"\bdymo\b", "DYMO"), (r"\bstar micronics\b", "Star Micronics"),
    (r"\boki\b|okidata", "OKI"), (r"\bsamsung electro.*print|\bml-\d{4}", "Samsung"),
    (r"\bprimera\b", "Primera"), (r"\broland dg\b", "Roland DG"), (r"\bmimaki\b", "Mimaki"),
    (r"\bultimaker\b", "UltiMaker"), (r"\bprusa\b", "Prusa"), (r"bambu lab", "Bambu Lab"),
    # network, firewall, wireless infrastructure
    (r"fortinet|fortigate", "Fortinet"), (r"palo alto net", "Palo Alto"), (r"sophos", "Sophos"),
    (r"watchguard", "WatchGuard"), (r"\bsonicwall\b", "SonicWall"), (r"check ?point", "Check Point"),
    (r"\bf5 networks\b", "F5"), (r"\bextreme networks\b", "Extreme"), (r"\bbrocade\b", "Brocade"),
    (r"\barista\b", "Arista"), (r"\bhuawei.*tech|\bhuawei\b", "Huawei"), (r"\balcatel-lucent\b", "Alcatel-Lucent"),
    (r"\bedgecore\b", "Edgecore"), (r"\btenda\b", "Tenda"), (r"\bmercusys\b", "Mercusys"),
    (r"\bengenius\b", "EnGenius"), (r"\bcambium\b", "Cambium"), (r"\bruijie\b", "Ruijie"),
    (r"\bgrandstream\b", "Grandstream"), (r"\bopnsense\b|\bpfsense\b|netgate", "Netgate"),
    (r"\bturris\b", "Turris"), (r"\bvodafone\b", "Vodafone"), (r"\bo2\b|telefonica", "O2"),
    (r"\bfreebox\b|\bfree sas\b", "Freebox"), (r"\bdeutsche telekom\b|\bspeedport\b", "Telekom"),
    (r"\bupc\b|liberty global", "UPC"), (r"\bsalt\b", "Salt"), (r"\binit7\b", "Init7"),
    # NAS, servers, virtualisation, storage
    (r"\btrunas\b|truenas|ixsystems", "TrueNAS"), (r"\bunraid\b|lime technology", "Unraid"),
    (r"\basustor\b", "ASUSTOR"), (r"\bterramaster\b", "TerraMaster"), (r"\bbuffalo\b", "Buffalo"),
    (r"\bnetapp\b", "NetApp"), (r"\bdell emc\b|\bemc corp\b", "Dell EMC"), (r"\bhitachi vantara\b", "Hitachi"),
    (r"\bproxmox\b", "Proxmox"), (r"\bnutanix\b", "Nutanix"), (r"\bcitrix\b|\bxen\b", "Citrix"),
    (r"\bqemu\b|red hat", "QEMU/KVM"), (r"\bparallels\b", "Parallels"), (r"microsoft hyper-?v", "Hyper-V"),
    # TV, audio, media, consoles
    (r"\bapple ?tv\b", "Apple"), (r"\bchromecast\b", "Google"), (r"\bfire ?tv\b", "Amazon"),
    (r"\bnvidia shield\b", "NVIDIA"), (r"\bdenon\b", "Denon"), (r"\bmarantz\b", "Marantz"),
    (r"\byamaha\b", "Yamaha"), (r"\bonkyo\b", "Onkyo"), (r"\bpioneer\b", "Pioneer"),
    (r"\bharman\b|\bjbl\b", "Harman"), (r"\bsennheiser\b", "Sennheiser"), (r"\bdevialet\b", "Devialet"),
    (r"\bbang ?& ?olufsen\b|bang og", "Bang & Olufsen"), (r"\bloewe\b", "Loewe"), (r"\bgrundig\b", "Grundig"),
    (r"\bpanasonic\b", "Panasonic"), (r"\bphilips\b", "Philips"), (r"\bsteam ?deck\b|\bvalve\b", "Valve"),
    (r"\bsonostv\b|\bnest\b", "Google"), (r"\bheos\b", "HEOS"), (r"\bbluesound\b", "Bluesound"),
    # smart home, sensors, industrial, building
    (r"\bshelly\b|allterco", "Shelly"), (r"\bsonoff\b|itead", "SONOFF"), (r"\baqara\b|lumi united", "Aqara"),
    (r"\bhomematic\b|\beq-?3\b", "Homematic"), (r"\bfibaro\b", "FIBARO"), (r"\bz-?wave\b", "Z-Wave"),
    (r"\bnetatmo\b", "Netatmo"), (r"\btado\b", "tado"), (r"\bnuki\b", "Nuki"), (r"\bdanalock\b", "Danalock"),
    (r"\bsomfy\b", "Somfy"), (r"\bvelux\b", "VELUX"), (r"\bhunter ?douglas\b", "Hunter Douglas"),
    (r"\bsiemens\b", "Siemens"), (r"\bschneider electric\b", "Schneider"), (r"\babb\b", "ABB"),
    (r"\bphoenix contact\b", "Phoenix Contact"), (r"\bbeckhoff\b", "Beckhoff"), (r"\bwago\b", "WAGO"),
    (r"\brockwell\b|allen-?bradley", "Rockwell"), (r"\bmoxa\b", "Moxa"), (r"\badvantech\b", "Advantech"),
    (r"\bknx\b|\bgira\b", "KNX"), (r"\bcrestron\b", "Crestron"), (r"\bextron\b", "Extron"),
    (r"\bapc\b|american power", "APC"), (r"\beaton\b", "Eaton"), (r"\briello\b", "Riello"),
    # point of sale, access control, time and attendance
    (r"\bingenico\b", "Ingenico"), (r"\bverifone\b", "Verifone"), (r"\bsumup\b", "SumUp"),
    (r"\bsquare, ?inc\b", "Square"), (r"\bworldline\b", "Worldline"), (r"\bnayax\b", "Nayax"),
    (r"\bhid global\b", "HID"), (r"\bsuprema\b", "Suprema"), (r"\bzkteco\b", "ZKTeco"),
    (r"\bdormakaba\b|\bkaba\b", "dormakaba"), (r"\bassa abloy\b", "ASSA ABLOY"), (r"\bsalto\b", "SALTO"),
    # VoIP and conferencing
    (r"\bpolycom\b|\bpoly\b", "Poly"), (r"\byealink\b", "Yealink"), (r"\bsnom\b", "snom"),
    (r"\bfanvil\b", "Fanvil"), (r"\bgigaset\b", "Gigaset"), (r"\bmitel\b", "Mitel"),
    (r"\bavaya\b", "Avaya"), (r"\bunify\b", "Unify"), (r"\blogitech\b", "Logitech"),
    (r"\bbarco\b", "Barco"), (r"\bneat\b|\bowl labs\b", "Meeting room device"),
    # medical and lab (hospital networks are full of these and nothing else names them)
    (r"\bdraeger\b|\bdräger\b", "Dräger"), (r"\bphilips healthcare\b", "Philips Healthcare"),
    (r"\bge healthcare\b", "GE Healthcare"), (r"\bsiemens healthineers\b", "Siemens Healthineers"),
    (r"\bmindray\b", "Mindray"), (r"\broche\b", "Roche"), (r"\babbott\b", "Abbott"),
    # consumer laptop / PC brands not already named above (several big in Switzerland / the DACH region)
    (r"wortmann|\bterra\b", "TERRA"), (r"\bmedion\b|\bakoya\b|\berazer\b", "Medion"), (r"\brazer\b", "Razer"),
    (r"\bdynabook\b", "Dynabook"), (r"\bfujitsu\b|\blifebook\b|\besprimo\b", "Fujitsu"),
    (r"\bvaio\b", "VAIO"), (r"\bchuwi\b", "CHUWI"), (r"\bgigabyte\b", "Gigabyte"),
]
BRAND_RX = [(re.compile(rx), b) for rx, b in BRANDS]
_SUFFIX = re.compile(r"\b(co\.?|ltd\.?|inc\.?|corp\.?|corporation|technologies|technology|electronics|gmbh|limited|"
                     r"international|communications|systems|digital|holdings|company|s\.a\.|ag|llc|plc)\b[,.]?",
                     re.I)

CAMERA_B = {"Hikvision", "Dahua", "Reolink", "Axis", "Amcrest", "Foscam", "Wyze", "Arlo", "eufy", "EZVIZ", "Uniview",
            "Vivotek", "Hanwha", "Lorex", "Annke", "Swann", "Imou", "Ring", "Mobotix", "GeoVision"}
PRINTER_B = {"Canon", "Epson", "Brother", "Xerox", "Ricoh", "Kyocera", "Lexmark", "Konica Minolta"}
MEDIA_B = {"Roku", "Sonos", "Vizio", "TCL", "Hisense", "Nintendo", "Sony PlayStation", "Microsoft Xbox", "Bose"}
NET_B = {"TP-Link", "Netgear", "AVM FRITZ!", "Ubiquiti", "MikroTik", "D-Link", "Linksys", "Zyxel", "Cisco", "Aruba",
         "Ruckus", "Juniper", "eero", "DrayTek", "Teltonika", "Swisscom", "Sunrise", "Technicolor", "Sagemcom",
         "Arcadyan", "Askey", "Sercomm", "ZTE", "ARRIS", "Compal", "Hitron"}
IOT_B = {"Espressif", "Tuya", "Shelly", "Philips Hue", "ecobee"}
SERVER_B = {"Synology", "QNAP", "Western Digital", "VMware", "VirtualBox", "Supermicro"}
PHONE_B = {"Samsung", "Xiaomi", "OnePlus", "OPPO", "vivo", "realme", "Motorola", "Fairphone", "Huawei"}
COMPUTER_PORTS = {135, 139, 445, 3389, 548, 5900}

# Laptop / notebook model lines -> the product line to show. Naming the LINE (not just the brand) is what
# turns "Dell" into "Dell Latitude" on an asset list. Matched against everything the device reveals about
# itself (hostname, mDNS/Bonjour model, UPnP, SNMP sysDescr, the MAC vendor). Order matters: more specific
# first. Deliberately high-precision - distinctive model names, not generic words that appear in banners.
LAPTOP_LINES = [
    (r"macbook ?air", "MacBook Air"), (r"macbook ?pro", "MacBook Pro"), (r"\bmacbook\b", "MacBook"),
    (r"\bthinkpad\b", "ThinkPad"), (r"\bthinkbook\b", "ThinkBook"), (r"\bideapad\b", "IdeaPad"),
    (r"\blegion\b", "Legion"), (r"\byoga\b", "Yoga"), (r"\bloq\b", "LOQ"),
    (r"\blatitude\b", "Latitude"), (r"\bxps\b", "XPS"), (r"\binspiron\b", "Inspiron"), (r"\bvostro\b", "Vostro"),
    (r"\bprecision\b", "Precision"), (r"\balienware\b", "Alienware"),
    (r"\belitebook\b", "EliteBook"), (r"\bprobook\b", "ProBook"), (r"\bzbook\b", "ZBook"),
    (r"\bpavilion\b", "Pavilion"), (r"\bspectre\b", "Spectre"), (r"\benvy\b", "Envy"), (r"\bomen\b", "OMEN"),
    (r"\bvictus\b", "Victus"),
    (r"\bzenbook\b", "ZenBook"), (r"\bvivobook\b", "VivoBook"), (r"\bexpertbook\b", "ExpertBook"),
    (r"\bzephyrus\b", "ROG Zephyrus"), (r"\brog\b|republic of gamers", "ROG"), (r"\btuf\b", "TUF"),
    (r"\baspire\b", "Aspire"), (r"\bswift\b", "Swift"), (r"\bnitro\b", "Nitro"), (r"\bpredator\b", "Predator"),
    (r"\btravelmate\b", "TravelMate"), (r"\bextensa\b", "Extensa"),
    (r"\bkatana\b", "Katana"), (r"\bcyborg\b", "Cyborg"), (r"\bstealth\b", "Stealth"), (r"\braider\b", "Raider"),
    (r"galaxy ?book", "Galaxy Book"), (r"\bmatebook\b", "MateBook"), (r"\bmagicbook\b", "MagicBook"),
    (r"lg ?gram", "LG gram"), (r"surface ?laptop", "Surface Laptop"), (r"surface ?book", "Surface Book"),
    (r"\bframework\b", "Framework Laptop"), (r"razer ?blade", "Razer Blade"),
    (r"\bmedion\b|\bakoya\b", "Medion"), (r"\bschenker\b|\bxmg\b", "SCHENKER/XMG"), (r"\btuxedo\b", "TUXEDO"),
    (r"wortmann|terra[- ]?(mobile|pad|book)", "TERRA"), (r"\bdynabook\b", "Dynabook"),
    (r"\blifebook\b", "Fujitsu LifeBook"), (r"\bvaio\b", "VAIO"), (r"\btoughbook\b|let's ?note", "Panasonic"),
    (r"\bchromebook\b", "Chromebook"),
    # model CODES, for laptops that announce "FX506" rather than "TUF" (matched after digits are split off)
    (r"\bf[xa] ?[5-7]\d\d", "TUF"), (r"\bg[auvz] ?[4-6]\d\d", "ROG Zephyrus"), (r"\bu[xm] ?[3-9]\d\d", "ZenBook"),
    (r"\bph ?[3-9]\d\d\b", "Predator"), (r"\bsf ?[1-5]\d\d\b", "Swift"), (r"\bmbp\b", "MacBook Pro"),
    # generic: no word boundary, because vendors glue it on ("ASUSLaptop", "HP-Laptop15", "MyNotebook")
    (r"notebook|laptop", "laptop"),
]
DESKTOP_LINES = [
    (r"\bimac\b", "iMac"), (r"mac ?mini", "Mac mini"), (r"mac ?studio", "Mac Studio"), (r"mac ?pro", "Mac Pro"),
    (r"\boptiplex\b", "OptiPlex"), (r"\bthinkcentre\b", "ThinkCentre"), (r"\bthinkstation\b", "ThinkStation"),
    (r"\belitedesk\b", "EliteDesk"), (r"\bprodesk\b", "ProDesk"), (r"\bproone\b", "ProOne"),
    (r"\bnuc\b", "Intel NUC"), (r"\besprimo\b", "Fujitsu ESPRIMO"),
    (r"\bworkstation\b", "workstation"), (r"\btower\b", "tower"),
    (r"desktop|(^|[-_ ])pc($|[-_. ])", "desktop PC"),
]
LAPTOP_RX = [(re.compile(rx), name) for rx, name in LAPTOP_LINES]
DESKTOP_RX = [(re.compile(rx), name) for rx, name in DESKTOP_LINES]

# Which company makes each model line. A laptop's MAC address belongs to its Wi-Fi / network card, and that
# card is usually made by someone else (most ASUS, MSI, Dell and Lenovo laptops ship Intel, Realtek,
# MediaTek or Qualcomm cards) - so "TUF" with an Intel MAC must read "ASUS TUF", not "Intel TUF".
MODEL_LINE_BRAND = {
    **dict.fromkeys(("MacBook Air", "MacBook Pro", "MacBook", "iMac", "Mac mini", "Mac Studio", "Mac Pro"), "Apple"),
    **dict.fromkeys(("ThinkPad", "ThinkBook", "IdeaPad", "Legion", "Yoga", "LOQ", "ThinkCentre", "ThinkStation"), "Lenovo"),
    **dict.fromkeys(("Latitude", "XPS", "Inspiron", "Vostro", "Precision", "Alienware", "OptiPlex"), "Dell"),
    **dict.fromkeys(("EliteBook", "ProBook", "ZBook", "Pavilion", "Spectre", "Envy", "OMEN", "Victus",
                     "EliteDesk", "ProDesk", "ProOne"), "HP"),
    **dict.fromkeys(("ZenBook", "VivoBook", "ExpertBook", "ROG Zephyrus", "ROG", "TUF"), "ASUS"),
    **dict.fromkeys(("Aspire", "Swift", "Nitro", "Predator", "TravelMate", "Extensa"), "Acer"),
    **dict.fromkeys(("Katana", "Cyborg", "Stealth", "Raider"), "MSI"),
    **dict.fromkeys(("Surface Laptop", "Surface Book", "Surface"), "Microsoft"),
    **dict.fromkeys(("Fujitsu LifeBook", "Fujitsu ESPRIMO"), "Fujitsu"),
    "Galaxy Book": "Samsung", "MateBook": "Huawei", "MagicBook": "Honor", "LG gram": "LG",
    "Framework Laptop": "Framework", "Razer Blade": "Razer", "Medion": "Medion", "SCHENKER/XMG": "SCHENKER",
    "TUXEDO": "TUXEDO", "TERRA": "TERRA", "Dynabook": "Dynabook", "VAIO": "VAIO", "Panasonic": "Panasonic",
    "Intel NUC": "Intel",
}
# Companies that make the Wi-Fi / Ethernet *chips or modules* inside other brands' computers. Their name in
# a MAC prefix says who made the network card, not who made the computer.
CHIP_VENDOR_RX = re.compile(r"(?i)\bintel\b|realtek|mediatek|qualcomm|atheros|broadcom|liteon|lite-on|azurewave|"
                            r"rivet|killer|hon ?hai|foxconn|murata|universal global|wistron|gemtek|ralink|marvell|"
                            r"chicony|cloud network technology|wi-fi/pc module")


def _match_line(blob, compiled):
    """First product line whose pattern appears in the device's text, or '' if none."""
    for rx, name in compiled:
        if rx.search(blob):
            return name
    return ""


def _hostpfx(*names, which):
    """True when a hostname follows the Windows default convention (LAPTOP-xxxx / DESKTOP-xxxx)."""
    for h in names:
        if h and h.lower().startswith(which + "-"):
            return True
    return False


def brand_of(blob, vendor):
    for rx, b in BRAND_RX:
        if rx.search(blob):
            return b
    v = _SUFFIX.sub("", vendor or "")
    v = re.sub(r"[\s,.\-]+$", "", re.sub(r"\s+", " ", v)).strip()
    return " ".join(v.split()[:2]).title() if v else ""


GENERIC_TITLES = {"", "index", "login", "home", "welcome", "document", "web management", "router", "401 unauthorized",
                  "404 not found", "403 forbidden", "error", "untitled", "index of /", "it works!"}


def identify(dev, gateway):
    """Decide what a device is. Fills type, brand, model, name, os and label."""
    up, web = dev.get("upnp") or {}, dev.get("http") or {}
    rdns = (dev.get("hostname") or "").split(".")[0]
    mnames = sorted(dev.get("mdns_names") or [])
    name = (up.get("name") or dev.get("mdns") or dev.get("netbios") or dev.get("wsd_name") or rdns
            or (mnames[0] if mnames else ""))
    wsd_kind, wsd_word = dev.get("wsd_kind") or ("", "")
    blob = " ".join([name, rdns, dev.get("mdns", ""), dev.get("netbios", ""), dev["vendor"], up.get("brand", ""),
                     dev.get("wsd_name", ""), dev.get("wsd_model", ""), " ".join(dev.get("wsd_types") or []),
                     up.get("model", ""), up.get("desc", ""), web.get("title", ""), web.get("server", ""),
                     web.get("realm", ""), " ".join(mnames), dev.get("mdns_model", "")]).lower()
    # what the device announces about itself over Bonjour/mDNS - see mdns_browse()
    hint = mdns_hint({"services": dev.get("mdns_svc") or [], "model": dev.get("mdns_model", ""),
                      "txt": dev.get("mdns_txt") or {}}) if (dev.get("mdns_svc") or dev.get("mdns_model")) else None
    if hint:
        blob += " " + " ".join([hint[3]] + [str(v) for v in (dev.get("mdns_txt") or {}).values()]).lower()
    ports, ttl = set(dev["ports"]), dev.get("ttl")
    brand = brand_of(blob, up.get("brand") or dev["vendor"])
    if hint and hint[2] and not brand:
        brand = hint[2]
    model = up.get("model", "") or (hint[3] if hint else "") or dev.get("wsd_model", "")
    if not model and web.get("title", "").lower() not in GENERIC_TITLES and len(web.get("title", "")) <= 40:
        model = web["title"]
    osg = "" if not ttl else ("Unix-like" if ttl <= 64 else "Windows" if ttl <= 128 else "Network gear")
    has = lambda *words: any(re.search(w, blob) for w in words)
    # hostnames glue separators and model numbers onto product names ("Galaxy-Book3", "XPS13", "NUC11"),
    # so split letter<->digit boundaries and treat - and _ as spaces before matching the model-line tables
    nblob = re.sub(r"(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])", " ", blob.replace("-", " ").replace("_", " "))
    lap_line = _match_line(nblob, LAPTOP_RX)    # a specific laptop model line if present: "Galaxy Book", "ThinkPad"...
    desk_line = _match_line(nblob, DESKTOP_RX)  # ...or a desktop one: "OptiPlex", "iMac", "tower"

    kind, word = "Unknown", "device"
    if dev["ip"] == gateway:
        kind, word = "Router", "Router / Gateway"
    elif hint and not hint[4]:
        kind, word = hint[0], hint[1]
    elif wsd_kind in ("Camera", "Printer"):          # stated by the device itself over WS-Discovery
        kind, word = wsd_kind, wsd_word
    elif ports & {554, 8554, 37777} or brand in CAMERA_B or has(r"\bcam\b|camera|\bipc\b|\bnvr\b|\bdvr\b|doorbell|tapo c"):
        kind, word = "Camera", "IP Camera"
    elif ports & {631, 9100, 515} or brand in PRINTER_B or has(r"printer|laserjet|officejet|deskjet|ecotank|pixma|\bmfc-"):
        kind, word = "Printer", "Printer"
    elif ports & {8008, 8009, 1400} or brand in MEDIA_B or has(
            r"chromecast|\btv\b|bravia|webos|smart-?tv|roku|fire ?tv|apple ?tv|homepod|sonos|\becho\b|soundbar|speaker|"
            r"playstation|xbox|nintendo|shield"):
        kind = "TV/Media"
        word = ("Game console" if has(r"playstation|xbox|nintendo") else
                "Speaker" if has(r"sonos|homepod|\becho\b|soundbar|speaker|bose") else
                "Chromecast" if has(r"chromecast") else
                "Streaming device" if has(r"roku|fire ?tv|apple ?tv|shield") else "Smart TV")
    elif not lap_line and not desk_line and (
            62078 in ports or has(r"iphone|ipad|android|galaxy|pixel|redmi|oneplus|oppo|realme|\bsm-|huawei")
            or (brand in PHONE_B and not ports & COMPUTER_PORTS)):
        # a laptop/desktop model line (Galaxy Book, MateBook, Pixelbook) outranks the "galaxy"/"pixel" phone keywords
        kind = "Phone"
        word = "iPad" if has("ipad") else "iPhone" if (has("iphone") or 62078 in ports) else "Phone / Tablet"
    elif brand in SERVER_B or has(r"\bnas\b|diskstation|proxmox|esxi"):
        kind, word = "Server", ("NAS" if brand in {"Synology", "QNAP", "Western Digital"} else "Server / VM")
    elif brand == "Raspberry Pi":
        kind, word = "Computer", ""
    elif lap_line or _hostpfx(rdns, name, which="laptop") or has(r"\bsurface\b|\bchromebook\b"):
        kind = "Laptop"
        word = lap_line if (lap_line and lap_line != "laptop") else ("Surface" if has(r"\bsurface\b") else "Laptop")
        if lap_line and lap_line != "laptop":
            model = model or lap_line
    elif desk_line or _hostpfx(rdns, name, which="desktop"):
        kind = "Desktop"
        word = desk_line if (desk_line and desk_line not in ("desktop PC", "tower", "workstation")) else "Desktop PC"
        if desk_line and desk_line not in ("desktop PC", "tower", "workstation"):
            model = model or desk_line
    elif brand in NET_B or has(r"router|fritz|gateway|access ?point|switch|\bap\b|repeater|mesh"):
        kind, word = "Network", "Network device (AP / switch / router)"
    elif brand in IOT_B:
        kind, word = "IoT", "Smart-home device"
    elif ports & COMPUTER_PORTS or 22 in ports or osg == "Windows" or wsd_kind == "Computer":
        kind = "Computer"
        word = "Windows PC" if (osg == "Windows" or ports & {135, 139, 445, 3389}) else \
               "Mac" if brand == "Apple" else "Computer"
    elif brand == "Apple":
        kind, word = "Phone", "iPhone / iPad / Mac"
    elif dev.get("random_mac") and not brand:
        kind, word = "Phone", "Phone / Tablet (private MAC)"
    elif brand or osg:
        kind, word = "IoT", "Network device"
    if kind in ("Unknown", "IoT") and hint and hint[4]:
        kind, word = "Computer", ("Mac" if brand == "Apple" else "Computer")

    # A recognised model line names its maker, and that beats a MAC prefix that only names the network
    # card's maker ("TUF" + an Intel Wi-Fi card = ASUS TUF). A real OEM prefix (Dell, Lenovo...) is kept.
    card = ""
    chip = bool(brand) and bool(CHIP_VENDOR_RX.search(brand))
    implied = MODEL_LINE_BRAND.get(word, "") if kind in ("Laptop", "Desktop") else ""
    if implied and (not brand or chip):
        brand = implied
    elif chip and kind in ("Laptop", "Desktop", "Computer") and implied != brand:
        # a PC whose maker we can't tell: don't pass the Wi-Fi chip off as the computer's brand
        card, brand = brand, ""

    label = f"{brand} {word}".strip() if word else brand
    if kind == "Unknown" and not brand:
        label = "Unknown device"
    if brand and word and word.lower().startswith(brand.lower()):
        label = word
    if model and model.lower() not in label.lower():
        label += f" ({model})"
    if card:
        label += " (third-party Wi-Fi module)" if "module" in card.lower() else f" ({card} network card)"
    # SNMP outranks every guess above it. Everything else here is inference - a MAC prefix, a banner, a
    # TTL - whereas sysDescr is the device stating its own model and firmware. Where it answered, it
    # decides the label and the name, and "Network gear" becomes something you could order a spare for.
    snmp = dev.get("snmp") or {}
    if snmp.get("sysdescr") or snmp.get("sysname"):
        descr = (snmp.get("sysdescr") or "").strip()
        dev["snmp_name"] = snmp.get("sysname", "")
        dev["snmp_descr"] = descr
        dev["snmp_uptime"] = fmt_uptime(snmp.get("sysuptime"))
        dev["snmp_location"] = snmp.get("syslocation", "")
        name = name or snmp.get("sysname", "")
        if descr:
            # sysDescr is often several lines of banner; the first line is the model and version
            first = descr.splitlines()[0].strip()
            label = first[:90] if first else label
            if kind in ("Unknown", "IoT") and re.search(r"(?i)switch|router|ios|junos|procurve|aruba|fortigate|mikrotik", descr):
                kind = "Network"
    dev.update(type=kind, brand=brand, model=model, name=name, os=osg, label=label or "Unknown device")
    dev["risk"], dev["risk_notes"] = risk_summary(ports)
    # an outdated / known-vulnerable web server announced in its own Server header
    wv = banner_vulns(web.get("server", ""))
    if wv:
        dev["risk_notes"] = list(dev["risk_notes"]) + [n for _s, n in wv]
        dev["risk"] = worst([dev["risk"] if dev["risk"] != "NONE" else ""] + [s for s, _n in wv]) or "LOW"
    # A certificate that expired last week is a live problem on a par with an exposed port, so it joins
    # the same risk line rather than hiding in a detail pane nobody opens. An expired or self-signed
    # cert lifts a device to at least MEDIUM; it never lowers a rating the ports already earned.
    cwarn = cert_warnings(dev.get("tls") or {})
    if cwarn:
        dev["risk_notes"] = list(dev.get("risk_notes") or []) + cwarn
        if any("EXPIRED" in w or "obsolete" in w for w in cwarn):
            dev["risk"] = "HIGH" if dev["risk"] == "HIGH" else "MEDIUM"
        elif dev["risk"] in ("NONE", "LOW"):
            dev["risk"] = "LOW" if dev["risk"] == "NONE" else dev["risk"]
    return dev


# ------------------------------------------------------------ active ARP discovery (Linux, root)
# The surest way to find a device on your own LAN is to ask for it by ARP: "who has 192.168.1.42?".
# Every host on the segment answers, even the ones that silently drop ping, speak no mDNS/WS-Discovery,
# and run no TCP service we probe. It is exactly what your OS already does to talk to a neighbour, so it
# is ordinary, benign local traffic - NOT a spoof: every request carries THIS machine's real IP and MAC,
# we only ever send requests (never forged replies), and we never claim another device's address.
# It needs a raw packet socket (Linux + root), so on anything else it returns {} and the scan falls back
# to the ping / ARP-cache / mDNS / WS-Discovery / NetBIOS / TCP methods it already uses.
def _arp_request_frame(src_mac_bytes, src_ip, target_ip):
    """Build one broadcast Ethernet+ARP 'who-has target_ip, tell src_ip' request. Pure bytes."""
    eth = b"\xff\xff\xff\xff\xff\xff" + src_mac_bytes + b"\x08\x06"        # dst broadcast, src us, ethertype ARP
    arp = (b"\x00\x01\x08\x00\x06\x04\x00\x01"                            # Ethernet/IPv4, hlen6 plen4, opcode REQUEST
           + src_mac_bytes + socket.inet_aton(src_ip)                     # sender hw + proto (us)
           + b"\x00\x00\x00\x00\x00\x00" + socket.inet_aton(target_ip))   # target hw unknown + proto
    frame = eth + arp
    return frame + b"\x00" * (60 - len(frame)) if len(frame) < 60 else frame   # pad to minimum frame size


def _parse_arp_reply(frame):
    """(sender_ip, sender_mac) from an Ethernet ARP *reply* frame, else None. Pure."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":      # too short, or not ARP
        return None
    arp = frame[14:]
    if arp[6:8] != b"\x00\x02":                             # opcode must be REPLY (2)
        return None
    return socket.inet_ntoa(arp[14:18]), ":".join(f"{b:02x}" for b in arp[8:14])


def _iface_for_ip(ip):
    """(iface_name, mac) for the Linux interface that currently holds `ip`, else ('', '')."""
    if OS != "Linux":
        return "", ""
    try:
        out = run(["ip", "-o", "-4", "addr", "show"])
    except Exception:
        return "", ""
    name = ""
    for line in out.splitlines():
        m = re.search(rf"^\d+:\s+(\S+)\s+inet\s+{re.escape(ip)}/", line)
        if m:
            name = m.group(1)
            break
    if not name:
        return "", ""
    return name, (_ifaces_linux().get(name) or {}).get("mac", "")


def arp_sweep(net, me_ip, cancel=None, wait=2.0):
    """Actively ARP every address in `net` and return {ip: mac} for everything that answers - including
    devices that are silent to ping and to every other probe. Linux + root only; on any other platform,
    missing privilege, or error it returns {} and never raises, so discovery degrades gracefully."""
    if OS != "Linux" or not hasattr(socket, "AF_PACKET") or not me_ip:
        return {}
    found = {}
    try:
        iface, mac = _iface_for_ip(me_ip)
        if not iface or not mac or mac == "00:00:00:00:00:00":
            return {}
        src_mac_bytes = bytes.fromhex(mac.replace(":", ""))
        if len(src_mac_bytes) != 6:
            return {}
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        try:
            s.bind((iface, socket.htons(0x0806)))
            targets = [str(h) for h in net.hosts() if str(h) != me_ip]
            for t in targets:
                if cancel is not None and cancel.is_set():
                    break
                try:
                    s.send(_arp_request_frame(src_mac_bytes, me_ip, t))
                except OSError:
                    break
            s.settimeout(0.3)
            end = time.time() + wait
            while time.time() < end:
                if cancel is not None and cancel.is_set():
                    break
                try:
                    frame = s.recv(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                r = _parse_arp_reply(frame)
                if not r:
                    continue
                try:
                    ok = ipaddress.ip_address(r[0]) in net and r[0] != me_ip
                except ValueError:
                    ok = False
                if ok:
                    found[r[0]] = norm_mac(r[1])
        finally:
            s.close()
    except (PermissionError, OSError, ValueError, AttributeError):
        return found
    return found


def scan(info, ports=True, vendors=True, log=print, cancel=None, deep=None, net=None):
    deep = ports if deep is None else deep
    stopped = (lambda: cancel is not None and cancel.is_set())
    me_ip = info.get("ip") or ""
    if net is None:
        if not me_ip or not info.get("mask"):
            log("Could not determine your network - are you connected?")
            return []
        net = ipaddress.ip_network(f"{me_ip}/{info['mask']}", strict=False)
        if net.num_addresses > 1024:  # keep sweeps sane on huge subnets
            net = ipaddress.ip_network(f"{me_ip}/24", strict=False)
    me_in = bool(me_ip) and ipaddress.ip_address(me_ip) in net
    hosts = [str(h) for h in net.hosts()]
    log(f"Scanning {net} ({len(hosts)} addresses)...")
    # Bonjour/mDNS discovery runs alongside the ping sweep: it finds devices that ignore ping entirely
    # (iPhones, many smart-home gadgets) and tells what they are, at no extra wall-clock cost
    mdns_box, mdns_t = {}, None
    if deep and me_in:
        def _mb():
            try:
                mdns_box.update(mdns_browse(me_ip, cancel=cancel))
            except Exception:
                pass
        mdns_t = threading.Thread(target=_mb, daemon=True)
        mdns_t.start()
    # WS-Discovery in parallel too: cameras, printers and Windows PCs that drop ping still answer it
    wsd_box, wsd_t = {}, None
    if deep and me_in:
        def _wb():
            try:
                wsd_box.update(wsd_browse(me_ip, cancel=cancel))
            except Exception:
                pass
        wsd_t = threading.Thread(target=_wb, daemon=True)
        wsd_t.start()
    # NetBIOS broadcast in parallel: one packet to the subnet broadcast, and every Windows / Samba host
    # answers with its name and MAC - catches the machines that block ping, at the cost of a single packet
    nbns_box, nbns_t = {}, None
    if deep and me_in and net.num_addresses <= 65536:
        bcast = str(net.broadcast_address)

        def _nb():
            try:
                nbns_box.update(nbns_broadcast(bcast, bind_ip=me_ip, cancel=cancel))
            except Exception:
                pass
        nbns_t = threading.Thread(target=_nb, daemon=True)
        nbns_t.start()
    # Active ARP sweep in parallel (Linux + root only): asks every address on the segment for its MAC and
    # catches devices that are silent to ping and to every other probe. Returns {} and costs nothing where
    # it isn't available, so the scan still has all its other discovery methods.
    arp_box, arp_sweep_t = {}, None
    if deep and me_in and net.num_addresses <= 4096:
        def _as():
            try:
                arp_box.update(arp_sweep(net, me_ip, cancel=cancel))
            except Exception:
                pass
        arp_sweep_t = threading.Thread(target=_as, daemon=True)
        arp_sweep_t.start()
    with cf.ThreadPoolExecutor(_workers(len(hosts))) as ex:
        res = list(ex.map(lambda h: (False, None, None) if stopped() else ping_rtt(h, 450), hosts))
    if stopped():
        return []
    t_sweep = time.time()
    alive = {h for h, (ok, _, _) in zip(hosts, res) if ok}
    ttls = {h: t for h, (ok, t, _) in zip(hosts, res) if ok and t}
    rtts = {h: m for h, (ok, _, m) in zip(hosts, res) if ok and m is not None}
    arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in net
           and ip != str(net.broadcast_address) and not ipaddress.ip_address(ip).is_multicast}
    # a single dropped ICMP packet shouldn't hide a real device, and some devices never answer ping at
    # all (ICMP blocked) but do answer a TCP connection - both are checked before giving up on an address.
    missed = [h for h in hosts if h not in alive and h not in arp]
    if missed and not stopped():
        log(f"Re-checking {len(missed)} silent address(es) (packet loss, or ICMP may be blocked)...")
        with cf.ThreadPoolExecutor(_workers(len(missed))) as ex:
            res2 = list(ex.map(lambda h: (False, None, None) if stopped() else ping_rtt(h), missed))
        rescued = 0
        for h, (ok, t, m) in zip(missed, res2):
            if ok:
                alive.add(h)
                rescued += 1
                if t:
                    ttls[h] = t
                if m is not None:
                    rtts[h] = m
        if rescued:
            log(f"{rescued} answered on the second try (packet loss on the first ping).")
        still_missing = [h for h in missed if h not in alive]
        if still_missing and not stopped():
            # One parallel sweep over every (address, port) pair, tuned to how fast this network actually
            # is - a silent address costs about one connect timeout instead of nine in series, so the whole
            # fallback finishes in a fraction of the time and still finds every ping-silent, TCP-reachable host.
            tcp_only = tcp_sweep(still_missing, timeout=adaptive_timeout(rtts.values()), stopped=stopped)
            if tcp_only:
                log(f"{len(tcp_only)} more answered a TCP connection but never ping (ICMP blocked) - still counted.")
            alive |= tcp_only
    if mdns_t is not None:
        mdns_t.join(timeout=4.0)
        mdns_box = dict(list(mdns_box.items()))
        extra = set()
        for ip in mdns_box:
            try:
                if ipaddress.ip_address(ip) in net and ip != str(net.broadcast_address):
                    extra.add(ip)
            except ValueError:
                pass
        newly = extra - alive - set(arp)
        if newly:
            log(f"{len(newly)} more device(s) found through Bonjour/mDNS (they don't answer ping).")
        alive |= extra
        if stopped():
            return []
    if wsd_t is not None:
        wsd_t.join(timeout=4.0)
        wsd_box = dict(list(wsd_box.items()))
        extra = set()
        for ip in wsd_box:
            try:
                if ipaddress.ip_address(ip) in net and ip != str(net.broadcast_address):
                    extra.add(ip)
            except ValueError:
                pass
        newly = extra - alive - set(arp)
        if newly:
            log(f"{len(newly)} more device(s) found through WS-Discovery (cameras / printers / PCs that ignore ping).")
        alive |= extra
        if stopped():
            return []
    if nbns_t is not None:
        nbns_t.join(timeout=3.0)
        nbns_box = dict(list(nbns_box.items()))
        extra = set()
        for ip in nbns_box:
            try:
                if ipaddress.ip_address(ip) in net and ip != str(net.broadcast_address):
                    extra.add(ip)
            except ValueError:
                pass
        newly = extra - alive - set(arp)
        if newly:
            log(f"{len(newly)} more device(s) found through NetBIOS (Windows / file-sharing hosts that ignore ping).")
        alive |= extra
        if stopped():
            return []
    if arp_sweep_t is not None:
        arp_sweep_t.join(timeout=4.0)
        arp_box = dict(list(arp_box.items()))
        newly = {ip for ip in arp_box if ip not in alive and ip not in arp}
        if newly:
            log(f"{len(newly)} more device(s) found by active ARP (silent to ping and every other probe).")
        for ip, mac in arp_box.items():
            alive.add(ip)
            arp.setdefault(ip, mac)        # ARP reply carries the MAC even for otherwise-silent devices
        if stopped():
            return []
    found = sorted(set(arp) | alive | ({me_ip} if me_in else set()), key=lambda x: tuple(map(int, x.split("."))))
    log(f"{len(found)} device(s) answered. Identifying them...")
    oui = load_oui(log=log) if vendors else {}
    ipv6_by_mac = ipv6_neighbors() if net is None or net == ipaddress.ip_network(f"{me_ip}/{info.get('mask', 32)}", strict=False) else {}
    devs = {}
    for ip in found:
        mac = arp.get(ip, "")
        first = int(mac.split(":")[0], 16) if mac else 0
        ipv6 = sorted(ipv6_by_mac.get(mac, [])) if mac else []
        devs[ip] = {"ip": ip, "mac": mac, "alive": ip in alive or ip == me_ip, "ports": [], "ttl": ttls.get(ip), "rtt": rtts.get(ip),
                    "vendor": vendor_of(mac, oui),
                    "random_mac": bool(mac) and bool(first & 2), "hostname": "", "netbios": "", "mdns": "",
                    "upnp": {}, "http": {}, "ipv6": ", ".join(ipv6)}
    for ip, rec in nbns_box.items():
        if ip in devs:
            if rec.get("name"):
                devs[ip]["netbios"] = rec["name"]
            if not devs[ip]["mac"] and rec.get("mac"):      # NetBIOS reports the MAC even with no ARP entry yet
                devs[ip]["mac"] = rec["mac"]
                first = int(rec["mac"].split(":")[0], 16)
                devs[ip]["vendor"] = vendor_of(rec["mac"], oui)
                devs[ip]["random_mac"] = bool(first & 2)
    for ip, rec in wsd_box.items():
        if ip in devs:
            devs[ip]["wsd_types"], devs[ip]["wsd_name"] = list(rec.get("types") or []), rec.get("name", "")
            devs[ip]["wsd_model"], devs[ip]["wsd_kind"] = rec.get("model", ""), (rec.get("kind"), rec.get("word"))
    for ip, rec in mdns_box.items():
        if ip in devs:
            devs[ip]["mdns_svc"] = sorted(rec.get("services") or [])
            devs[ip]["mdns_names"] = sorted(rec.get("names") or [])
            devs[ip]["mdns_model"] = rec.get("model", "")
            devs[ip]["mdns_txt"] = dict(rec.get("txt") or {})
    with cf.ThreadPoolExecutor(64) as ex:
        ssdp_f = ex.submit(ssdp_discover, me_ip) if (deep and me_in) else None
        # hostname lookups and port probes write to different keys of the same per-ip dicts and have no
        # data dependency on each other, so both are submitted to the shared pool together instead of one
        # strictly waiting for the other to finish first - genuine wall-clock time saved, same results.
        hostname_jobs = {ip: ex.submit(hostname_of, ip) for ip in found}
        if ports:
            log("Probing common ports...")
        # tune the per-port connect timeout to this network's measured speed - a fast LAN needn't wait
        # the full fixed timeout on every firewalled port (see adaptive_timeout); slow networks are unchanged
        ptimeout = adaptive_timeout(list(rtts.values()))
        port_jobs = ([ex.submit(lambda a, b: None if stopped() else probe(a, b, ptimeout), ip, p)
                      for ip in found if ip != me_ip for p in PORTS] if ports else [])
        for ip, fut in hostname_jobs.items():
            devs[ip]["hostname"] = fut.result()
        for j in port_jobs:
            r = j.result()
            if r:
                devs[r[0]]["ports"].append(r[1])
        if deep and not stopped():
            log("Fingerprinting (NetBIOS, mDNS, UPnP, web interface)...")
            ssdp = ssdp_f.result() if ssdp_f else {}
            others = [ip for ip in found if ip != me_ip]
            fps = ex.map(lambda ip: fingerprint(ip, set(devs[ip]["ports"]), ssdp.get(ip)), others)
            for ip, fp in zip(others, fps):
                devs[ip].update(fp)
    if stopped():
        return []
    # devices first seen by TCP or mDNS (not ping) often had no ARP entry yet when the table was read;
    # the probes since then have talked to them, so a second read fills in their hardware address
    if any(not d["mac"] for ip, d in devs.items() if ip != me_ip):
        try:
            arp2 = arp_table()
        except Exception:
            arp2 = {}
        for ip, d in devs.items():
            if not d["mac"] and arp2.get(ip):
                d["mac"] = arp2[ip]
                d["vendor"] = vendor_of(d["mac"], oui)
                try:
                    d["random_mac"] = bool(int(d["mac"].split(":")[0], 16) & 2)
                except ValueError:
                    pass
    # ARP-only addresses: the device answered nothing we sent. Either it is there and silent (a phone
    # asleep, a locked-down IoT box) or it left and only its cache entry remains - the OS can tell which.
    arp_only = [ip for ip, d in devs.items() if ip != me_ip and not d["alive"] and not d["ports"]
                and ip not in mdns_box and ip not in wsd_box and ip not in nbns_box]
    if arp_only and not stopped():
        try:
            gone = drop_arp_ghosts(arp_only, t_sweep, log=log, cancel=cancel)
        except Exception:
            gone = set()
        for ip in gone:
            devs.pop(ip, None)
        for ip in arp_only:
            if ip in devs:
                devs[ip]["arp_only"] = True
    for d in devs.values():
        d["ports"].sort()
        identify(d, info.get("gateway"))
        if d["ip"] == me_ip:  # the machine running the scan
            d["name"] = socket.gethostname()
            d["type"] = "Computer"
            d["os"] = {"Windows": "Windows", "Linux": "Linux", "Darwin": "macOS"}.get(OS, OS)
            d["label"] = f"{d['brand'] + ' ' if d['brand'] else ''}{d['os']} computer (this device)"
            d["ipv6"] = d["ipv6"] or ", ".join(info.get("ipv6_all") or [])
    result = list(devs.values())
    apply_notes(result)           # saved notes/tags survive every re-scan - keyed by MAC, not by this run
    # Both of these read files that were already being written and never read back for this purpose: the
    # by-MAC store that holds notes and approvals, and the scan history. Nothing extra is collected, and
    # a device gains "known here since March" or "never seen before" without another packet being sent.
    try:
        apply_seen(result)
    except Exception:
        pass                      # history is a convenience; a damaged folder must not fail a scan
    return result


# --- latency quality ------------------------------------------------------------------------------------
def latency_stats(samples, sent=0, received=None):
    """min / avg / max / jitter / loss% from a run of round-trip times.

    A single latency figure answers "is it reachable". It does not answer "is this link any good", which
    is what someone actually wants to know when a call keeps breaking up - and that question is answered
    by how much the number MOVES, not what it is. Jitter here is the mean absolute difference between
    consecutive samples: close enough to the RFC 3550 idea for a diagnostic readout, and far easier to
    reason about than a smoothed estimator when you are staring at a table.
    """
    vals = [v for v in (samples or []) if v is not None]
    received = len(vals) if received is None else received
    out = {"n": len(vals), "min": None, "avg": None, "max": None, "jitter": None, "loss": None}
    if sent:
        out["loss"] = round(100.0 * (sent - received) / sent, 1)
    if not vals:
        return out
    out["min"], out["max"] = round(min(vals), 1), round(max(vals), 1)
    out["avg"] = round(sum(vals) / len(vals), 1)
    if len(vals) > 1:
        out["jitter"] = round(sum(abs(b - a) for a, b in zip(vals, vals[1:])) / (len(vals) - 1), 1)
    return out


def link_quality(stats):
    """One word for a latency profile, so a long table can be skimmed. Jitter is weighted more heavily
    than raw latency on purpose: 120ms that never moves carries a call perfectly well, and 20ms that
    swings to 200ms does not."""
    if not stats or stats.get("avg") is None:
        return ""
    loss, jit, avg = stats.get("loss") or 0, stats.get("jitter") or 0, stats["avg"]
    if loss >= 10 or jit >= 60:
        return "BAD"
    if loss >= 2 or jit >= 25 or avg >= 300:
        return "POOR"
    if jit >= 10 or avg >= 120:
        return "OK"
    return "GOOD"


# --- LLDP / CDP neighbours (needs elevation) -------------------------------------------------------------
LLDP_MAC = "01:80:c2:00:00:0e"
CDP_MAC = "01:00:0c:cc:cc:cc"


def lldp_listen(seconds=35.0, log=print, cancel=None):
    """Listen for LLDP/CDP announcements and report which switch and port this machine is plugged into.

    This is the one piece of information nothing else here can work out: every other tool sees the
    network from the inside, whereas the switch itself announces its own name and the exact port the
    cable lands on. Worth the wait - switches announce on a timer, typically every 30 seconds, which
    is why the default listen window is a little over that.

    Needs a raw packet socket, so it needs elevation, and raw capture is only portable on Linux here:
    Windows would need a capture driver (npcap) installed and macOS needs access to a BPF device. Rather
    than failing obscurely, those cases return a plain explanation of what is missing.
    """
    if OS != "Linux":
        need = ("Windows needs a capture driver (npcap) for this" if OS == "Windows"
                else "macOS needs permission on a /dev/bpf device for this")
        return [], f"Listening for switch announcements is only supported on Linux in this build - {need}."
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        return [], ("Listening for switch announcements needs administrator rights (a raw packet socket). "
                    "Run NetScout with sudo for this one tool; nothing else here needs it.")
    except (AttributeError, OSError) as e:
        return [], f"Could not open a raw packet socket: {e}"
    found, end = {}, time.time() + seconds
    try:
        s.settimeout(1.0)
        while time.time() < end:
            if cancel is not None and cancel.is_set():
                break
            try:
                frame = s.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(frame) < 15:
                continue
            dst = ":".join(f"{b:02x}" for b in frame[0:6])
            etype = int.from_bytes(frame[12:14], "big")
            if etype == 0x88CC or dst == LLDP_MAC:
                rec = _parse_lldp(frame[14:])
                if rec:
                    rec["proto"] = "LLDP"
                    found[rec.get("chassis", "") + rec.get("port", "")] = rec
            elif dst == CDP_MAC:
                rec = _parse_cdp(frame)
                if rec:
                    rec["proto"] = "CDP"
                    found[rec.get("chassis", "") + rec.get("port", "")] = rec
    finally:
        try:
            s.close()
        except Exception:
            pass
    if not found:
        return [], ("Nothing announced itself within the listening window. Either the switch has LLDP/CDP "
                    "switched off, or this machine is behind something that does not forward it "
                    "(a desk hub, a VM bridge, or WiFi).")
    return list(found.values()), ""


def _parse_lldp(buf):
    """LLDP is a run of type/length/value records. Only the few worth showing are decoded."""
    out, i = {}, 0
    want = {1: "chassis", 2: "port", 3: "ttl", 4: "port_desc", 5: "name", 6: "desc"}
    while i + 2 <= len(buf):
        hdr = int.from_bytes(buf[i:i + 2], "big")
        t, n = hdr >> 9, hdr & 0x1FF
        i += 2
        val = buf[i:i + n]
        i += n
        if t == 0:                                      # end of frame
            break
        key = want.get(t)
        if not key:
            continue
        if t in (1, 2):
            # first byte is a subtype saying how to read the rest; a MAC comes as 6 raw bytes, and
            # anything else is text the switch chose itself
            body = val[1:]
            out[key] = (":".join(f"{b:02x}" for b in body) if len(body) == 6 and val[:1] in (b"\x04", b"\x03")
                        else body.decode("utf-8", "replace").strip("\x00 "))
        elif t == 3:
            out[key] = int.from_bytes(val, "big") if val else 0
        else:
            out[key] = val.decode("utf-8", "replace").strip("\x00 ")
    return out if out.get("chassis") or out.get("name") else {}


def _parse_cdp(frame):
    """CDP rides inside an 802.3 frame with a SNAP header; its body is type/length/value much like LLDP."""
    i = frame.find(b"\xaa\xaa\x03\x00\x00\x0c\x20\x00")
    if i < 0:
        return {}
    buf, out = frame[i + 8:], {}
    if len(buf) < 4:
        return {}
    j = 4                                               # version + ttl + checksum
    want = {1: "chassis", 3: "port", 5: "desc", 6: "model"}
    while j + 4 <= len(buf):
        t = int.from_bytes(buf[j:j + 2], "big")
        n = int.from_bytes(buf[j + 2:j + 4], "big")
        if n < 4 or j + n > len(buf):
            break
        val = buf[j + 4:j + n]
        j += n
        key = want.get(t)
        if key:
            out[key] = val.decode("utf-8", "replace").strip("\x00 ")
    return out if out.get("chassis") else {}


def lldp_lines(neighbours, err=""):
    if err:
        return [err]
    out = ["This machine is plugged into:", ""]
    for n in neighbours:
        out.append(f"  {n.get('name') or n.get('chassis', '?')}   ({n.get('proto', '')})")
        if n.get("port") or n.get("port_desc"):
            out.append(f"     port    : {n.get('port', '')}{'  - ' + n['port_desc'] if n.get('port_desc') else ''}")
        if n.get("chassis"):
            out.append(f"     chassis : {n['chassis']}")
        if n.get("model"):
            out.append(f"     model   : {n['model']}")
        if n.get("desc"):
            out.append(f"     software: {n['desc'].splitlines()[0][:100]}")
        out.append("")
    return out


# --- rogue DHCP servers ----------------------------------------------------------------------------------
def dhcp_servers(seconds=5.0, log=print, cancel=None):
    """Ask the network for an address and count who answers. More than one answer is the finding.

    A second DHCP server - someone's home router plugged in the wrong way round, a lab box left running,
    a VM bridging to the LAN - hands out addresses and a gateway for a network it knows nothing about,
    and the result is a handful of machines that mysteriously cannot reach anything while everything
    else is fine. It is a miserable fault to chase by hand and a trivial one to detect.

    Nothing is accepted: this sends DISCOVER and listens for OFFERs, then stops. No address is taken
    and no REQUEST is ever sent, so running it changes nothing on the network.
    """
    xid = random.getrandbits(32)
    # The client MAC goes in the DISCOVER. An all-zero one is legal but some servers decline to answer
    # it, so the real address of whichever interface carries this machine's own IP is used when it can
    # be worked out - that is the interface the broadcast will go out of.
    mac, me_ip = b"\x00" * 6, (net_info() or {}).get("ip", "")
    for ifc in list_interfaces():
        if ifc.get("mac") and (me_ip in (ifc.get("ipv4") or []) or not me_ip):
            raw = ifc["mac"].replace(":", "")
            if len(raw) == 12:
                try:
                    mac = bytes.fromhex(raw)
                except ValueError:
                    pass
            break
    pkt = (b"\x01\x01\x06\x00" + xid.to_bytes(4, "big") + b"\x00\x00\x80\x00"
           + b"\x00" * 16 + mac + b"\x00" * 10 + b"\x00" * 192
           + b"\x63\x82\x53\x63"                       # magic cookie
           + b"\x35\x01\x01"                           # DHCP message type = DISCOVER
           + b"\x37\x03\x01\x03\x06"                   # parameter request: mask, router, DNS
           + b"\xff")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", 68))
        except OSError:
            # port 68 is privileged, and often already held by the machine's own DHCP client. An
            # ephemeral port still reaches servers that reply to the source port; those that insist on
            # broadcasting back to 68 will be missed, so say so rather than reporting a clean result.
            s.bind(("", 0))
            partial = True
        else:
            partial = False
        s.settimeout(1.0)
        s.sendto(pkt, ("255.255.255.255", 67))
        seen, end = {}, time.time() + seconds
        while time.time() < end:
            if cancel is not None and cancel.is_set():
                break
            try:
                data, addr = s.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 240 or data[0] != 2 or int.from_bytes(data[4:8], "big") != xid:
                continue
            rec = _parse_dhcp_offer(data)
            rec["from"] = addr[0]
            seen[rec.get("server") or addr[0]] = rec
        note = ("Note: could not listen on the DHCP client port (it needs administrator rights, or this "
                "machine's own DHCP client already holds it), so a server that only broadcasts its reply "
                "may have been missed." if partial else "")
        return list(seen.values()), note
    except Exception as e:
        return [], f"Could not send a DHCP probe: {e}"
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _parse_dhcp_offer(data):
    out = {"offered": socket.inet_ntoa(data[16:20]), "server": "", "router": "", "mask": "", "dns": []}
    # Options always follow the 4-byte magic cookie, which a conforming server puts at offset 240. Found
    # rather than assumed: it costs nothing, and a fixed offset reads the cookie itself as an option if
    # anything upstream pads the fixed header differently.
    cookie = data.find(b"\x63\x82\x53\x63", 236)
    if cookie < 0:
        return out
    i = cookie + 4
    while i + 2 <= len(data):
        opt, n = data[i], data[i + 1]
        if opt == 255:
            break
        val = data[i + 2:i + 2 + n]
        i += 2 + n
        if opt == 54 and len(val) == 4:
            out["server"] = socket.inet_ntoa(val)
        elif opt == 1 and len(val) == 4:
            out["mask"] = socket.inet_ntoa(val)
        elif opt == 3 and len(val) >= 4:
            out["router"] = socket.inet_ntoa(val[:4])
        elif opt == 6:
            out["dns"] = [socket.inet_ntoa(val[j:j + 4]) for j in range(0, len(val) - 3, 4)]
    return out


def dhcp_lines(servers, note="", expected=""):
    if not servers:
        return ["No DHCP server answered." + (f"\n{note}" if note else "")]
    out = [f"{len(servers)} DHCP server(s) answered:", ""]
    for s in servers:
        flag = ""
        if expected and s.get("server") and s["server"] != expected:
            flag = "   <-- NOT the expected server"
        out.append(f"  {s.get('server') or s.get('from', '?')}{flag}")
        out.append(f"     offered : {s.get('offered', '')}   mask {s.get('mask', '-')}")
        out.append(f"     gateway : {s.get('router', '-')}   DNS {', '.join(s.get('dns') or []) or '-'}")
        out.append("")
    if len(servers) > 1:
        out.append("MORE THAN ONE DHCP SERVER IS ANSWERING on this network.")
        out.append("Unless that is deliberate (two servers deliberately sharing one scope), one of them")
        out.append("is handing out addresses it should not be, and the machines that happen to get an")
        out.append("address from it will have intermittent or no connectivity.")
    if note:
        out += ["", note]
    return out


# --- SNMP v2c, read-only -------------------------------------------------------------------------------
# Port 161 was already recognised by name and flagged as a risk, but never actually asked anything. One
# read-only GET of the system group turns "Network gear / Unknown device" into the exact model and
# firmware the device reports about itself - by far the most precise identification available on a
# network with managed switches, printers and access points, and it comes straight from the horse's
# mouth rather than from guessing at a MAC prefix.
#
# Written against the wire format directly rather than pulling in pysnmp, to keep the stdlib-only
# promise. SNMP's encoding is BER, which is simple enough for the few types a GET response can contain.
SNMP_OIDS = {"1.3.6.1.2.1.1.1.0": "sysdescr",    # free-text model/firmware string
             "1.3.6.1.2.1.1.3.0": "sysuptime",   # hundredths of a second since boot
             "1.3.6.1.2.1.1.5.0": "sysname",     # the device's own configured name
             "1.3.6.1.2.1.1.6.0": "syslocation"}
# "public" is the default read community on an enormous amount of gear, which is exactly why port 161
# is flagged as a risk in the first place. Tried in order; the first that answers wins.
SNMP_COMMUNITIES = ("public", "private")


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ber_tlv(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _ber_int(n):
    if n == 0:
        return _ber_tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return _ber_tlv(0x02, b.lstrip(b"\x00") or b"\x00")


def _ber_oid(oid):
    arcs = [int(x) for x in oid.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        if arc < 0x80:
            body += bytes([arc])
            continue
        chunks = []
        while arc:
            chunks.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        chunks[-1] &= 0x7F
        body += bytes(chunks)
    return _ber_tlv(0x06, body)


def _ber_parse(buf, i=0):
    """Minimal BER reader: returns (tag, value_bytes, next_index). Enough for a GET response."""
    tag = buf[i]
    n = buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


def _snmp_values(payload):
    """Pull the varbind values out of a GET response, as {oid: value}."""
    out = {}

    def walk(buf, depth=0):
        i = 0
        while i < len(buf) and depth < 8:
            try:
                tag, val, i = _ber_parse(buf, i)
            except (IndexError, ValueError):
                return
            if tag in (0x30, 0xA2):                       # SEQUENCE / GetResponse-PDU: descend
                if tag == 0x30 and len(val) > 2 and val[0] == 0x06:
                    try:
                        otag, oid_bytes, j = _ber_parse(val, 0)
                        vtag, vval, _ = _ber_parse(val, j)
                    except (IndexError, ValueError):
                        continue
                    out[_oid_str(oid_bytes)] = _snmp_scalar(vtag, vval)
                else:
                    walk(val, depth + 1)
    walk(payload)
    return out


def _oid_str(b):
    arcs = [b[0] // 40, b[0] % 40]
    cur = 0
    for byte in b[1:]:
        cur = (cur << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(cur)
            cur = 0
    return ".".join(str(a) for a in arcs)


def _snmp_scalar(tag, val):
    if tag == 0x04:                                        # OCTET STRING
        return val.decode("utf-8", "replace").strip()
    if tag in (0x02, 0x41, 0x42, 0x43, 0x44, 0x45):        # INTEGER / Counter / Gauge / TimeTicks
        return int.from_bytes(val, "big") if val else 0
    if tag == 0x06:
        return _oid_str(val)
    if tag in (0x05, 0x80, 0x81, 0x82):                    # NULL, or "no such object/instance"
        return None
    return val.decode("utf-8", "replace").strip() if val else None


def snmp_get(ip, oids=None, communities=SNMP_COMMUNITIES, timeout=0.6, port=161):
    """Read-only SNMP v2c GET. Returns {short_name: value} or {} if nothing answered.

    Deliberately quiet: a device with 161 closed, a wrong community, a v3-only agent or an ACL that
    drops us all look the same from here - no answer - and none of them is worth a message to the user
    during a scan. UDP, so a single short timeout is the whole cost of asking.
    """
    oids = oids or list(SNMP_OIDS)
    for community in communities:
        varbinds = b"".join(_ber_tlv(0x30, _ber_oid(o) + _ber_tlv(0x05, b"")) for o in oids)
        pdu = _ber_tlv(0xA0, _ber_int(random.randint(1, 0x7FFFFFFF)) + _ber_int(0) + _ber_int(0)
                       + _ber_tlv(0x30, varbinds))
        pkt = _ber_tlv(0x30, _ber_int(1) + _ber_tlv(0x04, community.encode()) + pdu)
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (ip, port))
            data, _ = s.recvfrom(4096)
        except Exception:
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
        vals = _snmp_values(data)
        got = {SNMP_OIDS[o]: v for o, v in vals.items() if o in SNMP_OIDS and v not in (None, "")}
        if got:
            got["community"] = community
            return got
    return {}


def _snmp_reqid(data):
    """The request-id out of a response PDU, or None. Matching it is what tells a reply to THIS request
    apart from a late or duplicated reply to the previous one - over UDP both arrive on the same socket
    and look alike, and accepting the wrong one walks a table backwards and ends it early."""
    try:
        tag, body, _ = _ber_parse(data, 0)                     # outer SEQUENCE
        if tag != 0x30:
            return None
        i = 0
        for _ in range(2):                                     # version, community
            _, _, i = _ber_parse(body, i)
        ptag, pdu, _ = _ber_parse(body, i)
        # every SNMP PDU type carries the request-id as its first field: GetRequest (A0), GetNext (A1),
        # Response (A2), SetRequest (A3), GetBulk (A5). A3 was missing, so the id could not be read off a
        # SetRequest - which made a switch that correctly applied a SET look like one that never answered.
        if ptag not in (0xA0, 0xA1, 0xA2, 0xA3, 0xA5):
            return None
        vtag, val, _ = _ber_parse(pdu, 0)
        return int.from_bytes(val, "big") if vtag == 0x02 else None
    except (IndexError, ValueError):
        return None


def _oid_tuple(oid):
    """An OID compared as numbers, not as text. "1.3.6.1.2.1.2.2.1.2.10" sorts BEFORE ".2" as a string
    and after it as a number, and the walk below depends on getting that right."""
    try:
        return tuple(int(x) for x in oid.split("."))
    except ValueError:
        return ()


def snmp_walk(ip, base, community=None, communities=SNMP_COMMUNITIES, timeout=0.8, limit=4096, port=161):
    """Walk an SNMP table with repeated GETNEXT. Returns {oid: value} for everything under `base`.

    GET only reads one named thing; a switch's interesting data lives in TABLES - one row per port -
    and reading those needs GETNEXT, which asks "what comes after this OID" and is walked until the
    answers leave the subtree. That is the whole difference between reading a device's name and
    reading the state of all 48 of its ports.
    """
    comms = [community] if community else list(communities)
    for comm in comms:
        out, cur, sock = {}, base, None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            while len(out) < limit:
                xid = random.randint(1, 0x7FFFFFFF)
                pdu = _ber_tlv(0xA1,                                   # GETNEXT
                               _ber_int(xid) + _ber_int(0) + _ber_int(0)
                               + _ber_tlv(0x30, _ber_tlv(0x30, _ber_oid(cur) + _ber_tlv(0x05, b""))))
                pkt = _ber_tlv(0x30, _ber_int(1) + _ber_tlv(0x04, comm.encode()) + pdu)
                vals = None
                # Up to three goes at each step, RE-SENDING on a timeout rather than giving up. SNMP
                # runs over UDP, so a dropped request or reply is ordinary rather than exceptional -
                # and abandoning the walk on the first one silently truncates the table, which is far
                # worse than slow: a missing row reads as a port that does not exist.
                for attempt in range(3):
                    try:
                        sock.sendto(pkt, (ip, port))
                        for _ in range(4):
                            data, _addr = sock.recvfrom(8192)
                            # the reply must be to THIS request: over UDP a late answer to the previous
                            # one arrives on the same socket and looks identical otherwise, and taking
                            # it walks the table backwards
                            if _snmp_reqid(data) != xid:
                                continue
                            cand = _snmp_values(data)
                            if cand and all(_oid_tuple(o) > _oid_tuple(cur) for o in cand):
                                vals = cand
                            break
                    except socket.timeout:
                        continue
                    if vals:
                        break
                if not vals:
                    break
                nxt = None
                for oid, val in vals.items():
                    if not oid.startswith(base + ".") and oid != base:
                        nxt = None
                        break                                          # walked off the end of the table
                    out[oid] = val
                    nxt = oid
                if not nxt:
                    break
                cur = nxt
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        if out:
            return out
    return {}


# Interface table columns worth reading. ifHighSpeed is in Mbit/s and is the one to trust: ifSpeed is a
# 32-bit value in bit/s and saturates at 4.2Gbit/s, so it cannot describe a 10G port at all.
IF_COLS = {"name": "1.3.6.1.2.1.31.1.1.1.1", "alias": "1.3.6.1.2.1.31.1.1.1.18",
           "descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3",
           "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8",
           "high_speed": "1.3.6.1.2.1.31.1.1.1.15",
           "in_err": "1.3.6.1.2.1.2.2.1.14", "out_err": "1.3.6.1.2.1.2.2.1.20",
           "in_oct": "1.3.6.1.2.1.2.2.1.10", "out_oct": "1.3.6.1.2.1.2.2.1.16",
           "discards": "1.3.6.1.2.1.2.2.1.13", "last_change": "1.3.6.1.2.1.2.2.1.9"}
FCS_ERRORS = "1.3.6.1.2.1.10.7.2.1.3"      # dot3StatsFCSErrors - the cable-quality counter


def snmp_ports(ip, community=None, log=print, cancel=None, port=161):
    """Every physical port on a switch, with the numbers that say whether its cable is healthy.

    Returns ([{port fields}], error). Ethernet ports only - the loopbacks, VLANs and tunnels that
    share the same table are filtered out, because none of them has a cable to be wrong about.
    """
    first = snmp_get(ip, communities=[community] if community else SNMP_COMMUNITIES, port=port)
    if not first:
        return [], (f"{ip} did not answer SNMP. The switch needs SNMP v2c enabled and a read community "
                    "this machine is allowed to use (the default 'public' and 'private' were tried).")
    comm = first.get("community", "public")
    cols = {}
    for key, base in IF_COLS.items():
        if cancel is not None and cancel.is_set():
            return [], ""
        cols[key] = {o.rsplit(".", 1)[-1]: v for o, v in snmp_walk(ip, base, community=comm, port=port).items()}
    fcs = {o.rsplit(".", 1)[-1]: v for o, v in snmp_walk(ip, FCS_ERRORS, community=comm, port=port).items()}
    idxs = sorted(set(cols["descr"]) | set(cols["name"]), key=lambda x: int(x) if x.isdigit() else 0)
    out = []
    for i in idxs:
        # ifType 6 is ethernetCsmacd. Anything else (24 loopback, 53 propVirtual, 136 l3ipvlan, ...)
        # has no physical cable, so it has no cable health to report.
        if int(cols["type"].get(i, 0) or 0) != 6:
            continue
        name = cols["name"].get(i) or cols["descr"].get(i) or f"if{i}"
        rec = {"index": i, "name": name, "alias": cols["alias"].get(i, ""),
               "admin_up": int(cols["admin"].get(i, 0) or 0) == 1,
               "oper_up": int(cols["oper"].get(i, 0) or 0) == 1,
               "speed": int(cols["high_speed"].get(i, 0) or 0),
               "in_err": int(cols["in_err"].get(i, 0) or 0), "out_err": int(cols["out_err"].get(i, 0) or 0),
               "fcs_err": int(fcs.get(i, 0) or 0), "discards": int(cols["discards"].get(i, 0) or 0),
               "in_oct": int(cols["in_oct"].get(i, 0) or 0), "out_oct": int(cols["out_oct"].get(i, 0) or 0)}
        rec.update(cable_verdict(rec))
        out.append(rec)
    return out, ""


def cable_verdict(p):
    """Judge one port's cable from its counters. {"verdict", "why"}.

    What a damaged patch cable actually looks like from the switch, in order of how often it happens:

      - it links at 100 Mbit/s on a gigabit port. Gigabit needs all four pairs; 100 needs two. A cable
        with a broken pair therefore still works, just at a tenth of the speed, silently, sometimes for
        years. This is the single most common bad-cable symptom in a rack and nobody notices it without
        looking at a table exactly like this one.
      - frames arrive failing their checksum (FCS errors). The cable passes traffic but corrupts some of
        it - marginal pairs, a crushed cable, interference, or a connector not fully seated.
      - the port is administratively up with its cable plugged in but never comes up.

    A clean port moves traffic with no errors, and says so, so a long list can be skimmed for the rows
    that are not fine.
    """
    if not p["admin_up"]:
        return {"verdict": "DISABLED", "why": "switched off by configuration, not a cable fault"}
    if not p["oper_up"]:
        return {"verdict": "DOWN", "why": "no link - nothing plugged in, the far end is off, or the cable is dead"}
    total_err = p["in_err"] + p["out_err"] + p["fcs_err"]
    traffic = p["in_oct"] + p["out_oct"]
    if p["speed"] and p["speed"] <= 100:
        return {"verdict": "REPLACE CABLE",
                "why": f"linked at only {p['speed']} Mbit/s - a gigabit port falling back to 100 almost "
                       "always means a broken pair in the cable; it works, just ten times too slowly"}
    if p["fcs_err"] > 0 and traffic and p["fcs_err"] > max(100, traffic // 1_000_000):
        return {"verdict": "REPLACE CABLE",
                "why": f"{p['fcs_err']} frames arrived corrupted (FCS errors) - a marginal or damaged cable"}
    if total_err > 0 and traffic and total_err > max(100, traffic // 500_000):
        return {"verdict": "SUSPECT",
                "why": f"{total_err} errors against the traffic carried - worth re-seating or swapping"}
    if total_err > 0:
        return {"verdict": "WATCH", "why": f"{total_err} error(s) so far - few, but not zero"}
    return {"verdict": "OK", "why": f"up at {p['speed'] or '?'} Mbit/s, no errors"}


def cable_lines(ports, err="", host=""):
    if err:
        return [err]
    if not ports:
        return ["No physical ethernet ports were reported by that device."]
    order = {"REPLACE CABLE": 0, "SUSPECT": 1, "WATCH": 2, "DOWN": 3, "OK": 4, "DISABLED": 5}
    rows = sorted(ports, key=lambda p: (order.get(p["verdict"], 9), p["name"]))
    bad = [p for p in rows if p["verdict"] in ("REPLACE CABLE", "SUSPECT")]
    out = [f"PORT / CABLE HEALTH - {host}", ""]
    out.append(f"{'PORT':<22}{'STATE':<16}{'SPEED':<12}{'ERRORS':<10}WHY")
    out.append("-" * 150)
    for p in rows:
        speed = f"{p['speed']} Mb" if p["speed"] else "-"
        errs = p["in_err"] + p["out_err"] + p["fcs_err"]
        out.append(f"{p['name'][:21]:<22}{p['verdict']:<16}{speed:<12}{errs:<10}{p['why']}")
    out.append("")
    if bad:
        out.append(f"{len(bad)} port(s) need attention:")
        for p in bad:
            out.append(f"  {p['name']}  {'(' + p['alias'] + ')' if p['alias'] else ''}  -  {p['why']}")
    else:
        out.append("No cable faults found - every connected port is up to speed and error-free.")
    return out


# LLDP read from the SWITCH over SNMP, rather than captured locally off the wire. This is how the
# switch-port question gets answered on Windows and macOS without any capture driver at all: the switch
# already knows who is plugged into which port, so ask it instead of sniffing for its announcements.
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_LOC_PORTID = "1.0.8802.1.1.2.1.3.7.1.3"
FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort: MAC address -> bridge port number
BRIDGE_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # bridge port -> ifIndex


def _snmp_locate(switch_ip, mac, community=None, port=161):
    """(ifindex, port_name, read_community, error) for the switch port a MAC is reachable through, from
    the switch's own forwarding table. The read community that worked is returned so a follow-up write
    does not have to rediscover it."""
    mac = norm_mac(mac)
    probe = snmp_get(switch_ip, communities=[community] if community else SNMP_COMMUNITIES, port=port)
    if not probe:
        return None, "", "", f"{switch_ip} did not answer SNMP."
    comm = probe.get("community", "public")
    fdb = snmp_walk(switch_ip, FDB_PORT, community=comm, port=port)
    if not fdb:
        return None, "", comm, (f"{switch_ip} answered SNMP but exposed no forwarding table. Many switches "
                                "only expose it per-VLAN; try the switch's own web interface for this one.")
    want = ".".join(str(int(b, 16)) for b in mac.split(":"))
    bridge_port = next((v for o, v in fdb.items() if o.endswith("." + want)), None)
    if bridge_port is None:
        return None, "", comm, f"{mac} was not in the forwarding table of {switch_ip} - it is reached through another switch."
    b2i = {o.rsplit(".", 1)[-1]: v for o, v in snmp_walk(switch_ip, BRIDGE_IFINDEX, community=comm, port=port).items()}
    ifindex = b2i.get(str(bridge_port), bridge_port)
    names = {o.rsplit(".", 1)[-1]: v for o, v in snmp_walk(switch_ip, IF_COLS["name"], community=comm, port=port).items()}
    return str(ifindex), names.get(str(ifindex), f"port {bridge_port}"), comm, ""


def snmp_find_mac(switch_ip, mac, community=None, cancel=None, port=161):
    """Which port of `switch_ip` a given MAC is reachable through. ("Gi1/0/14", "") or ("", reason).

    Cross-platform: needs no raw socket, no capture driver and no elevation - only SNMP read access to
    the switch - so it works identically on Windows, macOS and Linux, which local LLDP capture does not.
    """
    _ifindex, name, _comm, err = _snmp_locate(switch_ip, mac, community=community, port=port)
    return (name, "") if not err else ("", err)


# A switch's complete port map (the "X-ray"): for every physical port, its cable health AND the device(s)
# the switch has learned on it, from its own forwarding table - read-only, so pure observation. The
# VLAN-aware dot1q table is preferred because it also tells you which VLAN each device is on; the classic
# dot1d table is the fallback for simpler switches.
FDB_Q_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort:  .vlan.mac(6) -> bridge port  (VLAN-aware)
VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"   # dot1qVlanStaticName: vlan id -> human name


def _fdb_entries(walk_result, base, has_vlan):
    """Decode a walked forwarding-table column into [(mac, vlan_or_None, bridge_port)]. The MAC - and, for
    the VLAN-aware table, the VLAN - is carried in the OID suffix: dot1q is '.vlan.b1.b2.b3.b4.b5.b6',
    dot1d is '.b1.b2.b3.b4.b5.b6'."""
    base = base.rstrip(".")
    out = []
    for oid, portval in (walk_result or {}).items():
        if not oid.startswith(base + "."):
            continue
        try:
            nums = [int(a) for a in oid[len(base) + 1:].split(".")]
        except ValueError:
            continue
        need = 7 if has_vlan else 6
        if len(nums) < need:
            continue
        mac_bytes = nums[-6:]
        if any(b < 0 or b > 255 for b in mac_bytes):
            continue
        vlan = nums[0] if has_vlan else None
        try:
            bport = int(portval)
        except (TypeError, ValueError):
            continue
        if bport <= 0:
            continue
        out.append((":".join(f"{b:02x}" for b in mac_bytes), vlan, bport))
    return out


def switch_portmap(ip, community=None, inventory=None, ports=None, log=print, cancel=None, port=161):
    """A managed switch's complete port map: every physical port, its link health, and - from the switch's
    OWN forwarding table - the device(s) learned on it, each resolved to a name from the current scan and
    to its MAC vendor. Read-only SNMP: no admin rights, no packet capture, identical on every OS.

    Returns (ports, error). Each port dict is the one snmp_ports() returns, plus:
      hosts       - [{mac, vlan, vlan_name, device, vendor}] learned on that port, VLAN then MAC order
      host_count  - how many (a trunk/uplink learns the whole network beyond it - dozens means uplink)
      vlans       - the distinct VLAN ids seen on the port
      uplink      - True when the port has learned enough MACs to be a trunk/uplink rather than an endpoint
    `inventory` may be a {mac: label} map or a list of scan device dicts; unknown MACs fall back to vendor.
    `ports` lets a caller that already read the port health (e.g. CABLE TEST) hand it in, so the interface
    table isn't walked twice.
    """
    if ports is None:
        ports, err = snmp_ports(ip, community=community, log=log, cancel=cancel, port=port)
        if err:
            return [], err
    if cancel is not None and cancel.is_set():
        return ports, ""
    probe = snmp_get(ip, communities=[community] if community else SNMP_COMMUNITIES, port=port)
    comm = probe.get("community", community or "public")
    fdb = _fdb_entries(snmp_walk(ip, FDB_Q_PORT, community=comm, port=port), FDB_Q_PORT, True)
    if not fdb:                                             # simpler switch: classic, VLAN-less table
        fdb = _fdb_entries(snmp_walk(ip, FDB_PORT, community=comm, port=port), FDB_PORT, False)
    b2i = {o.rsplit(".", 1)[-1]: str(v) for o, v in snmp_walk(ip, BRIDGE_IFINDEX, community=comm, port=port).items()}
    vlan_names = {o.rsplit(".", 1)[-1]: v for o, v in snmp_walk(ip, VLAN_STATIC_NAME, community=comm, port=port).items()}

    inv = {}
    if isinstance(inventory, dict):
        inv = {norm_mac(k): v for k, v in inventory.items() if k}
    elif inventory:
        for d in inventory:
            if isinstance(d, dict) and d.get("mac"):
                inv[norm_mac(d["mac"])] = d.get("label") or d.get("name") or d.get("type") or ""
    try:
        oui = load_oui(download=False, log=lambda *a, **k: None)
    except Exception:
        oui = {}

    attached = {}
    for mac, vlan, bport in fdb:
        ifx = b2i.get(str(bport), str(bport))
        attached.setdefault(ifx, []).append({
            "mac": mac, "vlan": vlan,
            "vlan_name": vlan_names.get(str(vlan), "") if vlan is not None else "",
            "device": inv.get(norm_mac(mac), ""),
            "vendor": vendor_of(mac, oui)})
    for p in ports:
        hosts = sorted(attached.get(str(p["index"]), []), key=lambda h: (h.get("vlan") or 0, h["mac"]))
        p["hosts"] = hosts
        p["host_count"] = len(hosts)
        p["vlans"] = sorted({h["vlan"] for h in hosts if h.get("vlan") is not None})
        p["uplink"] = len(hosts) >= 4
    return ports, ""


def portmap_lines(ports, err="", host=""):
    """Readable port map for the console / a report: one row per port with what's plugged into it."""
    if err:
        return [err]
    if not ports:
        return ["No physical ethernet ports were reported by that device."]
    out = [f"SWITCH PORT MAP - {host}", "",
           f"{'PORT':<16}{'LINK':<10}{'SPEED':<10}{'VLAN':<10}CONNECTED DEVICE", "-" * 110]
    for p in sorted(ports, key=lambda p: int(p["index"]) if str(p["index"]).isdigit() else 0):
        link = "up" if p.get("oper_up") else ("off" if not p.get("admin_up") else "down")
        speed = f"{p['speed']} Mb" if p.get("speed") else "-"
        vlans = ",".join(str(v) for v in p.get("vlans", [])) or "-"
        if p.get("uplink"):
            who = f"<uplink / trunk - {p['host_count']} devices beyond this port>"
        elif p.get("hosts"):
            who = "; ".join((h["device"] or h["vendor"] or h["mac"])
                            + (f" ({h['mac']})" if h["device"] or h["vendor"] else "") for h in p["hosts"][:4])
        else:
            who = "-" if p.get("oper_up") else ""
        out.append(f"{p['name'][:15]:<16}{link:<10}{speed:<10}{vlans:<10}{who}")
    live = [p for p in ports if p.get("hosts") and not p.get("uplink")]
    out += ["", f"{len(live)} endpoint port(s) with a known device; "
                f"{sum(1 for p in ports if p.get('uplink'))} uplink/trunk port(s)."]
    return out


IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"   # ifAdminStatus: 1 = up, 2 = down (the write that isolates a port)


def _snmp_error_status(data):
    """The error-status field from a response PDU: 0 means the request was accepted. Non-zero is the
    switch refusing it - most often 'read-only' or 'no access', meaning the community used has no write
    rights. None if the field can't be read at all."""
    try:
        _tag, body, _ = _ber_parse(data, 0)
        i = 0
        for _ in range(2):                                  # version, community
            _, _, i = _ber_parse(body, i)
        _ptag, pdu, _ = _ber_parse(body, i)
        j = 0
        _, _, j = _ber_parse(pdu, j)                        # request-id
        etag, eval_, _ = _ber_parse(pdu, j)                 # error-status
        return int.from_bytes(eval_, "big") if etag == 0x02 else None
    except (IndexError, ValueError):
        return None


_SNMP_ERRORS = {1: "the value was too big for the switch", 2: "the switch has no such setting",
                3: "the switch rejected the value", 4: "the setting is read-only with this community",
                6: "this community has no write access", 17: "that object is not writable"}


def snmp_set(ip, oid, value, value_tag=0x02, community="private", timeout=1.0, port=161):
    """SNMP v2c SetRequest - the one state-changing SNMP call in NetScout. Returns (ok, error).

    This is deliberately the only write, and it exists for exactly one job: toggling a switch port's
    administrative status, which is how the network's OWN administrator takes a device off the network -
    through a switch they own, with a write community only they hold, on a named port, reversibly. That
    is a world apart from forging packets on the wire: nothing here injects traffic, spoofs an address,
    or touches a device NetScout does not have administrative credentials for. The write community is
    the gate, and there is no way around it - a switch with no write access simply refuses.
    """
    val = _ber_int(value) if value_tag == 0x02 else _ber_tlv(
        value_tag, value if isinstance(value, bytes) else str(value).encode())
    xid = random.randint(1, 0x7FFFFFFF)
    pdu = _ber_tlv(0xA3, _ber_int(xid) + _ber_int(0) + _ber_int(0)      # 0xA3 = SetRequest
                   + _ber_tlv(0x30, _ber_tlv(0x30, _ber_oid(oid) + val)))
    pkt = _ber_tlv(0x30, _ber_int(1) + _ber_tlv(0x04, community.encode()) + pdu)
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, port))
        for _ in range(4):
            data, _addr = s.recvfrom(4096)
            if _snmp_reqid(data) != xid:
                continue
            err = _snmp_error_status(data)
            if err:
                return False, _SNMP_ERRORS.get(err, f"the switch refused the change (error {err})")
            return True, ""
        return False, "no matching reply from the switch"
    except socket.timeout:
        return False, ("the switch did not answer - either SNMP write is disabled on it, or the write "
                       "community is wrong (reading a switch and writing to it use different communities)")
    except Exception as e:
        return False, str(e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def set_device_port(switch_ip, mac, up, read_community=None, write_community="private", port=161):
    """Enable or disable the switch port a device is plugged into. (ok, message).

    up=False cuts the device off the network entirely; up=True restores it. This is the auditable,
    reversible, admin way to isolate a machine - the same action a NAC appliance performs automatically
    when it quarantines a host. It works only against a managed switch you hold SNMP WRITE credentials
    for, which is the whole point: it is a control over your own infrastructure, not an attack on
    someone else's.
    """
    ifindex, name, _rcomm, err = _snmp_locate(switch_ip, mac, community=read_community, port=port)
    if err:
        return False, err
    ok, serr = snmp_set(switch_ip, f"{IF_ADMIN_STATUS}.{ifindex}", 1 if up else 2,
                        community=write_community, port=port)
    audit_log("switch port reconnect" if up else "switch port disconnect", target=f"{mac} ({name})",
              method=f"SNMP {switch_ip}", command=f"ifAdminStatus.{ifindex} := {'up(1)' if up else 'down(2)'}",
              ok=ok, detail="" if ok else str(serr)[:200])
    if not ok:
        return False, f"Found {mac} on {name}, but could not change it: {serr}"
    verb = "RECONNECTED" if up else "DISCONNECTED"
    return True, f"{verb} {mac} ({name} on {switch_ip})" + ("" if up else " - run again with reconnect to restore it")


def switch_lockdown(switch_ip, write_community, read_community=None, admin_mac="", keep_macs=(),
                    keep_ports=(), lift=False, port=161, cancel=None, log=print):
    """Emergency containment for a serious incident: disable EVERY device port on a managed switch you
    administer at once (lift=True re-enables them). This drops the whole LAN - phones, tablets, IoT and
    all - off the network in one action, because it removes their network access rather than touching the
    devices themselves (which is both what actually stops an attack spreading and what preserves the
    evidence). It is the standard "containment" step of incident response, done through infrastructure you
    own: gated on the switch's SNMP WRITE community, fully reversible, and auditable.

    Your own port and anything in keep_macs / keep_ports (normally this machine and the uplink/gateway) are
    LEFT UP so you stay in control. If it cannot first locate this computer's own port, it REFUSES rather
    than risk cutting you off. Returns {ok, error, changed:[(port,err)], kept:[port], failed:[(port,err)],
    located:{mac:ifindex}, lift}."""
    out = {"ok": False, "error": "", "changed": [], "kept": [], "failed": [], "located": {}, "lift": lift}
    ports, err = snmp_ports(switch_ip, community=read_community, log=log, cancel=cancel, port=port)
    if err:
        out["error"] = err
        return out
    if not ports:
        out["error"] = "The switch answered SNMP but exposed no ethernet ports to act on."
        return out
    keep = {str(p) for p in keep_ports}
    for mac in ([admin_mac] if admin_mac else []) + list(keep_macs):
        if not mac:
            continue
        ifindex, _name, _comm, e = _snmp_locate(switch_ip, mac, community=read_community, port=port)
        if ifindex:
            keep.add(str(ifindex))
            out["located"][norm_mac(mac)] = str(ifindex)
    # Safety gate: never disable everything unless at least one port is being kept, and - when an admin MAC
    # was given - unless THIS computer's own port was found. Otherwise the operator could cut themselves off.
    if not lift:
        if admin_mac and norm_mac(admin_mac) not in out["located"]:
            out["error"] = ("Could not find THIS computer's own port on the switch (its MAC is not in the "
                            "switch's forwarding table - it may reach the switch through another switch). "
                            "Refusing to lock down so you are not cut off. Run it from a machine on this "
                            "switch, or name the port(s) to keep up.")
            return out
        if not keep:
            out["error"] = ("Nothing was identified to keep online, so a lockdown could cut off your own "
                            "access. Name at least your own port (or the uplink) to keep, then try again.")
            return out
    target = 1 if lift else 2
    for p in ports:
        idx = str(p["index"])
        if idx in keep:
            out["kept"].append(p)
            continue
        if cancel is not None and cancel.is_set():
            break
        ok, serr = snmp_set(switch_ip, f"{IF_ADMIN_STATUS}.{idx}", target, community=write_community, port=port)
        if ok:
            out["changed"].append((p, ""))
        else:
            out["failed"].append((p, serr))
    out["ok"] = bool(out["changed"]) and not out["failed"]
    if not out["changed"] and not out["failed"]:
        out["error"] = "Every port was on the keep list - nothing to change."
    # one audit entry for the whole emergency action, with the port tally
    audit_log("lift switch lockdown" if lift else "EMERGENCY switch lockdown", target=switch_ip,
              method="SNMP", command=f"ifAdminStatus := {'up(1)' if lift else 'down(2)'} on all but {len(out['kept'])} kept",
              ok=out["ok"], detail=f"{len(out['changed'])} changed, {len(out['kept'])} kept, "
              f"{len(out['failed'])} failed" + (f"; {out['error']}" if out.get("error") else ""))
    return out


def lockdown_lines(result, switch_ip=""):
    """Readable summary of a switch_lockdown()."""
    verb = "LIFTED LOCKDOWN" if result.get("lift") else "EMERGENCY LOCKDOWN"
    if result.get("error") and not result.get("changed"):
        return [f"{verb} on {switch_ip}: NOT done - {result['error']}"]
    ch, kept, failed = result.get("changed", []), result.get("kept", []), result.get("failed", [])
    act = "re-enabled" if result.get("lift") else "disabled"
    out = [f"{verb} on {switch_ip}: {len(ch)} port(s) {act}, {len(kept)} kept online, {len(failed)} failed."]
    for p, _ in ch:
        out.append(f"  {act.upper():<11} {p.get('name', '?')}")
    for p in kept:
        out.append(f"  KEPT ONLINE {p.get('name', '?')} (you / uplink)")
    for p, e in failed:
        out.append(f"  FAILED      {p.get('name', '?')} - {e}")
    if not result.get("lift") and ch:
        out.append("The LAN is isolated. Run LIFT LOCKDOWN with the same credentials to bring the ports back.")
    return out


# --- respond to an attack: shut the offending host out of THIS machine -----------------------------------
# The honest, universal "cut it off when an attack happens": a rule in the firewall the OS already has, on
# the computer NetScout runs on. It needs admin/root on THIS machine (the OS enforces that), is fully
# reversible, is logged, and touches no other device. It does not - and this tool never will - force power
# off a device you hold no credentials for; that would be an attack, not a defence. Blocking an attacker at
# your own door is the defensive move, and it works without any special equipment.
FW_BLOCK_TAG = "NetScout-block"      # Windows rule-name prefix / Linux iptables comment marker


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def firewall_block_commands(ip, block=True, host_os=None):
    """OS-firewall commands to cut one host off from THIS machine (block=True) or restore it (block=False).
    Returns (list_of_argv, error). Each command drives the firewall the OS already ships; the IP is
    validated so nothing but a real address ever reaches the command line."""
    host_os = host_os or OS
    if not _valid_ip(ip):
        return [], "not a valid IP address"
    if host_os == "Windows":
        name = f"{FW_BLOCK_TAG} {ip}"
        if block:
            return ([["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in",
                      "action=block", f"remoteip={ip}"],
                     ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=out",
                      "action=block", f"remoteip={ip}"]], "")
        return ([["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]], "")
    if host_os == "Linux" and shutil.which("iptables"):
        tag = ["-m", "comment", "--comment", FW_BLOCK_TAG]       # so our own rules can be found and removed exactly
        flag = "-I" if block else "-D"
        return ([["iptables", flag, "INPUT", "-s", ip] + tag + ["-j", "DROP"],
                 ["iptables", flag, "OUTPUT", "-d", ip] + tag + ["-j", "DROP"]], "")
    return [], "Blocking a host at the firewall is supported on Windows and Linux (and needs admin / root)."


def firewall_block_host(ip, block=True, host_os=None):
    """Add (or remove) a firewall rule on THIS computer that blocks `ip`. Returns (ok, message)."""
    cmds, err = firewall_block_commands(ip, block, host_os)
    if not cmds:
        return False, err
    if not shutil.which(cmds[0][0]):
        return False, f"'{cmds[0][0]}' is not available on this computer."
    outs, ok_all = [], True
    for argv in cmds:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20, **NOWIN)
            if r.returncode != 0:
                ok_all = False
                outs.append(((r.stdout or "") + (r.stderr or "")).strip())
        except (OSError, subprocess.TimeoutExpired) as e:
            ok_all = False
            outs.append(str(e))
    audit_log("firewall block" if block else "firewall unblock", target=ip, method="local firewall",
              command=" ; ".join(" ".join(a) for a in cmds), ok=ok_all,
              detail="" if ok_all else "; ".join(o for o in outs if o)[:200])
    if ok_all:
        return True, (f"{ip} is now blocked at this computer's firewall - it can't reach this machine until "
                      "you UNBLOCK it." if block else
                      f"{ip} is unblocked - this machine will talk to it again.")
    joined = "; ".join(o for o in outs if o)
    low = joined.lower()
    if any(s in low for s in ("access is denied", "permission denied", "must be run as root", "operation not permitted")):
        return False, "Need administrator / root rights on THIS computer to change its firewall."
    if not block and ("no chain/target/match" in low or "does a matching rule exist" in low or "(2)" in low):
        return False, f"No firewall block for {ip} was found to remove (already unblocked?)."
    return False, (joined[:200] or "The firewall change failed.")


def parse_iptables_blocks(text):
    """`iptables -S` -> [ip] for the rules NetScout added (tagged with its comment)."""
    out = []
    for line in (text or "").splitlines():
        if FW_BLOCK_TAG in line:
            m = re.search(r"-[sd]\s+(" + IPV4 + r")", line)
            if m:
                out.append(m.group(1).split("/")[0])
    seen = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def parse_netsh_blocks(text):
    """`netsh advfirewall firewall show rule name=all` -> [ip] for NetScout's own block rules. Matched by
    the rule-name tag, so it works whatever language Windows prints its field labels in."""
    out = []
    for line in (text or "").splitlines():
        if FW_BLOCK_TAG in line:
            m = re.search(re.escape(FW_BLOCK_TAG) + r"\s+(" + IPV4 + r")", line)
            if m:
                out.append(m.group(1))
    seen = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def firewall_blocks(host_os=None):
    """The hosts NetScout is currently blocking at this computer's firewall (so it is never a one-way
    street - you can always see and undo them)."""
    host_os = host_os or OS
    if host_os == "Windows":
        return parse_netsh_blocks(run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], timeout=20))
    if host_os == "Linux" and shutil.which("iptables"):
        return parse_iptables_blocks(run(["iptables", "-S"], timeout=15))
    return []


def attackers_from_arp(findings, table, gateway=""):
    """The specific hosts implicated by arp_spoof_check(), as [{ip, mac, why}] - so a human can choose to
    block or isolate THAT host, rather than anything ever acting on 'any device'.

    Only ROUTER MAC SHARED names a safe target: a SEPARATE host that has taken the router's hardware
    address (the impersonator). ROUTER MAC CHANGED is deliberately NOT turned into a target - the only
    address in that finding is the gateway's own, and blocking the gateway would cut off the real router,
    not the attacker. The gateway is excluded outright as a belt-and-braces guard."""
    t = _clean_arp(table)
    gw = (gateway or "").strip()
    out, seen = [], set()
    for f in findings or []:
        if f.get("kind") != "ROUTER MAC SHARED":
            continue
        for ip in re.findall(IPV4, f.get("why", "")):
            mac = t.get(ip, "")
            if ip != gw and ip not in seen and mac:
                seen.add(ip)
                out.append({"ip": ip, "mac": mac, "why": f["kind"]})
    return out


# --- firewall & exposure --------------------------------------------------------------------------------
# A note on what this is and is not. Every one of Windows, macOS and Linux already ships a real,
# kernel-level firewall that inspects every packet before the OS does. Re-implementing packet filtering
# in a Python application would not sit in that path at all - it would be a toy that inspects nothing and
# hands the user a false sense of safety, which for a security tool is worse than doing nothing. So this
# does the genuinely useful thing instead: it reports whether the OS firewall is actually on, shows what
# this machine currently exposes to the network (its real attack surface), and can switch the OS firewall
# on and close that surface - driving the firewall the OS already has, rather than pretending to be one.

def firewall_status():
    """{"on": True/False/None, "backend": str, "detail": str}. None means it could not be determined."""
    if OS == "Windows":
        out = run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        states = re.findall(r"State\s+(ON|OFF)", out, re.I)
        if states:
            on = all(s.upper() == "ON" for s in states)
            return {"on": on, "backend": "Windows Defender Firewall",
                    "detail": ("on for all profiles" if on else "OFF for at least one profile - "
                               + ", ".join(states))}
        return {"on": None, "backend": "Windows Defender Firewall", "detail": "could not read the state"}
    if OS == "Darwin":
        fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        if os.path.exists(fw):
            out = run([fw, "--getglobalstate"])
            on = "enabled" in out.lower()
            return {"on": on, "backend": "macOS Application Firewall",
                    "detail": "enabled" if on else "disabled (System Settings > Network > Firewall)"}
        return {"on": None, "backend": "macOS Application Firewall", "detail": "control tool not found"}
    # Linux: several firewall front-ends exist; report whichever is actually in use
    if shutil.which("ufw"):
        out = run(["ufw", "status"])
        if "Status:" in out:
            # "active" is a substring of "inactive", so a naive `"active" in out` reports an INACTIVE
            # firewall as on - the most dangerous possible direction for this to be wrong. Match the
            # whole status word.
            on = bool(re.search(r"status:\s*active", out, re.I))
            return {"on": on, "backend": "ufw", "detail": "active" if on else "inactive (sudo ufw enable)"}
    if shutil.which("firewall-cmd"):
        out = run(["firewall-cmd", "--state"]).strip()
        if out:
            return {"on": out == "running", "backend": "firewalld", "detail": out}
    if shutil.which("nft"):
        out = run(["nft", "list", "ruleset"])
        has = bool(re.search(r"\bchain\b", out))
        return {"on": has or None, "backend": "nftables",
                "detail": "rules are loaded" if has else "no rules loaded, or needs root to read"}
    if shutil.which("iptables"):
        out = run(["iptables", "-S"])
        strict = bool(re.search(r"-P INPUT DROP", out))
        return {"on": strict or None, "backend": "iptables",
                "detail": "default-drop on INPUT" if strict else "default-accept, or needs root to read"}
    return {"on": None, "backend": "unknown", "detail": "no recognised Linux firewall front-end found"}


# Ports whose exposure is worth a specific warning - the services that get a machine compromised when
# they face the network unfirewalled. Keyed to the same risk vocabulary the device table already uses.
EXPOSURE_NOTES = {445: "SMB file sharing - a classic ransomware entry point if it faces the network",
                  3389: "Remote Desktop - brute-forced constantly; should never face the open network",
                  22: "SSH - fine if key-only, dangerous with passwords exposed to the network",
                  23: "Telnet - unencrypted, should not be running at all",
                  3306: "MySQL database exposed", 5432: "PostgreSQL database exposed",
                  27017: "MongoDB exposed", 6379: "Redis exposed - often unauthenticated",
                  9200: "Elasticsearch exposed", 5900: "VNC remote control exposed",
                  139: "NetBIOS - legacy file sharing", 135: "Windows RPC exposed",
                  1433: "SQL Server exposed", 2375: "Docker API exposed - full host control if unauthenticated"}


def listening_ports():
    """What this machine is currently offering to the network - its own attack surface. Returns
    [{"proto","port","addr","scope","note"}], where scope is 'network' for anything bound to a real or
    wildcard address (reachable from outside) versus 'local' for loopback only (not a network exposure).

    Knowing your own listening services is the first thing any hardening check does, and it is the thing
    people most often get wrong: a database or remote-desktop port left bound to 0.0.0.0 is how machines
    get owned, and nothing on the box announces it.
    """
    rows, seen = [], set()

    def add(proto, addr, port):
        try:
            port = int(port)
        except (ValueError, TypeError):
            return
        key = (proto, port, addr)
        if key in seen:
            return
        seen.add(key)
        local = addr in ("127.0.0.1", "::1") or addr.startswith("127.") or addr == "::1"
        rows.append({"proto": proto, "port": port, "addr": addr,
                     "scope": "local" if local else "network", "note": EXPOSURE_NOTES.get(port, "")})

    def split_hostport(token):
        """'0.0.0.0:22', '[::]:22', '*.22' and '*:*' all mean host + port. Returns (host, port) or None.
        Split on the LAST separator so IPv6 colons in the host don't confuse the port."""
        token = token.replace("*", "0.0.0.0")
        sep = token.rfind(":") if ":" in token.rsplit("]", 1)[-1] or "." not in token else token.rfind(".")
        if sep < 0:
            return None
        host, port = token[:sep].strip("[]"), token[sep + 1:]
        return (host or "0.0.0.0", port) if port.isdigit() else None

    # Fields are SPLIT rather than matched with one brittle column regex, because the column layout
    # differs by tool and the earlier regex silently skipped the wrong number of them and found nothing.
    if OS == "Windows":
        # netstat -ano:  Proto  Local Address  Foreign Address  State  PID
        for ln in run(["netstat", "-ano"]).splitlines():
            p = ln.split()
            if len(p) >= 3 and p[0] in ("TCP", "UDP") and (p[0] == "UDP" or "LISTEN" in ln.upper()):
                hp = split_hostport(p[1])
                if hp:
                    add(p[0].lower(), hp[0], hp[1])
    elif shutil.which("ss"):
        # ss -tulnH:  Netid State Recv-Q Send-Q  Local:Port  Peer:Port  -> local is the second-to-last col
        for ln in run(["ss", "-tulnH"]).splitlines():
            p = ln.split()
            if len(p) >= 5 and p[0] in ("tcp", "udp"):
                hp = split_hostport(p[-2])
                if hp:
                    add(p[0], hp[0], hp[1])
    else:
        # netstat -an (BSD / macOS):  Proto Recv-Q Send-Q  Local Address  Foreign Address  (state)
        for ln in run(["netstat", "-an"]).splitlines():
            p = ln.split()
            if len(p) < 5 or not p[0].lower().startswith(("tcp", "udp")):
                continue
            is_udp = p[0].lower().startswith("udp")
            if not is_udp and "LISTEN" not in ln.upper():
                continue
            hp = split_hostport(p[3])
            if hp:
                add("udp" if is_udp else "tcp", hp[0], hp[1])
    rows.sort(key=lambda r: (r["scope"] != "network", not r["note"], r["port"]))
    return rows


def firewall_set(on=True):
    """Turn the OS firewall on (or off). (ok, message). Needs administrator / root, and says so clearly
    rather than failing cryptically when it is not run with those rights."""
    if OS == "Windows":
        cmd = ["netsh", "advfirewall", "set", "allprofiles", "state", "on" if on else "off"]
        admin = "Right-click NetScout and 'Run as administrator' for this."
    elif OS == "Darwin":
        fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        cmd = ["sudo", "-n", fw, "--setglobalstate", "on" if on else "off"]
        admin = "Launch NetScout with sudo for this (a GUI can't show a password prompt), or run the command yourself in Terminal."
    elif shutil.which("ufw"):
        cmd = ["sudo", "-n", "ufw", "--force", "enable"] if on else ["sudo", "-n", "ufw", "disable"]
        admin = "Launch NetScout with sudo for this, or run 'sudo ufw enable' yourself."
    elif shutil.which("firewall-cmd"):
        cmd = ["sudo", "-n", "systemctl", "start" if on else "stop", "firewalld"]
        admin = "Launch NetScout with sudo for this."
    else:
        return False, ("No firewall front-end this tool can drive was found. On Linux, install ufw "
                       "(sudo apt install ufw) or firewalld, then try again.")
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=20, text=True, **NOWIN)
    except Exception as e:
        return False, f"Could not run the firewall command ({e}). {admin}"
    if p.returncode == 0:
        return True, f"Firewall turned {'ON' if on else 'OFF'}."
    tail = (p.stderr or p.stdout or "").strip().splitlines()
    reason = tail[-1] if tail else ""
    low = reason.lower()
    if "permission" in low or "denied" in low or "administrator" in low or "sudo" in low or "root" in low:
        return False, f"Needs more rights: {admin}"
    return False, f"The firewall command failed: {reason or 'unknown error'}. {admin}"


def firewall_lines(status, ports):
    out = ["FIREWALL & EXPOSURE", ""]
    mark = {True: "ON", False: "OFF", None: "?"}[status.get("on")]
    out.append(f"OS firewall ({status.get('backend', '?')}): {mark}  -  {status.get('detail', '')}")
    if status.get("on") is False:
        out.append("  >> Your firewall is OFF. Everything listed below is reachable from the network.")
    out.append("")
    net = [p for p in ports if p["scope"] == "network"]
    loc = [p for p in ports if p["scope"] == "local"]
    risky = [p for p in net if p["note"]]
    if risky:
        out.append(f"EXPOSED SERVICES THAT MATTER ({len(risky)}):")
        for p in risky:
            out.append(f"  {p['proto']}/{p['port']}  on {p['addr']}  -  {p['note']}")
        out.append("")
    out.append(f"ALL NETWORK-FACING PORTS ({len(net)}): reachable from other machines")
    for p in net:
        out.append(f"  {p['proto']}/{p['port']}  on {p['addr']}" + (f"  [{p['note']}]" if p["note"] else ""))
    out.append("")
    out.append(f"({len(loc)} more are bound to localhost only - not reachable from the network)")
    if net:
        out.append("")
        out.append("Each network-facing port is a door. Close the ones you don't need, and make sure the "
                   "firewall is on so the rest are only reachable by what you actually allow.")
    return out


# --- MAC address privacy --------------------------------------------------------------------------------
def random_mac(oui=None):
    """A randomly generated, locally-administered unicast MAC address.

    This is the real, legitimate version of 'don't be trackable by a fixed hardware address' - the same
    thing modern phones do by default. The first octet is forced locally-administered (bit 1 set) and
    unicast (bit 0 clear), which is correct for a made-up address and marks it as not factory-assigned.
    It changes the hardware address your adapter presents on the LAN; it does NOT change your IP, and it
    is not a cloak of invisibility (see set_mac's note).
    """
    first = None
    if oui:
        try:
            first = [int(x, 16) for x in re.split(r"[:-]", oui) if x][:3]
            if len(first) != 3:
                first = None
        except ValueError:
            first = None            # a malformed OUI falls back to a fully random address, never crashes
    if first is None:
        b = random.randint(0, 255)
        first = [(b & 0xFC) | 0x02, random.randint(0, 255), random.randint(0, 255)]
    rest = [random.randint(0, 255) for _ in range(6 - len(first))]
    return ":".join(f"{x:02x}" for x in (first + rest))


def set_mac(iface, mac):
    """Change an interface's MAC address. (ok, message). Needs admin/root, briefly drops the link, and
    is honest about the platforms where the OS or driver simply will not allow it."""
    mac = norm_mac(mac)
    if OS == "Linux":
        for args in (["ip", "link", "set", "dev", iface, "down"],
                     ["ip", "link", "set", "dev", iface, "address", mac],
                     ["ip", "link", "set", "dev", iface, "up"]):
            try:
                p = subprocess.run(["sudo", "-n"] + args, capture_output=True, timeout=15, text=True, **NOWIN)
            except Exception as e:
                return False, f"Could not run the command ({e}). This needs sudo."
            if p.returncode != 0:
                return False, (f"Failed to change the MAC: {(p.stderr or '').strip() or 'needs sudo'}. "
                               "Some adapters and most WiFi drivers refuse a MAC change.")
        return True, f"{iface} is now using {mac}. Reconnect to the network if it didn't come back on its own."
    if OS == "Darwin":
        try:
            p = subprocess.run(["sudo", "-n", "ifconfig", iface, "ether", mac], capture_output=True, timeout=15, text=True, **NOWIN)
        except Exception as e:
            return False, f"Could not run the command ({e}). This needs an administrator password."
        if p.returncode == 0:
            return True, f"{iface} is now using {mac}."
        return False, ("macOS blocks changing the Wi-Fi MAC on recent versions; it may work on a wired "
                       "adapter. (Wi-Fi already randomises its address per-network in System Settings.)")
    # Windows: the MAC is set per-adapter in the registry/driver and many drivers ignore it, so there is
    # no reliable scriptable path. Rather than half-do it, hand over exactly where to set it.
    return False, ("On Windows the MAC is changed per-adapter in Device Manager > your adapter > "
                   "Advanced > 'Network Address', or in the adapter's registry key. Many drivers ignore "
                   f"it. The randomly generated address to use is: {mac}")


def fmt_uptime(ticks):
    """SNMP sysUpTime is in hundredths of a second. '12d 4h' tells you at a glance whether that switch
    rebooted last night, which is usually the reason anyone looks."""
    if not ticks:
        return ""
    s = int(ticks) // 100
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d:
        return f"{d}d {h}h"
    return f"{h}h {m}m" if h else f"{m}m"


TYPE_GROUPS = {"laptop": {"Laptop", "Computer"}, "desktop": {"Desktop", "Computer"}, "phone": {"Phone"},
               "camera": {"Camera"}, "router": {"Router", "Network"}, "printer": {"Printer"},
               "media": {"TV/Media"}, "tv/media": {"TV/Media"}, "other": {"IoT", "Server", "Unknown"}}


def type_filter(devs, wanted):
    w = (wanted or "all").lower().strip()
    if w.endswith("s") and w[:-1] in TYPE_GROUPS:
        w = w[:-1]
    keep = TYPE_GROUPS.get(w)
    return devs if keep is None else [d for d in devs if d["type"] in keep]


def scan_lines(devs):
    lines = [f"{'IP':<16}{'MAC':<19}{'TYPE':<10}{'DEVICE':<42}{'NAME':<24}{'OS':<14}{'IPv6':<30}{'VENDOR':<30}NOTE",
             "-" * 170]
    for d in devs:
        lines.append(f"{d['ip']:<16}{d['mac'] or '-':<19}{d['type']:<10}{d['label'][:40]:<42}"
                     f"{d['name'][:22] or '-':<24}{d['os'] or '-':<14}{d.get('ipv6', '')[:28] or '-':<30}"
                     f"{d['vendor'][:30] or '-':<30}{d.get('note') or '-'}")
    lines.append(f"\n{len(devs)} device(s). Device names are best-effort: MAC vendor, hostnames (DNS/NetBIOS/mDNS), "
                 f"UPnP, web banners, open ports and TTL.\n'Computer' = looks like a PC/laptop but can't tell which.")
    return lines


# ------------------------------------------------------- device notes / tags
def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError):
        return default


def _save_json_atomic(path, data):
    """Write as temp-file-then-rename, same all-or-nothing pattern as load_oui()'s cache refresh - a
    crash or a concurrent write from another tab/process must never truncate the file that was already
    there. The temp name includes the pid so two processes writing at once never collide on it."""
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    tmp = os.path.join(folder, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


# ===================================================================== action audit log
# A defensive tool that can shut machines down, cut switch ports, push policies and block hosts needs an
# accountability trail. Every one of those actions is recorded here - who ran it, when, the exact command,
# and whether it worked - as an append-only JSON-lines file. It records what NetScout DID (state changes),
# never what it merely read (scans), and a failed audit write never breaks the action it was recording.
def _audit_actor():
    try:
        user = getpass.getuser()
    except Exception:
        user = "?"
    try:
        host = socket.gethostname()
    except Exception:
        host = "?"
    return f"{user}@{host}"


def _audit_rotate_if_big():
    """Keep only the most recent half once the log passes its size cap, so a long-lived install's audit
    trail stays bounded without ever losing the recent, relevant entries."""
    try:
        if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) > AUDIT_MAX_BYTES:
            with open(AUDIT_FILE, encoding="utf-8") as f:
                lines = f.readlines()
            with open(AUDIT_FILE, "w", encoding="utf-8") as f:
                f.writelines(lines[len(lines) // 2:])
    except Exception:
        pass


def audit_log(action, target="", method="", command="", ok=None, detail=""):
    """Append one action to the audit log. `command` may be an argv list or a string; it is truncated so a
    huge command line can't bloat the record. Never raises - auditing must not break the action."""
    try:
        if not isinstance(command, str):
            command = " ".join(str(c) for c in command)
        entry = {"ts": datetime.datetime.now().isoformat(timespec="seconds"), "actor": _audit_actor(),
                 "action": str(action), "target": str(target), "method": str(method),
                 "command": command[:500], "ok": ok, "detail": str(detail)[:300]}
        _audit_rotate_if_big()
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        try:
            os.chmod(AUDIT_FILE, 0o600)   # cheap, no subprocess; home-dir perms already cover Windows
        except OSError:
            pass
    except Exception:
        pass


def audit_entries(limit=1000):
    """The audit log as a list of dicts, NEWEST FIRST (at most `limit`). Malformed lines are skipped so a
    half-written final line never breaks the reader."""
    out = []
    try:
        with open(AUDIT_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    out.reverse()
    return out[:max(0, limit)]


def audit_log_lines(limit=1000):
    """A readable ACTION LOG (named audit_log_lines to stay clear of the Security Audit's audit_lines)."""
    es = audit_entries(limit)
    if not es:
        return ["ACTION LOG - nothing recorded yet.", "",
                "Every power-off, power policy, firewall block and switch-port change NetScout sends is",
                "logged here with who ran it, when, the exact command, and whether it worked - a complete,",
                "reviewable trail of everything the tool has done to your network."]
    out = [f"ACTION LOG - {len(es)} most recent action(s), newest first", ""]
    for e in es:
        mark = "OK  " if e.get("ok") is True else ("--  " if e.get("ok") is None else "FAIL")
        out.append(f"{mark} {e.get('ts', '')}   {e.get('actor', '')}")
        line = f"     {e.get('action', '')}"
        if e.get("target"):
            line += f"  ->  {e.get('target')}"
        if e.get("method"):
            line += f"   [{e.get('method')}]"
        out.append(line)
        if e.get("command"):
            out.append(f"     $ {e.get('command')}")
        if e.get("detail"):
            out.append(f"       {e.get('detail')}")
    return out


def profiles_load():
    """Saved multi-subnet scan profiles: {name: {"networks": "<text>", "ports": bool, "type": str,
    "count": int}}. A profile just remembers which networks (and options) to sweep, so an engineer can
    pick 'Server VLAN' or 'Guest WiFi' instead of retyping ranges."""
    p = _load_json(PROFILES_FILE, {})
    return p if isinstance(p, dict) else {}


def profiles_save(profiles):
    _save_json_atomic(PROFILES_FILE, profiles)


def profile_put(name, networks, ports=True, dtype="ALL"):
    """Add or replace one profile. `networks` is the raw text, validated with parse_networks before it is
    stored. Returns (ok, message)."""
    name = (name or "").strip()
    if not name:
        return False, "Give the profile a name first."
    try:
        nets = parse_networks(networks)
    except ValueError as e:
        return False, str(e)
    profs = profiles_load()
    profs[name] = {"networks": networks.strip(), "ports": bool(ports), "type": (dtype or "ALL"),
                   "count": sum(n.num_addresses for n in nets)}
    profiles_save(profs)
    return True, f"Saved profile '{name}' ({len(nets)} network(s))."


def profile_delete(name):
    """Remove one profile. Returns True if it existed."""
    profs = profiles_load()
    if name in profs:
        del profs[name]
        profiles_save(profs)
        return True
    return False


def load_notes():
    """{mac (lower, colon form): {"note": str, "updated": iso8601}}."""
    return _load_json(NOTES_FILE, {})


def set_note(mac, text):
    """Save (or, with an empty text, delete) the note/tag for one MAC. Returns the updated table."""
    mac = norm_mac(mac)
    notes = load_notes()
    text = (text or "").strip()
    rec = dict(notes.get(mac) or {})
    if text:
        rec.update(note=text, updated=datetime.datetime.now().isoformat(timespec="seconds"))
        notes[mac] = rec
    elif rec.get("approved"):
        # clearing the note must not quietly un-approve the device: those are two separate decisions
        # about the same MAC, and silently revoking an approval would turn a tidy-up into a security
        # change nobody asked for. Drop the text, keep the approval.
        rec.pop("note", None)
        notes[mac] = rec
    else:
        notes.pop(mac, None)
    _save_json_atomic(NOTES_FILE, notes)
    return notes


def set_approved(mac, approved=True):
    """Mark one MAC as known-and-expected on this network, or take that mark away.

    BACKGROUND WATCH alerts on devices it has never seen before, which on a busy network means a steady
    trickle of alerts for phones joining the guest WiFi - and an alert stream nobody trusts is an alert
    stream nobody reads. With an approved list, the question changes from "is this new?" to "is this
    unexpected?", which is the one actually worth waking someone for.

    Shares the by-MAC store the notes already use, so an approved device keeps its note and vice versa.
    """
    mac = norm_mac(mac)
    notes = load_notes()
    rec = dict(notes.get(mac) or {})
    if approved:
        rec["approved"] = True
        rec["approved_at"] = datetime.datetime.now().isoformat(timespec="seconds")
        notes[mac] = rec
    else:
        rec.pop("approved", None)
        rec.pop("approved_at", None)
        if rec.get("note"):
            notes[mac] = rec          # keep the note behind, it is a separate thing
        else:
            notes.pop(mac, None)      # nothing left worth a record
    _save_json_atomic(NOTES_FILE, notes)
    return notes


def approved_macs(notes=None):
    notes = load_notes() if notes is None else notes
    return {m for m, rec in notes.items() if isinstance(rec, dict) and rec.get("approved")}


def apply_notes(devs, notes=None):
    """Stamp dev['note'] and dev['approved'] from the saved-by-MAC table onto every device. Devices
    without a MAC (rare - e.g. a host only ever seen over IPv6) get neither; there is nothing to key
    them on, and guessing by IP would hand one device's approval to whoever gets that address next."""
    notes = load_notes() if notes is None else notes
    for d in devs:
        mac = norm_mac(d.get("mac", "")) if d.get("mac") else ""
        rec = notes.get(mac) or {} if mac else {}
        d["note"] = rec.get("note", "")
        d["approved"] = bool(rec.get("approved"))
    return devs


# --- TLS certificates ----------------------------------------------------------------------------------
TLS_PORTS = (443, 8443, 9443, 636, 993, 995, 465, 5986)


def tls_cert(ip, port=443, timeout=1.2):
    """Read the certificate a host serves, without verifying it - the point is to SEE what is there,
    including the expired and self-signed ones, which a verifying handshake would refuse to complete.

    Returns {} when nothing speaks TLS on that port. Expiring internal certificates are a recurring
    outage nobody goes looking for until something breaks, and every host serving HTTPS is already
    being port-scanned anyway, so the extra cost here is one handshake.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                cert = tls.getpeercert()           # {} when unverified, so DER is parsed below instead
                proto, cipher = tls.version(), (tls.cipher() or ("",))[0]
    except Exception:
        return {}
    out = {"port": port, "proto": proto or "", "cipher": cipher or ""}
    out.update(_cert_fields(cert, der))
    return out


def _cert_fields(cert, der):
    """Subject/issuer/expiry. With verification off, getpeercert() returns {}, so the few fields that
    matter are pulled out of the DER by looking for the two UTCTime/GeneralizedTime stamps and the
    commonName attributes - far less than a real X.509 parser, and enough to answer 'whose cert, and
    when does it die'."""
    out = {"subject": "", "issuer": "", "expires": "", "days_left": None, "self_signed": None}
    if cert:
        out["subject"] = dict(x[0] for x in cert.get("subject", []) if x).get("commonName", "")
        out["issuer"] = dict(x[0] for x in cert.get("issuer", []) if x).get("commonName", "")
        out["expires"] = cert.get("notAfter", "")
    if der:
        found = []
        for m in re.finditer(rb"\x06\x03\x55\x04\x03[\x0c\x13\x16](.)", der):
            n = m.group(1)[0]
            start = m.end()
            val = der[start:start + n]
            try:
                found.append(val.decode("utf-8"))
            except UnicodeDecodeError:
                pass
        if found:
            out["issuer"] = out["issuer"] or found[0]
            out["subject"] = out["subject"] or found[-1]
            out["self_signed"] = len(set(found)) == 1
        times = re.findall(rb"\x17\x0d(\d{12})Z", der) + re.findall(rb"\x18\x0f(\d{14})Z", der)
        if len(times) >= 2:
            out["expires"] = out["expires"] or _cert_time(times[1])
    if out["expires"]:
        try:
            exp = datetime.datetime.strptime(out["expires"], "%b %d %H:%M:%S %Y GMT")
            out["days_left"] = (exp - datetime.datetime.utcnow()).days
        except ValueError:
            pass
    return out


def _cert_time(raw):
    t = raw.decode()
    year = int(t[:2]) + (2000 if int(t[:2]) < 50 else 1900) if len(t) == 12 else int(t[:4])
    rest = t[2:] if len(t) == 12 else t[4:]
    try:
        dt = datetime.datetime(year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]))
    except ValueError:
        return ""
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def cert_warnings(cert):
    """Plain-language problems with a certificate, worst first. Empty when it's healthy."""
    if not cert:
        return []
    out, left = [], cert.get("days_left")
    if left is not None:
        if left < 0:
            out.append(f"certificate EXPIRED {abs(left)} day(s) ago")
        elif left <= 14:
            out.append(f"certificate expires in {left} day(s)")
        elif left <= 30:
            out.append(f"certificate expires in {left} days")
    if cert.get("self_signed"):
        out.append("self-signed certificate (browsers will warn)")
    proto = (cert.get("proto") or "").upper()
    if proto.startswith("TLSV1") and proto not in ("TLSV1.2", "TLSV1.3"):
        out.append(f"obsolete {cert['proto']} - TLS 1.2 is the modern minimum")
    return out


# --- IP / MAC conflicts --------------------------------------------------------------------------------
def ip_conflicts(devs):
    """Findings where addressing has gone wrong. Two shapes, both worth someone's attention:

      - one MAC answering on several IPs: usually a multi-homed host or a VM bridge, occasionally
        ARP spoofing, and always worth knowing about deliberately rather than by accident
      - one IP claimed by several MACs within a single scan: a genuine address conflict, which
        produces exactly the kind of intermittent breakage that is miserable to track down by hand

    Returns [{"kind", "key", "devices", "text"}].
    """
    by_mac, by_ip, out = {}, {}, []
    for d in devs:
        mac = norm_mac(d.get("mac", "")) if d.get("mac") else ""
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            by_mac.setdefault(mac, []).append(d)
        if d.get("ip"):
            by_ip.setdefault(d["ip"], []).append(d)
    for mac, ds in sorted(by_mac.items()):
        if len(ds) > 1:
            ips = ", ".join(d["ip"] for d in ds)
            label = next((d.get("label") or d.get("vendor") or "" for d in ds if d.get("label") or d.get("vendor")), "")
            out.append({"kind": "mac_on_many_ips", "key": mac, "devices": ds,
                        "text": f"{mac} answers on {len(ds)} addresses ({ips})"
                                + (f" - {label}" if label else "")})
    for ip, ds in sorted(by_ip.items()):
        macs = {norm_mac(d["mac"]) for d in ds if d.get("mac")}
        if len(macs) > 1:
            out.append({"kind": "ip_on_many_macs", "key": ip, "devices": ds,
                        "text": f"{ip} is claimed by {len(macs)} different MACs ({', '.join(sorted(macs))})"
                                " - address conflict"})
    return out


def conflicts_vs_history(devs, snapshots=None):
    """An IP whose MAC changed since the last scan. Mostly ordinary DHCP churn, which is why this is
    reported separately from a live conflict rather than mixed in with it - but it is also what an
    address being taken over looks like, so it is worth being able to see."""
    snaps = list_snapshots() if snapshots is None else snapshots
    if not snaps:
        return []
    prev = {d.get("ip"): norm_mac(d.get("mac", "")) for d in load_snapshot(snaps[0]["stamp"]) if d.get("mac")}
    out = []
    for d in devs:
        mac = norm_mac(d.get("mac", "")) if d.get("mac") else ""
        was = prev.get(d.get("ip"))
        if mac and was and was != mac:
            out.append({"kind": "ip_changed_hands", "key": d["ip"], "devices": [d],
                        "text": f"{d['ip']} was {was} in the previous scan, now {mac}"})
    return out


# --- first seen / last seen ----------------------------------------------------------------------------
def seen_index(snapshots=None):
    """{mac: {"first": stamp, "last": stamp, "count": n}} built from the scan history already on disk.

    Nothing new is collected for this - every scan has been written to HISTORY_DIR all along and only
    ever read back for comparisons. Knowing a device has been here since March, versus having turned up
    on Tuesday, is most of what anyone wants when they spot something unfamiliar in the list.
    """
    out = {}
    for snap in (list_snapshots() if snapshots is None else snapshots):
        stamp = snap["stamp"]
        for d in load_snapshot(stamp):
            mac = norm_mac(d.get("mac", "")) if d.get("mac") else ""
            if not mac:
                continue
            rec = out.setdefault(mac, {"first": stamp, "last": stamp, "count": 0})
            rec["count"] += 1
            if stamp < rec["first"]:
                rec["first"] = stamp
            if stamp > rec["last"]:
                rec["last"] = stamp
    return out


def stamp_pretty(stamp):
    """History stamps are filename-safe and written by save_snapshot as %Y%m%d_%H%M%S_%f, sometimes with
    a further _n suffix when two snapshots land in the same microsecond. Only the date and time are worth
    showing, so take the first two underscore-separated parts and ignore whatever follows."""
    parts = (stamp or "").split("_")
    if len(parts) >= 2:
        try:
            return datetime.datetime.strptime(parts[0] + parts[1], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M")
        except ValueError:
            pass
    return stamp or ""


def apply_seen(devs, index=None):
    """Stamp first/last sighting onto devices. A device with no history yet is marked as first seen
    now, rather than left blank - 'this is the first time' is itself the useful answer."""
    index = seen_index() if index is None else index
    for d in devs:
        mac = norm_mac(d.get("mac", "")) if d.get("mac") else ""
        rec = index.get(mac) if mac else None
        d["first_seen"] = stamp_pretty(rec["first"]) if rec else ""
        d["last_seen"] = stamp_pretty(rec["last"]) if rec else ""
        d["seen_count"] = rec["count"] if rec else 0
        d["is_new"] = bool(mac) and not rec
    return devs


# ------------------------------------------------------- scan history / comparison
def _history_path(stamp):
    return os.path.join(HISTORY_DIR, f"scan_{stamp}.json")


def save_snapshot(devs, label=""):
    """Persist one scan's results (IP/MAC/type/label/vendor/ports - not live fields like latency) so a
    later scan can be compared against it. Returns the stamp (filename key) it was saved under."""
    os.makedirs(HISTORY_DIR, exist_ok=True)
    # microsecond resolution, plus a numeric suffix on the rare exact collision - two snapshots saved
    # within the same second (manual "compare now" right after a scan, or a scheduled scan firing back
    # to back) must never silently overwrite one another.
    base = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    stamp, n = base, 0
    while os.path.exists(_history_path(stamp)):
        n += 1
        stamp = f"{base}_{n}"
    slim = [{"ip": d["ip"], "mac": d.get("mac", ""), "type": d.get("type", ""), "label": d.get("label", ""),
             "name": d.get("name", ""), "vendor": d.get("vendor", ""), "ports": sorted(d.get("ports", [])),
             "risk": d.get("risk", "")}
            for d in devs]
    risks = sum(1 for s in slim if _dev_risk_rank(s.get("risk")) >= 1)
    _save_json_atomic(_history_path(stamp), {"stamp": stamp, "label": label, "devices": slim,
                                             "device_count": len(slim), "risks": risks})
    snaps = list_snapshots()
    for old in snaps[HISTORY_MAX:]:          # keep the history folder from growing without bound
        try:
            os.remove(_history_path(old["stamp"]))
        except OSError:
            pass
    return stamp


def list_snapshots():
    """Newest first: [{"stamp", "label", "count"}]. Reads just enough of each file to list it cheaply."""
    out = []
    try:
        names = sorted(os.listdir(HISTORY_DIR), reverse=True)
    except OSError:
        return out
    for name in names:
        if not (name.startswith("scan_") and name.endswith(".json")):
            continue
        data = _load_json(os.path.join(HISTORY_DIR, name), {})
        if data:
            out.append({"stamp": data.get("stamp", name[5:-5]), "label": data.get("label", ""),
                        "count": len(data.get("devices", [])),
                        "risks": data.get("risks", sum(1 for d in data.get("devices", [])
                                                        if _dev_risk_rank(d.get("risk")) >= 1))})
    return out


def load_snapshot(stamp):
    data = _load_json(_history_path(stamp), {})
    return data.get("devices", [])


def diff_snapshots(old, new):
    """Compare two device lists (by MAC when both sides have one, else by IP). Returns:
    {"new": [...], "missing": [...], "changed": [(old_dev, new_dev, [field,...]), ...], "unchanged": n}.
    'new'/'missing' devices are objects from the respective list; a device that changed its IP but kept
    its MAC is matched (not reported as one missing + one new), which is the whole point of keying on MAC
    first - DHCP routinely hands out a different address to the same physical device between scans."""
    def key(d):
        return ("mac", d["mac"]) if d.get("mac") else ("ip", d["ip"])
    old_by, new_by = {key(d): d for d in old}, {key(d): d for d in new}
    new_keys, missing_keys = set(new_by) - set(old_by), set(old_by) - set(new_by)
    common = set(old_by) & set(new_by)
    changed = []
    for k in common:
        o, n = old_by[k], new_by[k]
        fields = [f for f in ("ip", "type", "label", "vendor") if (o.get(f) or "") != (n.get(f) or "")]
        if sorted(o.get("ports", [])) != sorted(n.get("ports", [])):
            fields.append("ports")
        # risk is compared only when the earlier snapshot actually recorded the field, so snapshots saved
        # before risk was stored (no "risk" key at all) don't spuriously report a change for every device -
        # while a device that genuinely went from NONE to HIGH is still caught.
        if "risk" in o and (o.get("risk") or "") != (n.get("risk") or ""):
            fields.append("risk")
        if fields:
            changed.append((o, n, fields))
    return {"new": [new_by[k] for k in new_keys], "missing": [old_by[k] for k in missing_keys],
            "changed": changed, "unchanged": len(common) - len(changed)}


def diff_lines(diff, old_label="", new_label=""):
    lines = [f"COMPARISON{'  ' + old_label + ' -> ' + new_label if old_label or new_label else ''}\n"]
    if diff["new"]:
        lines.append(f"NEW ({len(diff['new'])}):")
        for d in sorted(diff["new"], key=lambda d: d["ip"]):
            lines.append(f"  + {d['ip']:<16}{d.get('mac') or '-':<19}{d.get('label') or '-'}")
    if diff["missing"]:
        lines.append(f"\nNO LONGER SEEN ({len(diff['missing'])}):")
        for d in sorted(diff["missing"], key=lambda d: d["ip"]):
            lines.append(f"  - {d['ip']:<16}{d.get('mac') or '-':<19}{d.get('label') or '-'}")
    if diff["changed"]:
        lines.append(f"\nCHANGED ({len(diff['changed'])}):")
        for o, n, fields in sorted(diff["changed"], key=lambda t: t[1]["ip"]):
            for f in fields:
                lines.append(f"  ~ {n['ip']:<16}{n.get('mac') or '-':<19}{f}: {o.get(f) or '-'} -> {n.get(f) or '-'}")
    if not (diff["new"] or diff["missing"] or diff["changed"]):
        lines.append("No differences - every device matches the earlier snapshot.")
    lines.append(f"\n{diff['unchanged']} device(s) unchanged.")
    return lines


# =================================================================== 24/7 Guardian
# Turns NetScout from a one-shot scanner into a continuous watch: every cycle is saved to the scan
# history (above), diffed against the one before it into a plain-language "what changed" feed, checked
# against an approved baseline, and - for anything that crosses a severity threshold - pushed out as a
# desktop notification, an email, and/or a Slack/Teams/webhook message. All of it is Python standard
# library (json / smtplib / urllib), so it adds no dependency and runs anywhere NetScout already does.

GUARDIAN_DEFAULTS = {
    "enabled": False,        # is the Guardian watch running
    "interval": 300,         # seconds between cycles
    "baseline_on": False,    # also flag anything that drifts from the approved baseline
    "min_severity": "warn",  # only send alerts at or above this: info < warn < alert
    "desktop": True,         # show a desktop notification
    "email_on": False, "smtp_host": "", "smtp_port": 587, "smtp_user": "", "smtp_pass": "",
    "smtp_to": "", "smtp_tls": True,
    "webhook_on": False, "webhook_url": "",   # a Slack / Teams / generic incoming-webhook URL
}
_SEVERITY_RANK = {"info": 0, "warn": 1, "alert": 2}


def guardian_config_load():
    """The Guardian's settings, defaults filled in for any key the saved file is missing."""
    cfg = dict(GUARDIAN_DEFAULTS)
    cfg.update(_load_json(GUARDIAN_FILE, {}))
    return cfg


def guardian_config_save(cfg):
    """Persist the Guardian settings (merged onto the defaults so the file is always complete)."""
    full = dict(GUARDIAN_DEFAULTS)
    full.update(cfg or {})
    _save_json_atomic(GUARDIAN_FILE, full)
    return full


def _slim_device(d):
    return {"ip": d.get("ip", ""), "mac": d.get("mac", ""), "type": d.get("type", ""),
            "label": d.get("label", ""), "name": d.get("name", ""), "vendor": d.get("vendor", ""),
            "ports": sorted(d.get("ports", []) or []), "risk": d.get("risk", "")}


def _dev_name(d):
    return d.get("label") or d.get("name") or d.get("type") or d.get("ip") or "device"


def guardian_changes(old, new, stamp="", when=""):
    """Translate the difference between two scans into a severity-tagged, plain-language event feed.
    Pure function: give it two device lists, get back a list of events, newest-interesting first is up to
    the caller. Severities: 'alert' (act now), 'warn' (worth a look), 'info' (just so you know)."""
    d = diff_snapshots(old, new)
    ev = []

    def add(kind, severity, dev, text):
        ev.append({"ts": stamp, "when": when, "kind": kind, "severity": severity,
                   "ip": dev.get("ip", ""), "mac": dev.get("mac", ""), "label": _dev_name(dev), "text": text})

    for dv in d["new"]:
        where = dv.get("ip", "?") + ((", " + dv["mac"]) if dv.get("mac") else "")
        add("device_new", "warn", dv, f"New device joined: {_dev_name(dv)} ({where})")
    for dv in d["missing"]:
        add("device_gone", "info", dv, f"Device left the network: {_dev_name(dv)} ({dv.get('ip', '?')})")
    for o, n, fields in d["changed"]:
        name = _dev_name(n)
        if "ports" in fields:
            opened = sorted(set(n.get("ports", [])) - set(o.get("ports", [])))
            closed = sorted(set(o.get("ports", [])) - set(n.get("ports", [])))
            if opened:
                risky = [p for p in opened if p in RISKY_PORTS]
                sev = "alert" if risky else "warn"
                tail = f" (incl. risky {', '.join(map(str, risky))})" if risky else ""
                add("ports_opened", sev, n, f"{name}: new open port(s) {', '.join(map(str, opened))}{tail}")
            if closed:
                add("ports_closed", "info", n, f"{name}: port(s) closed {', '.join(map(str, closed))}")
        if "risk" in fields:
            up = _dev_risk_rank(n.get("risk")) > _dev_risk_rank(o.get("risk"))
            sev = ("alert" if _dev_risk_rank(n.get("risk")) >= 3 else "warn") if up else "info"
            verb = "rose" if up else "fell"
            add("risk_up" if up else "risk_down", sev, n,
                f"{name}: risk {verb} {o.get('risk') or 'NONE'} -> {n.get('risk') or 'NONE'}")
        if "vendor" in fields and o.get("mac") and o.get("mac") == n.get("mac"):
            add("vendor_changed", "warn", n,
                f"{name}: vendor changed {o.get('vendor') or '?'} -> {n.get('vendor') or '?'} (same MAC)")
        if "ip" in fields:
            add("ip_changed", "info", n, f"{name}: address changed {o.get('ip')} -> {n.get('ip')}")
        if "type" in fields:
            add("type_changed", "info", n, f"{name}: type changed {o.get('type') or '?'} -> {n.get('type') or '?'}")
    return ev


def guardian_timeline(limit=200, snapshots=None):
    """The full change feed across the saved history, newest first: diff each snapshot against the one
    before it and concatenate. Capped at `limit` events so a long history can't flood the view."""
    snaps = list(reversed(list_snapshots() if snapshots is None else snapshots))  # oldest -> newest
    events, prev = [], None
    for s in snaps:
        devs = load_snapshot(s["stamp"])
        if prev is not None:
            events.extend(guardian_changes(prev, devs, s["stamp"], stamp_pretty(s["stamp"])))
        prev = devs
    events.reverse()
    return events[:limit]


def guardian_trends(limit=60, snapshots=None):
    """Per-snapshot counts for the trend chart, oldest -> newest (last `limit` snapshots):
    [{"stamp","when","devices","risks"}]. Cheap - uses the counts already stored with each snapshot."""
    snaps = list(reversed(list_snapshots() if snapshots is None else snapshots))[-max(1, limit):]
    return [{"stamp": s["stamp"], "when": stamp_pretty(s["stamp"]),
             "devices": s.get("count", 0), "risks": s.get("risks", 0)} for s in snaps]


# --- approved "golden" baseline -----------------------------------------------------------------------
def guardian_baseline_save(devs):
    """Approve the current network as the known-good baseline. Drift from this is what gets flagged."""
    slim = [_slim_device(d) for d in devs]
    _save_json_atomic(BASELINE_FILE, {"saved": datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
                                      "devices": slim})
    return len(slim)


def guardian_baseline_load():
    return _load_json(BASELINE_FILE, {})


def guardian_baseline_clear():
    try:
        os.remove(BASELINE_FILE)
        return True
    except OSError:
        return False


def guardian_baseline_drift(devs):
    """Security-relevant drift from the approved baseline: a device that isn't in it, or a baseline device
    that has opened a new port. Empty list when no baseline has been approved yet."""
    base = guardian_baseline_load()
    if not base or not base.get("devices"):
        return []
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    d = diff_snapshots(base["devices"], devs)
    ev = []

    def add(kind, dev, text):
        ev.append({"ts": "", "when": when, "kind": kind, "severity": "alert",
                   "ip": dev.get("ip", ""), "mac": dev.get("mac", ""), "label": _dev_name(dev), "text": text})

    for dv in d["new"]:
        where = dv.get("ip", "?") + ((", " + dv["mac"]) if dv.get("mac") else "")
        add("baseline_new", dv, f"Not in your approved baseline: {_dev_name(dv)} ({where})")
    for o, n, fields in d["changed"]:
        if "ports" in fields:
            opened = sorted(set(n.get("ports", [])) - set(o.get("ports", [])))
            if opened:
                add("baseline_ports", n, f"{_dev_name(n)}: port(s) {', '.join(map(str, opened))} not in baseline")
    return ev


# --- sending alerts out of the app --------------------------------------------------------------------
def _smtp_send(cfg, msg):
    """Connect to the configured SMTP server and send one already-built EmailMessage. Shared by the
    Guardian's alert mail and the weekly health report so the connect/TLS/login logic lives in one place.
    Returns (ok, message); never raises."""
    host, to = (cfg.get("smtp_host") or "").strip(), (cfg.get("smtp_to") or "").strip()
    if not host or not to:
        return False, "email not configured (need an SMTP host and a recipient)"
    try:
        import smtplib
        if not msg["From"]:
            msg["From"] = (cfg.get("smtp_user") or "").strip() or ("netscout@" + (socket.gethostname() or "localhost"))
        if not msg["To"]:
            msg["To"] = to
        port = int(cfg.get("smtp_port") or 587)
        server = smtplib.SMTP_SSL(host, port, timeout=15) if port == 465 else smtplib.SMTP(host, port, timeout=15)
        try:
            if port != 465 and cfg.get("smtp_tls", True):
                server.starttls()
            if cfg.get("smtp_user"):
                server.login(cfg["smtp_user"], cfg.get("smtp_pass") or "")
            server.send_message(msg)
        finally:
            try:
                server.quit()
            except Exception:
                pass
        return True, "sent"
    except Exception as e:
        return False, f"email failed: {e}"


def notify_email(cfg, subject, body):
    """Send one plain-text alert email over SMTP using the Guardian's settings. Returns (ok, message);
    never raises - a monitoring tool must not crash because a mail server was briefly unreachable."""
    if not (cfg.get("smtp_host") or "").strip() or not (cfg.get("smtp_to") or "").strip():
        return False, "email not configured (need an SMTP host and a recipient)"
    try:
        import email.message
        msg = email.message.EmailMessage()
        msg["Subject"] = subject
        msg.set_content(body)
    except Exception as e:
        return False, f"email failed: {e}"
    return _smtp_send(cfg, msg)


def send_report_email(cfg, subject, text_body, html_body=None, attachment=None, attachment_name="report.html"):
    """Send the weekly health report: a plain-text body with an HTML alternative, plus an optional
    attachment (e.g. the HTML or PDF report as bytes). Returns (ok, message); never raises."""
    if not (cfg.get("smtp_host") or "").strip() or not (cfg.get("smtp_to") or "").strip():
        return False, "email not configured (need an SMTP host and a recipient)"
    try:
        import email.message
        msg = email.message.EmailMessage()
        msg["Subject"] = subject
        msg.set_content(text_body or "(see the attached report)")
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        if attachment is not None:
            data = attachment if isinstance(attachment, (bytes, bytearray)) else str(attachment).encode("utf-8")
            maintype, subtype = ("application", "pdf") if attachment_name.lower().endswith(".pdf") else ("text", "html")
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=attachment_name)
    except Exception as e:
        return False, f"email failed: {e}"
    return _smtp_send(cfg, msg)


def notify_webhook(url, payload):
    """POST a JSON payload to an incoming webhook (Slack, Teams, or any endpoint). Slack and Teams both
    render the 'text' field, so a plain message reaches all of them. Returns (ok, message); never raises."""
    url = (url or "").strip()
    if not url:
        return False, "no webhook URL set"
    if not re.match(r"^https?://", url, re.I):
        return False, "webhook URL must start with http:// or https://"
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        return True, "sent"
    except Exception as e:
        return False, f"webhook failed: {e}"


def guardian_dispatch(events, cfg=None, notify_fn=None):
    """Push the events out through whichever channels the settings enable, filtered to the minimum
    severity. Returns [(channel, ok, message)] - what was attempted and how it went. `notify_fn` lets the
    GUI supply its own desktop-notifier (and lets tests capture it); it defaults to the module notify()."""
    cfg = guardian_config_load() if cfg is None else cfg
    floor = _SEVERITY_RANK.get(cfg.get("min_severity", "warn"), 1)
    chosen = [e for e in events if _SEVERITY_RANK.get(e.get("severity", "info"), 0) >= floor]
    results = []
    if not chosen:
        return results
    n = len(chosen)
    subject = f"NetScout Guardian: {n} network change(s) need attention"
    body = "\n".join(f"[{e.get('severity', 'info').upper()}] {e.get('text', '')}" for e in chosen)
    if cfg.get("desktop", True):
        fn = notify_fn or notify
        try:
            fn("NetScout Guardian", f"{n} change(s): " + "; ".join(e.get("text", "") for e in chosen[:3]))
            results.append(("desktop", True, "shown"))
        except Exception as e:
            results.append(("desktop", False, str(e)))
    if cfg.get("email_on"):
        ok, msg = notify_email(cfg, subject, body)
        results.append(("email", ok, msg))
    if cfg.get("webhook_on"):
        ok, msg = notify_webhook(cfg.get("webhook_url"), {"text": subject + "\n" + body})
        results.append(("webhook", ok, msg))
    return results


def guardian_record(devs, label="guardian", cfg=None):
    """One Guardian cycle: diff this scan against the most recent saved snapshot, add any baseline drift,
    then save this scan as the new latest snapshot. Returns {"stamp","events","prev_count"}. Dispatch is
    left to the caller (so tests stay offline and the GUI controls when alerts fire)."""
    cfg = guardian_config_load() if cfg is None else cfg
    snaps = list_snapshots()
    prev = load_snapshot(snaps[0]["stamp"]) if snaps else []
    stamp = save_snapshot(devs, label=label)
    events = guardian_changes(prev, devs, stamp, stamp_pretty(stamp)) if prev else []
    if cfg.get("baseline_on"):
        events = events + guardian_baseline_drift(devs)
    return {"stamp": stamp, "events": events, "prev_count": len(prev)}


# --------------------------------------------------------------------- WiFi
def current_ssid():
    if OS == "Windows":
        m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", run(["netsh", "wlan", "show", "interfaces"]), re.M)
        return m.group(1) if m else None
    if OS == "Linux":
        for line in run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]).splitlines():
            if line.startswith("yes:"):
                return line[4:].replace("\\:", ":")
        return run(["iwgetid", "-r"]).strip() or None
    out = run(["networksetup", "-listallhardwareports"])
    m = re.search(r"Hardware Port: (?:Wi-Fi|AirPort)\s*\nDevice: (\w+)", out)
    dev = m.group(1) if m else "en0"
    m = re.search(r"Network:\s*(.+)", run(["networksetup", "-getairportnetwork", dev]))
    if not m:
        m = re.search(r"\bSSID : (.+)", run(["ipconfig", "getsummary", dev]))
    name = m.group(1).strip() if m else None
    return None if not name or "redacted" in name.lower() else name


def wifi_password(ssid):
    if OS == "Windows":
        tmp = tempfile.mkdtemp()
        try:
            run(["netsh", "wlan", "export", "profile", f"name={ssid}", "key=clear", f"folder={tmp}"])
            for f in os.listdir(tmp):
                m = re.search(r"<keyMaterial>(.*?)</keyMaterial>", open(os.path.join(tmp, f), encoding="utf-8",
                                                                         errors="ignore").read())
                if m:
                    return m.group(1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return None
    if OS == "Linux":
        out = run(["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", "id", ssid]).strip()
        return out or None
    out = run(["security", "find-generic-password", "-D", "AirPort network password", "-wa", ssid], timeout=90).strip()
    return out or None


def wifi_report(ssid=None, info=None):
    ssid = ssid or current_ssid()
    if not ssid:
        return ["No WiFi network detected. Use --ssid NAME to look up a saved network by name."], None
    pw = wifi_password(ssid)
    lines = [f"WiFi name (SSID): {ssid}",
             f"Password        : {pw if pw else 'not found (open network, or needs admin/sudo permission)'}"]
    if info:
        lines += ["", *info_lines(info)]
    return lines, pw


# ------------------------------------------------------- other networks you run
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def parse_range(text, max_hosts=4096):
    """Validate a CIDR range typed by the user. Only private (internal) IPv4 ranges, up to /20."""
    try:
        net = ipaddress.ip_network((text or "").strip(), strict=False)
    except ValueError:
        raise ValueError("Enter a range like 192.168.20.0/24")
    if net.version != 4:
        raise ValueError("Only IPv4 ranges are supported.")
    if not any(net.subnet_of(a) for a in RFC1918):
        raise ValueError("Only internal ranges can be scanned (10.x.x.x, 172.16-31.x.x, 192.168.x.x) - "
                         "your own networks.")
    if net.num_addresses > max_hosts:
        raise ValueError(f"Range too large - the maximum is a /20 ({max_hosts} addresses).")
    return net


# ------------------------------------------------------------- nearby WiFi
def rssi_to_pct(rssi):
    return max(0, min(100, 2 * (int(rssi) + 100)))


# 5 GHz uses this fixed set of 20 MHz channel numbers. 6 GHz numbers its channels 1,5,9,...,233 -
# which happens to reuse 149/153/157/161/165 from the 5 GHz list, so those five numbers are genuinely
# ambiguous without a frequency or explicit band string. Everything else that falls on the 6 GHz
# numbering (and isn't in the 5 GHz set) is 6 GHz-only - that's most WiFi 6E / WiFi 7 channels.
_5GHZ_CHANNELS = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                  149, 153, 157, 161, 165}
_AMBIGUOUS_CHANNELS = {149, 153, 157, 161, 165}
_6GHZ_ONLY_CHANNELS = set(range(1, 234, 4)) - _AMBIGUOUS_CHANNELS


def wifi_band(channel=None, freq=None, hint=""):
    m = re.search(r"(\d(?:\.\d)?)\s*ghz", hint or "", re.I)
    if m:
        return "2.4 GHz" if m.group(1) == "2" else f"{m.group(1)} GHz"
    if freq:
        return "2.4 GHz" if freq < 3000 else "5 GHz" if freq < 5925 else "6 GHz"
    if channel:
        if channel <= 14:
            return "2.4 GHz"
        if channel in _AMBIGUOUS_CHANNELS:
            return "5/6 GHz (?)"          # channel number alone can't tell these apart
        if channel in _6GHZ_ONLY_CHANNELS:
            return "6 GHz"
        return "5 GHz"
    return ""


WIFI_GEN = {"be": "Wi-Fi 7", "ax": "Wi-Fi 6", "ac": "Wi-Fi 5", "n": "Wi-Fi 4", "g": "Wi-Fi 3",
            "a": "Wi-Fi 2", "b": "Wi-Fi 1"}


def wifi_generation(std, band=None):
    """Map the raw 802.11 letter (as the OS reports it) to the marketing Wi-Fi generation name."""
    m = re.search(r"802\.11([a-z]+)", std or "", re.I)
    tag = (m.group(1) if m else (std or "")).lower()
    for code in ("be", "ax", "ac", "n", "g", "a", "b"):
        if code in tag:
            return "Wi-Fi 6E" if code == "ax" and band == "6 GHz" else WIFI_GEN[code]
    return ""


# 6 GHz "Preferred Scanning Channels" (every 4th 20 MHz channel, offset 5): the ones a client scans
# first, so an AP that wants to be found fast sits on one. Handy to flag in a 6 GHz / Wi-Fi 6E/7 audit.
_6GHZ_PSC = set(range(5, 234, 16))


def is_psc_channel(channel, band=None):
    return bool(channel) and (band or "").startswith("6") and channel in _6GHZ_PSC


def combine_standard(std, band=None, width=None):
    gen = wifi_generation(std, band)
    extra = f"{int(width)} MHz" if width else ""
    inside = ", ".join(x for x in (gen, extra) if x)
    if not std:
        return f"{gen}{' · ' + extra if extra else ''}" if gen else extra
    return f"{std} ({inside})" if inside else std


def wifi_risk(sec):
    s = (sec or "").lower().strip()
    if s in ("", "--", "none") or s.startswith("open"):
        return "OPEN"
    if "wep" in s:
        return "WEAK"
    if "wpa3" in s and "wpa2" not in s:
        return "BEST"          # WPA3-only: no downgrade path to WPA2's weaker 4-way handshake
    if "wpa3" in s or "wpa2" in s or "rsn" in s:
        return "OK"
    return "WEAK" if "wpa" in s else "?"


def wifi_grade(ap):
    """A professional-style security grade (A–F) for one network, with the reasons behind it.

    This is the single line a WiFi auditor cares about: not just "encrypted/not", but HOW well, taking
    in the WPA generation, whether management frames are protected (PMF / 802.11w, which is what stops
    deauth attacks), and whether WPS is left on (its PIN is a long-known weak point). Everything here is
    read passively from the network's own beacon - nothing is sent, nothing is attacked.
    """
    sec = (ap.get("security") or "").lower()
    risk = ap.get("risk") or wifi_risk(ap.get("security"))
    pmf, wps = ap.get("pmf"), ap.get("wps")
    if risk == "OPEN":
        grade, why = "F", ["no encryption - everything sent over it is readable by anyone in range"]
    elif "wep" in sec:
        grade, why = "F", ["WEP - broken since 2001, cracked in minutes; replace immediately"]
    elif "wpa" in sec and "wpa2" not in sec and "wpa3" not in sec:
        grade, why = "E", ["WPA1 - obsolete and weak; move to WPA2 or WPA3"]
    elif "wpa3" in sec and "wpa2" not in sec:
        grade, why = "A", ["WPA3 - the current best, with no downgrade path to a weaker mode"]
    elif "wpa3" in sec:
        grade, why = "B", ["WPA2/WPA3 transition - good, but a client can still be pushed to the weaker WPA2"]
    elif "wpa2" in sec or "rsn" in sec:
        grade, why = "C", ["WPA2 - acceptable, but no longer the strongest available"]
    else:
        return "?", ["security could not be determined from the beacon"]
    if pmf is True and grade in ("C", "B"):
        grade = {"C": "B", "B": "A"}[grade]
        why.append("management frames are protected (802.11w / PMF) - resistant to deauth attacks")
    elif pmf is False and grade in ("A", "B", "C"):
        why.append("NO management-frame protection - open to deauth / forced-disconnect attacks")
    if wps is True and grade not in ("F", "?"):
        grade = chr(min(ord("F"), ord(grade) + 1))
        why.append("WPS is enabled - its PIN is a known weak point; turn WPS off")
    return grade, why


# 2.4 GHz has only three channels that don't overlap each other; everyone should be on one of them.
NON_OVERLAP_24 = (1, 6, 11)


def best_channels(aps):
    """For each band, the clearest channel to put YOUR OWN network on. Returns
    {band: {"recommend": ch, "counts": {ch: n}, "note": str}}.

    This is the actionable half of a channel survey: not just "here's how busy each channel is", but
    "move to this one". On 2.4 GHz the channels overlap, so it weighs each candidate against its
    neighbours (a network on ch3 still interferes with ch1); on 5/6 GHz they don't overlap, so it's the
    least-used one that's heard.
    """
    cong = channel_congestion(aps)
    out = {}
    for band, counts in cong.items():
        if band.startswith("2.4"):
            # cost of each non-overlapping channel = everything within 2 channels of it (overlap range)
            cost = {c: sum(n for ch, n in counts.items() if abs(ch - c) <= 2) for c in NON_OVERLAP_24}
            best = min(NON_OVERLAP_24, key=lambda c: cost[c])
            out[band] = {"recommend": best, "counts": counts,
                         "note": f"use channel {best} (1/6/11 are the only non-overlapping choices on 2.4 GHz)"}
        else:
            best = min(counts, key=lambda c: counts[c]) if counts else None
            out[band] = {"recommend": best, "counts": counts,
                         "note": (f"channel {best} is the least crowded one heard" if best
                                  else "plenty of free channels - almost any will do")}
    return out


def pct_to_dbm(pct):
    """Inverse of rssi_to_pct() - an approximate dBm figure to show alongside the 0-100% the OS reports.
    Approximate because the % itself is already the OS's own simplification of the real radio RSSI."""
    return None if pct is None else int(round(pct / 2.0 - 100))


def _ap(ssid="", bssid="", sig=0, channel=None, band="", sec="", std="", connected=False):
    return {"ssid": ssid, "bssid": (bssid or "").lower(), "sig": int(sig), "channel": channel, "band": band,
            "security": sec or "Open", "standard": std, "connected": connected}


def parse_nmcli(text):
    aps = []
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 7:
            continue
        use, ssid, bssid, chan, freq, sig, sec = [p.replace("\\:", ":").replace("\\\\", "\\") for p in parts[:7]]
        ch = int(chan) if chan.strip().isdigit() else None
        fq = int(re.sub(r"\D", "", freq) or 0) or None
        aps.append(_ap(ssid, bssid, sig if sig.isdigit() else 0, ch, wifi_band(ch, fq),
                       "" if sec.strip() in ("", "--") else sec.strip(), "", use.strip() == "*"))
    return aps


def parse_netsh(text):
    aps, ssid, auth, enc, kv_after_ssid, cur = [], "", "", "", 0, None
    for line in text.splitlines():
        m = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*?)\s*$", line)
        if m:
            ssid, kv_after_ssid, auth, enc, cur = m.group(1), 0, "", "", None
            continue
        m = re.match(r"^\s*BSSID\s+\d+\s*:\s*((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", line)
        if m:
            cur = _ap(ssid, m.group(1), 0, None, "", auth if auth else "Open")
            cur["security"] = (auth + (" / " + enc if enc and enc.lower() not in ("none", "keine") else "")) or "Open"
            aps.append(cur)
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if cur is None:                       # per-SSID block: network type, authentication, encryption (in order)
            kv_after_ssid += 1
            if kv_after_ssid == 2:
                auth = val
            elif kv_after_ssid == 3:
                enc = val
            continue
        if "%" in val and re.match(r"^\d+\s*%", val):
            cur["sig"] = int(re.match(r"(\d+)", val).group(1))
        elif re.search(r"802\.11[a-z/]+", val):
            cur["standard"] = re.search(r"802\.11[a-z/]+", val).group(0)
        elif re.match(r"(?i)^(channel|kanal|canal|canale)", key) and val.split()[:1] and val.split()[0].isdigit():
            cur["channel"] = int(val.split()[0])
        elif re.search(r"\d(?:\.\d)?\s*GHz", val, re.I):
            cur["band"] = wifi_band(hint=val)
    for a in aps:
        a["band"] = a["band"] or wifi_band(a["channel"])
    return aps


def parse_airport(text):
    aps = []
    for line in text.splitlines():
        m = re.match(r"^\s*(.*?)\s+((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})\s+(-\d+)\s+(\d+)(?:,[+-]\d+)?\s+\S+\s+\S+\s+(.*)$",
                     line)
        if m:
            ssid, bssid, rssi, ch, sec = m.groups()
            ch = int(ch)
            aps.append(_ap(ssid, ":".join(x.zfill(2) for x in bssid.split(":")), rssi_to_pct(rssi), ch,
                           wifi_band(ch), "" if sec.strip() in ("NONE", "") else sec.strip()))
    return aps


def parse_system_profiler(text):
    aps, section, sec_indent, cur = [], "", 0, None
    for line in text.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped in ("Current Network Information:", "Other Local Wi-Fi Networks:"):
            section, sec_indent, cur = stripped, indent, None
            continue
        if not section or not stripped:
            continue
        if indent <= sec_indent:
            section, cur = "", None
            continue
        if stripped.endswith(":") and indent == sec_indent + 2:
            cur = _ap(stripped[:-1], "", 0, None, "", "", "", section.startswith("Current"))
            aps.append(cur)
        elif cur is not None and ":" in stripped:
            key, _, val = stripped.partition(":")
            val = val.strip()
            if key == "PHY Mode":
                cur["standard"] = val
            elif key == "Channel":
                m = re.match(r"(\d+)", val)
                cur["channel"] = int(m.group(1)) if m else None
                cur["band"] = wifi_band(cur["channel"], hint=val)
            elif key == "Security":
                cur["security"] = "Open" if val.lower().startswith("none") else val
            elif key.startswith("Signal"):
                m = re.match(r"(-\d+)", val)
                cur["sig"] = rssi_to_pct(m.group(1)) if m else 0
    return aps


def _iwctl_device():
    """First Wi-Fi device iwd (iwctl) is managing in station mode, or '' if none / iwd isn't in use."""
    for line in run(["iwctl", "device", "list"]).splitlines():
        m = re.match(r"^\s*(\S+)\s+station\b", line, re.I)
        if m:
            return m.group(1)
    return ""


_IWCTL_SEC = {"psk": "WPA2", "open": "", "8021x": "WPA2 802.1X", "wep": "WEP", "owe": "OWE (enhanced open)"}
_IWCTL_BARS = {1: 20, 2: 45, 3: 70, 4: 95}


def parse_iwctl(text):
    """iwd's 'station ... get-networks' table - a signal column of either raw dBm (newer iwd, with the
    'rssi-dbms' argument) or 1-4 stars (older iwd / default) - whichever this text actually has.
    iwd exposes no BSSID or channel here, unlike nmcli - callers should treat those as unavailable, not
    look for a bug when they're empty."""
    aps = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("-") or s.lower().startswith(("network name", "available networks")):
            continue
        connected = s.startswith(">")
        s = s.lstrip(">").strip()
        m = re.match(r"^(.*\S)\s{2,}(psk|open|8021x|wep|owe)\s+(-?\d+(?:\.\d+)?|\*{1,4})\s*$", s, re.I)
        if not m:
            continue
        ssid, sec_raw, sig_raw = m.groups()
        sig = rssi_to_pct(float(sig_raw)) if re.fullmatch(r"-?\d+(?:\.\d+)?", sig_raw) else \
            _IWCTL_BARS.get(len(sig_raw), 50)
        aps.append(_ap(ssid, "", sig, None, "", _IWCTL_SEC.get(sec_raw.lower(), sec_raw), "", connected))
    return aps


# 802.11 capability-block names iw prints, weakest to strongest, and their rank for "keep the highest"
_IW_PHY = [("ht capabilities", "802.11n"), ("vht capabilities", "802.11ac"),
           ("he capabilities", "802.11ax"), ("eht capabilities", "802.11be")]
_IW_PHY_RANK = {std: i for i, (_, std) in enumerate(_IW_PHY)}


def parse_iw(text):
    """`iw dev <dev> scan` - the richest source on Linux, and the only one that reports a TRUE signal
    level in dBm rather than a vendor's own 0-100 percentage. That matters beyond tidiness: the
    distance estimate works from dBm, and deriving it back out of a rounded percentage throws away
    precision the adapter actually measured."""
    aps, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"BSS ([0-9a-fA-F:]{17})", s)
        if m:
            if cur:
                aps.append(cur)
            cur = _ap(bssid=m.group(1).lower())
            cur["dbm"] = None
            continue
        if cur is None:
            continue
        # professional extras are checked INDEPENDENTLY (plain if, not elif) because they can appear on
        # the same indented lines the security block also matches - chaining them would let the RSN line
        # swallow the capabilities/WPS lines sitting under it.
        if "WPS:" in s or "Wi-Fi Protected Setup" in s:
            cur["wps"] = True                        # WPS left on - its PIN is a known weak point
        if "MFP-required" in s or "MFP-capable" in s or "Management frame protection" in s:
            cur["pmf"] = True                        # PMF / 802.11w: resists deauth attacks
        if "SAE" in s:
            cur["security"] = "WPA3"                 # SAE is WPA3's handshake, wherever it appears
        # the 802.11 generation, read from which capability blocks the beacon carries (iw doesn't print a
        # "802.11ax" string): EHT = Wi-Fi 7, HE = Wi-Fi 6, VHT = Wi-Fi 5, HT = Wi-Fi 4. Keep the highest.
        sl = s.lower()
        for rank, (tag, std) in enumerate(_IW_PHY):
            if tag in sl and rank > _IW_PHY_RANK.get(cur.get("standard"), -1):
                cur["standard"] = std
        wm = re.search(r"width:\s*(\d+)\s*MHz", s)   # the operating channel width (20/40/80/160/320)
        if wm:
            cur["width"] = max(cur.get("width") or 0, int(wm.group(1)))
        if s.startswith("SSID:"):
            cur["ssid"] = s[5:].strip()
        elif s.startswith("signal:"):
            sm = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", s)
            if sm:
                cur["dbm"] = float(sm.group(1))
                cur["sig"] = rssi_to_pct(float(sm.group(1)))
        elif s.startswith("freq:"):
            fm = re.search(r"(\d{4})", s)
            if fm:
                f = int(fm.group(1))
                cur["channel"] = ((f - 2407) // 5 if f < 2500 else
                                  (f - 5000) // 5 if f < 5925 else (f - 5950) // 5)
                cur["band"] = "2.4 GHz" if f < 2500 else "5 GHz" if f < 5925 else "6 GHz"
        elif ("RSN:" in s or "WPA:" in s) and not str(cur.get("security", "")).startswith("WPA3"):
            cur["security"] = "WPA2" if "RSN:" in s else "WPA"
        elif s.startswith("capability:") and "Privacy" not in s and not cur.get("security"):
            cur["security"] = "Open"
    if cur:
        aps.append(cur)
    for a in aps:
        a["security"] = a.get("security") or "Open"
    return [a for a in aps if a.get("bssid")]


def parse_wpa_cli(text):
    """`wpa_cli scan_results` - tab separated bssid / frequency / signal / flags / ssid. Present on
    essentially any Linux that runs wpa_supplicant, which includes the systemd-networkd and embedded
    setups that have neither NetworkManager nor iwd, and needs no root when the user is in netdev."""
    aps = []
    for line in text.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 4 or not re.fullmatch(r"[0-9a-fA-F:]{17}", parts[0]):
            continue
        bssid, freq, sig, flags = parts[0].lower(), parts[1], parts[2], parts[3]
        ssid = parts[4] if len(parts) > 4 else ""
        try:
            f, dbm = int(freq), float(sig)
        except ValueError:
            continue
        sec = ("WPA3" if "SAE" in flags else "WPA2" if "WPA2" in flags else "WPA" if "WPA" in flags
               else "WEP" if "WEP" in flags else "Open")
        a = _ap(ssid=ssid, bssid=bssid, sig=rssi_to_pct(dbm), sec=sec,
                channel=((f - 2407) // 5 if f < 2500 else (f - 5000) // 5 if f < 5925 else (f - 5950) // 5),
                band="2.4 GHz" if f < 2500 else "5 GHz" if f < 5925 else "6 GHz")
        a["dbm"] = dbm
        aps.append(a)
    return aps


def _wlan_structs():
    """The three wlanapi.h structures WlanScan needs, declared with fixed-width types only (no wintypes,
    no c_wchar) so the layout is identical - and testable - on every OS: GUID 16 bytes,
    WLAN_INTERFACE_INFO 532 bytes, its list header 8 bytes."""
    import ctypes as C

    class GUID(C.Structure):
        _fields_ = [("Data1", C.c_uint32), ("Data2", C.c_uint16), ("Data3", C.c_uint16), ("Data4", C.c_ubyte * 8)]

    class WLAN_INTERFACE_INFO(C.Structure):
        _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", C.c_uint16 * 256), ("isState", C.c_uint32)]

    class WLAN_INTERFACE_INFO_LIST(C.Structure):
        _fields_ = [("dwNumberOfItems", C.c_uint32), ("dwIndex", C.c_uint32),
                    ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]
    return GUID, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST


def win_wlan_scan(cancel=None, wait=4.0, dll=None):
    """Make Windows do a FRESH WiFi scan right now, then wait for it to finish. Returns True if asked.

    `netsh wlan show networks` only prints what Windows heard during its own last background scan - often
    a minute or more old, sometimes just the network you are on - so every 'pass' used to re-read the same
    stale list. WlanScan (the call the WiFi menu itself makes) needs no administrator rights. Drivers must
    complete a scan within 4 seconds, which is the wait. Any failure - an older Windows, no WiFi adapter,
    Location turned off on Windows 11 - quietly leaves things as they were: netsh still runs after this."""
    if dll is None and OS != "Windows":
        return False
    try:
        import ctypes as C
        GUID, INFO, LIST = _wlan_structs()
        wl = dll if dll is not None else C.WinDLL("wlanapi.dll")
        H = C.c_void_p
        wl.WlanOpenHandle.argtypes = [C.c_uint32, C.c_void_p, C.POINTER(C.c_uint32), C.POINTER(H)]
        wl.WlanOpenHandle.restype = C.c_uint32
        wl.WlanEnumInterfaces.argtypes = [H, C.c_void_p, C.POINTER(C.POINTER(LIST))]
        wl.WlanEnumInterfaces.restype = C.c_uint32
        wl.WlanScan.argtypes = [H, C.POINTER(GUID), C.c_void_p, C.c_void_p, C.c_void_p]
        wl.WlanScan.restype = C.c_uint32
        wl.WlanFreeMemory.argtypes = [C.c_void_p]
        wl.WlanFreeMemory.restype = None
        wl.WlanCloseHandle.argtypes = [H, C.c_void_p]
        wl.WlanCloseHandle.restype = C.c_uint32
        ver, h = C.c_uint32(), H()
        if wl.WlanOpenHandle(2, None, C.byref(ver), C.byref(h)) != 0:
            return False
        asked = 0
        try:
            plist = C.POINTER(LIST)()
            if wl.WlanEnumInterfaces(h, None, C.byref(plist)) != 0 or not plist:
                return False
            try:
                n = plist.contents.dwNumberOfItems
                base = C.addressof(plist.contents) + LIST.InterfaceInfo.offset
                for i in range(min(n, 16)):
                    info = INFO.from_address(base + i * C.sizeof(INFO))
                    if wl.WlanScan(h, C.byref(info.InterfaceGuid), None, None, None) == 0:
                        asked += 1
            finally:
                wl.WlanFreeMemory(C.cast(plist, C.c_void_p))
        finally:
            wl.WlanCloseHandle(h, None)
        if asked and wait:
            if cancel is not None:
                cancel.wait(wait)
            else:
                time.sleep(wait)
        return asked > 0
    except Exception:
        return False


def _wifi_list(log=print, cancel=None):
    """One passive look at the WiFi networks in range - what your OS WiFi menu shows. Returns (aps, error_text).

    Each platform tries several tools in turn rather than one, because the tool that exists varies by
    version, not just by OS: macOS deleted the `airport` binary in 14.4, and plenty of Linux installs
    run neither NetworkManager nor iwd. Falling through a chain is what makes this work on a machine
    nobody tested it on.
    """
    _wifi_list.fresh = False      # set True below when a fresh Windows scan was triggered
    err, aps = "", []
    if OS == "Linux":
        if _which("nmcli"):
            fields = "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY"
            # NetworkManager can ignore or rate-limit a rescan requested right after a previous one (or
            # right after boot, before it has finished its own first scan) - one quick retry before
            # falling back to its last cached results catches that instead of reporting "nothing found".
            for attempt in range(2):
                aps = parse_nmcli(run(["nmcli", "-t", "-f", fields, "dev", "wifi", "list", "--rescan", "yes"],
                                      timeout=30))
                if aps or attempt:
                    break
                time.sleep(1.0)
            if not aps:
                aps = parse_nmcli(run(["nmcli", "-t", "-f", fields, "dev", "wifi", "list", "--rescan", "no"]))
        elif _which("iwctl"):
            dev = _iwctl_device()
            if not dev:
                return [], "iwctl found no Wi-Fi device in station mode."
            aps = parse_iwctl(run(["iwctl", "station", dev, "get-networks", "rssi-dbms"], timeout=30))
            if not aps:
                aps = parse_iwctl(run(["iwctl", "station", dev, "get-networks"], timeout=30))
            if aps:
                log("Using iwd (iwctl) - it doesn't expose BSSID or channel, only nmcli (NetworkManager) "
                    "shows those on Linux.")
        elif _which("iw"):
            # iw needs a device name and usually root to trigger a fresh scan, but "scan dump" reads
            # the last results without either, so both are tried.
            dev = ""
            for ln in run(["iw", "dev"]).splitlines():
                dm = re.search(r"Interface\s+(\S+)", ln)
                if dm:
                    dev = dm.group(1)
                    break
            if dev:
                aps = parse_iw(run(["iw", "dev", dev, "scan"], timeout=30)) or \
                      parse_iw(run(["iw", "dev", dev, "scan", "dump"], timeout=30))
                if aps:
                    log("Using iw - it reports true signal strength in dBm, so distances are more accurate.")
        elif _which("wpa_cli"):
            run(["wpa_cli", "scan"], timeout=10)
            time.sleep(2.0)
            aps = parse_wpa_cli(run(["wpa_cli", "scan_results"], timeout=20))
            if aps:
                log("Using wpa_supplicant (wpa_cli) - true dBm readings, so distances are more accurate.")
        if not aps and not _which("nmcli") and not _which("iwctl") \
                and not _which("iw") and not _which("wpa_cli"):
            return [], ("No WiFi scanning tool found. Any one of these works: nmcli (NetworkManager), "
                        "iwctl (iwd), iw, or wpa_cli (wpa_supplicant).")
    elif OS == "Windows":
        # a fresh scan first, so what netsh prints is what is in the air NOW, not Windows' cached list
        _wifi_list.fresh = win_wlan_scan(cancel)
        if _wifi_list.fresh:
            log("Asked Windows for a fresh WiFi scan (no admin needed) - results are live, not cached.")
        aps = parse_netsh(run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30))
        if not aps:
            err = ("No WiFi networks found. Check that WiFi is on. On Windows 11, 'Location' must be enabled "
                   "(Settings > Privacy & security > Location).")
    else:
        # airport was deprecated and then REMOVED in macOS 14.4, so its absence is now the normal case
        # on a current Mac rather than an error; system_profiler is the supported route and works on
        # every version, old and new.
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.exists(airport):
            aps = parse_airport(run([airport, "-s"], timeout=30))
        if not aps:
            aps = parse_system_profiler(run(["system_profiler", "SPAirPortDataType"], timeout=60))
            if aps:
                log("macOS hides some details (MAC addresses, sometimes names) unless Location Services allow it.")
        if not aps:
            err = ("No WiFi networks found. On macOS 14.4 and later the old 'airport' tool no longer "
                   "exists, and the supported replacement needs Location Services switched on for "
                   "NetScout (System Settings > Privacy & Security > Location Services).")
    if not aps and not err:
        err = "No WiFi networks found - is WiFi switched on and an adapter present?"
    return aps, err


# --- hotspot detection (heuristic: names and MAC addresses, never a connection) -----------------------------
PHONE_SSID = re.compile(
    r"(?i)(iphone|ipad|androidap|androidshare|android ?hotspot|galaxy|pixel[ _]?\d|oneplus|redmi|xiaomi|poco ?[a-z]?\d|"
    r"\boppo\b|realme|\bvivo\b|xperia|moto ?(g|e|edge|razr|one|g\d)|huawei ?(p|mate|nova|y)\d|honor ?\d|nokia ?\d|"
    r"^SM-[A-Z]\d{3}|\bmi ?\d{1,2}\b|note ?\d{1,2}|infinix|tecno|fairphone|asus ?(zenfone|rog ?phone)|"
    r"handy|'s (phone|iphone|galaxy|pixel|s\d{2})|(mobile|my|personal|phone|wi-?fi) ?hotspot|tethering|tether|"
    r"^(deic|direct)-..-)")
MOBILE_ROUTER = re.compile(
    r"(?i)(mifi|jetpack|pocket ?wi-?fi|\b4g\b|\b5g\b|\blte\b|mobile ?wi-?fi|huawei[-_ ]?e\d{3,4}|airbox|nighthawk ?m\d|"
    r"\bgl-(mt|ar|x|b|s)\d|travelwifi|skyroam|solis|roaming ?man|\btp-?link_m\d|orbi ?lte|netgear ?(mr|lm)\d)")
PUBLIC_SSID = re.compile(
    r"(?i)(free ?wi-?fi|\bguest|\bgast\b|public|hotspot|\bfon\b|wifi ?on ?ice|starbucks|mcdonald|swisscom_auto|"
    r"telekom|attwifi|xfinity|cablewifi|bt-?wifi|airport|cafe|hotel|lounge|\beduroam\b|_?guest_?|visitor|"
    r"\bsbb\b|\u00f6bb|\boebb\b|\bwlan\b|gov|library|\buni-|campus|citywifi|citywlan)")
PHONE_VENDORS = ("apple", "samsung", "google", "xiaomi", "oneplus", "oppo", "vivo", "motorola", "huawei device",
                 "hmd", "realme", "sony mobile", "nothing", "lg electronics", "htc", "zte", "transsion",
                 "infinix", "tecno", "fairphone", "asustek", "guangdong oppo", "lenovo mobile")


def hotspot_kind(a, ssid_count=1):
    """('KIND', 'why') or ('', ''). A name that gives the game away is decisive on its own; everything
    else is weighed up together.

    The old version was a cascade of ifs that returned on the first match, which meant a single weak
    clue (a phone-maker OUI, say) was enough on its own, and several strong clues pointing the other way
    counted for nothing. It also ignored the two most telling signals in the data, both of which were
    already being collected for the STABLE column and then never used again:

      - a network that shows up in only SOME of the scan passes is behaving like something that walked
        past, which is exactly what a phone in someone's pocket does and exactly what a bolted-to-the-
        ceiling access point does not
      - a signal that swings wildly between passes means the transmitter is moving

    Against those, enterprise security and several access points sharing one SSID are strong evidence of
    ordinary infrastructure, and now count against the verdict instead of being ignored.
    """
    ssid, risk = a.get("ssid") or "", a.get("risk")
    if re.match(r"(?i)^direct-", ssid):
        return "WIFI DIRECT", "direct link of a printer, TV or phone"
    if PHONE_SSID.search(ssid):
        return "PHONE HOTSPOT", "the name looks like a phone's hotspot"
    if MOBILE_ROUTER.search(ssid):
        return "MOBILE ROUTER", "the name looks like a pocket / 4G router"
    if risk == "OPEN" and PUBLIC_SSID.search(ssid):
        return "PUBLIC HOTSPOT", "open network with a public-hotspot style name"

    bssid, vendor = (a.get("bssid") or ""), (a.get("vendor") or "")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", bssid):
        return "", ""
    score, why = 0, []

    def add(points, reason):
        nonlocal score
        score += points
        if points > 0:
            why.append(reason)

    if any(v in vendor.lower() for v in PHONE_VENDORS):
        add(3, f"made by a phone maker ({vendor})")
    if int(bssid[:2], 16) & 2 and not vendor:
        # Bit 1 of the first octet means locally administered: an address made up on the spot rather than
        # one burned in at the factory. Phones randomise, access points essentially never do. The "and no
        # vendor" half matters: a randomised address cannot match an OUI registration, so if the vendor
        # lookup DID resolve, the bit is contradicting itself and is worth nothing as evidence.
        add(2, "randomised MAC address")
    seen, passes = a.get("seen") or 1, a.get("passes") or 1
    if passes > 1 and seen < passes:
        add(2, f"only heard in {seen} of {passes} passes - it comes and goes")
    if (a.get("sig_range") or 0) >= 25:
        add(1, f"signal swung {a['sig_range']} points between passes - the transmitter is moving")
    band = a.get("band") or ""
    if band.startswith("2.4"):
        add(1, "2.4 GHz only, as phone hotspots normally are")
    elif band.startswith("6"):
        add(-2, "")                        # 6 GHz hotspots are vanishingly rare on phones
    # a hotspot runs one radio, so a 20 MHz (narrow) channel is the phone default; a ceiling AP on 6 GHz
    # or a wide 80/160/320 MHz channel is infrastructure, not a pocket device
    width = a.get("width") or 0
    if width and width <= 20 and band.startswith("2.4"):
        add(1, "narrow 20 MHz channel, as a phone hotspot uses")
    elif width >= 80:
        add(-2, f"wide {width} MHz channel - infrastructure, not a phone")
    gen = (a.get("gen") or "")
    if "Wi-Fi 7" in gen or "6E" in gen:
        add(-1, "")                        # Wi-Fi 7 / 6E is still rare on phone hotspots, common on new APs
    if not ssid:
        add(1, "hidden network name")
    if ssid_count > 1:
        add(-3, "")                        # several access points share this name: roaming infrastructure
    if re.search(r"(?i)enterprise|802\.1x|eap", a.get("security") or ""):
        add(-4, "")                        # company WiFi, never a phone
    if risk == "WEAK":
        add(-3, "")                        # nothing modern enough to be a phone hotspot still offers WEP
    if a.get("connected"):
        add(-2, "")                        # this is the network you are on

    if score >= 3:
        return "POSSIBLE HOTSPOT", "; ".join(why[:3])
    return "", ""


def wifi_freq(channel, band):
    if not channel:
        return None
    band = band or ""
    if band.startswith("6"):
        return 5950 + 5 * channel
    if band.startswith("5"):                      # also covers the ambiguous "5/6 GHz (?)" label
        return 5000 + 5 * channel
    return 2484 if channel == 14 else 2407 + 5 * channel


# Path-loss exponent by surroundings. This is the single biggest lever on distance accuracy, and it is
# a property of the BUILDING, not of the radio - which is why it is offered as a setting rather than
# guessed. 2.0 is free space; an open-plan office is about 2.7; plasterboard offices about 3.0; a
# warehouse with racking or a building with concrete cores is 3.5 and up.
ENVIRONMENTS = {"open": (2.0, "open air / line of sight"),
                "office_open": (2.7, "open-plan office"),
                "office": (3.0, "offices with partition walls"),
                "dense": (3.5, "concrete walls, racking, lift shafts")}
DEFAULT_ENV = "office"
# Typical access-point transmit power in dBm EIRP. A phone hotspot runs noticeably weaker than a
# ceiling AP, and assuming one figure for both is a large and avoidable error.
EIRP_AP, EIRP_PHONE = 20.0, 15.0


def est_distance(sig_pct, freq_mhz, eirp=None, n=None, env=DEFAULT_ENV, dbm=None, is_phone=False):
    """Distance in metres from signal strength, by the log-distance path-loss model.

    Accuracy, honestly: this cannot be made precise, and no amount of arithmetic here will change that.
    The input is one number - received power - and the output depends on transmit power, antenna gain
    and orientation, and everything the signal passed through on the way. Two APs at the same distance
    routinely differ by 20 dB, which is a factor of FIVE in the distance this returns. What can be
    improved, and is improved here, is the quality of the inputs:

      - a real dBm reading is used when the adapter gave one, instead of re-deriving it from a rounded
        percentage. That conversion alone cost up to 0.5 dB, and vendors do not even agree on how
        percent maps to dBm
      - the path-loss exponent matches the building instead of being fixed at 3.0 (see ENVIRONMENTS)
      - transmit power is assumed per device class: a phone hotspot is about 5 dB weaker than a ceiling
        access point, which is most of a factor of two in distance
      - calibrate_eirp() lets you stand a known distance away and solve for an AP's real transmit power,
        which removes the largest unknown entirely for that AP

    For a number to act on rather than squint at, use dist_range() - it reports the band the true
    distance is very likely to fall in, instead of a single figure that implies a precision nothing
    here can deliver.
    """
    rssi = dbm if dbm is not None else (None if not sig_pct else sig_pct / 2.0 - 100.0)
    if rssi is None or not freq_mhz:
        return None
    if n is None:
        n = ENVIRONMENTS.get(env, ENVIRONMENTS[DEFAULT_ENV])[0]
    if eirp is None:
        eirp = EIRP_PHONE if is_phone else EIRP_AP
    fspl_1m = 20 * math.log10(freq_mhz) - 27.55
    return 10 ** ((eirp - rssi - fspl_1m) / (10 * n))


def dist_range(sig_pct, freq_mhz, env=DEFAULT_ENV, dbm=None, is_phone=False, margin_db=6.0):
    """(low_m, high_m) - the band the true distance very likely falls in.

    A single distance figure is false precision. Re-running the model at plus and minus a few dB of
    the measured signal turns it into something honest: a range you can act on. 6 dB either way covers
    ordinary fading and antenna orientation, and is deliberately not widened to cover a wall, because
    the environment setting is what accounts for walls.
    """
    rssi = dbm if dbm is not None else (None if not sig_pct else sig_pct / 2.0 - 100.0)
    if rssi is None or not freq_mhz:
        return None
    near = est_distance(None, freq_mhz, env=env, dbm=rssi + margin_db, is_phone=is_phone)
    far = est_distance(None, freq_mhz, env=env, dbm=rssi - margin_db, is_phone=is_phone)
    return (round(near, 1), round(far, 1)) if near and far else None


def calibrate_eirp(sig_pct, freq_mhz, known_m, env=DEFAULT_ENV, dbm=None):
    """Solve for an access point's effective transmit power by measuring it from a KNOWN distance.

    Stand a measured distance from the AP, read the signal, and this returns the EIRP that makes the
    model agree. Feed that back into est_distance for that AP and the single largest unknown is gone -
    this is the only way to turn the estimate into something genuinely trustworthy, and it is why the
    'extremely precise' version of this question is answered by a tape measure plus this function
    rather than by a cleverer formula.
    """
    rssi = dbm if dbm is not None else (None if not sig_pct else sig_pct / 2.0 - 100.0)
    if rssi is None or not freq_mhz or not known_m or known_m <= 0:
        return None
    n = ENVIRONMENTS.get(env, ENVIRONMENTS[DEFAULT_ENV])[0]
    fspl_1m = 20 * math.log10(freq_mhz) - 27.55
    return round(rssi + fspl_1m + 10 * n * math.log10(known_m), 1)


def median(vals):
    vals = sorted(v for v in vals if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2.0


def fmt_distance(m):
    if m is None:
        return "-"
    return "<2 m" if m < 2 else ">200 m" if m > 200 else f"~{int(round(m / 5.0) * 5 if m >= 20 else round(m))} m"


def wifi_scan(log=print, passes=1, cancel=None, progress=None, pause=2.0, env=DEFAULT_ENV):
    """Passive list of WiFi networks in range - what your OS WiFi menu shows. Returns (aps, error_text).
    Nothing is sent to or from those networks; only their public beacons are read.
    passes > 1 looks again and again and merges the results, so weak / flickering networks are caught too.
    How far you can 'hear' is decided by your WiFi adapter and its antenna; software cannot add range."""
    passes = max(1, min(int(passes or 1), 12))
    merged, err, ok = {}, "", 0
    for i in range(passes):
        if cancel is not None and cancel.is_set():
            break
        if progress:
            progress(i + 1, passes)
        aps, e = _wifi_list(log if i == 0 else (lambda m: None), cancel=cancel)
        if aps:
            ok += 1
            for a in aps:
                key = a["bssid"] or f"{a['ssid']}#{a['channel']}"
                m = merged.get(key)
                if m is None:
                    a["seen"], a["sig_min"], a["sig_max"] = 1, a["sig"], a["sig"]
                    a["sig_samples"] = [a["sig"]]
                    a["dbm_samples"] = [a["dbm"]] if a.get("dbm") is not None else []
                    merged[key] = a
                    continue
                m["seen"] += 1
                m["sig_min"], m["sig_max"] = min(m["sig_min"], a["sig"]), max(m["sig_max"], a["sig"])
                m["sig"] = max(m["sig"], a["sig"])
                # every sample kept, because the distance estimate wants the MEDIAN rather than the
                # best one ever heard: the strongest sample is by definition the luckiest moment of
                # fading, so using it reports every network as closer than it is
                m.setdefault("sig_samples", [m["sig"]]).append(a["sig"])
                if a.get("dbm") is not None:
                    m.setdefault("dbm_samples", []).append(a["dbm"])
                m["connected"] = m["connected"] or a["connected"]
                for f in ("channel", "band", "standard"):
                    m[f] = m[f] or a[f]
                m["width"] = max(m.get("width") or 0, a.get("width") or 0)
        else:
            err = e or err
        # a pass that triggered its own fresh scan has already waited ~4 s for it; otherwise pause between looks
        if i < passes - 1 and not getattr(_wifi_list, "fresh", False):
            if cancel is not None:
                cancel.wait(pause)
            else:
                time.sleep(pause)
    if not merged:
        return [], err or "No WiFi networks found - is WiFi switched on and an adapter present?"
    aps = list(merged.values())
    cur = current_ssid()
    oui = load_oui(log=log)
    names = {}
    for a in aps:
        names[a["ssid"]] = names.get(a["ssid"], 0) + 1
    for a in aps:
        a["vendor"] = vendor_of(a["bssid"], oui)
        a["risk"] = wifi_risk(a["security"])
        # professional security read: a letter grade, the generation, and the PMF/WPS facts behind it.
        # pmf/wps are only known when the OS scanner exposed them (richest from `iw` on Linux); where it
        # didn't, they stay None and the grade is computed from encryption alone - still useful, just less
        # precise, and never guessed.
        a.setdefault("pmf", None)
        a.setdefault("wps", None)
        a.setdefault("width", 0)
        a["gen"] = wifi_generation(a.get("standard"), a.get("band"))
        a["psc"] = is_psc_channel(a.get("channel"), a.get("band"))   # 6 GHz preferred-scanning channel
        a["grade"], a["grade_why"] = wifi_grade(a)
        a["connected"] = a["connected"] or bool(cur and a["ssid"] == cur)
        a["passes"] = ok
        a.setdefault("sig_samples", [a["sig"]])
        a["sig_med"] = median(a["sig_samples"])
        # the hotspot verdict is not known yet at this point, so transmit power is judged from the
        # evidence that is: a phone-maker OUI or a randomised address means the weaker phone EIRP
        _vend = (a.get("vendor") or "").lower()
        _phoneish = any(v in _vend for v in PHONE_VENDORS) or (
            bool(a.get("bssid")) and not _vend
            and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", a.get("bssid") or "") is not None
            and bool(int((a["bssid"] or "00")[:2], 16) & 2))
        _freq = wifi_freq(a["channel"], a["band"])
        # a backend that gave real dBm (iw, wpa_cli) is used directly; otherwise the percentage is all
        # there is and gets converted as before
        _dbm_med = median(a.get("dbm_samples") or [])
        a["dbm_true"] = _dbm_med is not None
        a["dist_m"] = est_distance(a["sig_med"], _freq, env=env, is_phone=_phoneish, dbm=_dbm_med)
        a["dist"] = fmt_distance(a["dist_m"])
        a["dist_lo_hi"] = dist_range(a["sig_med"], _freq, env=env, is_phone=_phoneish, dbm=_dbm_med)
        a["dist_range"] = ("%s - %s" % (fmt_distance(a["dist_lo_hi"][0]), fmt_distance(a["dist_lo_hi"][1]))
                           if a["dist_lo_hi"] else "-")
        a["standard"] = combine_standard(a["standard"], a["band"], a.get("width"))
        # a real measurement is kept as-is; only a derived one is recomputed from the percentage
        a["dbm"] = a.get("dbm") if a.get("dbm") is not None else pct_to_dbm(a["sig"])
        # stability only means anything once the same network was actually seen more than once - with a
        # single look there is nothing yet to call steady or flickering
        a.setdefault("sig_min", a["sig"]); a.setdefault("sig_max", a["sig"])
        a["sig_range"] = a["sig_max"] - a["sig_min"]
        a["stable"] = (a["sig_range"] <= 10) if a["seen"] > 1 else None
        # classified LAST, deliberately: hotspot_kind weighs up how intermittent the network was and how
        # far its signal swung, and both of those are only known once the lines above have run. Calling
        # it any earlier (as this did) silently handed it a missing sig_range and threw that away.
        a["hot"], a["hot_why"] = hotspot_kind(a, names[a["ssid"]])
    # hotspots first (so they're visible immediately, not buried below a long list of fixed APs),
    # strongest signal first within each group
    aps.sort(key=lambda a: (0 if a["hot"] else 1, -a["sig"]))
    return aps, ""


def access_points(aps, devices=None, by="signal"):
    """Group the radios heard into the PHYSICAL access points behind them.

    A scan lists BSSIDs, not devices. One ceiling access point broadcasting two SSIDs on three radios
    shows up as six entries, so a list of BSSIDs says nothing about how many boxes are on the ceiling.
    Radios in one unit almost always share an OUI and sit within a few addresses of each other, which
    is enough to group them - and the result is an inventory of equipment rather than of transmissions.

    `devices`, when given (a device-scan result), lets an access point that is on YOUR OWN network be
    tagged with its IP - matched by its wired MAC sitting next to its radio's BSSID. A neighbour's access
    point heard over the air has no IP you could see: it is not on your network, only within earshot, so
    it is honestly left blank rather than invented.

    `by="distance"` sorts closest first; the default keeps the strongest-first order other callers rely on.
    """
    groups = {}
    for a in aps:
        b = (a.get("bssid") or "").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", b):
            continue
        # key on the first five octets: a multi-radio unit varies only the last one (and often only
        # its low nibble), while two separate units practically never land that close together
        key = (b[:14], (a.get("vendor") or "").lower())
        g = groups.setdefault(key, {"vendor": a.get("vendor", ""), "bssids": [], "ssids": set(),
                                    "bands": set(), "channels": set(), "security": set(), "sig": 0,
                                    "dbm": None, "dist_m": None, "dist_range": "", "hot": "", "ip": ""})
        g["bssids"].append(b)
        if a.get("ssid"):
            g["ssids"].add(a["ssid"])
        if a.get("band"):
            g["bands"].add(a["band"])
        if a.get("channel"):
            g["channels"].add(str(a["channel"]))
        if a.get("security"):
            g["security"].add(a["security"])
        try:
            asig = int(a.get("sig") or 0)
        except (TypeError, ValueError):
            asig = 0                # a backend that ever handed back a non-numeric signal must not crash the grouping
        if asig > g["sig"]:
            # the strongest radio of the unit carries the distance figures, since it is the one the
            # path-loss estimate is least wrong about
            g["sig"], g["dbm"] = asig, a.get("dbm")
            g["dist_m"], g["dist_range"] = a.get("dist_m"), a.get("dist_range", "")
        g["hot"] = g["hot"] or a.get("hot", "")
    dev_by_mac = {}
    for d in (devices or []):
        m = norm_mac(d.get("mac", "")) if d.get("mac") else ""
        if m:
            dev_by_mac[m] = d.get("ip", "")
    out = []
    for g in groups.values():
        g["radios"] = len(g["bssids"])
        g["ssids"], g["bands"] = sorted(g["ssids"]), sorted(g["bands"])
        g["channels"], g["security"] = sorted(g["channels"], key=lambda x: int(x) if x.isdigit() else 0), sorted(g["security"])
        g["bssid"] = g["bssids"][0]
        g["ip"] = _ap_ip(g["bssids"], dev_by_mac)
        out.append(g)
    if by == "distance":
        # closest first; an AP with no distance estimate sorts last, strongest-signal breaking ties
        return sorted(out, key=lambda g: (g["dist_m"] if g["dist_m"] is not None else 1e9, -g["sig"]))
    return sorted(out, key=lambda g: -g["sig"])


def _ap_ip(bssids, dev_by_mac):
    """The LAN IP of an access point, matched from a device scan. Exact BSSID match first; then the
    common case where the box's wired MAC is a neighbour of its radio's BSSID (same first five octets,
    last octet within a handful) - which is how most APs are built. Best-effort and conservative: no
    match means no IP shown, never a guessed one."""
    bset = {b.lower() for b in bssids}
    for mac, ip in dev_by_mac.items():
        if mac in bset:
            return ip
    for b in bssids:
        try:
            base, last = b[:14], int(b[15:17], 16)
        except (ValueError, IndexError):
            continue
        for mac, ip in dev_by_mac.items():
            if mac[:14] == base:
                try:
                    if abs(int(mac[15:17], 16) - last) <= 4:
                        return ip
                except (ValueError, IndexError):
                    pass
    return ""


def hunt_trend(samples, warm_delta=3):
    """Direction-finding for walking down a specific access point. Given the recent run of signal-%
    readings for one BSSID (oldest first), returns (direction, bars, note).

    You cannot fix an access point's exact spot from one reading in one place - that is physics, not a
    missing feature. What genuinely locates it is motion: walk, and watch whether the signal climbs.
    This turns a stream of readings into WARMER / COLDER / STEADY, which is exactly how a rogue AP gets
    hunted down in practice. `bars` is a 0-5 closeness gauge from the latest reading.
    """
    vals = [v for v in samples if v is not None]
    latest = vals[-1] if vals else 0
    bars = max(0, min(5, 1 + latest // 20)) if vals else 0
    if len(vals) < 3:
        return "...", bars, "keep moving - a direction needs a few readings"
    recent = sum(vals[-2:]) / 2.0
    prior = sum(vals[-4:-2]) / len(vals[-4:-2]) if len(vals) >= 4 else vals[0]
    diff = recent - prior
    if diff >= warm_delta:
        return "WARMER", bars, "getting closer - keep going this way"
    if diff <= -warm_delta:
        return "COLDER", bars, "moving away - turn around"
    return "STEADY", bars, "about the same - try a different direction"


def rogue_aps(aps):
    """Networks whose name is being broadcast by hardware that does not match the rest of it.

    An evil twin is an attacker's access point advertising a name people's laptops already trust, so
    they join it instead of the real one. What gives it away is inconsistency within a single SSID:
    the genuine deployment is one vendor's equipment configured identically, and the impostor is
    something else - a different manufacturer, or the same name offered with the security dropped so
    that anything will associate.

    Returns [{"ssid", "severity", "why", "bssids"}]. Judgement, not proof: a site genuinely mid-way
    through replacing its access points will light this up too, which is why the reason is always
    spelled out rather than just a verdict.
    """
    by_ssid = {}
    for a in aps:
        if a.get("ssid"):
            by_ssid.setdefault(a["ssid"], []).append(a)
    out = []
    for ssid, group in sorted(by_ssid.items()):
        if len(group) < 2:
            continue
        vendors = {(a.get("vendor") or "").strip() for a in group if a.get("vendor")}
        risks = {a.get("risk") for a in group if a.get("risk")}
        why, sev = [], ""
        if len(vendors) > 1:
            why.append("broadcast by hardware from " + " and ".join(sorted(vendors)))
            sev = "SUSPECT"
        if "OPEN" in risks and len(risks) > 1:
            why.append("the same name is offered both secured and completely open")
            sev = "HIGH"
        if {"WEAK", "OPEN"} & risks and {"OK", "BEST"} & risks:
            why.append("one radio offers weaker security than the others using this name")
            sev = sev or "SUSPECT"
        if why:
            out.append({"ssid": ssid, "severity": sev, "why": "; ".join(why),
                        "bssids": [a.get("bssid", "") for a in group]})
    return out


def wifi_audit_lines(aps):
    """The security read on what was heard: open networks, weak encryption, possible evil twins, and
    anything broadcasting a hotspot inside a site that is not supposed to have one."""
    out, open_n = [], [a for a in aps if a.get("risk") == "OPEN"]
    weak = [a for a in aps if a.get("risk") == "WEAK"]
    hot = [a for a in aps if a.get("hot")]
    rogues = rogue_aps(aps)
    out.append("WIFI SECURITY AUDIT")
    out.append("")
    if rogues:
        out.append(f"POSSIBLE EVIL TWINS ({len(rogues)}):")
        for r in rogues:
            out.append(f"  [{r['severity']}] {r['ssid']} - {r['why']}")
            out.append(f"      radios: {', '.join(b for b in r['bssids'] if b)}")
        out.append("")
    if open_n:
        out.append(f"OPEN / UNENCRYPTED ({len(open_n)}): anything sent over these is readable by anyone in range")
        for a in open_n:
            out.append(f"  {a.get('ssid') or '<hidden>'}  ({a.get('bssid', '')})  {a.get('dist', '')}")
        out.append("")
    if weak:
        out.append(f"OBSOLETE ENCRYPTION ({len(weak)}): WEP and WPA1 are broken and should be replaced")
        for a in weak:
            out.append(f"  {a.get('ssid') or '<hidden>'}  ({a.get('security', '')})  {a.get('bssid', '')}")
        out.append("")
    if hot:
        out.append(f"HOTSPOTS / TETHERING ({len(hot)}): a personal hotspot inside a managed site bypasses "
                   "the network's own controls entirely")
        for a in hot:
            out.append(f"  {a.get('ssid') or '<hidden>'}  [{a['hot']}]  {a.get('dist', '')}  - {a.get('hot_why', '')}")
        out.append("")
    if not (rogues or open_n or weak or hot):
        out.append("Nothing of concern: every network in range is encrypted with something current, no "
                   "name is served by mismatched hardware, and no hotspots are broadcasting.")

    # professional extras: a security grade per network, and a channel recommendation. The grade is
    # computed here if the network doesn't already carry one, so this works whether or not wifi_scan
    # graded them first.
    graded = []
    for a in aps:
        g = a.get("grade")
        why = a.get("grade_why")
        if not g:
            g, why = wifi_grade(a)
        if g and g != "?":
            graded.append((g, a.get("ssid"), (why or ["?"])[0]))
    if graded:
        order = {"F": 0, "E": 1, "D": 2, "C": 3, "B": 4, "A": 5}
        graded.sort(key=lambda t: order.get(t[0], 9))
        tally = {}
        for g, _ssid, _why in graded:
            tally[g] = tally.get(g, 0) + 1
        out += ["", "SECURITY GRADES (A = best, F = wide open):",
                "  " + "   ".join(f"{g}: {tally[g]}" for g in "ABCDEF" if g in tally)]
        for g, ssid, why in graded:
            if g in ("F", "E", "D"):                 # spell out only the ones that need attention
                out.append(f"  [{g}] {(ssid or '<hidden>'):<22} {why}")

    rec = best_channels(aps)
    if rec:
        out += ["", "BEST CHANNEL FOR YOUR OWN NETWORK:"]
        for band in sorted(rec, key=lambda b: (not b.startswith("2.4"), not b.startswith("5"), b)):
            out.append(f"  {band}: {rec[band]['note']}")
    return out


def channel_congestion(aps):
    """{band: {channel: ap_count}} - how many networks share each channel you can hear. The same thing a
    router's own 'auto channel' feature goes by, for choosing a quieter channel for your own network."""
    out = {}
    for a in aps:
        if a.get("channel") and a.get("band"):
            out.setdefault(a["band"], {}).setdefault(a["channel"], 0)
            out[a["band"]][a["channel"]] += 1
    return out


def congestion_lines(aps):
    cong = channel_congestion(aps)
    if not cong:
        return []
    lines = ["\nCHANNEL CONGESTION (networks sharing each channel you can hear):"]
    for band in sorted(cong, key=lambda b: (b != "2.4 GHz", b != "5 GHz", b)):
        counts = cong[band]
        busiest = max(counts.items(), key=lambda kv: kv[1])
        quietest = min(counts.items(), key=lambda kv: kv[1])
        lines.append(f"  {band}: " + ", ".join(f"ch{ch} x{n}" for ch, n in sorted(counts.items())) +
                     f"   busiest: ch{busiest[0]} ({busiest[1]})   least busy heard: ch{quietest[0]} ({quietest[1]})")
    return lines


def nearby_lines(aps, hot_only=False):
    rows = [a for a in aps if a["hot"]] if hot_only else aps
    lines = [f"{'SIGNAL':<8}{'DBM':<7}{'DIST':<9}{'NETWORK (SSID)':<28}{'HOTSPOT':<18}{'BSSID (MAC)':<19}"
             f"{'VENDOR':<20}{'CH':<5}{'BAND':<9}{'STANDARD':<22}{'SECURITY':<18}{'STABLE':<8}SEEN", "-" * 185]
    for a in rows:
        stable = "-" if a.get("stable") is None else ("yes" if a["stable"] else "no")
        lines.append(f"{str(a['sig']) + '%':<8}{str(a.get('dbm', '-')):<7}{a['dist']:<9}"
                     f"{(a['ssid'] or '<hidden>')[:26]:<28}{a['hot'] or '-':<18}"
                     f"{a['bssid'] or 'hidden by OS':<19}{(a['vendor'] or '-')[:18]:<20}{str(a['channel'] or '-'):<5}"
                     f"{a['band'] or '-':<9}{(a['standard'] or '-')[:20]:<22}{a['security'][:16]:<18}{stable:<8}"
                     f"{a['seen']}/{a.get('passes', 1)}")
    hot = [a for a in aps if a["hot"]]
    lines.append(f"\n{len(rows)} network(s) listed, {len(aps)} heard, {len(hot)} look like hotspots. "
                 "Hotspot detection is a guess from names and MAC addresses.")
    for a in hot:
        lines.append(f"  {a['ssid'] or '<hidden>'}: {a['hot']} - {a['hot_why']}")
    lines.append("IP addresses of a network are only visible once you are connected to it. "
                 "Distances and dBm are rough estimates from the reported signal strength. STABLE needs "
                 "more than one pass to judge (- = only seen once).")
    lines += congestion_lines(aps)
    return lines


# --------------------------------------------------------------- Bluetooth (BLE + classic)
BT_KIND = [
    (re.compile(r"(?i)airpods|galaxy buds|\bbuds\b|earbuds|earphone|headphone|\bheadset\b"), "Headphones / earbuds"),
    (re.compile(r"(?i)\bspeaker\b|soundlink|boombox|megaboom|\bflip\d|\bcharge\d|soundcore|echo dot|homepod"),
     "Speaker"),
    (re.compile(r"(?i)apple watch|galaxy watch|\bwatch\b|garmin|fitbit|mi band|amazfit|whoop"),
     "Smartwatch / fitness band"),
    (re.compile(r"(?i)airtag|smarttag|\btile\b|chipolo"), "Tracker tag"),
    (re.compile(r"(?i)\bkeyboard\b"), "Keyboard"),
    (re.compile(r"(?i)\bmouse\b|magic trackpad|\btrackpad\b"), "Mouse / trackpad"),
    (re.compile(r"(?i)apple tv|chromecast|fire ?tv|\broku\b|\bandroid tv\b"), "TV / media player"),
    (re.compile(r"(?i)\bxbox\b|playstation|\bps[45]\b|joy-con|pro controller|dualsense|dualshock"),
     "Game controller"),
    (re.compile(r"(?i)\bcarplay\b|android auto|\bsync\d|\bcar\b"), "Car"),
    (re.compile(r"(?i)iphone|ipad|galaxy s\d|pixel \d|oneplus|xiaomi|huawei p\d|redmi"), "Phone / tablet"),
    (re.compile(r"(?i)\bprinter\b"), "Printer"),
    (re.compile(r"(?i)\bglucose\b|\bscale\b|blood pressure|thermometer|oximeter"), "Health device"),
]


def bt_kind(name):
    for pat, kind in BT_KIND:
        if pat.search(name or ""):
            return kind
    return ""


def ble_distance(rssi, tx_power=-59, n=2.0):
    """Very rough metres from BLE signal strength (log-distance model). tx_power is the reference
    strength at 1 metre; when the device's own advertisement includes a real tx_power (see
    _ble_scan_async), that is used instead of the -59 default - more precise, though still only ever
    'near / far', never a real measurement."""
    if rssi is None:
        return None
    return 10 ** ((tx_power - rssi) / (10 * n))


# Public, documented BLE pairing-protocol markers - not a guess at a specific model, only "this looks
# like an Apple / Microsoft / Fast-Pair-capable device". Genuinely useful because many modern devices
# (AirPods in their case, Apple Watch, etc.) advertise NO name at all over BLE for privacy, so name
# matching alone (bt_kind) leaves them as "<unnamed>" even though the advertisement itself says who made
# them. Deliberately NOT attempting to decode an exact model from Apple's undocumented payload bytes -
# that would be guesswork this tool can't verify and shouldn't present as fact.
_FAST_PAIR_UUIDS = {"0000fe2c-0000-1000-8000-00805f9b34fb", "fe2c"}
_APPLE_MANUFACTURER_ID = 0x004C   # Apple: Continuity / proximity-pairing protocols
_MS_MANUFACTURER_ID = 0x0006      # Microsoft: Swift Pair beacon when the first data byte is 0x03


# Microsoft's Connected Devices Platform beacon (documented in the open MS-CDP specification): Windows PCs
# with Bluetooth on broadcast it so "nearby sharing" and phone-linking can find them. Byte 0 is the scenario
# (1 = CDP beacon); the low 5 bits of byte 1 say what kind of device is broadcasting. It is the one passive
# signal that tells a LAPTOP from a DESKTOP outright - and it works for PCs that are not on your network.
MS_CDP_DEVICE = {1: "Xbox console", 6: "iPhone (Microsoft app)", 7: "iPad (Microsoft app)",
                 8: "Android device (Microsoft app)", 9: "Windows desktop PC", 11: "Windows phone",
                 12: "Linux device", 13: "Windows IoT device", 14: "Surface Hub", 15: "Windows laptop",
                 16: "Windows tablet"}


def ms_cdp_device(data):
    """Kind of device named in a Microsoft CDP beacon's manufacturer data, or "" if it isn't one."""
    if not data or len(data) < 2 or data[0] != 0x01:
        return ""
    return MS_CDP_DEVICE.get(data[1] & 0x1F, "")


def ble_protocol_hint(manufacturer, service_uuids):
    """(vendor_hint, kind_hint) from those markers, or ("", "") if none matched."""
    if {u.lower() for u in (service_uuids or [])} & _FAST_PAIR_UUIDS:
        return "", "Fast Pair device (earbuds / accessory)"
    md = manufacturer or {}
    if _APPLE_MANUFACTURER_ID in md:
        return "Apple", ""
    data = md.get(_MS_MANUFACTURER_ID)
    if data and data[0] == 0x03:
        return "Microsoft", "Windows Swift Pair device"
    if ms_cdp_device(data):
        return "Microsoft", ms_cdp_device(data)
    return "", ""


# ---- BLE advertisement decoding: what a device says about itself, read from its public advertisement -----
# Everything here is decoded from fields whose meaning is publicly documented (Bluetooth SIG assigned
# numbers, Apple's iBeacon spec, Google's Eddystone spec, the Find My / tracker formats documented by the
# anti-stalking research and apps such as AirGuard). Nothing is connected to; nothing is sent.

def _uuid16(u):
    """'0000feed-0000-1000-8000-00805f9b34fb' / 'feed' / 0xFEED -> 0xFEED (None if not a 16-bit SIG UUID)."""
    if isinstance(u, int):
        return u if 0 <= u <= 0xFFFF else None
    s = str(u or "").strip().lower()
    m = re.fullmatch(r"0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb", s) or re.fullmatch(r"(?:0x)?([0-9a-f]{4})", s)
    return int(m.group(1), 16) if m else None


# Bluetooth SIG company identifiers (Assigned Numbers) - only well-known, high-confidence entries. The ID
# names who defined the manufacturer-data format, which is normally the brand on the box.
BT_COMPANY = {0x0006: "Microsoft", 0x004C: "Apple", 0x0075: "Samsung", 0x00E0: "Google", 0x0087: "Garmin",
              0x0059: "Nordic Semiconductor", 0x000F: "Broadcom", 0x0002: "Intel", 0x000D: "Texas Instruments",
              0x0157: "Huami (Amazfit / Mi Band)", 0x038F: "Xiaomi", 0x027D: "Huawei", 0x009E: "Bose",
              0x012D: "Sony", 0x00C4: "LG Electronics", 0x0171: "Amazon", 0x01DA: "Logitech",
              0x0499: "Ruuvi", 0x02E5: "Espressif", 0x0057: "Harman"}

# Apple Continuity message types (first byte of each TLV in Apple's manufacturer data) -> what it means
APPLE_CONTINUITY = {0x02: "iBeacon", 0x03: "AirPrint", 0x05: "AirDrop", 0x06: "HomeKit", 0x07: "AirPods / Beats",
                    0x08: "Hey Siri", 0x09: "AirPlay receiver", 0x0A: "AirPlay source", 0x0B: "Apple Watch",
                    0x0C: "Handoff", 0x0D: "Instant Hotspot", 0x0E: "Instant Hotspot", 0x0F: "Nearby Action",
                    0x10: "Nearby (iPhone / iPad / Mac)", 0x12: "Find My"}
# what kind of device each Continuity message points to (first match in this order wins)
_APPLE_KIND = [(0x07, "Earbuds / headphones"), (0x0B, "Smartwatch"), (0x09, "AirPlay receiver"),
               (0x06, "HomeKit accessory"), (0x03, "Printer"), (0x0D, "Phone (hotspot)"),
               (0x0C, "Phone / tablet / computer"), (0x10, "Phone / tablet / computer"),
               (0x05, "Phone / tablet / computer"), (0x0F, "Phone / tablet / computer")]

# Item trackers, by the 16-bit service UUID they advertise (as used by anti-stalking detectors)
TRACKER_UUIDS = {0xFEED: "Tile", 0xFEEC: "Tile", 0xFD5A: "Samsung SmartTag", 0xFE33: "Chipolo"}
_EDDYSTONE = 0xFEAA
_EDDY_SCHEME = {0x00: "http://www.", 0x01: "https://www.", 0x02: "http://", 0x03: "https://"}
_EDDY_EXPAND = [".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
                ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"]


def _int8(b):
    return b - 256 if b > 127 else b


def apple_continuity(data):
    """Walk Apple's manufacturer data as [type][length][payload]... -> [(type, payload bytes)].
    Stops cleanly at anything malformed instead of guessing past it."""
    out, i, data = [], 0, bytes(data or b"")
    while i + 2 <= len(data):
        t, n = data[i], data[i + 1]
        if i + 2 + n > len(data):
            break
        out.append((t, data[i + 2:i + 2 + n]))
        i += 2 + n
    return out


def eddystone_url(frame):
    """Eddystone-URL frame (0x10, tx, scheme, encoded...) -> 'https://...' or ''."""
    if len(frame) < 3 or frame[0] != 0x10 or frame[2] not in _EDDY_SCHEME:
        return ""
    s = _EDDY_SCHEME[frame[2]]
    for b in frame[3:]:
        if b < len(_EDDY_EXPAND):
            s += _EDDY_EXPAND[b]
        elif 0x20 < b < 0x7F:
            s += chr(b)
        else:
            return ""
    return s


def ble_decode(manufacturer=None, uuids=None, service_data=None):
    """Everything a BLE advertisement says about its sender, decoded from documented formats.

    Returns {"company", "kind", "apple", "tracker", "tracker_note", "separated", "beacon", "ref_1m", "tx_0m"}:
      company      maker from the manufacturer-data company ID ("" if unknown)
      kind         what kind of device the advertisement points to ("" if it doesn't say)
      apple        Apple Continuity message names heard (AirPods, Handoff, Find My, ...)
      tracker      "Apple Find My" / "Tile" / "Samsung SmartTag" / "Chipolo" / "Google Find My Device" / ""
      separated    Find My: True when the beacon is the long 'separated from its owner' form - the case
                   anti-stalking tools warn about (an AirTag that is travelling with you, not its owner)
      beacon       "iBeacon <uuid> <major>/<minor>" or "Eddystone <url|uid>" ("" if not a beacon)
      ref_1m       calibrated signal at 1 m when the advertisement carries one (iBeacon measured power)
      tx_0m        transmit power at 0 m (Eddystone UID/URL), for distance calibration
    """
    md = {int(k): bytes(v or b"") for k, v in (manufacturer or {}).items()}
    u16 = {x for x in (_uuid16(u) for u in (uuids or [])) if x is not None}
    sd = {}
    for k, v in (service_data or {}).items():
        x = _uuid16(k)
        if x is not None:
            sd[x] = bytes(v or b"")
    out = {"company": "", "kind": "", "apple": [], "tracker": "", "tracker_note": "", "separated": False,
           "beacon": "", "ref_1m": None, "tx_0m": None}
    for cid in md:
        if cid in BT_COMPANY:
            out["company"] = BT_COMPANY[cid]
            break
    apple = md.get(_APPLE_MANUFACTURER_ID)
    if apple:
        msgs = apple_continuity(apple)
        types = [t for t, _ in msgs]
        out["apple"] = sorted({APPLE_CONTINUITY[t] for t in types if t in APPLE_CONTINUITY})
        for t, payload in msgs:
            if t == 0x02 and len(payload) >= 21:          # iBeacon: uuid(16) major(2) minor(2) power(1)
                u = payload[:16].hex()
                u = f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}"
                major, minor = int.from_bytes(payload[16:18], "big"), int.from_bytes(payload[18:20], "big")
                out["beacon"] = f"iBeacon {u} {major}/{minor}"
                out["ref_1m"] = _int8(payload[20])
            if t == 0x12:
                out["tracker"] = "Apple Find My"
                # 25-byte payload = the full rotating public key, broadcast once a Find My item has been
                # away from its owner's devices for a while; the 2-byte form means the owner is nearby
                out["separated"] = len(payload) >= 25
                out["tracker_note"] = ("separated from its owner - if it keeps showing up wherever you go, "
                                       "it may be travelling with you" if out["separated"]
                                       else "near its owner")
        for t, kind in _APPLE_KIND:
            if t in types:
                out["kind"] = kind
                break
    ms = md.get(_MS_MANUFACTURER_ID)
    if ms and ms[0] == 0x03:
        out["kind"] = out["kind"] or "Windows Swift Pair device"
    if ms_cdp_device(ms):                              # a Windows PC saying "I am a laptop / a desktop"
        out["kind"] = out["kind"] or ms_cdp_device(ms)
    if u16 & {0xFE2C}:
        out["kind"] = out["kind"] or "Fast Pair device (earbuds / accessory)"
    for x in sorted(u16 | set(sd)):
        if x in TRACKER_UUIDS and not out["tracker"]:
            out["tracker"] = TRACKER_UUIDS[x]
    eddy = sd.get(_EDDYSTONE)
    if eddy:
        ft = eddy[0]
        if ft in (0x40, 0x41):                         # Find My Device network (Google's tracker format)
            out["tracker"] = out["tracker"] or "Google Find My Device"
            if ft == 0x41:
                out["separated"] = True
                out["tracker_note"] = "in unwanted-tracking mode (away from its owner)"
        elif ft == 0x10 and len(eddy) >= 3:
            out["tx_0m"] = _int8(eddy[1])
            url = eddystone_url(eddy)
            out["beacon"] = f"Eddystone {url}" if url else "Eddystone URL"
        elif ft == 0x00 and len(eddy) >= 18:
            out["tx_0m"] = _int8(eddy[1])
            out["beacon"] = f"Eddystone UID {eddy[2:12].hex()}/{eddy[12:18].hex()}"
        elif ft == 0x20:
            out["beacon"] = out["beacon"] or "Eddystone telemetry"
    if out["tracker"]:
        out["kind"] = "Item tracker" if out["tracker"] != "Apple Find My" or not out["kind"] else out["kind"]
    elif out["beacon"]:
        out["kind"] = out["kind"] if out["kind"] and not out["kind"].startswith("Phone") else "Beacon"
    return out


# free-space loss over the first metre at 2.44 GHz: 20*log10(2440) - 27.55 = 40.2 dB
BLE_LOSS_1M = 40.2


def ble_ref_1m(adv_tx_power=None, ref_1m=None, tx_0m=None):
    """Expected signal (dBm) at 1 metre - the anchor every distance estimate hangs on.

    An advertisement's TX Power Level is the power at the ANTENNA (0 m), not at one metre - using it as the
    1 m figure (as this tool once did) put a device at 3 km instead of 3 m. Order of preference: a beacon's
    own calibrated 1 m figure (iBeacon), then a stated transmit power minus the first metre's loss, then the
    typical phone / tag value of -59 dBm."""
    if ref_1m is not None and -100 < ref_1m < 0:
        return float(ref_1m)
    for tx in (tx_0m, adv_tx_power):
        if tx is not None and -40 <= tx <= 20:
            return float(tx) - BLE_LOSS_1M
    return -59.0


def ble_distance_range(rssi, ref_1m=-59.0, env=DEFAULT_ENV, margin_db=6.0):
    """(low, high) metres for a BLE reading: the same honest band WiFi uses (dist_range) - body blocking,
    a phone in a pocket or a tag in a bag easily move BLE by +-6 dB."""
    if rssi is None:
        return None
    n = ENVIRONMENTS.get(env, ENVIRONMENTS[DEFAULT_ENV])[0]
    return (ble_distance(rssi + margin_db, ref_1m, n), ble_distance(rssi - margin_db, ref_1m, n))


async def _ble_wait(duration, cancel):
    step, elapsed = 0.25, 0.0
    while elapsed < duration:
        if cancel is not None and cancel.is_set():
            break
        await asyncio.sleep(step)
        elapsed += step


async def _ble_scan_async(duration, cancel, log):
    from bleak import BleakScanner  # optional dependency - imported lazily so the rest of NetScout needs no extra package
    found = {}

    def on_detect(device, adv=None):
        try:
            rssi = getattr(adv, "rssi", None) if adv is not None else getattr(device, "rssi", None)
            name = (getattr(adv, "local_name", None) if adv is not None else None) or device.name or ""
            tx = getattr(adv, "tx_power", None) if adv is not None else None
            manuf = dict(getattr(adv, "manufacturer_data", None) or {}) if adv is not None else {}
            uuids = list(getattr(adv, "service_uuids", None) or []) if adv is not None else []
            sdata = dict(getattr(adv, "service_data", None) or {}) if adv is not None else {}
            prev = found.get(device.address)
            # every reading is kept (the last 40): one advertisement's RSSI swings +-5 dB or more, and the
            # median of many is what makes the distance and the nearest-first order trustworthy
            samples = (prev["rssi_samples"] if prev else []) + ([rssi] if rssi is not None else [])
            found[device.address] = {
                "address": device.address, "name": name or (prev["name"] if prev else ""),
                "rssi": rssi if rssi is not None else (prev["rssi"] if prev else None),
                "rssi_samples": samples[-40:],
                "tx_power": tx if tx is not None else (prev.get("tx_power") if prev else None),
                "seen": (prev["seen"] + 1) if prev else 1,
                "manufacturer": {**(prev["manufacturer"] if prev else {}), **manuf},
                "service_data": {**(prev["service_data"] if prev else {}), **sdata},
                "uuids": sorted(set((prev["uuids"] if prev else []) + uuids))}
        except Exception:
            pass  # one odd/malformed advertisement must never take the whole scan down with it

    try:
        # active scanning also requests the scan RESPONSE, which often carries the device's name even
        # when its passive advertisement doesn't - a real improvement in how many devices get named.
        # Not every bleak backend/version accepts the kwarg, so an unsupported one falls back cleanly.
        async with BleakScanner(detection_callback=on_detect, scanning_mode="active") as scanner:
            await _ble_wait(duration, cancel)
    except TypeError:
        async with BleakScanner(detection_callback=on_detect) as scanner:
            await _ble_wait(duration, cancel)
    return list(found.values())


def ensure_bleak(log=print):
    """Import bleak, installing it on the fly the first time it's missing (pip install, same Python this
    is running under). Returns True once bleak is importable, False if that genuinely didn't work."""
    try:
        import bleak  # noqa: F401
        return True
    except ImportError:
        pass
    if getattr(sys, "frozen", False):
        # Running as a packaged executable (PyInstaller etc.) - sys.executable IS this program, not a
        # real Python interpreter, so "sys.executable -m pip install ..." below would install nothing; it
        # would just relaunch this program with those words as bogus arguments. bleak has to be bundled in
        # at build time instead (see the packaging instructions) - there is nothing to self-repair here.
        log("This packaged copy of NetScout was built without the 'bleak' package, so Bluetooth scanning "
            "isn't available in it. Use the regular Python version, or ask whoever built this copy to "
            "rebuild it with bleak included (pip install bleak before running PyInstaller).")
        return False
    log("The 'bleak' package (needed for Bluetooth scanning) is not installed yet - installing it now, once...")
    try:
        # --only-binary=:all: refuses to fall back to BUILDING bleak (or, on Windows, its winrt-* dependencies)
        # from source when no ready-made wheel matches this exact Python build/platform. Without it, an unusual
        # interpreter (a pre-release version, or the free-threaded "3.13t" build) that no wheel has been
        # published for yet makes pip try to COMPILE winrt's C++/WinRT bindings instead - which needs a full,
        # fully C++20-conformant MSVC toolchain and can take minutes only to fail with an obscure internal
        # compiler crash, instead of the clear, instant "no matching distribution" pip would otherwise give.
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--user", "--only-binary=:all:", "bleak"],
                           capture_output=True, text=True, timeout=120, **NOWIN)
    except Exception as e:
        log(f"Could not run pip automatically ({e}).")
        return False
    if r.returncode != 0:
        out = (r.stderr or "") + (r.stdout or "")
        tail = next((ln for ln in reversed(out.splitlines()) if ln.strip()), "")
        hint = ""
        if "No matching distribution" in out or "Could not find a version" in out:
            # exactly the failure --only-binary=:all: above is meant to surface quickly: this Python build
            # has no prebuilt bleak (or winrt) wheel yet, rather than some other install problem.
            hint = ("\nThis usually means no ready-made 'bleak' package exists yet for this exact Python "
                    "build. Try a standard Python 3.11, 3.12 or 3.13 from python.org instead (not a "
                    "pre-release or a 'free-threaded' / 't' build), then run NetScout again.")
        log("Automatic install failed" + (f": {tail.strip()}" if tail else ".") + hint +
            "\nYou can install it yourself with:  pip install bleak   (or: pip install --user bleak)")
        return False
    try:
        import importlib
        importlib.invalidate_caches()          # the running interpreter hasn't seen this new package yet
        import bleak  # noqa: F401
        log("bleak installed successfully.")
        return True
    except ImportError:
        log("bleak was installed but isn't importable yet - please restart NetScout once.")
        return False


_BT_LOCK = threading.Lock()


def _parse_bluetoothctl(lines):
    """Parse bluetoothctl's live discovery output into [{"address", "name", "rssi", "seen"}]. 'seen'
    counts how many [NEW]/[CHG] lines mentioned that address - the same idea as the BLE side's 'seen'."""
    OTHER_KEYS = ("paired", "trusted", "connected", "legacypairing", "uuid", "class", "appearance", "icon",
                  "txpower", "servicedata", "manufacturerdata", "modalias", "adapter", "alias")
    devices = {}

    def rec(addr):
        return devices.setdefault(addr, {"address": addr, "name": "", "rssi": None, "seen": 0})
    for line in lines:
        m = re.search(r"\[(?:NEW|CHG)\]\s+Device\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s*(.*)", line)
        if not m:
            continue
        addr, rest = m.group(1).upper(), m.group(2).strip()
        d = rec(addr)
        d["seen"] += 1
        rs = re.match(r"RSSI:\s*(-?\d+)", rest)
        nm = re.match(r"Name:\s*(.*)", rest)
        if rs:
            d["rssi"] = int(rs.group(1))
        elif nm:
            d["name"] = nm.group(1).strip()
        elif rest and not re.match(rf"(?i)^(?:{'|'.join(OTHER_KEYS)}):", rest):
            d["name"] = rest          # "[NEW] Device AA:BB:.. Some Device Name" - name right after the address
    return list(devices.values())


def _classic_bt_scan_linux(duration, cancel):
    """Linux-only best-effort classic (BR/EDR) Bluetooth discovery via BlueZ's bluetoothctl. BLE-only
    gear (most modern earbuds/trackers) already shows up through the BLE scan; this additionally catches
    classic-only devices (older headsets, car kits, BT-serial peripherals) a BLE scan never sees. Windows
    and macOS ship no equivalent command-line discovery tool, so this stays Linux-only - BLE detection
    (the main part of this scan) is unaffected and works the same on every OS either way."""
    if OS != "Linux" or not shutil.which("bluetoothctl"):
        return []
    secs = max(1, int(round(duration)))
    try:
        p = subprocess.Popen(["bluetoothctl", "--timeout", str(secs), "scan", "on"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except Exception:
        return []
    lines, end = [], time.time() + secs + 5
    try:
        while True:
            if cancel is not None and cancel.is_set():
                p.terminate()
                break
            line = p.stdout.readline()
            if line:
                lines.append(line)
            elif p.poll() is not None:
                break
            if time.time() > end:
                p.terminate()
                break
    except Exception:
        pass
    finally:
        try:
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    return _parse_bluetoothctl(lines)


def bluetooth_scan(duration=8, log=print, cancel=None, include_classic=True, env=DEFAULT_ENV):
    """Passive Bluetooth discovery: BLE advertisements everywhere (via bleak), plus - Linux only, best
    effort - classic (BR/EDR) devices via bluetoothctl (see _classic_bt_scan_linux). Connects to nothing
    and changes nothing on any device. Needs the optional 'bleak' package (installed automatically on
    first use, see ensure_bleak) and a Bluetooth adapter that is turned on. Returns (devices, error_text).
    Only one Bluetooth scan runs at a time (a lock, not a queue) - most OS Bluetooth stacks don't handle
    two concurrent discovery sessions from the same process cleanly, so a second call while one is already
    running is told to wait rather than risking a confusing failure or a crash."""
    if not ensure_bleak(log):
        return [], ("Bluetooth scanning needs the 'bleak' package, and installing it automatically just now "
                   "didn't work (see the message above - usually no internet access, or no permission to "
                   "write to Python's package folder).\n"
                   "Install it yourself with:  pip install bleak   (or: pip install --user bleak)\n"
                   "Then run this tool again. No administrator rights are normally needed - only that "
                   "Bluetooth itself is switched on.")
    if not _BT_LOCK.acquire(blocking=False):
        return [], "A Bluetooth scan is already running (in another tab or window) - wait for it to finish."
    try:
        log(f"Listening for Bluetooth devices ({duration:g}s - press STOP to end early)...")
        want_classic = include_classic and OS == "Linux" and bool(shutil.which("bluetoothctl"))
        ex = cf.ThreadPoolExecutor(1) if want_classic else None
        classic_future = ex.submit(_classic_bt_scan_linux, duration, cancel) if ex else None
        try:
            found = asyncio.run(_ble_scan_async(duration, cancel, log))
        except Exception as e:
            if ex:
                ex.shutdown(wait=False)
            msg = str(e) or type(e).__name__
            hint = ""
            if OS == "Linux":
                hint = " Make sure the 'bluetooth' service is running and your user can access the adapter (BlueZ)."
            elif OS == "Darwin":
                hint = " macOS may ask for Bluetooth permission the first time - allow it and try again."
            elif OS == "Windows":
                hint = " Check that Bluetooth is turned on in Windows Settings."
            return [], f"Bluetooth scan failed: {msg}.{hint}"
        for d in found:
            d["transport"] = "BLE"
        classic = []
        if classic_future:
            try:
                classic = classic_future.result(timeout=max(5.0, duration + 8))
            except Exception:
                classic = []
            ex.shutdown(wait=False)
        ble_addrs = {d["address"] for d in found}
        for c in classic:
            if c["address"] in ble_addrs:        # already heard the same address over BLE - don't double-list it
                continue
            c.update(transport="Classic", tx_power=None, manufacturer={}, uuids=[], service_data={},
                     rssi_samples=[c["rssi"]] if c.get("rssi") is not None else [])
            found.append(c)
        oui = load_oui(log=log)
        for d in found:
            finish_bt_device(d, oui, env)
        # trackers first (the thing worth seeing), then nearest first by the smoothed signal
        found.sort(key=lambda d: (0 if d.get("tracker") else 1, -(d["rssi"] if d["rssi"] is not None else -999)))
        trackers = [d for d in found if d.get("tracker")]
        if trackers:
            away = sum(1 for d in trackers if d.get("separated"))
            log(f"{len(trackers)} item tracker(s) heard" + (f", {away} away from its owner" if away else "") + ".")
        return found, ""
    finally:
        _BT_LOCK.release()


def finish_bt_device(d, oui=None, env=DEFAULT_ENV):
    """Fill in everything derived from one heard device (vendor, kind, tracker, beacon, smoothed signal,
    calibrated distance and its range). Separate from bluetooth_scan so it can be tested on its own."""
    oui = oui or {}
    mac = d["address"] if re.fullmatch(MACRE, d.get("address") or "") else ""
    first = int(mac.split(":")[0], 16) if mac else 0
    # "randomised address" is a BLE privacy feature - classic (BR/EDR) addresses are (virtually)
    # always the real burned-in one, so the label is only meaningful for the BLE rows.
    d["mac_random"] = bool(mac) and bool(first & 0x02) and d.get("transport", "BLE") == "BLE"
    d["vendor"] = "" if d["mac_random"] else vendor_of(mac, oui)
    dec = ble_decode(d.get("manufacturer"), d.get("uuids"), d.get("service_data"))
    d["tracker"], d["separated"], d["beacon"] = dec["tracker"], dec["separated"], dec["beacon"]
    d["tracker_note"], d["apple_msgs"] = dec["tracker_note"], dec["apple"]
    hint_vendor, hint_kind = ble_protocol_hint(d.get("manufacturer"), d.get("uuids"))
    d["kind"] = dec["kind"] if dec["tracker"] else (bt_kind(d.get("name")) or dec["kind"] or hint_kind)
    maker = dec["company"] or hint_vendor
    if not d["vendor"] and maker:
        d["vendor"] = f"{maker} (BT company ID)"
    # the reading used everywhere is the MEDIAN of all advertisements heard, not whichever came last
    samples = [r for r in (d.get("rssi_samples") or []) if r is not None]
    d["rssi_last"] = d.get("rssi")
    if samples:
        med = median(samples)
        d["rssi"] = int(round(med))
        d["rssi_spread"] = max(samples) - min(samples)
    d["sig"] = rssi_to_pct(d["rssi"]) if d.get("rssi") is not None else None
    ref = ble_ref_1m(d.get("tx_power"), dec["ref_1m"], dec["tx_0m"])
    d["ref_1m"] = ref
    n = ENVIRONMENTS.get(env, ENVIRONMENTS[DEFAULT_ENV])[0]
    d["dist_m"] = ble_distance(d.get("rssi"), tx_power=ref, n=n)
    d["dist"] = fmt_distance(d["dist_m"])
    lo_hi = ble_distance_range(d.get("rssi"), ref, env)
    d["dist_range"] = f"{fmt_distance(lo_hi[0])} - {fmt_distance(lo_hi[1])}" if lo_hi else "-"
    if d["tracker"]:
        d["status"] = f"TRACKER: {d['tracker']}" + (" - away from owner" if d["separated"] else "")
    elif d["beacon"]:
        d["status"] = d["beacon"].split(" ")[0] + " beacon"
    elif d["apple_msgs"]:
        d["status"] = ", ".join(m for m in d["apple_msgs"] if m != "Find My")[:40]
    else:
        d.setdefault("status", "")
    return d


def nearby_computers(devices):
    """Laptops and desktop PCs among the Bluetooth devices heard - found from the Windows 'Connected
    Devices' beacon (which states laptop vs desktop outright) or from a laptop model line in the advertised
    name (MacBook, ThinkPad, TUF...). These are computers physically near you, whether or not they are on
    your network. Returns {"laptops": [...], "desktops": [...], "text": one summary line}."""
    laptops, desktops = [], []
    for d in devices or []:
        kind = str(d.get("kind") or "").lower()
        name = str(d.get("name") or "").lower().replace("-", " ").replace("_", " ")
        name = re.sub(r"(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])", " ", name)
        if "laptop" in kind or _match_line(name, LAPTOP_RX):
            laptops.append(d)
        elif "desktop" in kind or _match_line(name, DESKTOP_RX) not in ("", "tower", "workstation"):
            desktops.append(d)                     # ("tower" alone is usually a Bluetooth speaker, not a PC)

    def who(d):
        name = d.get("name") or ""
        name = "" if name == "<unnamed>" else name
        return f"{name or d.get('kind') or 'computer'} (~{d.get('dist') or '?'})"

    if not laptops and not desktops:
        text = ""
    else:
        parts = []
        if laptops:
            parts.append(f"{len(laptops)} laptop{'s' if len(laptops) != 1 else ''}: " + ", ".join(who(d) for d in laptops[:6]))
        if desktops:
            parts.append(f"{len(desktops)} desktop PC{'s' if len(desktops) != 1 else ''}: " + ", ".join(who(d) for d in desktops[:6]))
        text = "COMPUTERS NEARBY - " + "  |  ".join(parts)
    return {"laptops": laptops, "desktops": desktops, "text": text}


def bt_lines(devices):
    lines = [f"{'SIGNAL':<10}{'DIST':<9}{'TRANSPORT':<11}{'NAME':<28}{'KIND':<26}{'ADDRESS':<20}{'VENDOR':<26}SEEN",
             "-" * 136]
    for d in devices:
        sig = f"{d['sig']}%" if d.get("sig") is not None else "-"
        lines.append(f"{sig:<10}{d['dist']:<9}{d.get('transport', 'BLE'):<11}{(d['name'] or '<unnamed>')[:26]:<28}"
                     f"{d['kind'] or '-':<26}{d['address']:<20}"
                     f"{(d['vendor'] or ('random address' if d.get('mac_random') else '-'))[:24]:<26}{d['seen']}")
    classic_n = sum(1 for d in devices if d.get("transport") == "Classic")
    trackers = [d for d in devices if d.get("tracker")]
    near = nearby_computers(devices)["text"]
    if near:
        lines.append("\n" + near)
    if trackers:
        lines.append("\nITEM TRACKERS HEARD (AirTag / Find My, Tile, SmartTag, Chipolo, Google Find My Device):")
        for d in trackers:
            lines.append(f"  {d['tracker']:<22} {d['address']:<20} ~{d['dist']:<8} "
                         f"{d.get('tracker_note') or ''}")
        lines.append("  A tracker near its owner is normal. One marked 'away from owner' that keeps turning up "
                     "wherever you go - over several scans, in different places - is worth checking: your "
                     "phone's own tracker alerts (iPhone: Find My; Android: Unknown tracker alerts) can make it "
                     "play a sound so you can find it.")
    lines.append(f"\n{len(devices)} Bluetooth device(s) heard"
                 + (f" ({classic_n} classic/BR-EDR, the rest BLE)" if classic_n else "") +
                 ". This only lists public advertisements/discovery responses - nothing is connected to and "
                 "nothing on any device is changed. Phones and many modern devices use a randomised BLE "
                 "address that changes over time, so vendor/name can be unavailable, and the same physical "
                 "device may appear more than once over a long scan. Distances are rough estimates. Classic "
                 "(BR/EDR) discovery is Linux-only for now (via bluetoothctl) - BLE detection works everywhere.")
    return lines


# ----------------------------------------------------------------- port scanner
SERVICE_NAMES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS session",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE/IPsec", 514: "Syslog",
    515: "LPD printing", 548: "AFP (Mac file sharing)", 554: "RTSP (video)", 587: "SMTP submission", 631: "IPP printing",
    636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS proxy", 1194: "OpenVPN", 1400: "Sonos",
    1433: "MS SQL", 1521: "Oracle DB", 1723: "PPTP VPN", 1883: "MQTT", 2049: "NFS", 2375: "Docker API",
    3000: "HTTP (dev)", 3128: "Squid proxy", 3306: "MySQL", 3389: "RDP", 5000: "UPnP / Synology", 5060: "SIP",
    5353: "mDNS", 5432: "PostgreSQL", 5555: "Android debug (ADB)", 5672: "AMQP", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 7000: "AirPlay", 7547: "TR-069 (ISP management)", 8000: "HTTP alt", 8008: "HTTP / Chromecast",
    8009: "Chromecast / AJP", 8080: "HTTP alt", 8081: "HTTP alt", 8088: "HTTP alt", 8291: "MikroTik Winbox",
    8443: "HTTPS alt", 8554: "RTSP alt", 8888: "HTTP alt", 9000: "HTTP alt", 9100: "JetDirect printing",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 37777: "Dahua DVR", 62078: "iOS sync",
    79: "finger", 177: "XDMCP", 2082: "cPanel", 2083: "cPanel (TLS)", 2379: "etcd", 3478: "STUN",
    4444: "metasploit/alt", 5500: "VNC (reverse)", 5601: "Kibana", 5938: "TeamViewer", 5984: "CouchDB",
    6000: "X11", 6667: "IRC", 7001: "WebLogic", 8086: "InfluxDB", 8123: "Home Assistant", 8161: "ActiveMQ",
    8883: "MQTT (TLS)", 9042: "Cassandra", 10000: "Webmin", 15672: "RabbitMQ admin", 25565: "Minecraft",
    31337: "backdoor (historic)", 32400: "Plex", 51820: "WireGuard",
}
RISKY_PORTS = {
    20: "FTP data channel - FTP itself already sends passwords in clear text",
    21: "FTP sends passwords in clear text", 23: "Telnet is unencrypted - disable it",
    69: "TFTP has no authentication", 111: "RPC portmapper exposed", 135: "Windows RPC exposed",
    139: "NetBIOS exposed", 161: "SNMP - check community strings (default 'public'/'private' are well known)",
    445: "SMB file sharing - keep off untrusted networks. If SMBv1 is still enabled on this host, turn it "
         "off (it is a known ransomware/WannaCry-style vector; this scan cannot see the SMB version itself)",
    512: "rexec - cleartext remote execution, obsolete and dangerous",
    513: "rlogin - cleartext remote login, obsolete and dangerous",
    548: "AFP file sharing - keep off untrusted networks, older clients can still negotiate weak auth",
    1433: "Database reachable on the LAN", 1723: "PPTP VPN is outdated and has known weaknesses",
    1900: "UPnP/SSDP exposed - some routers/IoT gear accept configuration changes from any device on the LAN",
    2049: "NFS share reachable", 2323: "Alternate Telnet - a common default on IoT botnet targets (Mirai and similar)",
    2375: "Docker API without TLS - whoever can reach this has full control of the host",
    3306: "Database reachable on the LAN", 3389: "Remote Desktop reachable - make sure the password is strong "
          "and (ideally) it's not reachable outside the LAN",
    5432: "Database reachable on the LAN", 5555: "Android debug bridge open - often unauthenticated shell access",
    5900: "VNC remote screen reachable - check it has a real password", 6379: "Redis often has no password",
    7547: "ISP management port (TR-069) - normally only the ISP should reach this",
    8291: "MikroTik Winbox admin - keep this off the internet, it has had serious vulnerabilities",
    9200: "Elasticsearch often has no password", 11211: "Memcached has no authentication",
    27017: "MongoDB reachable on the LAN",
    79: "finger - obsolete service that leaks account names",
    177: "XDMCP remote login manager - cleartext and obsolete, turn it off",
    1521: "Oracle database reachable on the LAN",
    2082: "cPanel admin panel over cleartext HTTP - keep off untrusted networks and use the TLS port",
    2083: "cPanel admin panel exposed - restrict who can reach it",
    2379: "etcd reachable - it often stores cluster secrets and is frequently left unauthenticated",
    4444: "Common Metasploit / malware default port - find out what is actually listening here",
    5500: "VNC reverse-connection listener - unexpected unless you set up remote support",
    5601: "Kibana reachable - often unauthenticated and exposes everything in Elasticsearch",
    5938: "TeamViewer remote control - fine if you installed it, a warning sign if you did not",
    5984: "CouchDB reachable - older versions allow an unauthenticated admin takeover (CVE-2017-12635)",
    6000: "X11 display server exposed - can allow remote keylogging and screen capture; bind it to localhost",
    6667: "IRC - a classic botnet command-and-control channel, unexpected on most networks",
    7001: "Oracle WebLogic admin - repeatedly hit by critical remote code execution; patch and restrict",
    8086: "InfluxDB reachable on the LAN",
    8161: "ActiveMQ console - has had remote code execution flaws; restrict and patch",
    9042: "Cassandra database reachable on the LAN",
    10000: "Webmin admin panel - has had critical remote code execution (CVE-2019-15107); restrict and patch",
    15672: "RabbitMQ management - the default guest/guest login is well known; change it",
    31337: "Historic backdoor port (Back Orifice and similar) - investigate what is listening",
}


def risk_summary(ports):
    """(level, [reason, ...]) for a set of open ports - level is NONE / LOW / MEDIUM / HIGH.
    A rough count-and-severity heuristic, not a vulnerability scanner: it only ever looks at which TCP
    ports answered a connection, nothing about what is actually running behind them or how it's configured."""
    hits = [RISKY_PORTS[p] for p in sorted(ports) if p in RISKY_PORTS]
    if not hits:
        return "NONE", []
    # a handful of ports are flagged as more serious on their own (full-control/no-auth-by-default services);
    # two or more risky ports open together also raises the level even if none of them individually would
    severe = {2375, 23, 2323, 5900, 5555, 512, 513, 4444, 6667, 31337, 6000}
    if any(p in severe for p in ports) or len(hits) >= 3:
        return "HIGH", hits
    if len(hits) == 2:
        return "MEDIUM", hits
    return "LOW", hits
COMMON_PORTS = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 67, 69, 79, 80, 81, 88, 106, 110, 111, 113, 119, 123, 135, 137,
                139, 143, 161, 179, 199, 389, 427, 443, 444, 445, 465, 500, 513, 514, 515, 543, 544, 548, 554, 587,
                631, 636, 646, 873, 990, 993, 995, 1025, 1080, 1194, 1400, 1433, 1434, 1521, 1723, 1883, 2000, 2049,
                2121, 2375, 3000, 3128, 3306, 3389, 3478, 4444, 4567, 5000, 5060, 5222, 5353, 5432, 5555, 5631, 5672,
                5900, 5985, 5986, 6000, 6379, 6667, 7000, 7547, 8000, 8008, 8009, 8080, 8081, 8088, 8291, 8443, 8554,
                8888, 9000, 9090, 9100, 9200, 10000, 11211, 27017, 37777, 49152, 62078,
                177, 2082, 2083, 2379, 5500, 5601, 5938, 5984, 7001, 8086, 8123, 8161, 8883,
                9042, 15672, 25565, 31337, 32400, 51820]
MAX_PROBES = 600_000
HTTP_PORTS = {80, 81, 3000, 5000, 7547, 8000, 8008, 8080, 8081, 8088, 8888, 9000}


def service_name(port):
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def parse_ports(text):
    """'common' | '1-1024' | 'all' | '22,80,443,8000-8100'  ->  sorted list of port numbers."""
    t = (text or "").strip().lower()
    if t in ("", "common"):
        return list(COMMON_PORTS)
    if t in ("well-known", "wellknown", "1-1024"):
        return list(range(1, 1025))
    if t == "all":
        return list(range(1, 65536))
    out = set()
    for part in re.split(r"[,\s]+", t):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)-(\d+)", part)
        if m:
            a, b = sorted((int(m.group(1)), int(m.group(2))))
            out.update(range(a, b + 1))
        elif part.isdigit():
            out.add(int(part))
        else:
            raise ValueError(f"'{part}' is not a port or a range like 8000-8100")
    if not out or min(out) < 1 or max(out) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(out)


def is_private_ip(ip):
    a = ipaddress.ip_address(ip)
    return a.is_loopback or any(a in n for n in RFC1918)


DISCOVERY_PORTS = (443, 80, 445, 22, 135, 139, 3389, 8080, 62078)


def tcp_alive(ip, ports=DISCOVERY_PORTS, timeout=0.4):
    """A host is alive if a TCP connect is answered - even by 'connection refused'. Needs no admin rights and
    no ICMP, so it also finds hosts that block ping."""
    for p in ports:
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                return True
        except (ConnectionRefusedError, ConnectionResetError):
            return True
        except OSError:
            continue
    return False


def tcp_sweep(hosts, ports=DISCOVERY_PORTS, timeout=0.4, stopped=None):
    """Which of `hosts` answer a TCP connect on any of `ports`, returned as a set. Every (host, port) pair is
    probed in one parallel wave with a per-host early exit, so a silent address costs about a single connect
    timeout instead of one-per-port in series, and a reachable host is counted the moment its fastest port
    replies. A 'connection refused'/'reset' still means something is there. Needs no admin rights and no ICMP,
    so it finds hosts that block ping - far faster and more thorough on every network than checking hosts one
    at a time with tcp_alive()."""
    hosts = list(hosts)
    if not hosts:
        return set()
    stop = stopped if callable(stopped) else (lambda: False)
    found, lock = set(), threading.Lock()
    pairs = [(h, p) for h in hosts for p in ports]

    def _one(hp):
        h, p = hp
        if h in found or stop():       # another port already proved this host is up - don't bother
            return
        try:
            socket.create_connection((h, p), timeout=timeout).close()
        except (ConnectionRefusedError, ConnectionResetError):
            pass                       # refused/reset is still an answer: a host is there
        except OSError:
            return                     # timed out / unreachable on this port
        with lock:
            found.add(h)

    with cf.ThreadPoolExecutor(_workers(len(pairs))) as ex:
        list(ex.map(_one, pairs))
    return found


def discover_hosts(net, log=print, cancel=None):
    """Hosts of a network that answer a ping, show up in the ARP table, or answer a TCP connect.
    All three work without administrator / root rights."""
    stopped = (lambda: cancel is not None and cancel.is_set())
    hosts = [str(h) for h in net.hosts()]
    log(f"Looking for live hosts in {net} ({len(hosts)} addresses)...")
    with cf.ThreadPoolExecutor(128) as ex:
        res = list(ex.map(lambda h: False if stopped() else is_alive(h), hosts))
    found = {h for h, ok in zip(hosts, res) if ok}
    found |= {ip for ip in arp_table() if ipaddress.ip_address(ip) in net
              and ip != str(net.broadcast_address) and not ipaddress.ip_address(ip).is_multicast}
    rest = [h for h in hosts if h not in found]
    if rest and not stopped():
        log(f"{len(found)} answered ping/ARP; checking the other {len(rest)} with TCP (finds hosts that block ping)...")
        found |= tcp_sweep(rest, stopped=stopped)
    me = local_ip()
    if me and ipaddress.ip_address(me) in net:
        found.add(me)
    return sorted(found, key=lambda x: tuple(map(int, x.split("."))))


def resolve_targets(text, info, log=print, cancel=None):
    """Target text -> list of IPs. Empty = your whole network; also IP, host name, or an internal CIDR range.
    Only internal (private) addresses are accepted: this tool is for networks you run."""
    tokens = [t for t in re.split(r"[,\s]+", (text or "").strip()) if t]
    if not tokens:
        if not info.get("ip") or not info.get("mask"):
            raise ValueError("Could not determine your network - are you connected?")
        net = ipaddress.ip_network(f"{info['ip']}/{info['mask']}", strict=False)
        if net.num_addresses > 1024:
            net = ipaddress.ip_network(f"{info['ip']}/24", strict=False)
        return discover_hosts(net, log, cancel)
    out = []
    for t in tokens:
        if "/" in t:
            out += discover_hosts(parse_range(t), log, cancel)
            continue
        try:
            ip = str(ipaddress.ip_address(t))
        except ValueError:
            try:
                ip = socket.gethostbyname(t)
            except OSError:
                raise ValueError(f"Cannot resolve '{t}'.")
        if not is_private_ip(ip):
            raise ValueError(f"{ip} is not an internal address. Only your own networks (10.x, 172.16-31.x, "
                             "192.168.x) can be scanned.")
        out.append(ip)
    return sorted(set(out), key=lambda x: tuple(map(int, x.split("."))))


def parse_networks(text, max_total=16384):
    """Several networks from one field (comma / whitespace / newline separated CIDRs or ranges) -> a
    de-duplicated list of ip_network objects, for a multi-subnet / multi-site scan. Reuses parse_range per
    token (CIDR, a.b.c.d-e, or a bare IP). Raises ValueError (which the caller shows) on a bad token or when
    the total would be unreasonably large."""
    tokens = [t for t in re.split(r"[,\s]+", (text or "").strip()) if t]
    if not tokens:
        raise ValueError("Enter one or more networks, e.g. 10.0.1.0/24, 10.0.2.0/24")
    nets, seen, total = [], set(), 0
    for t in tokens:
        net = parse_range(t)                 # raises ValueError on a bad token
        if str(net) in seen:
            continue
        seen.add(str(net))
        total += net.num_addresses
        if total > max_total:
            raise ValueError(f"That's over {max_total} addresses in one scan - narrow the networks (e.g. "
                             "/24s) or run them separately.")
        nets.append(net)
    return nets


def scan_sites(info, networks, ports=True, vendors=True, log=print, cancel=None, deep=None):
    """Scan several networks in one pass and return ONE device list, each device tagged with the network it
    was found on (d["site"]). Subnets other than your own are reached over the router (ping / TCP sweep);
    mDNS and ARP naturally only enrich the local one. Devices are de-duplicated across overlapping networks
    by (ip, mac). Honours cancel between networks."""
    stopped = (lambda: cancel is not None and cancel.is_set())
    merged, seen = [], set()
    nets = list(networks or [])
    for i, net in enumerate(nets):
        if stopped():
            break
        label = str(net)
        log(f"--- Site {i + 1}/{len(nets)}: {label} ---")
        for d in scan(info, ports=ports, vendors=vendors, log=log, cancel=cancel, deep=deep, net=net):
            key = (d.get("ip"), (d.get("mac") or "").lower())
            if key in seen:
                continue
            seen.add(key)
            d["site"] = label
            merged.append(d)
    return merged


def grab_banner(ip, port):
    """What an open service says about itself (first line, or the HTTP Server header)."""
    try:
        with socket.create_connection((ip, port), timeout=1.0) as s:
            s.settimeout(1.0)
            if port in HTTP_PORTS:
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScout\r\n\r\n".encode())
            data = s.recv(300)
    except OSError:
        return ""
    text = data.decode("latin-1", "ignore")
    m = re.search(r"(?im)^server:\s*(.+)$", text)
    if m:
        return "HTTP " + re.sub(r"[^\x20-\x7e]", "", m.group(1).strip())[:50]
    line = text.strip().splitlines()[0] if text.strip() else ""
    return re.sub(r"[^\x20-\x7e]", "", line)[:60]


def port_scan(targets, ports, log=print, cancel=None, grab_banners=True, timeout=0.5, progress=None):
    """TCP connect scan (no special privileges needed). Returns one dict per OPEN port."""
    stopped = (lambda: cancel is not None and cancel.is_set())
    if len(targets) * len(ports) > MAX_PROBES:
        raise ValueError(f"Too many probes ({len(targets)} hosts x {len(ports)} ports). "
                         f"The limit is {MAX_PROBES:,} - use fewer ports or hosts.")
    if len(ports) > 1024 and len(targets) > 1:
        raise ValueError("Scanning more than 1024 ports is limited to a single host.")
    jobs = [(ip, p) for ip in targets for p in ports]

    def one(job):
        if stopped():
            return None
        try:
            with socket.create_connection(job, timeout=timeout):
                return job
        except OSError:
            return None
    opened = []
    with cf.ThreadPoolExecutor(_workers(min(len(jobs), 4000), hi=384)) as ex:
        for i in range(0, len(jobs), 4000):
            if stopped():
                break
            opened += [r for r in ex.map(one, jobs[i:i + 4000]) if r]
            if progress:
                progress(min(len(jobs), i + 4000), len(jobs), len(opened))
        if opened and not stopped():
            # confirm each candidate with one more connection - filters out a one-off transient success
            # (a flaky hop, a race on the remote port) so "open" in the results means it answered twice
            confirmed = list(ex.map(one, opened))
            opened = [job for job, ok in zip(opened, confirmed) if ok]
        banners = list(ex.map(lambda j: grab_banner(*j) if grab_banners and not stopped() else "", opened))
        # TLS ports say nothing until a handshake - read the certificate instead (whose, and when it dies)
        tls_jobs = [j for j, b in zip(opened, banners) if grab_banners and not b and j[1] in TLS_PORTS]
        tls_info = dict(zip(tls_jobs, ex.map(lambda j: {} if stopped() else tls_cert(*j), tls_jobs)))
    res = []
    for (ip, p), b in zip(opened, banners):
        cert = tls_info.get((ip, p)) or {}
        if cert and not b:
            left = cert.get("days_left")
            b = (f"TLS {cert.get('proto', '')} CN={cert.get('subject') or '?'}"
                 + ("" if left is None else f" ({left} days left)" if left >= 0 else " (EXPIRED)"))[:60]
        vulns = banner_vulns(b)
        notes = [RISKY_PORTS.get(p, "")] + [n for _s, n in vulns] + cert_warnings(cert)
        res.append({"ip": ip, "port": p, "proto": "TCP", "state": "open", "service": service_name(p), "banner": b,
                    "note": " | ".join(x for x in notes if x), "vuln": worst([s for s, _n in vulns]),
                    "vulns": [list(v) for v in vulns]})
    res.sort(key=lambda r: (tuple(map(int, r["ip"].split("."))), r["port"]))
    return res


def port_lines(results):
    lines = [f"{'IP':<16}{'PORT':<8}{'SERVICE':<26}{'BANNER / INFO':<50}NOTE", "-" * 130]
    for r in results:
        lines.append(f"{r['ip']:<16}{str(r['port']) + '/tcp':<8}{r['service'][:24]:<26}{r['banner'][:48] or '-':<50}"
                     f"{r['note']}")
    hosts = len({r["ip"] for r in results})
    lines.append(f"\n{len(results)} open port(s) on {hosts} host(s). Closed and filtered ports are not listed.")
    return lines


# ------------------------------------------------------------------- output
# =========================================================== device-scan detection summary
TYPE_SINGULAR = {"Phone": "phone", "Laptop": "laptop", "Desktop": "desktop", "Computer": "computer",
                 "Camera": "camera", "Printer": "printer", "Router": "router", "Network": "network device",
                 "Server": "server / NAS", "IoT": "smart-home / IoT device", "TV/Media": "TV / media device",
                 "Unknown": "unidentified device"}
TYPE_PLURAL = {"Phone": "phones", "Laptop": "laptops", "Desktop": "desktops", "Computer": "computers",
               "Camera": "cameras", "Printer": "printers", "Router": "routers", "Network": "network devices",
               "Server": "servers / NAS", "IoT": "smart-home / IoT", "TV/Media": "TVs / media",
               "Unknown": "unidentified"}


def detection_summary(devs):
    """What the device scan actually recognised, in one readable block: how many of each kind of device,
    and which brands. Returns {"total", "by_type": [(type, n)], "by_brand": [(brand, n)], "text": str}."""
    by_type, by_brand = {}, {}
    for d in devs or []:
        t = d.get("type") or "Unknown"
        by_type[t] = by_type.get(t, 0) + 1
        b = (d.get("brand") or "").strip()
        if b:
            by_brand[b] = by_brand.get(b, 0) + 1
    order = lambda kv: (kv[0] == "Unknown", -kv[1], kv[0])
    types = sorted(by_type.items(), key=order)
    brands = sorted(by_brand.items(), key=lambda kv: (-kv[1], kv[0]))
    total = sum(by_type.values())
    if not total:
        text = "No devices detected."
    else:
        parts = [f"{n} {(TYPE_PLURAL if n != 1 else TYPE_SINGULAR).get(t, t.lower())}" for t, n in types]
        text = f"DETECTED {total} DEVICE{'S' if total != 1 else ''}: " + ", ".join(parts)
        if brands:
            text += "  |  BRANDS: " + ", ".join(f"{b} x{n}" if n > 1 else b for b, n in brands[:12])
            if len(brands) > 12:
                text += f" (+{len(brands) - 12} more)"
    return {"total": total, "by_type": types, "by_brand": brands, "text": text}


# =========================================================== weekly health report
HEALTH_GRADE_MAP = {4: "F", 3: "D", 2: "C", 1: "B", 0: "A"}


def _dev_key(d):
    """Stable identity for week-over-week comparison: the MAC when we have one, else the IP."""
    return (d.get("mac") or "").lower() or d.get("ip") or ""


def _dev_reason(d):
    """One readable line of why a device is flagged, from the risk notes the scan already gathered."""
    return "; ".join(str(n) for n in (d.get("risk_notes") or []))[:160]


def health_report(devs, info=None, prev_devs=None, when=None):
    """Build a weekly network-health summary from an ALREADY-collected device list. Pure - no scanning,
    no I/O - so it is trivially testable and the caller decides how the devices were gathered (a fresh scan
    or a saved snapshot). `prev_devs` (e.g. last week's snapshot) adds a what-changed section. The grade is
    worst-risk-wins (one CRITICAL device is an F), which is the right bias for a security health check.
    Returns a dict the renderers and the emailer consume."""
    devs = devs or []
    summ = detection_summary(devs)
    rank = _DEV_RISK_RANK
    risk_counts = {}
    for d in devs:
        k = (d.get("risk") or "NONE").upper()
        risk_counts[k] = risk_counts.get(k, 0) + 1
    worst = max((rank.get((d.get("risk") or "").upper(), 0) for d in devs), default=0)
    risky = sorted((d for d in devs if rank.get((d.get("risk") or "").upper(), 0) >= 2),
                   key=lambda d: rank.get((d.get("risk") or "").upper(), 0), reverse=True)
    change = None
    if prev_devs is not None:
        cur = {_dev_key(d): d for d in devs if _dev_key(d)}
        prev = {_dev_key(d): d for d in prev_devs if _dev_key(d)}
        change = {"new": [cur[k] for k in cur if k not in prev],
                  "gone": [prev[k] for k in prev if k not in cur],
                  "prev_total": len(prev_devs), "delta": len(devs) - len(prev_devs)}
    return {"when": when or datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "total": summ["total"], "by_type": summ["by_type"], "summary_text": summ["text"],
            "grade": HEALTH_GRADE_MAP[worst], "risk_counts": risk_counts, "risky": risky,
            "change": change, "info": info or {}}


def health_report_lines(report):
    """The weekly report as plain text - the email body and the on-screen / CLI version."""
    r = report
    rc = r["risk_counts"]
    out = [f"NETSCOUT WEEKLY HEALTH REPORT - {r['when']}", "",
           f"Overall grade:  {r['grade']}", "", r["summary_text"], ""]
    present = [f"{k.title()}: {rc[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE") if rc.get(k)]
    if present:
        out.append("Risk levels - " + ", ".join(present))
    if r["risky"]:
        out += ["", f"Needs attention ({len(r['risky'])}), worst first:"]
        for d in r["risky"][:30]:
            why = _dev_reason(d)
            out.append(f"  [{(d.get('risk') or '').upper()}] {d.get('ip', ''):<15} "
                       f"{(d.get('label') or d.get('type') or 'device')}" + (f"  - {why}" if why else ""))
    else:
        out += ["", "No medium-or-higher risks found."]
    ch = r.get("change")
    if ch:
        out += ["", f"Since last week: {ch['delta']:+d} devices ({ch['prev_total']} -> {r['total']})."]
        if ch["new"]:
            out.append("  New:  " + ", ".join((d.get("label") or d.get("ip", "")) for d in ch["new"][:15]))
        if ch["gone"]:
            out.append("  Gone: " + ", ".join((d.get("label") or d.get("ip", "")) for d in ch["gone"][:15]))
    return out


def weekly_schedule_command(os_name, program=None, at="08:00", weekday="MON"):
    """The single command to run the weekly report automatically every week on this OS, so it sends on its
    own without NetScout having to be open. `program` is how NetScout is launched (the built exe, or
    'python netscout_gui.py'); a sensible placeholder is used when it isn't known. The built app accepts
    'wreport' as a command-line argument, so the scheduled task just runs it headless."""
    prog = program or ("NetScout.exe" if os_name == "Windows" else "netscout")
    parts = (at or "08:00").split(":")
    hh, mm = (parts + ["0", "0"])[:2]
    if os_name == "Windows":
        return (f'schtasks /create /tn "NetScout-WeeklyReport" /tr "\\"{prog}\\" wreport --email" '
                f'/sc weekly /d {weekday} /st {at} /f')
    dow = {"MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6, "SUN": 0}.get((weekday or "MON").upper(), 1)
    return (f'(crontab -l 2>/dev/null; echo "{int(mm)} {int(hh)} * * {dow} {prog} wreport --email") | crontab -')


def health_report_html(report):
    """The weekly report as a branded, self-contained HTML page (reuses html_report's styling)."""
    r = report
    sections = [("Summary", [f"Overall grade:  {r['grade']}", r["summary_text"]], r["grade"] in ("D", "F"))]
    if r["risky"]:
        lines = []
        for d in r["risky"][:50]:
            why = _dev_reason(d)
            lines.append(f"[{(d.get('risk') or '').upper()}] {d.get('ip', '')}  "
                         f"{(d.get('label') or d.get('type') or 'device')}" + (f" - {why}" if why else ""))
        sections.append((f"Needs attention ({len(r['risky'])})", lines, True))
    else:
        sections.append(("Risks", ["No medium-or-higher risks found."], False))
    ch = r.get("change")
    if ch:
        clines = [f"{ch['delta']:+d} devices since last week ({ch['prev_total']} -> {r['total']})."]
        if ch["new"]:
            clines.append("New:  " + ", ".join((d.get("label") or d.get("ip", "")) for d in ch["new"][:20]))
        if ch["gone"]:
            clines.append("Gone: " + ", ".join((d.get("label") or d.get("ip", "")) for d in ch["gone"][:20]))
        sections.append(("Changes this week", clines, False))
    return html_report("Weekly Health Report", info=r["info"], sections=sections)


# =========================================================== WiFi threat detection (deauth / evil twin)
# 802.11 reason codes that show up in a disconnect. 6 and 7 are what deauthentication attack tools send by
# default (a forged "you're not associated" from the access point) - a burst of them is the classic
# fingerprint of a deauth flood. 1 ("unspecified") is also common in attacks but also in normal life, so it
# only counts as part of a burst.
DEAUTH_REASONS = {1: "unspecified", 2: "previous authentication no longer valid", 3: "station is leaving",
                  4: "inactivity", 5: "access point is full", 6: "class 2 frame from non-authenticated station",
                  7: "class 3 frame from non-associated station", 8: "station left the BSS",
                  15: "4-way handshake timeout", 23: "IEEE 802.1X authentication failed"}
ATTACK_REASONS = {6, 7}
BENIGN_REASONS = {3, 8}          # the device itself chose to leave


def _parse_ts(text):
    """Best-effort timestamp from a log line, as seconds since the epoch (or None)."""
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", text or "")
    if m:
        try:
            return time.mktime(time.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            return None
    return None


def parse_disconnect_log(text, source=""):
    """Turn OS WiFi logs into disconnect events: [{"ts", "bssid", "reason", "local", "raw"}].

    Understands the Linux kernel (dmesg / journalctl -k: "deauthenticated from <mac> (Reason: 7=...)"),
    wpa_supplicant ("CTRL-EVENT-DISCONNECTED bssid=<mac> reason=7 locally_generated=1"), the Windows
    WLAN-AutoConfig event log (event 8003, as printed by wevtutil /f:text) and macOS unified-log lines
    that mention a deauth/disassoc reason."""
    events = []
    if not text:
        return events
    if "Event ID:" in text or "WLAN AutoConfig" in text or source == "windows":
        for block in re.split(r"\n(?=Event\[\d+\])", text):
            if "8003" not in block and "disconnected" not in block.lower():
                continue
            reason_txt = (re.search(r"Reason:\s*(.+)", block) or [None, ""])[1].strip()
            ssid = (re.search(r"SSID:\s*(.+)", block) or [None, ""])[1].strip()
            low = reason_txt.lower()
            local = "by the user" in low
            code = None
            m = re.search(r"\b(?:reason code|code)[:\s]*(\d+)", low)
            if m:
                code = int(m.group(1))
            elif "driver" in low or "not available" in low or "deauth" in low:
                code = 1
            ts = _parse_ts((re.search(r"Date:\s*(\S+)", block) or [None, ""])[1])
            events.append({"ts": ts, "bssid": "", "ssid": ssid, "reason": code, "local": local,
                           "raw": reason_txt or block.strip()[:120]})
        return events
    for line in text.splitlines():
        low = line.lower()
        m = re.search(r"(deauthenticat(?:ed|ing)|disassociat(?:ed|ing)) from (" + MACRE + r")[^(]*\(reason:\s*(\d+)", line, re.I)
        if m:
            events.append({"ts": _parse_ts(line), "bssid": norm_mac(m.group(2)), "ssid": "",
                           "reason": int(m.group(3)), "local": "by local choice" in low, "raw": line.strip()[:160]})
            continue
        m = re.search(r"CTRL-EVENT-DISCONNECTED bssid=(" + MACRE + r") reason=(\d+)", line)
        if m:
            events.append({"ts": _parse_ts(line), "bssid": norm_mac(m.group(1)), "ssid": "",
                           "reason": int(m.group(2)), "local": "locally_generated=1" in line,
                           "raw": line.strip()[:160]})
            continue
        if ("deauth" in low or "disassoc" in low) and "reason" in low:
            m = re.search(r"reason[^0-9]{0,12}(\d+)", low)
            bm = re.search(MACRE, line)
            events.append({"ts": _parse_ts(line), "bssid": norm_mac(bm.group(0)) if bm else "", "ssid": "",
                           "reason": int(m.group(1)) if m else None, "local": "by local choice" in low,
                           "raw": line.strip()[:160]})
    return events


def read_disconnect_log(minutes=60):
    """Read the OS's own record of recent WiFi disconnects. Returns (events, note). Nothing is captured
    from the air: this reads logs the OS already keeps, so it works with any adapter and no admin rights
    on most systems (where it can't read them, `note` says so)."""
    minutes = max(1, int(minutes or 60))
    if OS == "Windows":
        out = run(["wevtutil", "qe", "Microsoft-Windows-WLAN-AutoConfig/Operational",
                   "/q:*[System[(EventID=8003)]]", "/c:300", "/rd:true", "/f:text"], timeout=20)
        ev = [e for e in parse_disconnect_log(out, "windows")
              if e["ts"] is None or e["ts"] >= time.time() - minutes * 60]
        return ev, ("" if out else "Could not read the WLAN-AutoConfig event log.")
    if OS == "Darwin":
        out = run(["log", "show", "--last", f"{minutes}m", "--style", "syslog", "--predicate",
                   'eventMessage CONTAINS[c] "deauth" OR eventMessage CONTAINS[c] "disassoc"'], timeout=40)
        return parse_disconnect_log(out), ("" if out else "Could not read the macOS unified log.")
    texts = []
    if shutil.which("journalctl"):
        texts.append(run(["journalctl", "-k", "--since", f"-{minutes}min", "-o", "short-iso", "--no-pager"], timeout=20))
        texts.append(run(["journalctl", "--since", f"-{minutes}min", "-o", "short-iso", "--no-pager",
                          "-g", "CTRL-EVENT-DISCONNECTED"], timeout=20))
    texts.append(run(["dmesg", "--time-format", "iso"], timeout=10) or run(["dmesg"], timeout=10))
    text = "\n".join(t for t in texts if t)
    seen, ev = set(), []
    for e in parse_disconnect_log(text):
        if e["ts"] is not None and e["ts"] < time.time() - minutes * 60:
            continue
        k = (e["ts"], e["bssid"], e["reason"])
        if k not in seen:
            seen.add(k)
            ev.append(e)
    note = "" if text.strip() else ("Could not read the kernel/WiFi logs - run NetScout with sudo, or add "
                                    "your user to the 'adm' / 'systemd-journal' group.")
    return ev, note


def deauth_verdict(events, window_s=600, burst=5):
    """Is this a deauthentication attack, or ordinary WiFi life? Returns {"level", "why", "count",
    "attack_frames"}. level is "ATTACK", "SUSPICIOUS" or "OK".

    ATTACK: several disconnects carrying the forged-frame reason codes (6/7), or a burst of `burst`+
    disconnects the device did not choose itself, inside `window_s` seconds.
    SUSPICIOUS: some of that, but below the attack threshold."""
    real = [e for e in events if not e.get("local") and e.get("reason") not in BENIGN_REASONS]
    attack = [e for e in real if e.get("reason") in ATTACK_REASONS]
    stamps = sorted(e["ts"] for e in real if e.get("ts"))
    peak = 0
    j = 0
    for i in range(len(stamps)):
        while stamps[i] - stamps[j] > window_s:
            j += 1
        peak = max(peak, i - j + 1)
    if not stamps:
        peak = len(real)          # no timestamps at all: judge on the raw count
    why = []
    if len(attack) >= 3:
        why.append(f"{len(attack)} disconnects with reason 6/7 - the codes deauth attack tools forge")
    if peak >= burst:
        why.append(f"{peak} forced disconnects within {window_s // 60} minutes")
    if why:
        level = "ATTACK"
    elif attack or peak >= 2:
        level = "SUSPICIOUS"
        why.append(f"{len(real)} unexplained disconnect(s)" + (f", {len(attack)} with reason 6/7" if attack else ""))
    else:
        level = "OK"
        why.append("no sign of forced disconnects" if not real else
                   f"{len(real)} isolated disconnect(s) - normal WiFi behaviour")
    return {"level": level, "why": "; ".join(why), "count": len(real), "attack_frames": len(attack)}


_RISK_RANK = {"OPEN": 0, "WEAK": 1, "OK": 2, "BEST": 3}


def wifi_threats(prev, cur, watch_ssids=None, flood=15):
    """Compare two WiFi scans and report what CHANGED in a way that signals an attack in progress.
    Returns [{"severity", "kind", "ssid", "bssid", "why"}], most severe first.

    - EVIL TWIN: a name you could already hear gains a new radio from a different manufacturer, or one
      offering weaker security than the original.
    - DOWNGRADE: the same radio now advertises weaker security than before.
    - TARGET LOST: a watched network (your own, normally) vanished while others are still heard - what a
      jammer or deauth flood looks like from the outside.
    - BEACON FLOOD: a large number of brand-new networks appeared at once (fake-AP flooding).
    Purely passive - it compares beacons the OS already heard; nothing is sent."""
    prev, cur = prev or [], cur or []
    watch = {s for s in (watch_ssids or []) if s}
    pb = {a.get("bssid"): a for a in prev if a.get("bssid")}
    cb = {a.get("bssid"): a for a in cur if a.get("bssid")}
    p_ssid = {}
    for a in prev:
        if a.get("ssid"):
            p_ssid.setdefault(a["ssid"], []).append(a)
    out = []
    new = [a for b, a in cb.items() if b not in pb]
    for a in new:
        olds = p_ssid.get(a.get("ssid") or "\0")
        if not olds:
            continue
        old_vendors = {(o.get("vendor") or "").strip() for o in olds if o.get("vendor")}
        old_best = max(_RISK_RANK.get(o.get("risk"), 2) for o in olds)
        why = []
        if a.get("vendor") and old_vendors and a["vendor"].strip() not in old_vendors:
            why.append(f"new radio made by {a['vendor']} (the existing ones are {', '.join(sorted(old_vendors))})")
        if _RISK_RANK.get(a.get("risk"), 2) < old_best:
            why.append(f"offers weaker security ({a.get('security') or 'Open'}) than the original")
        if why:
            out.append({"severity": "HIGH" if (a.get("ssid") in watch or len(why) > 1) else "MEDIUM",
                        "kind": "EVIL TWIN", "ssid": a.get("ssid", ""), "bssid": a.get("bssid", ""),
                        "why": "; ".join(why)})
    for b, a in cb.items():
        o = pb.get(b)
        if o and _RISK_RANK.get(a.get("risk"), 2) < _RISK_RANK.get(o.get("risk"), 2):
            out.append({"severity": "HIGH", "kind": "DOWNGRADE", "ssid": a.get("ssid", ""), "bssid": b,
                        "why": f"security changed from {o.get('security') or 'Open'} to {a.get('security') or 'Open'}"})
    cur_ssids = {a.get("ssid") for a in cur}
    for s in sorted(watch):
        if s in p_ssid and s not in cur_ssids and len(cur) >= 2:
            out.append({"severity": "HIGH", "kind": "TARGET LOST", "ssid": s, "bssid": "",
                        "why": "your network vanished while other networks are still heard - possible "
                               "jamming or deauthentication flood (or the router just restarted)"})
    if prev and len(new) >= flood:
        out.append({"severity": "MEDIUM", "kind": "BEACON FLOOD", "ssid": "", "bssid": "",
                    "why": f"{len(new)} new networks appeared at once - possible fake-AP flooding"})
    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    out.sort(key=lambda t: (rank.get(t["severity"], 3), t["kind"], t["ssid"]))
    return out


def threat_lines(threats, verdict=None, note=""):
    out = ["WIFI THREAT MONITOR", ""]
    if verdict:
        out.append(f"DEAUTH CHECK: {verdict['level']} - {verdict['why']}")
        if verdict["level"] == "ATTACK":
            out.append("  What to do: move to 5 GHz/6 GHz, enable PMF (802.11w, 'Protected Management Frames')")
            out.append("  on your router - it makes forged deauth frames useless - and use WPA3 if you can.")
        out.append("")
    if note:
        out += [f"NOTE: {note}", ""]
    if threats:
        out.append(f"CHANGES THAT LOOK LIKE AN ATTACK ({len(threats)}):")
        for t in threats:
            out.append(f"  [{t['severity']}] {t['kind']:<13} {(t['ssid'] or '-'):<24} {t['bssid'] or ''}")
            out.append(f"        {t['why']}")
    else:
        out.append("No suspicious changes between scans.")
    return out


# =========================================================== spectrum / interference analysis
DFS_5GHZ = set(range(52, 145))       # channels where the router must give way to radar


def _overlap_24(d):
    """How much a 20 MHz 2.4 GHz signal `d` channels away bleeds into this one (5 MHz per channel)."""
    return {0: 1.0, 1: 0.75, 2: 0.45, 3: 0.2}.get(abs(d), 0.0)


def spectrum_analysis(aps):
    """Per band, per channel: how many networks sit on it, the strongest one, and an interference score
    that also counts the neighbours bleeding in. Returns {band: [{"channel", "count", "strongest",
    "co", "adjacent", "score", "level", "dfs"}]} sorted by channel.

    co = same-channel interference (networks that must take turns with you - airtime is shared),
    adjacent = overlap from neighbouring channels (pure noise - worse, they can't even coordinate).
    The score weights each network by how loud it is here, because a faint far-away network barely
    matters and a strong one next door matters a lot."""
    by_band = {}
    for a in aps or []:
        ch, band = a.get("channel"), a.get("band") or ""
        if not ch or not band:
            continue
        try:
            ch = int(ch)
        except (TypeError, ValueError):
            continue
        by_band.setdefault(band, []).append((ch, max(0, min(100, int(a.get("sig") or 0))) / 100.0))
    out = {}
    for band, sigs in by_band.items():
        if band.startswith("2.4"):
            cands = range(1, 14)
        else:
            cands = sorted({c for c, _ in sigs})
        rows = []
        for c in cands:
            same = [w for ch, w in sigs if ch == c]
            co = sum(same)
            adj = (sum(w * _overlap_24(ch - c) for ch, w in sigs if ch != c) if band.startswith("2.4") else 0.0)
            score = round(co + adj, 2)
            level = ("CLEAR" if score < 0.3 else "LIGHT" if score < 1.0 else "BUSY" if score < 2.0 else "CONGESTED")
            rows.append({"channel": c, "count": len(same), "strongest": int(max(same) * 100) if same else 0,
                         "co": round(co, 2), "adjacent": round(adj, 2), "score": score, "level": level,
                         "dfs": (not band.startswith("2.4")) and band.startswith("5") and c in DFS_5GHZ})
        out[band] = rows
    return out


def spectrum_lines(aps):
    sp = spectrum_analysis(aps)
    if not sp:
        return ["SPECTRUM ANALYSIS", "", "No channel information - run a WiFi scan first (or the OS didn't report channels)."]
    rec = best_channels(aps)
    out = ["SPECTRUM ANALYSIS - how crowded each channel is where you are standing", "",
           "score = loudness-weighted interference (same channel + overlap from neighbours).",
           "CLEAR < 0.3   LIGHT < 1   BUSY < 2   CONGESTED >= 2", ""]
    for band in sorted(sp, key=lambda b: (not b.startswith("2.4"), not b.startswith("5"), b)):
        out.append(f"{band}:")
        out.append(f"  {'CH':>4} {'NETS':>4} {'TOP%':>5} {'SAME':>5} {'NEIGH':>6} {'SCORE':>6}  LEVEL      LOAD")
        for r in sp[band]:
            bar = "#" * min(30, int(round(r["score"] * 8)))
            out.append(f"  {r['channel']:>4} {r['count']:>4} {r['strongest']:>5} {r['co']:>5} {r['adjacent']:>6} "
                       f"{r['score']:>6}  {r['level']:<10} {bar}{'  (DFS/radar)' if r['dfs'] else ''}")
        if band in rec:
            out.append(f"  -> {rec[band]['note']}")
        out.append("")
    out.append("Limit: this is built from the networks your adapter can decode. Non-WiFi interference")
    out.append("(microwaves, baby monitors, Bluetooth) is invisible to it - that needs a hardware spectrum analyser.")
    return out


# =========================================================== coverage survey / heatmap
SURVEY_FILE = os.path.join(os.path.expanduser("~"), ".netscout_survey.json")


def signal_quality(dbm):
    """The industry thresholds used in WiFi site surveys (dBm, higher = better)."""
    if dbm is None:
        return "NONE"
    return ("EXCELLENT" if dbm >= -55 else "GOOD" if dbm >= -67 else "FAIR" if dbm >= -75
            else "POOR" if dbm >= -85 else "NONE")


def survey_sample(aps, location):
    """One survey point: what every network sounds like at `location` (a name you type, e.g. 'Kitchen')."""
    loc = (location or "").strip() or f"Spot {time.strftime('%H:%M:%S')}"
    readings = {}
    for a in aps or []:
        key = a.get("bssid") or f"{a.get('ssid', '')}#{a.get('channel')}"
        dbm = a.get("dbm")
        if dbm is None:
            dbm = pct_to_dbm(a.get("sig"))
        readings[key] = {"ssid": a.get("ssid", ""), "dbm": dbm, "band": a.get("band", ""),
                         "sig": a.get("sig")}
    return {"location": loc, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "readings": readings}


def survey_load():
    data = _load_json(SURVEY_FILE, [])
    return [s for s in data if isinstance(s, dict) and "location" in s and isinstance(s.get("readings"), dict)] \
        if isinstance(data, list) else []


def survey_save(samples):
    _save_json_atomic(SURVEY_FILE, list(samples or []))


def survey_add(samples, sample):
    """Add a point; measuring the same location again replaces the older measurement."""
    out = [s for s in (samples or []) if s.get("location", "").lower() != sample["location"].lower()]
    out.append(sample)
    return out


def survey_table(samples, ssid=None):
    """Rows for the coverage table: per location, the best signal of `ssid` (or of the strongest network
    there if no ssid is given). Returns [{"location", "ssid", "dbm", "quality", "band", "time"}]."""
    rows = []
    for s in samples or []:
        cands = [r for r in s["readings"].values() if r.get("dbm") is not None and (not ssid or r.get("ssid") == ssid)]
        best = max(cands, key=lambda r: r["dbm"]) if cands else None
        rows.append({"location": s["location"], "ssid": (best or {}).get("ssid", ssid or ""),
                     "dbm": (best or {}).get("dbm"), "quality": signal_quality((best or {}).get("dbm")),
                     "band": (best or {}).get("band", ""), "time": s.get("time", "")})
    return rows


def survey_lines(samples, ssid=None):
    rows = survey_table(samples, ssid)
    out = [f"COVERAGE SURVEY{' - ' + ssid if ssid else ''}", ""]
    if not rows:
        out += ["No survey points yet.", "",
                "How to do a survey: walk to a spot, type its name (e.g. 'Kitchen'), press ADD SPOT.",
                "Repeat in every room. The table then shows where the WiFi is strong and where it's weak."]
        return out
    out.append(f"{'LOCATION':<22}{'dBm':>6}  {'QUALITY':<10} {'BAND':<9} HEAT")
    for r in rows:
        heat = "" if r["dbm"] is None else "#" * max(1, min(25, int((r["dbm"] + 95) / 2)))
        out.append(f"{r['location'][:21]:<22}{'' if r['dbm'] is None else r['dbm']:>6}  {r['quality']:<10} "
                   f"{r['band'][:8]:<9} {heat}")
    weak = [r["location"] for r in rows if r["quality"] in ("POOR", "NONE")]
    out.append("")
    out.append("EXCELLENT >= -55 dBm   GOOD >= -67 (fine for video calls)   FAIR >= -75   POOR >= -85")
    if weak:
        out.append(f"Weak spots: {', '.join(weak)} - consider a mesh node / access point closer to these.")
    else:
        out.append("No weak spots among the places measured.")
    return out


# =========================================================== power management (Wake-on-LAN / shutdown)
def wol_packet(mac):
    """The Wake-on-LAN 'magic packet': 6 x FF followed by the target MAC 16 times."""
    m = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(m) != 12:
        raise ValueError(f"not a MAC address: {mac!r}")
    return b"\xff" * 6 + bytes.fromhex(m) * 16


def _directed_broadcast(ip, mask):
    try:
        i = struct.unpack("!I", socket.inet_aton(ip))[0]
        m = struct.unpack("!I", socket.inet_aton(mask))[0]
        return socket.inet_ntoa(struct.pack("!I", (i & m) | (~m & 0xFFFFFFFF)))
    except (OSError, struct.error, TypeError):
        return None


def wake_on_lan(mac, ip=None, mask=None, port=9):
    """Power a sleeping/off computer ON over the network. Returns (ok, message).
    Works only when that computer has Wake-on-LAN enabled in its BIOS/UEFI and network adapter, and is
    plugged in (usually by cable - most laptops cannot be woken over WiFi)."""
    try:
        pkt = wol_packet(mac)
    except ValueError as e:
        return False, str(e)
    targets = ["255.255.255.255"]
    if ip and mask:
        b = _directed_broadcast(ip, mask)
        if b and b not in targets:
            targets.append(b)
    sent = 0
    for t in targets:
        for p in {port, 7, 9}:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(pkt, (t, p))
                    sent += 1
            except OSError:
                pass
    if not sent:
        return False, "Could not send the wake-up packet (no network?)."
    return True, (f"Wake-up packet sent to {norm_mac(mac)}. If Wake-on-LAN is enabled on that machine it "
                  "powers on within ~30 seconds.")


POWER_ACTIONS = ("off", "restart", "cancel")


def power_methods(dev):
    """Which legitimate remote power-off routes a scanned device offers, judged from its open ports and
    type: 'windows' (Windows remote shutdown, needs admin rights on it) and/or 'ssh' (needs an SSH key
    login with sudo on it). Phones, TVs, cameras and IoT gadgets have no standard remote power-off."""
    ports = set(dev.get("ports") or [])
    t = dev.get("type") or ""
    os_ = (dev.get("os") or "").lower()
    m = []
    if ports & {135, 139, 445} or ("windows" in os_ and t in ("Computer", "Laptop", "Desktop", "Server")):
        m.append("windows")
    if ports & {5985, 5986}:          # WinRM - the modern remote-management route into a Windows machine
        m.append("winrm")
    if 22 in ports:
        m.append("ssh")
    return m
# IPMI (a server's out-of-band BMC) is never auto-detected: it answers on UDP 623, which a TCP port scan
# can't see, and its address is usually a SEPARATE management IP. It is offered as a method the operator
# chooses and points at the BMC themselves - still fully credential-gated (the BMC authenticates).


def shutdown_command(ip, action="off", method="windows", user="", delay=30, host_os=None):
    """The OS-standard command that asks a machine you administer to shut down. Returns (argv, error).

    Deliberately only routes where the TARGET checks your credentials itself: Windows refuses unless
    you're an administrator on that PC; SSH refuses without your key and passwordless sudo. NetScout
    can't power off something you have no rights over - by design."""
    host_os = host_os or OS
    # power ON / hard CYCLE / graceful SOFT-off exist only through a server's out-of-band BMC (IPMI); for
    # every other method the way to turn a machine on is Wake-on-LAN, so reject them here rather than
    # silently coercing "on" into "off" (which would power a machine down when asked to bring it up).
    if action in ("on", "cycle", "soft") and method != "ipmi":
        return None, "powering on / cycling over the network is an IPMI-only action - use Wake-on-LAN for other devices"
    valid = POWER_ACTIONS + (("on", "cycle", "soft") if method == "ipmi" else ())
    action = action if action in valid else "off"
    if not re.fullmatch(r"[0-9A-Za-z.\-:]+", ip or ""):
        return None, "invalid address"
    delay = max(0, min(int(delay or 0), 600))
    if method == "windows":
        if host_os != "Windows":
            return None, "Windows remote shutdown can only be sent from a Windows PC - use SSH instead."
        if action == "cancel":
            return ["shutdown", "/a", "/m", f"\\\\{ip}"], ""
        return (["shutdown", "/s" if action == "off" else "/r", "/f", "/t", str(delay), "/m", f"\\\\{ip}",
                 "/c", "NetScout: the network administrator is shutting this PC down. Save your work."], "")
    if method == "winrm":
        # WinRM authenticates as the Windows user running NetScout (Kerberos / the current token), so it
        # reaches a machine you administer with no password handling here. Windows-to-Windows only.
        if host_os != "Windows":
            return None, "WinRM remote shutdown can only be sent from a Windows PC - use SSH instead."
        verb = {"off": "Stop-Computer", "restart": "Restart-Computer"}.get(action)
        if verb is None:
            return None, "WinRM can't cancel a pending shutdown - use the WINDOWS method for that."
        return (["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"{verb} -ComputerName {ip} -Force"], "")
    if method == "ssh":
        if not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", user or ""):
            return None, "enter the user name to log in as (SSH)"
        mins = max(0, (delay + 59) // 60)
        remote = {"off": f"sudo -n shutdown -h +{mins}", "restart": f"sudo -n shutdown -r +{mins}",
                  "cancel": "sudo -n shutdown -c || sudo -n killall shutdown"}[action]
        return (["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "-o", "StrictHostKeyChecking=accept-new",
                 f"{user}@{ip}", remote], "")
    if method == "ipmi":
        # out-of-band power through a server's BMC. The BMC checks -U/-P itself; the password is handed to
        # ipmitool through the IPMITOOL_PASSWORD environment variable (-E), never written on the command
        # line (where it would show up in the process list), and never stored by NetScout.
        if not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", user or ""):
            return None, "enter the BMC user name to log in as (IPMI)"
        act = {"off": "off", "restart": "reset", "on": "on", "cycle": "cycle", "soft": "soft"}.get(action)
        if act is None:
            return None, "IPMI power is immediate - there is nothing to cancel."
        return (["ipmitool", "-I", "lanplus", "-H", ip, "-U", user, "-E", "chassis", "power", act], "")
    return None, f"unknown method {method!r}"


def explain_power_result(out, method):
    """Translate the usual failures into what to actually do about them."""
    low = (out or "").lower()
    if method == "windows":
        if "(5)" in low or "access is denied" in low:
            return "Access denied - you need administrator rights on that PC (same user/password, or a domain admin)."
        if "(53)" in low or "network path was not found" in low:
            return ("That PC doesn't accept remote shutdown: allow 'Remote Shutdown' / File and Printer Sharing "
                    "in its firewall, and make sure it's on.")
        if "(1115)" in low or "(1116)" in low:
            return "A shutdown was already in progress / nothing to cancel."
    if method == "ssh":
        if "permission denied" in low:
            return "SSH login refused - set up an SSH key for that user first (ssh-copy-id)."
        if "password is required" in low or "a terminal is required" in low:
            return "Logged in, but sudo wants a password - allow passwordless 'shutdown' for that user in sudoers."
        if "could not resolve" in low or "timed out" in low or "refused" in low or "no route" in low:
            return "Could not reach SSH on that device (is it on, and is SSH enabled?)."
        if "not found" in low:
            return "This computer has no 'ssh' program - on Windows: Settings > Optional features > OpenSSH Client."
    if method == "winrm":
        if "access is denied" in low or "accessdenied" in low:
            return "Access denied - you need admin rights on that PC, and WinRM must trust this machine."
        if "cannot connect" in low or "winrm" in low or "connecting to remote server" in low:
            return ("That PC isn't reachable over WinRM: on it, run 'Enable-PSRemoting' as admin (and allow it "
                    "through its firewall).")
        if "not found" in low:
            return "This needs PowerShell, which every supported Windows has - check it's a Windows PC."
    if method == "ipmi":
        if "not found" in low:
            return "IPMI needs the 'ipmitool' program. Linux: install 'ipmitool'. Windows: use its .exe build."
        if "password" in low or "authentication" in low or "privilege" in low:
            return "The BMC refused the login - check the IPMI user name, password and that it has operator rights."
        if "unable to establish" in low or "timeout" in low or "no route" in low:
            return "Could not reach the BMC - check its management IP and that IPMI-over-LAN is enabled."
    return ""


def remote_power(ip, action="off", method="windows", user="", delay=30, secret=None):
    """Ask a machine you administer to power off / restart (or cancel a pending one). Returns (ok, msg).
    `secret` is only ever the BMC password for the IPMI method, and is passed through the environment so
    it never appears on a command line or in NetScout's own state."""
    argv, err = shutdown_command(ip, action, method, user, delay)
    if not argv:
        return False, err
    if not shutil.which(argv[0]):
        return False, explain_power_result("not found", method) or f"'{argv[0]}' is not available here."
    env = None
    if method == "ipmi" and secret is not None:
        env = dict(os.environ, IPMITOOL_PASSWORD=secret)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=25, env=env, **NOWIN)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        ok = r.returncode == 0
    except subprocess.TimeoutExpired:
        return False, "No answer in time - the device may be off or blocking the request."
    except OSError as e:
        return False, str(e)
    verb = {"off": "power off", "restart": "restart", "cancel": "cancel", "on": "power on",
            "cycle": "power cycle", "soft": "graceful shutdown"}.get(action, "power")
    # argv never carries the IPMI password (it is passed through the environment), so it is safe to record.
    audit_log(verb, target=ip, method=method, command=argv, ok=ok,
              detail="" if ok else (out[:200] or "failed"))
    if ok:
        # IPMI (and a cancel) act at once; the delayed Windows/SSH routes are the only ones you can call back
        tail = "" if (method == "ipmi" or action == "cancel") else \
               f" It happens in about {max(1, delay)} seconds - use CANCEL to stop it."
        return True, f"{ip}: {verb} request accepted.{tail}"
    return False, explain_power_result(out, method) or (out[:200] or "The request failed.")


def parse_query_user(text):
    """Windows `query user /server:X` -> [{"user", "state", "idle"}] (idle in minutes, 0 = active now)."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.strip().lstrip(">").split()
        if len(parts) < 4:
            continue
        state_i = next((i for i, p in enumerate(parts) if p.lower() in ("active", "disc", "aktiv", "getr.")), None)
        if state_i is None:
            continue
        idle_s = parts[state_i + 1] if state_i + 1 < len(parts) else "."
        mins = 0
        if idle_s not in (".", "none", "keine"):
            m = re.fullmatch(r"(?:(\d+)\+)?(?:(\d+):)?(\d+)", idle_s)
            if m:
                mins = int(m.group(1) or 0) * 1440 + int(m.group(2) or 0) * 60 + int(m.group(3))
        out.append({"user": parts[0], "state": parts[state_i].lower(), "idle": mins})
    return out


def usage_verdict(sessions, load=None, idle_after=15):
    """Is anyone using this machine? Returns ("IN USE" | "IDLE" | "UNKNOWN", reason)."""
    if sessions is None:
        return "UNKNOWN", "could not ask the machine"
    active = [s for s in sessions if s.get("state") in ("active", "aktiv") and s.get("idle", 0) < idle_after]
    if active:
        return "IN USE", "signed in and active: " + ", ".join(s["user"] for s in active)
    if load is not None and load >= 1.0:
        return "IN USE", f"nobody active at the keyboard, but it is busy (load {load:.2f})"
    if sessions:
        return "IDLE", f"{len(sessions)} session(s), none active in the last {idle_after} min"
    return "IDLE", "nobody signed in" + (f", load {load:.2f}" if load is not None else "")


def remote_usage(ip, method="windows", user=""):
    """Check whether a machine is in use before powering it off. Returns (verdict, reason)."""
    if method == "windows":
        if OS != "Windows" or not shutil.which("query"):
            return "UNKNOWN", "checking a Windows PC's sessions needs NetScout running on Windows"
        try:
            r = subprocess.run(["query", "user", f"/server:{ip}"], capture_output=True, text=True,
                               timeout=15, **NOWIN)
            out = (r.stdout or "") + "\n" + (r.stderr or "")
        except (OSError, subprocess.TimeoutExpired):
            return "UNKNOWN", "no answer"
        low = out.lower()
        if "no user exists" in low or "kein benutzer" in low:
            return usage_verdict([])
        if "access is denied" in low or "error 5" in low:
            return "UNKNOWN", "access denied - you need admin rights on that PC"
        s = parse_query_user(r.stdout or "")
        return usage_verdict(s if (r.stdout or "").strip() else None)
    if method == "ssh":
        argv, err = shutdown_command(ip, "cancel", "ssh", user)
        if not argv:
            return "UNKNOWN", err
        argv = argv[:-1] + ["who; echo LOAD=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg | tr -d '{}' | awk '{print $1}')"]
        out = run(argv, timeout=15)
        if not out:
            return "UNKNOWN", "could not log in over SSH (key set up?)"
        load = None
        m = re.search(r"LOAD=([\d.]+)", out)
        if m:
            load = float(m.group(1))
        sessions = [{"user": l.split()[0], "state": "active", "idle": 0}
                    for l in out.splitlines() if l.strip() and not l.startswith("LOAD=")]
        return usage_verdict(sessions, load)
    return "UNKNOWN", "unknown method"


def power_candidates(devs, host_os=None, prefer=None, exclude_ips=None):
    """The devices a bulk power-off may legitimately touch: only ones that expose a credentialed route
    (Windows admin shutdown, or SSH), each paired with the method that will be used. Anything with no
    such route - phones, TVs, cameras, printers, unknown gadgets - and the machines in exclude_ips (the
    operator's own PC) are left out. This never invents a way to switch off a device you hold no rights
    on; the target still authenticates the request itself.
    """
    host_os = host_os or OS
    exclude = set(exclude_ips or [])
    pref = prefer if prefer in ("windows", "winrm", "ssh") else None
    # WinRM never auto-shuts a machine ahead of the plain Windows route (same target, one credential path is
    # enough); SSH leads off-Windows. A bulk run only ever uses routes that need no typed secret.
    order = ["windows", "winrm", "ssh"] if host_os == "Windows" else ["ssh", "windows", "winrm"]
    out = []
    for d in devs or []:
        if d.get("ip") in exclude:
            continue
        avail = power_methods(d)
        if not avail:
            continue
        method = (pref if pref in avail else None) if pref else next((m for m in order if m in avail), None)
        if method == "windows" and host_os != "Windows":
            method = "ssh" if "ssh" in avail else None
        if method:
            out.append({"dev": d, "ip": d.get("ip"), "label": d.get("label", ""), "method": method})
    return out


def bulk_power_lines(results):
    """Readable summary of a bulk shutdown. results: [{"ip","label","method","outcome","detail"}],
    outcome one of 'off','skipped-inuse','skipped-nouser','failed'."""
    done = [r for r in results if r["outcome"] == "off"]
    inuse = [r for r in results if r["outcome"] == "skipped-inuse"]
    nouser = [r for r in results if r["outcome"] == "skipped-nouser"]
    failed = [r for r in results if r["outcome"] == "failed"]
    out = [f"BULK SHUTDOWN: {len(done)} shut down, {len(inuse)} left on (in use), "
           f"{len(failed)} failed, {len(nouser)} skipped (need SSH user)."]
    for r in done:
        out.append(f"  OFF       {r['ip']:<15} {r['label'][:40]} ({r['method']})")
    for r in inuse:
        out.append(f"  IN USE    {r['ip']:<15} {r['label'][:40]} - left running: {r['detail']}")
    for r in failed:
        out.append(f"  FAILED    {r['ip']:<15} {r['label'][:40]} - {r['detail']}")
    for r in nouser:
        out.append(f"  SKIPPED   {r['ip']:<15} {r['label'][:40]} - enter an SSH user to include it")
    return out


def power_lines(devs):
    out = ["POWER CONTROL - wake up or shut down machines you administer", "",
           f"{'IP':<16}{'TYPE':<11}{'DEVICE':<34}{'MAC':<19}POWER OFF VIA"]
    for d in devs or []:
        m = power_methods(d)
        out.append(f"{d.get('ip', ''):<16}{d.get('type', ''):<11}{(d.get('label') or '')[:32]:<34}"
                   f"{d.get('mac') or '-':<19}{', '.join(m) if m else '- (no remote power-off)'}")
    out += ["", "WAKE (power on) works with Wake-on-LAN enabled on the target (usually wired PCs).",
            "POWER OFF works on machines where you hold the credential the TARGET checks: Windows admin,",
            "WinRM, SSH + sudo, or a server BMC over IPMI. Phones, TVs, cameras and gadgets have none.",
            "During an attack you can also BLOCK the offending host at THIS computer's own firewall, or -",
            "with a managed switch - DISCONNECT it by its switch port. Both are reversible and need the",
            "matching credential; NetScout never forces power off a device you hold no rights on."]
    return out


# =========================================================== power POLICY (idle sleep, after-hours off)
# The difference from POWER CONTROL above: that sends a one-off shutdown *now*. This pushes a lasting
# power POLICY onto a machine you administer - "sleep after 20 min idle", "shut down at 22:00 every night" -
# so it saves power on its own, every day, without NetScout having to be there. It travels the exact same
# credentialed channel as a shutdown (WinRM into a Windows box, SSH into a Linux/Mac box, or applied to the
# machine NetScout runs on): the target authenticates it, so NetScout still never changes a machine you hold
# no rights over. Everything here is reversible - every action that sets something has a matching one that
# clears it - and read-only until you choose to apply it.
POLICY_ACTIONS = ("sleep", "wake_sleep_off", "schedule_off", "cancel_off", "allow_mgmt", "revoke_mgmt")
_POLICY_TITLES = {
    "sleep": "Sleep when idle",
    "wake_sleep_off": "Never sleep (stay awake)",
    "schedule_off": "Shut down after hours",
    "cancel_off": "Cancel the nightly shutdown",
    "allow_mgmt": "Allow IT management (root-cause fix)",
    "revoke_mgmt": "Remove the IT-management allowance",
}
MGMT_RULE = "NetScout IT Management"      # firewall-rule name, so the allowance can be found and revoked
NIGHTLY_TASK = "NetScout-NightlyOff"      # scheduled-task / cron name for the after-hours shutdown
_CRON_FILE = "/etc/cron.d/netscout-nightly-off"


def _valid_cidr(subnet):
    """True for an IPv4/IPv6 address or CIDR network (what the IT-management allowance is scoped to)."""
    s = (subnet or "").strip()
    if not s:
        return False
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _parse_hhmm(at_time):
    """'22:00' -> (22, 0); None on anything that isn't a 24-hour clock time."""
    m = re.fullmatch(r"\s*([01]?\d|2[0-3]):([0-5]\d)\s*", at_time or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def power_policy_script(target_os, action, idle_minutes=20, at_time="22:00", it_subnet=""):
    """Build the policy SCRIPT to run ON a machine of `target_os` ('Windows' | 'Linux' | 'Darwin').
    Pure - it only composes text, it never runs anything. Returns (script, human_description, error):
    `script` is for the target's own shell (PowerShell/cmd on Windows, /bin/sh on Linux/Mac), ready for
    apply_power_policy() to carry over WinRM/SSH. One action that sets something always has a partner that
    clears it, so nothing here is a one-way door.
    """
    if action not in POLICY_ACTIONS:
        return "", "", f"unknown policy action {action!r}"
    tos = target_os if target_os in ("Windows", "Linux", "Darwin") else ""
    if not tos:
        return "", "", f"unsupported target OS {target_os!r}"
    mins = max(1, min(int(idle_minutes or 0), 240))
    title = _POLICY_TITLES.get(action, action)

    hm = None
    if action == "schedule_off":
        hm = _parse_hhmm(at_time)
        if not hm:
            return "", "", "enter the shutdown time as HH:MM (24-hour), e.g. 22:00"
    if action == "allow_mgmt" and not _valid_cidr(it_subnet):
        return "", "", "enter the IT-management network as an IP or CIDR, e.g. 10.0.0.0/8"

    if tos == "Windows":
        if action == "sleep":
            s = ("powercfg /change standby-timeout-ac {m}; powercfg /change standby-timeout-dc {m}; "
                 "powercfg /change monitor-timeout-ac {m}; powercfg /change monitor-timeout-dc {m}"
                 ).format(m=mins)
            return s, f"{title}: sleep the display and the PC after {mins} min idle (on battery and plugged in).", ""
        if action == "wake_sleep_off":
            s = ("powercfg /change standby-timeout-ac 0; powercfg /change standby-timeout-dc 0")
            return s, f"{title}: the PC will no longer sleep on its own (display still sleeps).", ""
        if action == "schedule_off":
            hh, mm = hm
            # schtasks runs the shutdown as SYSTEM so it works with nobody logged in; /f overwrites a prior
            # copy. No custom /c message - the 120-second /t timer already shows Windows' own shutdown
            # warning, and leaving the message out keeps the quoting bulletproof inside a WinRM scriptblock.
            s = ("schtasks /create /tn {tn} /tr 'shutdown /s /f /t 120' /sc daily /st {hh:02d}:{mm:02d} "
                 "/ru SYSTEM /rl HIGHEST /f").format(tn=NIGHTLY_TASK, hh=hh, mm=mm)
            return s, f"{title}: shut down every day at {hh:02d}:{mm:02d} (2-min warning; cancellable).", ""
        if action == "cancel_off":
            s = "schtasks /delete /tn {tn} /f".format(tn=NIGHTLY_TASK)
            return s, f"{title}: remove the nightly-shutdown task.", ""
        if action == "allow_mgmt":
            # The root-cause fix for a laptop on the Public firewall profile: rather than weaken the
            # firewall, add ONE scoped inbound allow for the IT-management subnet only, so WinRM/RDP/SMB
            # answer IT from that subnet on every profile. Everything else stays blocked.
            s = ("New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Action Allow -Profile Any "
                 "-RemoteAddress {net} -Protocol TCP -LocalPort 5985,5986,3389,445 -Enabled True "
                 "-ErrorAction Stop").format(name=MGMT_RULE, net=it_subnet.strip())
            return s, (f"{title}: let the IT subnet {it_subnet.strip()} reach WinRM/RDP/SMB on this PC even on "
                       "the Public profile - scoped to that subnet, reversible."), ""
        if action == "revoke_mgmt":
            s = "Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue".format(name=MGMT_RULE)
            return s, f"{title}: remove the IT-management allowance.", ""

    if tos == "Darwin":
        if action == "sleep":
            s = "sudo -n pmset -a sleep {m}; sudo -n pmset -a displaysleep {m}".format(m=mins)
            return s, f"{title}: sleep the Mac and its display after {mins} min idle.", ""
        if action == "wake_sleep_off":
            s = "sudo -n pmset -a sleep 0"
            return s, f"{title}: the Mac will not sleep on its own (display still sleeps).", ""
        if action == "schedule_off":
            hh, mm = hm
            s = "sudo -n pmset repeat shutdown MTWRFSU {hh:02d}:{mm:02d}:00".format(hh=hh, mm=mm)
            return s, f"{title}: shut down every day at {hh:02d}:{mm:02d} (macOS pmset schedule).", ""
        if action == "cancel_off":
            s = "sudo -n pmset repeat cancel"
            return s, f"{title}: cancel the macOS scheduled shutdown.", ""
        if action in ("allow_mgmt", "revoke_mgmt"):
            return "", "", ("macOS firewalls per-application, not per-port/subnet - there's no scoped-port "
                            "rule to add. Use SSH (port 22) for management instead.")

    if tos == "Linux":
        if action in ("sleep", "wake_sleep_off"):
            # Idle sleep on Linux is owned by the desktop/login manager, not a single server-side switch, so
            # rather than ship a fragile command that silently does nothing, say so and point at the reliable
            # win: a scheduled after-hours shutdown.
            return "", "", ("idle-sleep policy on Linux is managed by the desktop environment - use 'Shut down "
                            "after hours' for dependable Linux power saving.")
        if action == "schedule_off":
            hh, mm = hm
            # No wall-message in the cron line: it would need spaces inside the single-quoted printf arg and
            # break the quoting once this script is carried over SSH. The shutdown still broadcasts its own.
            line = "{mm} {hh} * * * root /sbin/shutdown -h now".format(hh=hh, mm=mm)
            s = ("printf '%s\\n' '{line}' | sudo -n tee {f} >/dev/null && sudo -n chmod 644 {f}"
                 ).format(line=line, f=_CRON_FILE)
            return s, f"{title}: cron shuts the machine down every day at {hh:02d}:{mm:02d}.", ""
        if action == "cancel_off":
            s = "sudo -n rm -f {f}".format(f=_CRON_FILE)
            return s, f"{title}: remove the nightly-shutdown cron entry.", ""
        if action == "allow_mgmt":
            net = it_subnet.strip()
            # ufw if present (friendliest), else iptables; tagged so revoke_mgmt finds exactly these rules.
            s = ("if command -v ufw >/dev/null 2>&1; then "
                 "sudo -n ufw allow from {net} to any port 22 comment '{name}'; "
                 "else sudo -n iptables -I INPUT -s {net} -p tcp --dport 22 -m comment --comment '{name}' "
                 "-j ACCEPT; fi").format(net=net, name=MGMT_RULE)
            return s, (f"{title}: allow the IT subnet {net} to reach SSH on this machine."), ""
        if action == "revoke_mgmt":
            s = ("if command -v ufw >/dev/null 2>&1; then "
                 "sudo -n ufw --force delete allow from any to any port 22 2>/dev/null; fi; "
                 "sudo -n iptables -S INPUT 2>/dev/null | grep -F -- '{name}' | sed 's/^-I/-D/;s/^-A/-D/' "
                 "| while read -r r; do sudo -n iptables $r; done").format(name=MGMT_RULE)
            return s, f"{title}: remove the IT-management SSH allowance.", ""

    return "", "", f"'{action}' isn't available for {target_os}."


def _ps_encoded(inner):
    """A PowerShell -EncodedCommand payload (base64 of UTF-16LE). Lets any script - quotes, spaces and all -
    cross to a remote Windows box through WinRM with zero shell-quoting guesswork."""
    return base64.b64encode(inner.encode("utf-16-le")).decode("ascii")


def power_policy_transport(ip, action, method, target_os, user="", idle_minutes=20, at_time="22:00",
                           it_subnet=""):
    """The exact command NetScout would run to APPLY a policy, without running it. Returns (argv, desc, err).
    method: 'winrm' (into a Windows PC), 'ssh' (into Linux/Mac), or 'local' (the machine NetScout runs on).
    Separating this out means the GUI can show the operator precisely what will happen before it happens."""
    if method not in ("winrm", "ssh", "local"):
        return None, "", f"unknown method {method!r}"
    tos = target_os or ("Windows" if method == "winrm" else OS if method == "local" else "Linux")
    script, desc, err = power_policy_script(tos, action, idle_minutes, at_time, it_subnet)
    if err:
        return None, "", err
    if method == "local":
        if OS == "Windows":
            return ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", _ps_encoded(script)], desc, ""
        return ["/bin/sh", "-c", script], desc, ""
    if method == "winrm":
        if OS != "Windows":
            return None, "", "WinRM can only be sent from a Windows PC - use SSH for a non-Windows target."
        if not re.fullmatch(r"[0-9A-Za-z.\-:]+", ip or ""):
            return None, "", "invalid address"
        inner = "Invoke-Command -ComputerName {ip} -ScriptBlock {{ {s} }}".format(ip=ip, s=script)
        return ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", _ps_encoded(inner)], desc, ""
    # ssh
    if not re.fullmatch(r"[0-9A-Za-z.\-:]+", ip or ""):
        return None, "", "invalid address"
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", user or ""):
        return None, "", "enter the user name to log in as (SSH)"
    return (["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "-o", "StrictHostKeyChecking=accept-new",
             f"{user}@{ip}", script], desc, "")


def _explain_policy_result(out, method, target_os):
    """Turn the usual apply failures into a next step."""
    low = (out or "").lower()
    if "access is denied" in low or "accessdenied" in low or "(5)" in low:
        return "Access denied - you need admin rights on that machine (and WinRM must trust this one)."
    if "cannot connect" in low or "connecting to remote server" in low or "winrm" in low:
        return "Couldn't reach it over WinRM - run 'Enable-PSRemoting' as admin on the target first."
    if "permission denied" in low:
        return "SSH login refused - set up an SSH key for that user first (ssh-copy-id)."
    if "sudo" in low and ("password" in low or "terminal" in low):
        return "Logged in, but sudo needs a password - allow passwordless sudo for the policy commands."
    if "timed out" in low or "timeout" in low or "no route" in low or "could not resolve" in low:
        return "Couldn't reach the device (is it on, and is the management channel enabled?)."
    if "already exists" in low:
        return "It's already set that way - nothing to change."
    return ""


def apply_power_policy(ip, action, method, target_os, user="", idle_minutes=20, at_time="22:00",
                       it_subnet="", dry_run=False):
    """Apply a lasting power policy to a machine you administer, over its credentialed channel.
    Returns (ok, message). With dry_run=True it changes nothing and returns the exact command instead,
    so the operator can review it first."""
    argv, desc, err = power_policy_transport(ip, action, method, target_os, user, idle_minutes, at_time,
                                             it_subnet)
    if err:
        return False, err
    if dry_run:
        return True, "WOULD RUN:\n  " + " ".join(argv) + "\n\n" + desc
    if not shutil.which(argv[0]):
        tool = argv[0]
        hint = {"ssh": "install an SSH client (Windows: Settings > Optional features > OpenSSH Client)",
                "powershell": "PowerShell ships with Windows - check you're on Windows"}.get(tool, "")
        return False, f"'{tool}' isn't available here" + (f" - {hint}." if hint else ".")
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=40, **NOWIN)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        ok = r.returncode == 0
    except subprocess.TimeoutExpired:
        return False, "No answer in time - the device may be off or blocking the management channel."
    except OSError as e:
        return False, str(e)
    # the transport argv is base64 for WinRM, so record the human-readable intent (`desc`), which is what an
    # auditor actually needs - plus the channel and target.
    audit_log(f"power policy: {action}", target=(ip or "this machine"), method=method, command=desc, ok=ok,
              detail="" if ok else (out[:200] or "failed"))
    if ok:
        where = ip if method != "local" else "this machine"
        return True, f"{where}: {desc}"
    return False, _explain_policy_result(out, method, target_os) or (out[:200] or "The policy change failed.")


def deployment_pack(it_subnet="10.0.0.0/8", at_time="22:00", idle_minutes=20):
    """Ready-to-hand-out fleet scripts so an admin can roll the power policy out to EVERY machine at once
    (via Group Policy / Intune / cron), instead of one device at a time. Pure: returns {filename: text}.
    Covers the root-cause Public-profile fix, a GPO power plan, and the after-hours shutdown."""
    hm = _parse_hhmm(at_time) or (22, 0)
    hh, mm = hm
    mins = max(1, min(int(idle_minutes or 0), 240))
    net = it_subnet.strip() if _valid_cidr(it_subnet) else "10.0.0.0/8"
    files = {}

    files["NetScout-PowerPolicy.ps1"] = f"""# NetScout fleet power policy (Windows) - run as administrator, or push via GPO/Intune.
# Idempotent: safe to run again. Everything here is reversible (see the -Undo switch).
param([switch]$Undo)
$ErrorActionPreference = 'Stop'
$task = '{NIGHTLY_TASK}'
$rule = '{MGMT_RULE}'
if ($Undo) {{
    schtasks /delete /tn $task /f 2>$null
    Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    powercfg /change standby-timeout-ac 30; powercfg /change standby-timeout-dc 15
    Write-Host 'NetScout power policy removed.'
    return
}}
# 1. Sleep when idle (display + system), on battery and plugged in.
powercfg /change monitor-timeout-ac {mins}; powercfg /change monitor-timeout-dc {mins}
powercfg /change standby-timeout-ac {mins}; powercfg /change standby-timeout-dc {mins}
# 2. After-hours shutdown every day at {hh:02d}:{mm:02d}, as SYSTEM so it works with nobody logged in.
#    The 120s /t timer shows Windows' own shutdown warning; no custom message keeps the quoting simple.
schtasks /create /tn $task /tr 'shutdown /s /f /t 120' /sc daily /st {hh:02d}:{mm:02d} /ru SYSTEM /rl HIGHEST /f
# 3. Root-cause fix: let IT reach WinRM/RDP/SMB from {net} even on the Public profile (scoped, nothing else).
if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {{
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Profile Any `
        -RemoteAddress {net} -Protocol TCP -LocalPort 5985,5986,3389,445 -Enabled True
}}
Write-Host 'NetScout power policy applied. Undo with:  NetScout-PowerPolicy.ps1 -Undo'
"""

    files["netscout-nightly-off.sh"] = f"""#!/bin/sh
# NetScout fleet power policy (Linux) - run with sudo, or drop via your config manager.
# Usage:  sudo sh netscout-nightly-off.sh         (apply)
#         sudo sh netscout-nightly-off.sh --undo  (remove)
set -e
CRON='{_CRON_FILE}'
if [ "$1" = "--undo" ]; then
    rm -f "$CRON"
    echo "NetScout nightly shutdown removed."
    exit 0
fi
printf '%s\\n' '{mm} {hh} * * * root /sbin/shutdown -h now "NetScout after-hours shutdown"' > "$CRON"
chmod 644 "$CRON"
echo "NetScout nightly shutdown installed for {hh:02d}:{mm:02d} daily."
"""

    files["ROOT-CAUSE-public-profile.md"] = f"""# Why idle laptops don't answer IT - and the fix

## The root cause
Most of the laptops are on the Windows **"Public"** network profile. On that profile Windows blocks the
inbound management channels by design - **WinRM (5985/5986), Remote Desktop (3389) and file/printer sharing
(445)**. So when IT tries to reach a machine to put it to sleep or shut it down after hours, the machine
simply doesn't answer. It's not off; it's firewalled. That's *correct* behaviour on a cafe Wi-Fi - the
problem is only that the office network is being treated as Public.

## The fix (two options - pick one)

### Option A - recommended: a scoped allow rule (reversible, narrow)
Leave the Public profile as-is and add **one** inbound allow, limited to the IT-management subnet
(`{net}`). Nothing else on the network gains anything.

```powershell
New-NetFirewallRule -DisplayName '{MGMT_RULE}' -Direction Inbound -Action Allow -Profile Any `
    -RemoteAddress {net} -Protocol TCP -LocalPort 5985,5986,3389,445 -Enabled True
```
Undo: `Remove-NetFirewallRule -DisplayName '{MGMT_RULE}'`

NetScout applies exactly this when you choose **Allow IT management** on a device, and `NetScout-PowerPolicy.ps1`
applies it fleet-wide.

### Option B: tell Windows the office network is not Public
If the office network should be trusted, set its category so the Domain/Private rules apply:
```powershell
Set-NetConnectionProfile -InterfaceAlias 'Ethernet' -NetworkCategory Private
```
On a domain, joining the domain does this automatically (the network becomes "DomainAuthenticated").

## Then: the power policy
Once IT can reach the machines, roll out sleep-when-idle + after-hours shutdown with **Group Policy**
(see `GPO-rollout.md`) or per-device from NetScout's POWER POLICY actions.
"""

    files["GPO-rollout.md"] = f"""# Rolling the power policy out with Group Policy (whole fleet at once)

## 1. The power plan (sleep when idle) - built into GPO
`Computer Configuration > Policies > Administrative Templates > System > Power Management > Sleep Settings`
- **Specify the system sleep timeout (plugged in / on battery)** -> Enabled -> {mins*60} seconds
- `...> Video and Display Settings`: **Turn off the display (plugged in / on battery)** -> {mins*60} seconds

(Equivalent to `powercfg /change standby-timeout-* {mins}` on every machine, enforced centrally.)

## 2. After-hours shutdown - a scheduled task via GPO Preferences
`Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks`
-> New -> Scheduled Task (At least Windows 7):
- Run as: `NT AUTHORITY\\SYSTEM`,  Trigger: Daily at **{hh:02d}:{mm:02d}**
- Action: `shutdown`  Arguments: `/s /f /t 120 /c "NetScout: after-hours shutdown - save your work."`

## 3. The root-cause firewall allow - a startup script via GPO
`Computer Configuration > Policies > Windows Settings > Scripts > Startup` -> add `NetScout-PowerPolicy.ps1`
(or just its firewall block). This makes the laptops reachable from the IT subnet on the Public profile.

## Or skip GPO
Hand `NetScout-PowerPolicy.ps1` to Intune / PDQ / your config manager, or run it once per machine. It does
all three steps and is reversible with `-Undo`.
"""

    files["README.txt"] = f"""NetScout power-saving deployment pack
=====================================
Generated for IT subnet {net}, idle sleep {mins} min, nightly shutdown {hh:02d}:{mm:02d}.

  ROOT-CAUSE-public-profile.md  - WHY idle machines don't answer IT, and the fix (read this first)
  GPO-rollout.md                - deploy to the whole fleet with Group Policy
  NetScout-PowerPolicy.ps1      - one Windows script: sleep + nightly-off + IT allow (reversible: -Undo)
  netscout-nightly-off.sh       - Linux equivalent (reversible: --undo)

Everything is credentialed and reversible. NetScout never powers off or changes a machine you don't
administer; the target authenticates every command.
"""
    return files


# how much a left-on machine costs, so the savings are concrete. Defaults are documented and overridable.
IDLE_WATTS = 50            # a typical desktop/laptop left on but idle (screen may be off)
DEFAULT_PRICE_KWH = 0.29   # CHF per kWh, a representative Swiss commercial rate (override per site)
AFTER_HOURS = 14           # hours/day a machine is left on outside a 9-hour working day (nights ~ weekends avg)


def power_saver_report(devs, idle_ips=None, watts=IDLE_WATTS, hours_per_day=AFTER_HOURS,
                       price_kwh=DEFAULT_PRICE_KWH, currency="CHF", days_per_year=250):
    """Estimate the power wasted by machines left on after hours, and what a policy would save. Pure.
    `idle_ips`: addresses NetScout actually found idle (optional - sharpens the list). Returns a dict with
    totals and per-device rows; power_saver_lines() renders it. Figures are clearly estimates."""
    rows = []
    for d in devs or []:
        if not power_methods(d):
            continue                      # only machines a policy could actually reach
        ip = d.get("ip", "")
        idle = None if idle_ips is None else (ip in set(idle_ips))
        if idle is False:
            continue                      # known to be in use - don't count it
        kwh_day = watts * hours_per_day / 1000.0
        rows.append({
            "ip": ip, "label": (d.get("label") or d.get("type") or "")[:40],
            "method": (power_methods(d) or ["-"])[0],
            "idle": idle,
            "kwh_year": round(kwh_day * days_per_year, 1),
            "cost_year": round(kwh_day * days_per_year * price_kwh, 2),
        })
    total_kwh = round(sum(r["kwh_year"] for r in rows), 1)
    total_cost = round(sum(r["cost_year"] for r in rows), 2)
    return {
        "rows": sorted(rows, key=lambda r: r["cost_year"], reverse=True),
        "machines": len(rows), "total_kwh_year": total_kwh, "total_cost_year": total_cost,
        "currency": currency, "watts": watts, "hours_per_day": hours_per_day,
        "price_kwh": price_kwh, "days_per_year": days_per_year,
    }


def power_saver_lines(report):
    """Readable POWER SAVER report."""
    r = report
    cur = r["currency"]
    out = ["POWER SAVER - estimated waste from machines left on after hours", "",
           f"{r['machines']} machine(s) a power policy could reach and that aren't known to be in use.",
           f"Estimated waste: {r['total_kwh_year']:.0f} kWh/year  =  {r['total_cost_year']:.0f} {cur}/year.",
           f"(assuming {r['watts']} W idle, {r['hours_per_day']} h/day after hours, "
           f"{r['days_per_year']} days/year, {r['price_kwh']:.2f} {cur}/kWh - adjust to your site)", ""]
    if r["rows"]:
        out.append(f"{'IP':<16}{'DEVICE':<34}{'VIA':<8}{'kWh/yr':>8}{'  ' + cur + '/yr':>10}")
        for row in r["rows"]:
            tag = "" if row["idle"] is None else (" (idle now)" if row["idle"] else "")
            out.append(f"{row['ip']:<16}{(row['label'] + tag)[:32]:<34}{row['method']:<8}"
                       f"{row['kwh_year']:>8.0f}{row['cost_year']:>10.0f}")
    out += ["", "Apply 'Sleep when idle' and 'Shut down after hours' from POWER POLICY to recover this,",
            "or hand out the deployment pack to set the whole fleet at once. Every change is reversible."]
    return out


# =========================================================== mDNS / Bonjour service discovery
# Devices announce what they ARE over mDNS: a printer offers _ipp, a Chromecast _googlecast, an iPhone
# _companion-link plus its exact model ("iPhone15,2") in _device-info. Asking the whole network once, at
# the start of a scan, identifies devices that every other method only guesses at - including phones with
# private (randomised) MAC addresses, whose vendor lookup comes back empty.
MDNS_GROUP = ("224.0.0.251", 5353)
MDNS_SERVICES = (
    "_device-info._tcp", "_companion-link._tcp", "_airplay._tcp", "_raop._tcp", "_mediaremotetv._tcp",
    "_googlecast._tcp", "_androidtvremote2._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_amzn-wplay._tcp",
    "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp", "_uscan._tcp",
    "_hap._tcp", "_homekit._tcp", "_matter._tcp", "_matterc._udp", "_hue._tcp", "_esphomelib._tcp",
    "_shelly._tcp", "_miio._udp", "_axis-video._tcp", "_rtsp._tcp", "_adisk._tcp", "_airport._tcp",
    "_smb._tcp", "_afpovertcp._tcp", "_workstation._tcp", "_rfb._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
    "_http._tcp", "_nvstream._tcp", "_sleep-proxy._udp", "_apple-mobdev2._tcp", "_hap._udp", "_meshcop._udp",
    "_googlezone._tcp")
SERVICE_LABELS = {
    "_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay audio", "_mediaremotetv._tcp": "Apple TV remote",
    "_googlecast._tcp": "Chromecast", "_androidtvremote2._tcp": "Android TV", "_spotify-connect._tcp": "Spotify Connect",
    "_sonos._tcp": "Sonos", "_amzn-wplay._tcp": "Amazon Alexa/Fire", "_ipp._tcp": "printing (IPP)",
    "_ipps._tcp": "printing (IPPS)", "_printer._tcp": "printing (LPD)", "_pdl-datastream._tcp": "printing (raw 9100)",
    "_scanner._tcp": "scanner", "_uscan._tcp": "scanner (eSCL)", "_hap._tcp": "HomeKit", "_homekit._tcp": "HomeKit",
    "_matter._tcp": "Matter", "_matterc._udp": "Matter (commissioning)", "_hue._tcp": "Philips Hue",
    "_esphomelib._tcp": "ESPHome", "_shelly._tcp": "Shelly", "_miio._udp": "Xiaomi Mi Home",
    "_axis-video._tcp": "Axis camera", "_rtsp._tcp": "video stream (RTSP)", "_adisk._tcp": "Time Machine disk",
    "_airport._tcp": "AirPort", "_smb._tcp": "file sharing (SMB)", "_afpovertcp._tcp": "file sharing (AFP)",
    "_workstation._tcp": "workstation", "_rfb._tcp": "screen sharing (VNC)", "_ssh._tcp": "SSH",
    "_sftp-ssh._tcp": "SFTP", "_http._tcp": "web page", "_companion-link._tcp": "Apple Continuity",
    "_device-info._tcp": "device info", "_nvstream._tcp": "NVIDIA GameStream", "_sleep-proxy._udp": "sleep proxy",
    "_apple-mobdev2._tcp": "iPhone / iPad sync", "_hap._udp": "HomeKit (Thread)", "_meshcop._udp": "Thread border router",
    "_googlezone._tcp": "Google speaker group"}
# (services, type, word, brand) - first match wins; the generic "computer" services come last and are
# only used when nothing more specific decided what the device is.
MDNS_KIND = [
    ({"_googlecast._tcp"}, "TV/Media", "Chromecast / Google TV", "Google"),
    ({"_androidtvremote2._tcp"}, "TV/Media", "Android TV", ""),
    ({"_axis-video._tcp"}, "Camera", "IP Camera", "Axis"),
    ({"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp", "_uscan._tcp"},
     "Printer", "Printer", ""),
    ({"_mediaremotetv._tcp"}, "TV/Media", "Apple TV", "Apple"),
    ({"_sonos._tcp", "_spotify-connect._tcp", "_amzn-wplay._tcp", "_raop._tcp", "_googlezone._tcp"},
     "TV/Media", "Speaker", ""),
    ({"_airplay._tcp"}, "TV/Media", "AirPlay receiver", ""),
    ({"_hap._tcp", "_hap._udp", "_homekit._tcp", "_matter._tcp", "_matterc._udp", "_hue._tcp", "_esphomelib._tcp",
      "_shelly._tcp", "_miio._udp"}, "IoT", "Smart-home device", ""),
    ({"_rtsp._tcp"}, "Camera", "IP Camera", ""),
    ({"_adisk._tcp"}, "Server", "NAS / Time Machine", ""),
    ({"_airport._tcp"}, "Network", "AirPort base station", "Apple"),
    ({"_apple-mobdev2._tcp"}, "Phone", "iPhone / iPad", "Apple"),
    ({"_meshcop._udp"}, "Network", "Thread border router", ""),
    ({"_companion-link._tcp"}, "Phone", "iPhone / iPad / Mac", "Apple"),
]
MDNS_COMPUTER = {"_smb._tcp", "_afpovertcp._tcp", "_workstation._tcp", "_rfb._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
                 "_nvstream._tcp"}
# Apple model identifiers (from _device-info "model=" / AirPlay "model=") -> what the device is
APPLE_MODELS = [(r"^iphone", "Phone", "iPhone"), (r"^ipad", "Phone", "iPad"), (r"^ipod", "Phone", "iPod"),
                (r"^macbook", "Laptop", "MacBook"), (r"^imac", "Desktop", "iMac"), (r"^macmini", "Desktop", "Mac mini"),
                (r"^macpro", "Desktop", "Mac Pro"), (r"^mac\d+,", "Desktop", "Mac"), (r"^appletv", "TV/Media", "Apple TV"),
                (r"^audioaccessory", "TV/Media", "HomePod"), (r"^watch", "Phone", "Apple Watch"),
                (r"^airport", "Network", "AirPort base station")]


def _dns_query(names, qtype=12, qid=0x4E53):
    pkt = struct.pack("!HHHHHH", qid, 0, len(names), 0, 0, 0)
    for n in names:
        for label in n.rstrip(".").split("."):
            b = label.encode()[:63]
            pkt += bytes([len(b)]) + b
        pkt += b"\x00" + struct.pack("!HH", qtype, 1)
    return pkt


def parse_dns_records(data):
    """Every resource record in a DNS / mDNS message: [(name, type, value)]. PTR -> name, A -> address,
    TXT -> [strings], SRV -> (port, target). Truncated or malformed packets yield what was readable."""
    out = []
    if len(data) < 12:
        return out
    qd, an, ns_, ar = struct.unpack("!HHHH", data[4:12])
    off = 12
    try:
        for _ in range(qd):
            off = _dns_name(data, off)[1] + 4
        for _ in range(min(an + ns_ + ar, 400)):
            name, off = _dns_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdlen]
            if rtype == 12:
                val = _dns_name(data, off)[0]
            elif rtype == 1 and rdlen == 4:
                val = socket.inet_ntoa(rd)
            elif rtype == 16:
                val, i = [], 0
                while i < len(rd):
                    n = rd[i]
                    val.append(rd[i + 1:i + 1 + n].decode("utf-8", "ignore"))
                    i += 1 + n
            elif rtype == 33 and rdlen >= 6:
                val = (struct.unpack("!H", rd[4:6])[0], _dns_name(data, off + 6)[0])
            else:
                val = rd
            out.append((name, rtype, val))
            off += rdlen
    except (IndexError, struct.error, ValueError, OSError):
        pass
    return out


_SVC_RE = re.compile(r"(_[A-Za-z0-9\-]+\._(?:tcp|udp))(?:\.|$)")


def mdns_absorb(found, src, records):
    """Fold one mDNS answer into {ip: {"services", "names", "model", "txt"}}. Answers a sleep proxy gives
    on behalf of a sleeping Mac carry that Mac's own address in an A record - those go to the Mac."""
    addrs = {v for _n, t, v in records if t == 1 and isinstance(v, str)}
    ip = next(iter(addrs)) if len(addrs) == 1 else src
    rec = found.setdefault(ip, {"services": set(), "names": set(), "model": "", "txt": {}})
    for name, rtype, val in records:
        if rtype == 12 and isinstance(val, str):
            if name.lower().startswith("_services._dns-sd."):
                m = _SVC_RE.search(val)
                if m:
                    rec["services"].add(m.group(1).lower())
                continue
            m = _SVC_RE.search(name)
            if m:
                rec["services"].add(m.group(1).lower())
                inst = val.split("." + m.group(1))[0] if ("." + m.group(1)) in val else ""
                if inst and not inst.startswith("_") and m.group(1).lower() != "_sleep-proxy._udp":
                    rec["names"].add(re.sub(r"\\(\d{3})", lambda x: chr(int(x.group(1))), inst)[:60])
        elif rtype == 33:
            m = _SVC_RE.search(name)
            if m:
                rec["services"].add(m.group(1).lower())
        elif rtype == 16 and isinstance(val, list):
            kv = {}
            for t in val:
                if "=" in t:
                    k, v = t.split("=", 1)
                    kv[k.lower()] = v.strip()
            rec["txt"].update({k: v for k, v in kv.items() if k in ("model", "md", "ty", "fn", "am", "usb_mdl",
                                                                     "usb_mfg", "manufacturer", "product")})
            for k in ("model", "am", "md", "ty", "usb_mdl", "product"):
                if kv.get(k) and not rec["model"]:
                    rec["model"] = kv[k][:60]
    return found


def mdns_browse(bind_ip=None, wait=2.5, cancel=None):
    """Ask the local network which mDNS services exist and who offers them. Uses 'legacy unicast'
    queries (sent from an ordinary port), so the answers come straight back to this socket and nothing
    has to share UDP 5353 with the operating system's own Bonjour/Avahi. Returns {ip: {...}}."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        if bind_ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
            except OSError:
                pass
        s.settimeout(0.25)
        names = ["_services._dns-sd._udp.local"] + [t + ".local" for t in MDNS_SERVICES]
        packets = [_dns_query(names[i:i + 8]) for i in range(0, len(names), 8)]
        for p in packets:
            s.sendto(p, MDNS_GROUP)
        resent, t0 = False, time.time()
        while time.time() - t0 < wait:
            if cancel is not None and cancel.is_set():
                break
            if not resent and time.time() - t0 > wait / 2:      # one repeat catches what the first lost
                for p in packets:
                    s.sendto(p, MDNS_GROUP)
                resent = True
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                continue
            mdns_absorb(found, addr[0], parse_dns_records(data))
    except OSError:
        pass
    finally:
        s.close()
    return found


def mdns_hint(rec):
    """(type, word, brand, model, weak) from a device's mDNS record, or None. weak = only generic
    computer services were seen, so it should not override a more specific identification."""
    if not rec:
        return None
    svc, model = set(rec.get("services") or ()), (rec.get("model") or "")
    m = model.lower().replace(" ", "")
    for rx, kind, word in APPLE_MODELS:
        if re.search(rx, m):
            return kind, word, "Apple", model, False
    apple_svc = svc & {"_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_afpovertcp._tcp", "_adisk._tcp"}
    for need, kind, word, brand in MDNS_KIND:
        if svc & need:
            if kind == "Printer" and rec.get("txt", {}).get("ty"):
                model = rec["txt"]["ty"]
            # a Mac is also an AirPlay receiver, and a PC running Spotify offers Spotify Connect - with
            # file sharing / SSH / screen sharing alongside, it is a computer, not a speaker
            if (kind == "TV/Media" and word in ("Speaker", "AirPlay receiver")) or word == "iPhone / iPad / Mac":
                if svc & MDNS_COMPUTER:
                    return ("Computer", "Mac", "Apple", model, False) if apple_svc else \
                        ("Computer", "Computer", "", model, False)
            return kind, word, brand, model, False
    if svc & MDNS_COMPUTER:
        return "Computer", "Computer", "", model, True
    return None


def service_list(rec):
    return sorted({SERVICE_LABELS.get(s, s.strip("_").split(".")[0]) for s in (rec or {}).get("services", ())
                   if s not in ("_device-info._tcp", "_sleep-proxy._udp")})


# =========================================================== outdated / vulnerable service versions
def _vt(*parts):
    return tuple(int(p) for p in parts)


AUDIT_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}
AUDIT_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
# TCP ports that are a finding on their own, with (severity, what, the fix)
AUDIT_PORTS = {
    23: ("CRITICAL", "Telnet (unencrypted remote control) is open", "Turn Telnet off; use SSH instead."),
    2323: ("CRITICAL", "Telnet (alt port) is open", "Turn Telnet off; use SSH instead."),
    2375: ("CRITICAL", "Docker API is exposed with no TLS", "Bind the Docker socket to localhost / enable TLS."),
    512: ("HIGH", "A Berkeley r-service (rexec) is open", "Disable rexec/rlogin/rsh; use SSH."),
    513: ("HIGH", "A Berkeley r-service (rlogin) is open", "Disable rexec/rlogin/rsh; use SSH."),
    5555: ("HIGH", "Android Debug Bridge (adb) is open", "Turn off USB/network debugging on the device."),
    5900: ("HIGH", "VNC remote desktop is open", "Require a strong VNC password, or tunnel it over SSH/VPN."),
    445: ("MEDIUM", "Windows/Samba file sharing (SMB) is reachable", "Limit SMB to trusted hosts; never expose it to the internet."),
    139: ("MEDIUM", "Legacy NetBIOS file sharing is reachable", "Disable NetBIOS over TCP/IP where it isn't needed."),
    3389: ("MEDIUM", "Windows Remote Desktop (RDP) is open", "Restrict RDP to a VPN; enable Network Level Authentication."),
    21: ("LOW", "FTP (unencrypted file transfer) is open", "Use SFTP/FTPS instead of plain FTP."),
    8291: ("MEDIUM", "MikroTik Winbox admin is reachable", "Keep Winbox off the internet; update RouterOS."),
}


# ============================================================ website / HTTP health
# Point it at a site and get the everyday "is it healthy and is it set up right?" answer: does it respond,
# how fast, what redirects does it go through, what status, is it HTTPS with a valid non-expiring
# certificate, and are the common security response-headers in place. Reuses the TLS-certificate reader
# and the shared A-F scorer. The network fetch is isolated behind one injectable function so the parsing,
# redirect-following, header analysis and scoring are all tested offline.

# (response header, severity if MISSING, what's missing, how to fix) - the headers a hardened site sets
SEC_HEADERS = [
    ("Strict-Transport-Security", "MEDIUM", "HSTS is not set - a browser can be downgraded to plain HTTP",
     "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    ("Content-Security-Policy", "LOW", "No Content-Security-Policy - weaker protection against XSS/injection",
     "Add a Content-Security-Policy suited to the site."),
    ("X-Frame-Options", "LOW", "No X-Frame-Options / frame-ancestors - clickjacking is possible",
     "Add 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive)."),
    ("X-Content-Type-Options", "LOW", "No X-Content-Type-Options - browsers may MIME-sniff responses",
     "Add 'X-Content-Type-Options: nosniff'."),
    ("Referrer-Policy", "INFO", "No Referrer-Policy - full URLs may leak in the Referer header",
     "Add e.g. 'Referrer-Policy: strict-origin-when-cross-origin'."),
]
_REDIRECT_CODES = {301, 302, 303, 307, 308}


def parse_target_url(text):
    """Normalise a user-typed target into {scheme, host, port, path, url}. A bare host defaults to HTTPS.
    Raises ValueError on anything unusable."""
    t = (text or "").strip()
    if not t:
        raise ValueError("Enter a website, e.g. example.com or https://example.com/status")
    if "://" not in t:
        t = "https://" + t
    u = urllib.parse.urlparse(t)
    if u.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{u.scheme}' - use http or https.")
    if not u.hostname:
        raise ValueError("Could not read a hostname from that.")
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    return {"scheme": u.scheme, "host": u.hostname, "port": port, "path": path, "url": t}


def security_header_report(headers, https=True):
    """Which hardening headers are present/missing. headers: a dict (case-insensitive). On plain HTTP, HSTS
    is not counted as missing (it only applies to HTTPS). Returns [{header, present, severity, note, fix}]."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    out = []
    for name, sev, note, fix in SEC_HEADERS:
        if name == "Strict-Transport-Security" and not https:
            continue
        out.append({"header": name, "present": name.lower() in h, "severity": sev, "note": note, "fix": fix})
    return out


def _http_probe(scheme, host, port, path, timeout=6.0):
    """One HTTP(S) GET. Returns (status, headers_dict, body_snippet, error). TLS is not verified here (the
    certificate is inspected separately by tls_cert), so an expired/self-signed cert still lets us read the
    response instead of failing the whole check."""
    c = None
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            c = http.client.HTTPConnection(host, port, timeout=timeout)
        c.request("GET", path or "/", headers={"User-Agent": "NetScout/health", "Connection": "close",
                                               "Accept": "*/*"})
        r = c.getresponse()
        headers = {k: v for k, v in r.getheaders()}
        body = r.read(8192).decode("utf-8", "ignore")
        return r.status, headers, body, ""
    except Exception as e:
        return None, {}, "", f"{type(e).__name__}: {e}"
    finally:
        try:
            if c:
                c.close()
        except Exception:
            pass


def web_check(url, timeout=6.0, max_redirects=5, probe=None):
    """Fetch a site (following redirects), inspect its certificate and security headers, and score it A-F.
    Returns {input, final_url, scheme, status, ok, ms, chain, server, title, cert, sec, findings, + grade}.
    The `probe` is injectable for testing."""
    t = parse_target_url(url)
    probe = probe or _http_probe
    findings, chain, seen = [], [], set()

    def add(sev, title, detail, fix):
        findings.append({"severity": sev, "title": title, "detail": detail, "fix": fix, "where": t["host"]})

    cur = (t["scheme"], t["host"], t["port"], t["path"])
    status, headers, body, err, hops = None, {}, "", "", 0
    t0 = time.time()
    while True:
        s, hdrs, body, e = probe(*cur, timeout=timeout)
        disp = f"{cur[0]}://{cur[1]}" + ("" if cur[2] in (80, 443) else f":{cur[2]}") + cur[3]
        if e:
            err = e
            chain.append((None, disp))
            break
        status, headers = s, hdrs
        chain.append((s, disp))
        loc = {k.lower(): v for k, v in hdrs.items()}.get("location")
        if s in _REDIRECT_CODES and loc and hops < max_redirects:
            nu = urllib.parse.urlparse(urllib.parse.urljoin(disp, loc))
            key = (nu.scheme, nu.hostname or cur[1], nu.port or (443 if nu.scheme == "https" else 80),
                   (nu.path or "/") + (("?" + nu.query) if nu.query else ""))
            if nu.scheme not in ("http", "https") or key in seen:
                break
            seen.add(key)
            cur, hops = key, hops + 1
            continue
        break
    ms = round((time.time() - t0) * 1000, 1)
    final_scheme, final_host, final_port, final_path = cur
    final_url = chain[-1][1] if chain else t["url"]

    # certificate (final hop, if HTTPS)
    cert = {}
    if final_scheme == "https" and not err:
        cert = tls_cert(final_host, final_port)
        for w in cert_warnings(cert):
            wl = w.lower()
            sev = "HIGH" if "expired" in wl else "MEDIUM" if ("expires" in wl or "obsolete" in wl) else "LOW"
            add(sev, "TLS certificate / protocol problem", f"{final_host}:{final_port} - {w}",
                "Renew/replace the certificate and disable obsolete TLS versions.")

    # status / reachability
    if err:
        add("HIGH", "Site did not respond", f"{t['host']}: {err}",
            "Check the host is up and reachable on that port from here.")
    elif status and status >= 500:
        add("HIGH", f"Server error (HTTP {status})", f"{final_url} returned {status}.",
            "Check the application/server logs.")
    elif status and 400 <= status < 500:
        add("MEDIUM", f"Client error (HTTP {status})", f"{final_url} returned {status}.",
            "Confirm the path and that the resource exists / is reachable without auth.")

    # plain HTTP on the final hop
    if not err and final_scheme == "http":
        add("MEDIUM", "Served over plain HTTP", f"{final_url} is not encrypted.",
            "Serve the site over HTTPS and redirect HTTP to HTTPS.")

    # security headers (only meaningful when we actually got a response)
    sec = security_header_report(headers, https=(final_scheme == "https")) if not err else []
    for item in sec:
        if not item["present"]:
            add(item["severity"], f"Missing header: {item['header']}", item["note"], item["fix"])

    low = {k.lower(): v for k, v in (headers or {}).items()}
    server = (low.get("server") or "").strip()[:60]
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""

    g = grade_findings(findings)
    res = {"input": t["url"], "final_url": final_url, "scheme": final_scheme, "status": status,
           "ok": bool(status and status < 400), "ms": ms, "chain": chain, "server": server, "title": title,
           "cert": cert, "sec": sec, "error": err, "redirects": max(0, len(chain) - 1), **g}
    return res


def web_lines(result):
    """Report-ready rendering of a web_check()."""
    r = result
    icon = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[-]", "INFO": "[i]"}
    head = f"WEBSITE HEALTH  {r['input']}   GRADE {r['grade']}  ({r['score']}/100)"
    out = [head, ""]
    if r["error"]:
        out += [f"  UNREACHABLE: {r['error']}", "", "  FINDINGS:"]
        for f in r["findings"]:
            out.append(f"    {icon.get(f['severity'], '[-]')} {f['title']} - {f['detail']}")
            if f.get("fix"):
                out.append(f"        FIX: {f['fix']}")
        return out
    out.append(f"  Status          : HTTP {r['status']}" + ("  (OK)" if r["ok"] else ""))
    out.append(f"  Final URL       : {r['final_url']}")
    if r["redirects"]:
        out.append("  Redirects       : " + "  ->  ".join(f"{s or '!'} {u}" for s, u in r["chain"]))
    out.append(f"  Response time   : {r['ms']} ms")
    if r["server"]:
        out.append(f"  Server          : {r['server']}")
    if r["title"]:
        out.append(f"  Title           : {r['title']}")
    if r["cert"]:
        c = r["cert"]
        left = c.get("days_left")
        when = ("EXPIRED" if left is not None and left < 0 else f"{left} days left" if left is not None
                else c.get("expires", "?"))
        out.append(f"  Certificate     : CN={c.get('subject') or '?'}  issuer={c.get('issuer') or '?'}  ({when})")
    if r["sec"]:
        present = [s["header"] for s in r["sec"] if s["present"]]
        missing = [s["header"] for s in r["sec"] if not s["present"]]
        out.append(f"  Security headers: {len(present)}/{len(r['sec'])} present"
                   + (f"  (missing: {', '.join(missing)})" if missing else ""))
    out.append("")
    if r["findings"]:
        out.append("  FINDINGS:")
        for f in r["findings"]:
            out.append(f"    {icon.get(f['severity'], '[-]')} {f['title']} - {f['detail']}")
            if f.get("fix"):
                out.append(f"        FIX: {f['fix']}")
    else:
        out.append("  No issues found - responds cleanly, HTTPS with a healthy certificate and the common "
                   "security headers in place.")
    out += ["", "Checks only what an ordinary web request reveals - it does not attack the site. Check sites "
            "you own or are authorised to assess."]
    return out


# ============================================================ DNS toolkit
# A small unicast DNS client (stdlib UDP) for the everyday "what does DNS say?" questions: forward and
# reverse lookups and the common record types, against the system resolver or one you name, with the
# response time and status. The wire-format builder and the answer parser are pure and fully tested
# offline; only the send itself touches the network.

DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
             "SRV": 33, "CAA": 257}
DNS_TYPE_NAMES = {v: k for k, v in DNS_TYPES.items()}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN (no such name)", 4: "NOTIMP",
              5: "REFUSED"}


def _default_resolver():
    """The system's first configured DNS server, falling back to Cloudflare's 1.1.1.1."""
    try:
        dns = (net_info() or {}).get("dns") or ""
        for part in re.split(r"[,\s]+", dns):
            if part.strip():
                return part.strip()
    except Exception:
        pass
    try:
        m = re.search(rf"^nameserver\s+({IPV4})", open("/etc/resolv.conf").read(), re.M)
        if m:
            return m.group(1)
    except OSError:
        pass
    return "1.1.1.1"


def reverse_name(ip):
    """IP -> reverse-DNS name (x.x.x.x.in-addr.arpa / nibble.ip6.arpa). A non-IP is returned unchanged."""
    try:
        return ipaddress.ip_address(ip.strip()).reverse_pointer
    except ValueError:
        return ip


def _dns_build(name, qtype, qid):
    """A standard recursive (RD=1) DNS query packet for one name/type."""
    pkt = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        b = label.encode("utf-8")[:63]
        pkt += bytes([len(b)]) + b
    return pkt + b"\x00" + struct.pack("!HH", qtype, 1)


def _dns_parse_answers(data):
    """Every resource record in a DNS reply as (name, TYPE_STR, value_str, ttl), decoding A, AAAA, NS,
    CNAME, PTR, MX, TXT and SOA into readable values (anything else -> hex). Compression-pointer aware;
    a truncated/malformed packet yields whatever was readable."""
    out = []
    if len(data) < 12:
        return out
    qd, an, ns_, ar = struct.unpack("!HHHH", data[4:12])
    off = 12
    try:
        for _ in range(qd):
            off = _dns_name(data, off)[1] + 4
        for _ in range(min(an + ns_ + ar, 300)):
            name, off = _dns_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                val = socket.inet_ntoa(rd)
            elif rtype == 28 and rdlen == 16:
                val = socket.inet_ntop(socket.AF_INET6, rd)
            elif rtype in (2, 5, 12):
                val = _dns_name(data, off)[0]
            elif rtype == 15 and rdlen >= 3:
                val = f"{struct.unpack('!H', rd[:2])[0]} {_dns_name(data, off + 2)[0]}"
            elif rtype == 16:
                parts, i = [], 0
                while i < len(rd):
                    n = rd[i]
                    parts.append(rd[i + 1:i + 1 + n].decode("utf-8", "ignore"))
                    i += 1 + n
                val = " ".join(parts)
            elif rtype == 6:
                mname, o2 = _dns_name(data, off)
                rname, _o3 = _dns_name(data, o2)
                val = f"{mname} {rname}"
            else:
                val = rd.hex()
            out.append((name, DNS_TYPE_NAMES.get(rtype, str(rtype)), val, ttl))
            off += rdlen
    except (IndexError, struct.error, ValueError, OSError):
        pass
    return out


def dns_query(name, rtype="A", server=None, timeout=3.0):
    """Send ONE UDP DNS query and return (records, meta). records: [(name, TYPE, value, ttl)].
    meta: {server, rtype, name, ms, rcode, rcode_name, answers, truncated, error}. PTR with an IP name is
    turned into the correct reverse name automatically."""
    rtype = (rtype or "A").upper()
    qt = DNS_TYPES.get(rtype, 1)
    server = server or _default_resolver()
    qname = reverse_name(name.strip()) if rtype == "PTR" else name.strip().rstrip(".")
    meta = {"server": server, "rtype": rtype, "name": qname, "ms": None, "rcode": None,
            "rcode_name": "", "answers": 0, "truncated": False, "error": ""}
    if not qname:
        meta["error"] = "Enter a hostname (or an IP for a PTR / reverse lookup)."
        return [], meta
    pkt = _dns_build(qname, qt, random.randint(0, 0xFFFF))
    t0 = time.time()
    try:
        fam = socket.AF_INET6 if ":" in server else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(pkt, (server, 53))
            data, _ = s.recvfrom(8192)
        finally:
            s.close()
    except OSError as e:
        meta["error"] = f"No response from {server}: {e}"
        return [], meta
    meta["ms"] = round((time.time() - t0) * 1000, 1)
    if len(data) < 12:
        meta["error"] = "Short/!invalid DNS reply."
        return [], meta
    flags = struct.unpack("!H", data[2:4])[0]
    meta["rcode"] = flags & 0x0F
    meta["rcode_name"] = DNS_RCODES.get(meta["rcode"], f"rcode {meta['rcode']}")
    meta["truncated"] = bool(flags & 0x0200)
    recs = _dns_parse_answers(data)
    # answers only (exclude the echoed question); the parser already skips the question section
    meta["answers"] = len(recs)
    return recs, meta


def dns_lookup(name, server=None, timeout=3.0):
    """Convenience: for an IP, do a reverse (PTR) lookup; otherwise query the common record types.
    Returns {"reverse": bool, "server":..., "blocks":[(rtype, records, meta)...]}."""
    name = (name or "").strip()
    try:
        ipaddress.ip_address(name)
        is_ip = True
    except ValueError:
        is_ip = False
    server = server or _default_resolver()
    if is_ip:
        recs, meta = dns_query(name, "PTR", server, timeout)
        return {"reverse": True, "server": server, "blocks": [("PTR", recs, meta)]}
    blocks = []
    for rt in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
        recs, meta = dns_query(name, rt, server, timeout)
        blocks.append((rt, recs, meta))
        if meta["error"]:          # resolver unreachable - stop hammering it
            break
    return {"reverse": False, "server": server, "blocks": blocks}


def dns_lines(result):
    """Report-ready rendering of a dns_lookup()."""
    out = [f"DNS  {'reverse lookup' if result['reverse'] else 'lookup'}  via {result['server']}", ""]
    any_err = ""
    for rtype, recs, meta in result["blocks"]:
        if meta["error"]:
            any_err = meta["error"]
            continue
        ms = f"  ({meta['ms']} ms)" if meta.get("ms") is not None else ""
        status = "" if meta["rcode"] == 0 else f"  [{meta['rcode_name']}]"
        if recs:
            out.append(f"{rtype}{ms}{status}")
            for name, t, val, ttl in recs:
                out.append(f"  {t:<6} {val}   (ttl {ttl}s)")
        elif meta["rcode"] not in (0, None):
            out.append(f"{rtype}{ms}: {meta['rcode_name']}")
        else:
            out.append(f"{rtype}{ms}: no records")
    if any_err and not any(recs for _r, recs, _m in result["blocks"]):
        out.append("")
        out.append(any_err + "  (is the resolver reachable from this machine?)")
    return out


# ============================================================ subnet calculator
# Pure IPv4/IPv6 subnet mathematics on the stdlib `ipaddress` module - the everyday network-engineer
# utility. Given a CIDR, an IP + mask, or a bare address it works out the network, broadcast, usable host
# range, host count, netmask/wildcard and the address's scope; it can also split a block into equal subnets
# and test whether an address falls inside one. No network access - deterministic and fully testable.

def _normalize_cidr(text):
    """Accept '10.0.0.0/24', '10.0.0.0/255.255.255.0', '10.0.0.0 255.255.255.0' and bare addresses (IPv4 or
    IPv6), returning a string ip_network(strict=False) understands. Raises ValueError on empty input."""
    t = " ".join((text or "").split()).strip()
    if not t:
        raise ValueError("Enter an address, e.g. 192.168.1.0/24, 10.0.0.5, or 172.16.0.0 255.255.0.0")
    if " " in t:                       # "IP MASK" -> "IP/MASK"
        ip, mask = t.split(" ", 1)
        t = f"{ip.strip()}/{mask.strip()}"
    return t


def subnet_info(text):
    """Full facts about a subnet or address as a dict. Raises ValueError on bad input."""
    t = _normalize_cidr(text)
    net = ipaddress.ip_network(t, strict=False)        # strict=False: a host IP carrying a prefix is fine
    try:
        typed = ipaddress.ip_address(t.split("/", 1)[0])
    except ValueError:
        typed = None
    v, num = net.version, net.num_addresses
    info = {"input": (text or "").strip(), "version": v, "cidr": str(net), "network": str(net.network_address),
            "prefix": net.prefixlen, "netmask": str(net.netmask), "wildcard": str(net.hostmask),
            "num_addresses": num, "address": str(typed) if typed is not None else "",
            "is_private": net.is_private, "is_global": net.is_global, "is_multicast": net.is_multicast,
            "is_loopback": net.is_loopback, "is_link_local": net.is_link_local, "is_reserved": net.is_reserved}
    if v == 4:
        info["broadcast"] = str(net.broadcast_address)
        if net.prefixlen == 32:
            info.update(first_host=str(net.network_address), last_host=str(net.network_address), usable=1)
        elif net.prefixlen == 31:                       # RFC 3021 point-to-point: both addresses usable
            hs = list(net)
            info.update(first_host=str(hs[0]), last_host=str(hs[1]), usable=2)
        else:
            info.update(first_host=str(net.network_address + 1), last_host=str(net.broadcast_address - 1),
                        usable=num - 2)
    else:
        info["broadcast"] = ""
        if net.prefixlen == 128:
            info.update(first_host=str(net.network_address), last_host=str(net.network_address), usable=1)
        else:
            info.update(first_host=str(net.network_address + 1), last_host=str(net.network_address + (num - 1)),
                        usable=num - 1)
    return info


def subnet_split(text, new_prefix):
    """Split a block into equal subnets of prefix `new_prefix`. Returns (list_of_cidr_strings, note). The
    list is capped so an enormous split can't blow up; the note states the true total."""
    net = ipaddress.ip_network(_normalize_cidr(text), strict=False)
    new_prefix = int(new_prefix)
    if new_prefix < net.prefixlen:
        raise ValueError(f"/{new_prefix} is larger than the /{net.prefixlen} you're splitting - choose a bigger number.")
    if new_prefix > net.max_prefixlen:
        raise ValueError(f"/{new_prefix} is not valid for IPv{net.version} (max /{net.max_prefixlen}).")
    total = 2 ** (new_prefix - net.prefixlen)
    cap, subs = 1024, []
    for i, s in enumerate(net.subnets(new_prefix=new_prefix)):
        if i >= cap:
            break
        subs.append(str(s))
    note = f"{total:,} subnet(s) of /{new_prefix}" + (f" (showing the first {cap:,})" if total > cap else "")
    return subs, note


def ip_in_subnet(ip, text):
    """True if `ip` is inside the given subnet. Raises ValueError on bad input."""
    net = ipaddress.ip_network(_normalize_cidr(text), strict=False)
    return ipaddress.ip_address((ip or "").strip()) in net


def subnet_lines(info):
    """Report-ready rendering of subnet_info()."""
    scope = next((lbl for key, lbl in (("is_loopback", "loopback"), ("is_link_local", "link-local"),
                  ("is_multicast", "multicast"), ("is_private", "private"), ("is_reserved", "reserved"))
                  if info.get(key)), "global / public")
    out = [f"SUBNET  {info['cidr']}   (IPv{info['version']}, {scope})", ""]
    if info.get("address") and info["address"] != info["network"]:
        out.append(f"  Address entered : {info['address']}")
    out += [f"  Network         : {info['network']}/{info['prefix']}",
            f"  Netmask         : {info['netmask']}"]
    if info["version"] == 4:
        out += [f"  Wildcard        : {info['wildcard']}", f"  Broadcast       : {info['broadcast']}"]
    out += [f"  Host range      : {info['first_host']}  ->  {info['last_host']}",
            f"  Usable hosts    : {info['usable']:,}",
            f"  Total addresses : {info['num_addresses']:,}"]
    return out


# ============================================================ full branded HTML report
# One shareable, self-contained HTML security report carrying the NetScout brand (the reaper mascot and
# wordmark, the red/black identity). It stitches together the Security Audit, the Server Scan and the
# Vulnerability Scan into an executive summary + detailed sections, with an overall A-F grade. Pure: it
# takes already-gathered scan data and returns an HTML string (no network), so it is fully testable. Every
# piece of scanned text (hostnames, banners, SSIDs) is HTML-escaped, so a hostile banner cannot inject
# markup into the page. It also prints beautifully to PDF from any browser (Ctrl/Cmd-P -> Save as PDF).

REAPER_SVG = '<svg role="img" aria-label="Grim reaper mascot with a scythe" viewBox="0 0 420 580">\n<defs>\n<radialGradient id="eyeR" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#FFD2D8"></stop><stop offset="42%" stop-color="#FF3A52"></stop><stop offset="100%" stop-color="#360610"></stop></radialGradient>\n<linearGradient id="bladeR" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#F4F5F9"></stop><stop offset="55%" stop-color="#AFB3BE"></stop><stop offset="100%" stop-color="#5E626E"></stop></linearGradient>\n<linearGradient id="robeR" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#282B34"></stop><stop offset="46%" stop-color="#15171D"></stop><stop offset="100%" stop-color="#090A0E"></stop></linearGradient>\n</defs>\n<ellipse cx="210" cy="556" rx="152" ry="16" fill="#000000" opacity="0.5"></ellipse>\n<ellipse cx="182" cy="548" rx="84" ry="12" fill="#E01E37" opacity="0.07"></ellipse>\n<ellipse cx="252" cy="552" rx="92" ry="12" fill="#E01E37" opacity="0.05"></ellipse>\n<path d="M128 196 C96 226 94 300 80 360 C68 414 58 476 50 548 L70 512 L88 550 L112 512 L134 552 L158 514 L182 550 L206 510 L230 552 L254 514 L278 550 L300 512 L322 552 L344 514 L362 548 C356 476 350 414 340 360 C326 300 324 226 292 196 C252 250 168 250 128 196 Z" fill="url(#robeR)" stroke="#05070B" stroke-width="3.5"></path>\n<g fill="none" stroke="#0A0B0F" stroke-width="3" opacity="0.7" stroke-linecap="round">\n<path d="M150 232 C148 320 150 430 156 520"></path>\n<path d="M210 250 C210 340 208 450 210 540"></path>\n<path d="M272 232 C274 320 272 430 266 520"></path>\n</g>\n<path d="M210 214 C198 300 198 420 205 540 L215 540 C222 420 222 300 210 214 Z" fill="#05060A" opacity="0.55"></path>\n<path d="M210 60 C162 60 126 100 124 154 C123 184 108 200 120 218 C150 200 180 214 210 214 C240 214 270 200 300 218 C312 200 297 184 296 154 C294 100 258 60 210 60 Z" fill="url(#robeR)" stroke="#05070B" stroke-width="3.5"></path>\n<path d="M210 86 C174 86 150 114 150 156 L160 158 C162 122 182 100 210 100 C238 100 258 122 260 158 L270 156 C270 114 246 86 210 86 Z" fill="#05060A"></path>\n<path d="M210 92 C178 92 156 118 156 156 C156 196 182 224 210 224 C238 224 264 196 264 156 C264 118 242 92 210 92 Z" fill="#030406"></path>\n<g>\n<path d="M210 102 C180 102 160 128 162 160 C163 180 172 196 186 205 L234 205 C248 196 257 180 258 160 C260 128 240 102 210 102 Z" fill="#E9EAEE"></path>\n<path d="M234 205 C248 196 257 180 258 160 C259 144 254 130 246 120 C250 142 247 174 230 196 Z" fill="#BCBFC7"></path>\n<path d="M186 205 C172 196 163 180 162 160 C161 146 165 132 173 122 C170 144 173 176 190 198 Z" fill="#FFFFFF" opacity="0.5"></path>\n<g stroke="#8A8E98" stroke-width="1.5" fill="none" stroke-linecap="round" opacity="0.8"><path d="M198 118 l6 10 l-4 8"></path><path d="M225 122 l-5 9"></path></g>\n<path d="M172 150 C183 141 197 141 206 148" fill="none" stroke="#C7CAD0" stroke-width="3"></path>\n<path d="M214 148 C223 141 237 141 248 150" fill="none" stroke="#C7CAD0" stroke-width="3"></path>\n<path d="M174 150 C174 137 184 131 192 134 C201 137 205 147 203 160 C201 174 193 183 183 181 C175 179 174 163 174 150 Z" fill="#030406"></path>\n<path d="M246 150 C246 137 236 131 228 134 C219 137 215 147 217 160 C219 174 227 183 237 181 C245 179 246 163 246 150 Z" fill="#030406"></path>\n<circle cx="189" cy="157" r="13" fill="#E01E37" opacity="0.30"></circle>\n<circle cx="231" cy="157" r="13" fill="#E01E37" opacity="0.30"></circle>\n<circle cx="189" cy="157" r="6.5" fill="url(#eyeR)"></circle>\n<circle cx="231" cy="157" r="6.5" fill="url(#eyeR)"></circle>\n<path d="M210 162 C205 174 197 182 201 192 C205 187 208 187 210 191 C212 187 215 187 219 192 C223 182 215 174 210 162 Z" fill="#030406"></path>\n<path d="M176 186 C182 192 190 194 196 192" fill="none" stroke="#AEB1B9" stroke-width="2" opacity="0.55"></path>\n<path d="M244 186 C238 192 230 194 224 192" fill="none" stroke="#AEB1B9" stroke-width="2" opacity="0.55"></path>\n<path d="M184 198 L236 198 L232 212 L188 212 Z" fill="#E9EAEE" stroke="#05070B" stroke-width="1.4"></path>\n<g stroke="#05070B" stroke-width="1.5"><line x1="195" y1="198" x2="194" y2="212"></line><line x1="206" y1="198" x2="206" y2="212"></line><line x1="217" y1="198" x2="218" y2="212"></line><line x1="226" y1="198" x2="227" y2="211"></line></g>\n<path d="M190 212 C189 226 198 236 210 236 C222 236 231 226 230 212 L224 213 L220 224 L210 226 L200 224 L196 213 Z" fill="#DADCE2" stroke="#05070B" stroke-width="1.4"></path>\n</g>\n<path d="M140 244 C118 268 108 302 116 334 C120 348 132 352 144 344 C134 314 138 282 156 260 Z" fill="url(#robeR)" stroke="#05070B" stroke-width="3"></path>\n<g id="rp-lhand">\n<path d="M129.6 333.2 L118.0 359.2" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<path d="M134.4 334.8 L122.0 360.8" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L121.1 364.0" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<path d="M121.1 364.0 Q121.6 374.4 122.0 384.8" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M122.0 384.8 L122.5 404.0" stroke="#05070B" stroke-width="7" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L118.2 364.0" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<path d="M118.2 364.0 Q117.4 376.0 116.8 387.9" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M116.8 387.9 L116.0 410.0" stroke="#05070B" stroke-width="7" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L115.0 364.0" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<path d="M115.0 364.0 Q112.8 375.4 111.2 386.9" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M111.2 386.9 L109.0 408.0" stroke="#05070B" stroke-width="7" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L111.9 364.0" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<path d="M111.9 364.0 Q108.3 373.9 105.6 383.8" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M105.6 383.8 L102.0 402.0" stroke="#05070B" stroke-width="7" stroke-linecap="round" fill="none"/>\n<path d="M118.0 358.0 Q108.0 356.0 100.0 362.0" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<ellipse cx="120.0" cy="360.0" rx="7.5" ry="7.5" fill="#05070B"/>\n<path d="M129.6 333.2 L118.0 359.2" stroke="#D7D9DF" stroke-width="5.2" stroke-linecap="round" fill="none"/>\n<path d="M134.4 334.8 L122.0 360.8" stroke="#D7D9DF" stroke-width="5.2" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L121.1 364.0" stroke="#E2E3E8" stroke-width="5.0" stroke-linecap="round" fill="none"/>\n<path d="M121.1 364.0 Q121.6 374.4 122.0 384.8" stroke="#E2E3E8" stroke-width="4.8" stroke-linecap="round" fill="none"/>\n<path d="M122.0 384.8 L122.5 404.0" stroke="#E2E3E8" stroke-width="4.0" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L118.2 364.0" stroke="#E2E3E8" stroke-width="5.0" stroke-linecap="round" fill="none"/>\n<path d="M118.2 364.0 Q117.4 376.0 116.8 387.9" stroke="#E2E3E8" stroke-width="4.8" stroke-linecap="round" fill="none"/>\n<path d="M116.8 387.9 L116.0 410.0" stroke="#E2E3E8" stroke-width="4.0" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L115.0 364.0" stroke="#E2E3E8" stroke-width="5.0" stroke-linecap="round" fill="none"/>\n<path d="M115.0 364.0 Q112.8 375.4 111.2 386.9" stroke="#E2E3E8" stroke-width="4.8" stroke-linecap="round" fill="none"/>\n<path d="M111.2 386.9 L109.0 408.0" stroke="#E2E3E8" stroke-width="4.0" stroke-linecap="round" fill="none"/>\n<path d="M120.0 360.0 L111.9 364.0" stroke="#E2E3E8" stroke-width="5.0" stroke-linecap="round" fill="none"/>\n<path d="M111.9 364.0 Q108.3 373.9 105.6 383.8" stroke="#E2E3E8" stroke-width="4.8" stroke-linecap="round" fill="none"/>\n<path d="M105.6 383.8 L102.0 402.0" stroke="#E2E3E8" stroke-width="4.0" stroke-linecap="round" fill="none"/>\n<path d="M118.0 358.0 Q108.0 356.0 100.0 362.0" stroke="#E2E3E8" stroke-width="5.0" stroke-linecap="round" fill="none"/>\n<ellipse cx="120.0" cy="360.0" rx="5.5" ry="5.5" fill="#CFD1D8"/>\n<circle cx="121.1" cy="364.0" r="3.1" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="122.0" cy="384.8" r="2.6" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="118.2" cy="364.0" r="3.1" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="116.8" cy="387.9" r="2.6" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="115.0" cy="364.0" r="3.1" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="111.2" cy="386.9" r="2.6" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="111.9" cy="364.0" r="3.1" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="105.6" cy="383.8" r="2.6" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n<circle cx="108.0" cy="356.0" r="2.8" fill="#CFD1D8" stroke="#05070B" stroke-width="1.1"/>\n</g><!--/rp-lhand-->\n<path d="M280 244 C302 268 314 302 306 334 C302 350 290 356 278 348 C286 316 282 282 264 260 Z" fill="url(#robeR)" stroke="#05070B" stroke-width="3"/>\n<path d="M306 334 C302 350 290 356 278 348" fill="none" stroke="#2C3039" stroke-width="2"/>\n<g style="transform-box: fill-box; transform-origin: 74% 82%; transform: rotate(3deg)">\n<path d="M248 356 C300 262 332 152 350 72" fill="none" stroke="#0C0D11" stroke-width="15" stroke-linecap="round"></path>\n<path d="M248 356 C300 262 332 152 350 72" fill="none" stroke="#585C68" stroke-width="7" stroke-linecap="round"></path>\n<path d="M248 356 C300 262 332 152 350 72" fill="none" stroke="#8C909A" stroke-width="2" stroke-linecap="round" opacity="0.7"></path>\n<g stroke="#0A0B0F" stroke-width="11" stroke-linecap="round"><path d="M256 340 l12 -6"></path><path d="M270 310 l12 -6"></path><path d="M284 280 l11 -6"></path></g>\n<path d="M350 72 C300 30 224 24 172 64 C212 48 272 48 322 78 C300 66 258 66 230 82 C282 70 334 86 360 116 C372 100 364 82 350 72 Z" fill="url(#bladeR)" stroke="#05070B" stroke-width="3"></path>\n<path d="M172 64 C212 48 272 48 322 78" fill="none" stroke="#FBFBFE" stroke-width="2.5"></path>\n<path d="M232 50 l11 5" stroke="#FF5A6E" stroke-width="3" stroke-linecap="round" opacity="0.9"></path>\n</g>\n<g id="rp-hand">\n<path d="M289.4 340.8 L277.7 347.1" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M292.6 347.2 L280.3 352.9" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M276.5 350.5 L265.5 346.6" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M265.5 346.6 Q253.7 345.8 248.0 338.0" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M248.0 338.0 L249.1 343.2" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M276.5 350.5 L270.4 337.1" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M270.4 337.1 Q258.6 336.3 252.0 328.1" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M252.0 328.1 L252.9 333.7" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M276.5 350.5 L275.2 327.6" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M275.2 327.6 Q263.3 326.8 256.3 318.3" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M256.3 318.3 L257.1 324.2" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M276.5 350.5 L279.8 317.9" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M279.8 317.9 Q267.9 317.1 261.4 308.9" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M261.4 308.9 L262.3 314.5" stroke="#05070B" stroke-width="8" stroke-linecap="round" fill="none"/>\n<path d="M274.5 340.5 L281.7 324.1" stroke="#05070B" stroke-width="9.5" stroke-linecap="round" fill="none"/>\n<path d="M281.7 324.1 L278.2 302.3" stroke="#05070B" stroke-width="8.5" stroke-linecap="round" fill="none"/>\n<ellipse cx="276.5" cy="350.5" rx="8" ry="8.5" fill="#05070B"/>\n<path d="M289.4 340.8 L277.7 347.1" stroke="#D7D9DF" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M292.6 347.2 L280.3 352.9" stroke="#D7D9DF" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<ellipse cx="276.5" cy="350.5" rx="6" ry="6.5" fill="#CFD1D8"/>\n<path d="M276.5 350.5 L265.5 346.6" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M248.0 338.0 L249.1 343.2" stroke="#A9ADB6" stroke-width="4.6" stroke-linecap="round" fill="none"/>\n<path d="M265.5 346.6 Q253.7 345.8 248.0 338.0" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M276.5 350.5 L270.4 337.1" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M252.0 328.1 L252.9 333.7" stroke="#A9ADB6" stroke-width="4.6" stroke-linecap="round" fill="none"/>\n<path d="M270.4 337.1 Q258.6 336.3 252.0 328.1" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M276.5 350.5 L275.2 327.6" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M256.3 318.3 L257.1 324.2" stroke="#A9ADB6" stroke-width="4.6" stroke-linecap="round" fill="none"/>\n<path d="M275.2 327.6 Q263.3 326.8 256.3 318.3" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M276.5 350.5 L279.8 317.9" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M261.4 308.9 L262.3 314.5" stroke="#A9ADB6" stroke-width="4.6" stroke-linecap="round" fill="none"/>\n<path d="M279.8 317.9 Q267.9 317.1 261.4 308.9" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M274.5 340.5 L281.7 324.1" stroke="#E2E3E8" stroke-width="5.6" stroke-linecap="round" fill="none"/>\n<path d="M281.7 324.1 L278.2 302.3" stroke="#E2E3E8" stroke-width="4.8" stroke-linecap="round" fill="none"/>\n<circle cx="265.5" cy="346.6" r="3.4" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="248.0" cy="338.0" r="3.0" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="270.4" cy="337.1" r="3.4" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="252.0" cy="328.1" r="3.0" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="275.2" cy="327.6" r="3.4" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="256.3" cy="318.3" r="3.0" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="279.8" cy="317.9" r="3.4" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="261.4" cy="308.9" r="3.0" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n<circle cx="281.7" cy="324.1" r="3.2" fill="#CFD1D8" stroke="#05070B" stroke-width="1.2"/>\n</g><!--/rp-hand-->\n</svg>'     # the brand reaper (injected at build time; kept as data, not drawn here)

_GRADE_COLORS = {"A": "#1a7f37", "B": "#2a9d8f", "C": "#c08a00", "D": "#d9731f", "F": "#c0271a"}
_SEV_COLORS = {"CRITICAL": "#b3261e", "HIGH": "#d9731f", "MEDIUM": "#c79a00", "LOW": "#5a6672", "INFO": "#8a8f99"}
_SEV_LABEL = {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW", "INFO": "INFO"}


def _esc(x):
    return html.escape(str(x if x is not None else ""))


def _grade_color(g):
    return _GRADE_COLORS.get(g, "#5a6672")


def report_css():
    """The report's stylesheet: dark branded header, clean light printable body, red accents."""
    return """
:root{--red:#E01E37;--ink:#1b2026;--mut:#5a6672;--line:#e3e6ea;--panel:#ffffff;--page:#f4f5f7}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--page);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",
Roboto,Helvetica,Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:900px;margin:0 auto;padding:0 20px 48px}
header.brand{background:linear-gradient(135deg,#0C0D10,#14161B);color:#F2F3F6;border-bottom:4px solid var(--red);
padding:26px 20px}
.brand-in{max-width:900px;margin:0 auto;display:flex;align-items:center;gap:20px}
.reaper{flex:0 0 auto;filter:drop-shadow(0 2px 6px rgba(224,30,55,.35))}
.reaper svg{height:76px;width:auto;display:block}
.brand-txt{flex:1 1 auto}
.wordmark{font-weight:800;letter-spacing:.14em;font-size:30px;line-height:1}
.wordmark span{color:var(--red)}
.tagline{color:#C7CBD2;font-size:12px;letter-spacing:.22em;text-transform:uppercase;margin-top:6px}
.headgrade{flex:0 0 auto;text-align:center}
.gradebadge{display:flex;align-items:center;justify-content:center;width:74px;height:74px;border-radius:16px;
font-size:40px;font-weight:800;color:#fff;box-shadow:0 3px 10px rgba(0,0,0,.35)}
.gscore{color:#C7CBD2;font-size:12px;margin-top:6px;letter-spacing:.05em}
.meta{max-width:900px;margin:0 auto;padding:12px 20px;color:var(--mut);font-size:12.5px;
border-bottom:1px solid var(--line);background:#fff}
.meta b{color:var(--ink)}
h2{font-size:17px;margin:34px 0 12px;padding-bottom:7px;border-bottom:2px solid var(--line);
display:flex;align-items:center;gap:10px}
h2 .pill{font-size:11px;font-weight:700;color:#fff;padding:2px 9px;border-radius:999px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0 4px}
.tile{flex:1 1 120px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;
box-shadow:0 1px 2px rgba(16,22,30,.04)}
.tile .k{color:var(--mut);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.tile .v{font-size:26px;font-weight:800;margin-top:3px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0;
box-shadow:0 1px 2px rgba(16,22,30,.04);page-break-inside:avoid}
.srvhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.srvhead .ip{font-weight:700;font-size:15px}
.srvhead .role{color:var(--mut);font-size:12px}
.gtag{margin-left:auto;font-weight:800;color:#fff;border-radius:8px;padding:3px 11px;font-size:14px}
.sev{display:inline-block;min-width:42px;text-align:center;color:#fff;font-weight:700;font-size:10.5px;
border-radius:5px;padding:2px 6px;margin-right:8px;vertical-align:middle}
.finding{display:flex;gap:10px;padding:9px 0;border-top:1px solid var(--line)}
.finding:first-child{border-top:none}
.finding .body{flex:1}
.finding .title{font-weight:600}
.finding .detail{color:var(--mut);font-size:13px;margin-top:2px}
.finding .fix{font-size:13px;margin-top:3px}
.finding .fix b{color:#1a7f37}
.muted{color:var(--mut)}
.clean{color:#1a7f37;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-size:11px;letter-spacing:.06em;text-transform:uppercase}
tr:nth-child(even) td{background:#fafbfc}
code{background:#f0f2f4;border-radius:4px;padding:1px 5px;font-size:12.5px}
footer{max-width:900px;margin:30px auto 0;padding:16px 20px;color:var(--mut);font-size:12px;
border-top:1px solid var(--line)}
.disc{background:#fff6f2;border:1px solid #f3d6cc;border-left:4px solid var(--red);border-radius:8px;
padding:12px 14px;color:#5a3a33;font-size:12.5px;margin-top:14px}
@media print{body{background:#fff}.card,.tile{box-shadow:none}header.brand{padding:18px 20px}
a{color:inherit;text-decoration:none}}
"""


def _finding_rows(findings, where_prefix=True):
    out = []
    for f in findings:
        sev = f.get("severity", "INFO")
        col = _SEV_COLORS.get(sev, "#8a8f99")
        where = f"<code>{_esc(f.get('where'))}</code> " if where_prefix and f.get("where") else ""
        fix = f"<div class='fix'><b>FIX</b> {_esc(f.get('fix'))}</div>" if f.get("fix") else ""
        out.append(
            f"<div class='finding'><div><span class='sev' style='background:{col}'>{_SEV_LABEL.get(sev, sev)}"
            f"</span></div><div class='body'><div class='title'>{where}{_esc(f.get('title'))}</div>"
            f"<div class='detail'>{_esc(f.get('detail'))}</div>{fix}</div></div>")
    return "".join(out)


def _collect_findings(data):
    """All findings across the report, de-duplicated by (severity, title, where), for the headline grade."""
    seen, allf = set(), []
    pools = []
    if data.get("audit"):
        pools.append(data["audit"].get("findings", []))
    if data.get("vulns"):
        for rep in data["vulns"].get("servers", []):
            pools.append(rep.get("findings", []))
    elif data.get("servers"):
        for rep in data["servers"].get("servers", []):
            pools.append(rep.get("findings", []))
    for pool in pools:
        for f in pool:
            key = (f.get("severity"), f.get("title"), f.get("where"))
            if key not in seen:
                seen.add(key)
                allf.append(f)
    return allf


def report_html(data):
    """Render a full branded HTML report. `data`: {title?, generated?, info?, devices?, audit?, servers?,
    vulns?}. Missing sections are simply skipped. Returns a complete, self-contained HTML document."""
    title = data.get("title") or "Network Security Report"
    generated = data.get("generated") or time.strftime("%Y-%m-%d %H:%M")
    info = data.get("info") or {}
    devices = data.get("devices") or []
    overall = grade_findings(_collect_findings(data))
    g = overall["grade"]
    c = overall["counts"]

    net = " · ".join(x for x in [
        f"network {_esc(info.get('ip'))}" if info.get("ip") else "",
        f"gateway {_esc(info.get('gateway'))}" if info.get("gateway") else ""] if x) or "network"
    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>NetScout — {_esc(title)}</title>
<style>{report_css()}</style></head><body>
<header class="brand"><div class="brand-in">
<div class="reaper">{REAPER_SVG}</div>
<div class="brand-txt"><div class="wordmark">NET<span>SCOUT</span></div>
<div class="tagline">{_esc(title)}</div></div>
<div class="headgrade"><div class="gradebadge" style="background:{_grade_color(g)}">{g}</div>
<div class="gscore">{overall['score']}/100</div></div>
</div></header>
<div class="meta">Generated <b>{_esc(generated)}</b> &nbsp;·&nbsp; {net} &nbsp;·&nbsp; <b>{len(devices)}</b> device(s) seen</div>
<div class="wrap">
<h2>Executive summary</h2>
<div class="tiles">
<div class="tile"><div class="k">Overall grade</div><div class="v" style="color:{_grade_color(g)}">{g}</div></div>
<div class="tile"><div class="k">Findings</div><div class="v">{sum(c.values())}</div></div>
<div class="tile"><div class="k">Critical</div><div class="v" style="color:{_SEV_COLORS['CRITICAL']}">{c.get('CRITICAL', 0)}</div></div>
<div class="tile"><div class="k">High</div><div class="v" style="color:{_SEV_COLORS['HIGH']}">{c.get('HIGH', 0)}</div></div>
<div class="tile"><div class="k">Devices</div><div class="v">{len(devices)}</div></div>
</div>
<p class="muted">{_esc(overall['summary'])}</p>"""]

    # ---- Security Audit ----
    au = data.get("audit")
    if au:
        parts.append(f"<h2>Security audit <span class='pill' style='background:{_grade_color(au['grade'])}'>"
                     f"grade {au['grade']} · {au['score']}/100</span></h2>")
        parts.append("<div class='card'>" + (_finding_rows(au["findings"]) if au["findings"]
                     else "<span class='clean'>No issues found in the network posture check.</span>") + "</div>")

    # ---- Servers ----
    srv = data.get("servers")
    if srv and srv.get("servers"):
        s = srv["summary"]
        parts.append(f"<h2>Servers <span class='pill' style='background:{_grade_color(s.get('worst_grade', 'A'))}'>"
                     f"{s['scanned']} audited · worst {s.get('worst_grade', 'A')}</span></h2>")
        for rep in srv["servers"]:
            ports = ", ".join(str(p) for p in rep.get("open_ports", [])) or "none"
            parts.append(
                f"<div class='card'><div class='srvhead'><span class='ip'>{_esc(rep['ip'])}</span>"
                + (f"<span class='role'>{_esc(rep.get('hostname'))}</span>" if rep.get("hostname") else "")
                + f"<span class='role'>[{_esc(rep.get('role'))}]</span>"
                + f"<span class='gtag' style='background:{_grade_color(rep['grade'])}'>{rep['grade']}</span></div>"
                + f"<div class='muted' style='margin:6px 0 2px'>Open ports: <code>{_esc(ports)}</code></div>"
                + (_finding_rows(rep["findings"], where_prefix=False) if rep["findings"]
                   else "<div class='clean' style='margin-top:6px'>No issues on this host.</div>")
                + "</div>")

    # ---- Vulnerabilities ----
    vu = data.get("vulns")
    if vu and vu.get("vulns"):
        rows = "".join(
            f"<tr><td><span class='sev' style='background:{_SEV_COLORS.get(v['severity'], '#888')}'>"
            f"{_SEV_LABEL.get(v['severity'], v['severity'])}</span></td><td><code>{_esc(v['host'])}</code></td>"
            f"<td>{_esc(v['title'])}<div class='detail muted'>{_esc(v.get('detail'))}</div></td></tr>"
            for v in vu["vulns"])
        parts.append(f"<h2>Vulnerabilities &amp; exposures <span class='pill' style='background:{_SEV_COLORS['HIGH']}'>"
                     f"{len(vu['vulns'])} finding(s)</span></h2>")
        parts.append(f"<table><thead><tr><th>Severity</th><th>Host</th><th>Finding</th></tr></thead><tbody>"
                     f"{rows}</tbody></table>")

    parts.append(
        "<div class='disc'>This report was produced by NetScout, a defensive network tool, from a scan of a "
        "network the operator is responsible for. Findings are version- and exposure-based (“update, or "
        "confirm it’s patched”) and the scans only read — nothing here exploits or attacks any "
        "device. Assess only networks you own or are authorised to assess.</div>")
    parts.append(f"</div><footer>NetScout Security Report &nbsp;·&nbsp; generated {_esc(generated)} &nbsp;·&nbsp; "
                 "defensive, read-only assessment</footer></body></html>")
    return "".join(parts)


# ============================================================ server scan + vulnerability scan
# One deep, active security audit of a chosen HOST (or many), reusing the same port scanner, banner/version
# fingerprinting, TLS-certificate reader and known-vulnerability signatures the rest of NetScout uses, then
# scored with the same A-F model as the passive Security Audit. Two tools are built on this one engine:
#   * SERVER SCAN  - aimed at the servers found on your LAN; a full per-server report.
#   * VULN SCAN    - aimed at every host; surfaces everything vulnerable, worst-first.
#
# Honest scope (same as the rest of the tool): detection is VERSION/EXPOSURE based - it connects to and
# READS from the target (open ports, service banners, certificates) and matches them against a built-in
# signature set. It is not an exploit framework and not a live-CVE-feed lookup, so every finding is phrased
# "update, or confirm it's patched". Scan only hosts you own or are authorised to assess.

def grade_findings(findings):
    """Shared A-F scorer for a list of findings (used by the passive audit and the active scans), so one
    severity model governs the whole tool. Returns {findings(sorted), counts, score, grade, worst, summary}."""
    findings = sorted(findings, key=lambda x: AUDIT_ORDER.get(x["severity"], 9))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in AUDIT_WEIGHT}
    score = max(0, 100 - sum(AUDIT_WEIGHT[f["severity"]] for f in findings))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    worst = next((f["severity"] for f in findings), "INFO")
    if not findings:
        summary = "No issues found in what was scanned. Keep firmware current and re-run regularly."
    else:
        summary = (f"{len(findings)} issue(s): "
                   + ", ".join(f"{counts[s]} {s.lower()}" for s in AUDIT_WEIGHT if counts[s])
                   + f". Most serious: {worst.lower()}.")
    return {"findings": findings, "counts": counts, "score": score, "grade": grade, "worst": worst,
            "summary": summary}


# the full set of TCP ports a server audit probes (common server/service ports across web, remote access,
# databases, mail, file sharing, management and monitoring) - well under port_scan's single-host limit.
SERVER_PORTS = sorted({
    21, 22, 23, 25, 53, 69, 80, 81, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445, 465, 512, 513, 514,
    515, 548, 587, 623, 631, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083,
    2086, 2087, 2095, 2096, 2222, 2323, 2375, 2376, 3000, 3128, 3268, 3269, 3306, 3389, 4444, 4567, 5000,
    5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986, 6379, 7001, 8000, 8006, 8008, 8080, 8081, 8083, 8086,
    8088, 8089, 8090, 8096, 8123, 8181, 8291, 8443, 8444, 8500, 8888, 9000, 9090, 9100, 9200, 9300, 9443,
    10000, 11211, 15672, 27017, 27018, 61616,
})
# ports whose web interface is plain HTTP (used to grab a Server header / title / login realm)
HTTP_PORTS = frozenset({80, 81, 591, 2082, 2086, 2095, 3000, 5000, 5601, 7001, 8000, 8006, 8008, 8080, 8081,
                        8083, 8086, 8088, 8089, 8090, 8096, 8123, 8181, 8500, 8888, 9000, 9090, 10000})
# data stores / management planes that must never be openly reachable without authentication in front
EXPOSED_DATASTORES = {
    6379: ("HIGH", "Redis", "Redis is reachable; by default it needs no password - anyone who can reach it "
                            "can read or wipe it. Bind it to localhost, require a password, firewall the port."),
    27017: ("HIGH", "MongoDB", "MongoDB is reachable on the network. Enable authentication and bind it to the "
                               "hosts that need it."),
    9200: ("HIGH", "Elasticsearch", "Elasticsearch HTTP API is reachable. Put it behind authentication and "
                                    "restrict the port."),
    11211: ("HIGH", "Memcached", "Memcached is reachable - it has no auth and is abused for DDoS amplification. "
                                 "Bind it to localhost and firewall UDP/TCP 11211."),
    5984: ("HIGH", "CouchDB", "CouchDB is reachable. Require authentication and restrict the port."),
    9000: ("MEDIUM", "management/UI port", "A management or app port is reachable; make sure it requires a login."),
    5601: ("MEDIUM", "Kibana", "Kibana is reachable - it often fronts all your logs. Put it behind authentication."),
    15672: ("MEDIUM", "RabbitMQ admin", "The RabbitMQ management UI is reachable. Restrict it and change default "
                                        "credentials."),
}
# (ports-that-signal-a-role, short role label) - combined into one role string per host
ROLE_RULES = [
    (frozenset({80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 3000}), "Web"),
    (frozenset({22, 2222}), "SSH"),
    (frozenset({3389}), "RDP/Windows"),
    (frozenset({5985, 5986}), "WinRM"),
    (frozenset({445, 139, 548, 2049, 111}), "File"),
    (frozenset({3306, 5432, 1433, 1521, 27017, 27018, 6379, 11211, 9200, 9300, 5984}), "Database"),
    (frozenset({25, 465, 587, 110, 143, 993, 995}), "Mail"),
    (frozenset({53}), "DNS"),
    (frozenset({161, 623}), "Mgmt/IPMI"),
    (frozenset({9100, 515, 631}), "Print"),
    (frozenset({5900}), "VNC"),
    (frozenset({1194, 1723}), "VPN"),
    (frozenset({2375, 2376, 2049, 8006, 8500}), "Virt/Container"),
]


def infer_server_role(ports, label=""):
    """A short, human role for a host from its open ports (and its scan label as a fallback)."""
    pset = set(ports or [])
    roles = [name for ps, name in ROLE_RULES if pset & ps]
    if roles:
        return "+".join(dict.fromkeys(roles))
    lab = (label or "").lower()
    if any(w in lab for w in ("server", "nas", "vm", "esxi", "proxmox", "synology", "qnap", "truenas", "hypervisor")):
        return "Server"
    if "router" in lab or "gateway" in lab:
        return "Router/Gateway"
    if "printer" in lab:
        return "Printer"
    if "camera" in lab:
        return "Camera"
    return "Host"


def detect_servers(devices):
    """From a device-scan result, pick the hosts worth a server audit - anything with a service listening,
    or typed as a server/NAS/router/printer - and attach an inferred role and the reason it was picked.
    Pure + deterministic, so it is fully testable."""
    out = []
    for d in devices or []:
        ip = d.get("ip", "")
        if not ip:
            continue
        ports = sorted({p for p in (d.get("ports") or []) if isinstance(p, int)})
        typ = d.get("type") or ""
        lab = d.get("label") or ""
        serverish = typ in ("Server", "Router", "Printer", "Network") or any(
            w in lab.lower() for w in ("server", "nas", "router", "gateway", "printer", "vm", "esxi", "proxmox"))
        if ports or serverish:
            out.append({"ip": ip, "hostname": d.get("hostname", "") or d.get("name", ""), "label": lab,
                        "ports": ports, "role": infer_server_role(ports, lab),
                        "why": "listening service(s)" if ports else f"typed as {typ or 'server'}"})
    return out


def audit_server(ip, hostname="", label="", port_results=None, do_tls=True, do_http=True, cancel=None):
    """Full security audit of ONE host from its open-port scan results (port_scan dicts). Adds TLS-certificate
    and HTTP-server detail, turns everything into severity-ranked findings with fixes, and scores it A-F.
    Returns {ip, hostname, label, role, open_ports, ports, certs, http, findings, counts, score, grade, ...}."""
    port_results = port_results or []
    findings = []

    def add(sev, title, detail, fix):
        findings.append({"severity": sev, "title": title, "detail": detail, "fix": fix, "where": ip})

    open_ports = sorted({r["port"] for r in port_results})
    role = infer_server_role(open_ports, label)
    ports_detail, certs, https = [], [], []
    for r in sorted(port_results, key=lambda r: r["port"]):
        p = r["port"]
        if p in AUDIT_PORTS:
            sev, what, fix = AUDIT_PORTS[p]
            add(sev, what, f"{ip}: TCP {p} is open.", fix)
        if p in EXPOSED_DATASTORES:
            sev, what, why = EXPOSED_DATASTORES[p]
            add(sev, f"{what} is exposed on the network", f"{ip}:{p} - {why}", "Restrict the port to trusted "
                "hosts and require authentication.")
        for sev, note in (r.get("vulns") or []):
            add(sev or "HIGH", "Known-vulnerable software", f"{ip}:{p} {note}",
                "Update to a supported, patched version (or confirm your vendor back-ported the fix).")
        ports_detail.append({"port": p, "service": r.get("service", ""), "banner": r.get("banner", ""),
                             "note": r.get("note", "")})
    if do_tls:
        for p in open_ports:
            if cancel is not None and cancel.is_set():
                break
            if p in TLS_PORTS:
                c = tls_cert(ip, p)
                if c:
                    c = dict(c, port=p)
                    certs.append(c)
                    for w in cert_warnings(c):
                        wl = w.lower()
                        sev = ("HIGH" if "expired" in wl else "MEDIUM" if ("expires" in wl or "obsolete" in wl)
                               else "LOW")
                        add(sev, "TLS certificate / protocol problem", f"{ip}:{p} - {w}",
                            "Renew or replace the certificate, and disable obsolete TLS versions.")
    if do_http:
        for p in open_ports:
            if cancel is not None and cancel.is_set():
                break
            if p in HTTP_PORTS:
                h = http_banner(ip, p)
                if h and (h.get("server") or h.get("title") or h.get("realm")):
                    h = dict(h, port=p)
                    https.append(h)
                    if h.get("realm"):
                        add("LOW", "Admin login served over plain HTTP",
                            f"{ip}:{p} exposes a login prompt ('{h['realm']}') without encryption.",
                            "Serve the admin interface over HTTPS only.")
    g = grade_findings(findings)
    return {"ip": ip, "hostname": hostname or "", "label": label or "", "role": role,
            "open_ports": open_ports, "ports": ports_detail, "certs": certs, "http": https, **g}


def server_scan(servers, ports=None, cancel=None, log=print, progress=None, do_tls=True, do_http=True):
    """Deep-audit a list of hosts (each {ip, hostname?, label?, ...}, e.g. from detect_servers). Runs one
    confirmed TCP port scan across SERVER_PORTS, then a full audit per host. Returns {servers:[report...],
    summary:{...}}."""
    servers = [s for s in (servers or []) if s.get("ip")]
    if not servers:
        return {"servers": [], "summary": {"scanned": 0, "open_ports": 0, "counts": {k: 0 for k in AUDIT_WEIGHT},
                                           "worst": "INFO", "worst_grade": "A", "message": "No hosts to scan."}}
    ports = list(ports or SERVER_PORTS)
    ips = [s["ip"] for s in servers]
    log(f"Auditing {len(ips)} host(s) across {len(ports)} ports each (confirmed TCP connect scan)...")
    results = port_scan(ips, ports, log=log, cancel=cancel, grab_banners=True, progress=progress)
    by_ip = {}
    for r in results:
        by_ip.setdefault(r["ip"], []).append(r)
    reports = []
    for s in servers:
        if cancel is not None and cancel.is_set():
            break
        rep = audit_server(s["ip"], s.get("hostname", ""), s.get("label", ""), by_ip.get(s["ip"], []),
                           do_tls=do_tls, do_http=do_http, cancel=cancel)
        rep["why"] = s.get("why", "")
        reports.append(rep)
    reports.sort(key=lambda r: (AUDIT_ORDER.get(r["worst"], 9), -len(r["open_ports"])))
    agg = {k: 0 for k in AUDIT_WEIGHT}
    for rep in reports:
        for k in AUDIT_WEIGHT:
            agg[k] += rep["counts"].get(k, 0)
    worst_sev = next((k for k in sorted(AUDIT_WEIGHT, key=lambda s: AUDIT_ORDER.get(s, 9)) if agg[k]), "INFO")
    worst_grade = max((rep["grade"] for rep in reports), default="A")   # 'F' > ... > 'A'
    summary = {"scanned": len(reports), "open_ports": sum(len(r["open_ports"]) for r in reports),
               "counts": agg, "worst": worst_sev, "worst_grade": worst_grade}
    return {"servers": reports, "summary": summary}


def vuln_scan(devices, ports=None, cancel=None, log=print, progress=None):
    """Vulnerability-focused scan of EVERY host passed in: deep-audits each, then flattens all findings into
    one worst-first list of vulnerabilities, each tagged with its host. Reuses server_scan. Returns the
    server_scan result plus {vulns:[...], vuln_hosts:int}."""
    targets = []
    for d in devices or []:
        ip = d.get("ip", "")
        if not ip:
            continue
        ports_seen = sorted({p for p in (d.get("ports") or []) if isinstance(p, int)})
        targets.append({"ip": ip, "hostname": d.get("hostname", "") or d.get("name", ""),
                        "label": d.get("label", ""), "ports": ports_seen})
    res = server_scan(targets, ports=ports, cancel=cancel, log=log, progress=progress)
    vulns = []
    for rep in res["servers"]:
        host = rep["hostname"] or rep["label"] or rep["ip"]
        for f in rep["findings"]:
            vulns.append(dict(f, host=rep["ip"], host_name=host, role=rep["role"]))
    vulns.sort(key=lambda x: AUDIT_ORDER.get(x["severity"], 9))
    res["vulns"] = vulns
    res["vuln_hosts"] = sum(1 for rep in res["servers"] if rep["findings"])
    return res


def _audit_header(rep):
    h = rep["ip"] + (f"  ({rep['hostname']})" if rep["hostname"] else "")
    return f"{h}    [{rep['role']}]    GRADE {rep['grade']}  ({rep['score']}/100)"


def server_scan_lines(result):
    """Readable, report-ready rendering of a server_scan() - one block per host, worst hosts first."""
    servers, s = result["servers"], result["summary"]
    icon = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[-]", "INFO": "[i]"}
    if not servers:
        return ["SERVER SCAN", s.get("message", "No servers found to scan - run a device scan first.")]
    tally = ", ".join(f"{s['counts'][k]} {k.lower()}" for k in AUDIT_WEIGHT if s["counts"].get(k))
    out = [f"SERVER SCAN - {s['scanned']} server(s) audited",
           f"Worst grade: {s['worst_grade']}   -   {s['open_ports']} open port(s) total   -   "
           + (f"issues: {tally}" if tally else "no issues found"), ""]
    for rep in servers:
        out.append("=" * 78)
        out.append(_audit_header(rep))
        if rep.get("why"):
            out.append(f"  picked: {rep['why']}")
        if rep["ports"]:
            out.append("  OPEN PORTS:")
            for p in rep["ports"]:
                extra = p["banner"] or ""
                if p["note"]:
                    extra = extra + ("  |  " if extra else "") + p["note"]
                out.append((f"    {str(p['port']) + '/tcp':<10}{p['service'][:18]:<18}" + extra).rstrip())
        else:
            out.append("  No open TCP ports in the audited set.")
        for c in rep["certs"]:
            left = c.get("days_left")
            when = ("EXPIRED" if left is not None and left < 0 else f"{left} days left" if left is not None
                    else c.get("expires", "?"))
            out.append(f"  TLS :{c.get('port', '')}  CN={c.get('subject') or '?'}  "
                       f"issuer={c.get('issuer') or '?'}  ({when})")
        for h in rep["http"]:
            title = f'"{h["title"]}"' if h.get("title") else ""
            bits = "  ".join(x for x in [h.get("server", ""), title] if x)
            if bits:
                out.append(f"  HTTP :{h.get('port', '')}  {bits}")
        if rep["findings"]:
            out.append("  FINDINGS:")
            for f in rep["findings"]:
                out.append(f"    {icon.get(f['severity'], '[-]')} {f['title']} - {f['detail']}")
                if f.get("fix"):
                    out.append(f"        FIX: {f['fix']}")
        else:
            out.append("  No security issues found on this host.")
        out.append("")
    out.append("Full security audit of the hosts you selected. NetScout only connects to and reads from them "
               "(ports, banners, certificates); it does not exploit anything. Audit only hosts you own or are "
               "authorised to assess.")
    return out


def vuln_scan_lines(result):
    """Readable rendering of a vuln_scan() - a single worst-first list of every vulnerability found, grouped
    by severity and tagged with its host."""
    vulns, s = result["vulns"], result["summary"]
    icon = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[-]", "INFO": "[i]"}
    out = [f"VULNERABILITY SCAN - {s['scanned']} host(s) scanned"]
    if not vulns:
        out += ["", "No vulnerabilities found in what was scanned. Nice. Keep firmware/software current and "
                "re-run regularly.", "", "Detection is version/exposure based, so this means nothing KNOWN-"
                "vulnerable was seen - not a guarantee. Scan only hosts you're authorised to assess."]
        return out
    tally = ", ".join(f"{s['counts'][k]} {k.lower()}" for k in AUDIT_WEIGHT if s["counts"].get(k))
    out.append(f"{len(vulns)} vulnerability/exposure finding(s) on {result['vuln_hosts']} host(s)   -   {tally}")
    out.append("")
    cur = None
    for v in vulns:
        if v["severity"] != cur:
            cur = v["severity"]
            out.append(cur)
        where = v["host"] + (f" ({v['host_name']})" if v.get("host_name") and v["host_name"] != v["host"] else "")
        out.append(f"  {icon.get(v['severity'], '[-]')} {where}: {v['title']}")
        if v.get("detail"):
            out.append(f"       {v['detail']}")
        if v.get("fix"):
            out.append(f"       FIX: {v['fix']}")
    out.append("")
    out.append("Detection is version- and exposure-based (service banners, open ports, certificates) matched "
               "against a built-in signature set - 'update, or confirm it's patched'. It is not an exploit "
               "scanner. Scan only hosts you own or are authorised to assess.")
    return out


# Devices widely known to ship with a fixed or well-documented default login. This is DEFENSIVE advice to
# the owner of the network being audited - "if you never changed this, change it now" - which is exactly
# what a professional network assessment flags. NetScout never tries a credential; it only advises.
# (brand/label regex, required type or "" for any, the login the owner should confirm they changed)
DEFAULT_LOGIN_RULES = [
    (r"hikvision", "", "admin / 12345 on older units (newer ones force a password at first setup)"),
    (r"dahua", "", "admin / admin"),
    (r"\baxis\b", "", "root with a password set at first boot - older units shipped with a fixed one"),
    (r"ubiquiti|unifi", "", "ubnt / ubnt on older firmware"),
    (r"idrac", "", "root / calvin on the iDRAC management controller"),
    (r"\bilo\b|hewlett|\bhpe\b", "Server", "the iLO password printed on the server's pull-out tag"),
    (r"supermicro", "", "ADMIN / ADMIN on the IPMI/BMC controller"),
    (r"synology|qnap", "", "the admin account with a blank password if it was never set"),
    (r"mikrotik|routeros", "", "admin with a blank password on older RouterOS"),
]
# fallback by device type when the brand isn't one of the above
GENERIC_DEFAULT_LOGIN = {
    "Camera": "many IP cameras ship with admin / admin or admin / 12345",
    "Router": "many routers ship with admin / admin or a password printed on a sticker",
    "Printer": "many printers leave the web console with no password or admin / admin",
}


def default_login_advice(dev):
    """If this device is a kind known to ship with a well-known default login, return (severity, text)
    reminding the owner to confirm they changed it, else None. Pure, testable; tries nothing."""
    blob = f"{dev.get('brand', '')} {dev.get('label', '')} {dev.get('model', '')}".lower()
    typ = dev.get("type") or ""
    for rx, want_type, login in DEFAULT_LOGIN_RULES:
        if re.search(rx, blob) and (not want_type or want_type.lower() == typ.lower()):
            return "MEDIUM", login
    g = GENERIC_DEFAULT_LOGIN.get(typ)
    return ("LOW", g) if g else None


def _ipkey(ip):
    """Sort IPv4 numerically; anything else sorts last without raising."""
    try:
        return (0,) + tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (1, ip)


def network_conflicts(devices, info=None):
    """Classic LAN problems visible in a single scan: one hardware address answering on several IPs (a sign
    of ARP spoofing / man-in-the-middle, a misconfigured bridge, or a deliberately multi-homed host), and
    more than one device acting as a gateway (a rogue router or an accidental double-NAT). Returns a list of
    finding dicts {severity,title,detail,fix,where}. Pure + deterministic, so it is fully testable."""
    out, by_mac = [], {}
    for d in devices or []:
        mac, ip = norm_mac(d.get("mac") or ""), d.get("ip") or ""
        if not ip or not mac or mac == "00:00:00:00:00:00" or mac.startswith(("01:00:5e", "33:33", "ff:ff:ff")):
            continue
        by_mac.setdefault(mac, []).append(ip)
    for mac, ips in sorted(by_mac.items()):
        uniq = sorted(set(ips), key=_ipkey)
        if len(uniq) > 1:
            out.append({"severity": "MEDIUM", "title": "The same hardware address is on more than one IP",
                        "detail": f"MAC {mac} answers on {', '.join(uniq)}. That can be ARP spoofing / a "
                                  "man-in-the-middle, a misconfigured switch or bridge, or one host that is "
                                  "multi-homed on purpose.",
                        "fix": "Confirm it is expected; if not, find the switch port that MAC is on and investigate.",
                        "where": uniq[0]})
    routers = sorted({d.get("ip", "") for d in (devices or []) if d.get("type") == "Router" and d.get("ip")},
                     key=_ipkey)
    if len(routers) > 1:
        out.append({"severity": "MEDIUM", "title": "More than one device looks like a gateway/router",
                    "detail": f"These all look like routers: {', '.join(routers)}. A second gateway usually means "
                              "a rogue device, an accidental double-NAT, or an old router that got plugged back in.",
                    "fix": "Make sure only your intended gateway is routing; remove or reconfigure the rest.",
                    "where": routers[0]})
    return out


THREAT_PORT_BASE = {"HIGH": 45, "MEDIUM": 22, "LOW": 8, "NONE": 0}


def threat_score(dev):
    """The engine's answer to "what do I fix FIRST?" for ONE device: fuse every signal the scan already
    gathered - exposed/risky ports, known-vulnerable software, a likely-default password, and whether the
    device is new/unrecognised - into a single 0-100 attention score, a level, and a plain-English top
    reason. nmap hands you ports; this hands you priorities. Pure + deterministic, so it is fully testable.
    Returns {score, level, top, factors:[(weight, reason), ...]}."""
    factors = []
    ports = set(dev.get("ports") or [])
    lvl, reasons = risk_summary(ports)
    if THREAT_PORT_BASE.get(lvl, 0):
        factors.append((THREAT_PORT_BASE[lvl], reasons[0] if reasons else f"{lvl.lower()}-risk open ports"))
    for note in (dev.get("risk_notes") or []):            # software the scan already flagged as vulnerable
        if re.search(r"(?i)vulnerab|outdated|end.?of.?life|\bCVE\b|known[- ]exploit", note):
            factors.append((35, "runs software with known vulnerabilities"))
            break
    adv = default_login_advice(dev)
    if adv:
        factors.append((20 if adv[0] == "MEDIUM" else 8, "may still have its default password"))
    if dev.get("is_new") or (dev.get("state") or dev.get("status")) == "NEW":
        factors.append((12, "new, unrecognised device on the network"))
    if dev.get("type") in ("Camera", "Server", "Router", "NAS") and factors:   # higher blast radius
        factors.append((8, f"a {dev.get('type', '').lower()} is higher-impact if it's compromised"))

    score = min(100, sum(w for w, _ in factors))
    level = ("CRITICAL" if score >= 70 else "HIGH" if score >= 45 else
             "MEDIUM" if score >= 22 else "LOW" if score >= 8 else "OK")
    top = max(factors, key=lambda f: f[0])[1] if factors else "nothing of concern found"
    return {"score": score, "level": level, "top": top, "factors": sorted(factors, reverse=True)}


def rank_devices(devs):
    """Annotate each device in place with 'threat' (0-100), 'threat_level' and 'threat_why', then return the
    list ordered by attention score, highest first (stable, so ties keep the caller's order)."""
    for d in devs or []:
        t = threat_score(d)
        d["threat"], d["threat_level"], d["threat_why"] = t["score"], t["level"], t["top"]
    return sorted(devs or [], key=lambda d: d.get("threat", 0), reverse=True)


def security_audit(devices, aps=None, info=None, extra_findings=None):
    """Score a network's security posture from what a scan already gathered, and list what to fix.

    A defensive assessment, not an attack: it only reads the results NetScout collected (open ports, device
    risk, WiFi encryption, WPS/PMF, new devices) and turns them into severity-ranked findings with a fix for
    each, an overall score (0-100) and a grade. Pure function - no network access - so it is deterministic
    and testable. Returns {score, grade, findings:[{severity,title,detail,fix,where}], counts, summary}."""
    devices, aps = devices or [], aps or []
    findings = []

    def add(sev, title, detail, fix, where=""):
        findings.append({"severity": sev, "title": title, "detail": detail, "fix": fix, "where": where})

    for d in devices:
        who = d.get("label") or d.get("hostname") or d.get("ip") or "a device"
        ports = set(d.get("ports") or [])
        for p in sorted(ports):
            if p in AUDIT_PORTS:
                sev, what, fix = AUDIT_PORTS[p]
                add(sev, what, f"{who} ({d.get('ip', '?')}) has TCP {p} open.", fix, d.get("ip", ""))
        # an outdated / known-vulnerable service the scan already flagged in the device's own notes
        for note in (d.get("risk_notes") or []):
            if re.search(r"(?i)vulnerab|outdated|end.?of.?life|CVE|known[- ]exploit", note):
                add("HIGH", "Runs software with known vulnerabilities",
                    f"{who} ({d.get('ip', '?')}): {note}", "Update the firmware / software to a supported version.",
                    d.get("ip", ""))
        if d.get("is_new"):
            add("LOW", "A new, unrecognised device is on the network",
                f"{who} ({d.get('ip', '?')}) was not seen before.",
                "Confirm you recognise it; if not, investigate and isolate it.", d.get("ip", ""))
        adv = default_login_advice(d)
        if adv:
            sev, login = adv
            add(sev, "May still have its default password",
                f"{who} ({d.get('ip', '?')}) is a kind of device that {login}.",
                "Log in and set a strong, unique password if you haven't already.", d.get("ip", ""))

    for fc in network_conflicts(devices, info):    # duplicate MAC / IP, more than one gateway
        add(fc["severity"], fc["title"], fc["detail"], fc["fix"], fc.get("where", ""))

    for a in aps:
        if not a.get("connected") and not a.get("is_mine"):
            continue   # only YOUR network is your finding - a neighbour's or a passing hotspot is not
        ssid = a.get("ssid") or "<hidden>"
        risk = a.get("risk") or ""
        if risk == "OPEN" or (a.get("security") or "").lower() in ("open", "none", ""):
            add("HIGH", "An open (unencrypted) WiFi network is in use",
                f"'{ssid}' has no encryption - anyone nearby can read its traffic.",
                "Set WPA2 or WPA3 with a strong passphrase.", ssid)
        elif risk == "WEAK":
            add("HIGH", "WiFi uses outdated, breakable encryption",
                f"'{ssid}' uses WEP or WPA1.", "Switch to WPA2/WPA3; retire hardware that can't do it.", ssid)
        if a.get("wps") is True:
            add("MEDIUM", "WiFi Protected Setup (WPS) is enabled",
                f"'{ssid}' has WPS on - its PIN can be brute-forced.", "Turn WPS off in the router.", ssid)
        if a.get("pmf") is False and risk not in ("OPEN", "WEAK"):
            add("LOW", "WiFi has no management-frame protection (PMF)",
                f"'{ssid}' allows forced-disconnect (deauth) attacks.", "Enable PMF/802.11w (required or optional).", ssid)

    for f in (extra_findings or []):      # e.g. rogue DHCP / ARP-spoofing already detected elsewhere
        add(f.get("severity", "HIGH"), f.get("title", "Issue"), f.get("detail", ""), f.get("fix", ""), f.get("where", ""))

    return grade_findings(findings)      # one shared A-F scorer for the passive audit and the active scans


def audit_lines(result):
    """Readable, report-ready rendering of a security_audit()."""
    r = result
    out = [f"SECURITY POSTURE: {r['grade']}  ({r['score']}/100)", r["summary"], ""]
    if not r["findings"]:
        return out
    icon = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[-]", "INFO": "[i]"}
    cur = None
    for f in r["findings"]:
        if f["severity"] != cur:
            cur = f["severity"]
            out.append(f"{cur}")
        out.append(f"  {icon.get(f['severity'], '[-]')} {f['title']}")
        if f.get("detail"):
            out.append(f"       {f['detail']}")
        if f.get("fix"):
            out.append(f"       FIX: {f['fix']}")
    out.append("")
    out.append("This audit reads only what the scan already saw (open ports, encryption, device risk). It is "
               "a posture check, not a penetration test.")
    return out


def banner_vulns(banner):
    """[(severity, note)] for software versions in a banner that are end-of-life or have well-known
    serious vulnerabilities. Version-based only - a vendor that back-ports fixes without bumping the
    number shows up here too, which is why the notes say 'update or confirm it is patched'."""
    b, out = banner or "", []

    def add(sev, note):
        out.append((sev, note))
    m = re.search(r"OpenSSH[_-](\d+)\.(\d+)", b)
    if m:
        v = _vt(*m.groups())
        if v < (7, 4):
            add("HIGH", f"OpenSSH {v[0]}.{v[1]} is years out of support, with several known vulnerabilities - update")
        elif (8, 5) <= v <= (9, 7):
            add("MEDIUM", f"OpenSSH {v[0]}.{v[1]} is in the range hit by CVE-2024-6387 'regreSSHion' (remote code "
                          "execution on Linux) - update to 9.8+ or confirm the fix was back-ported")
    m = re.search(r"dropbear[_-](\d{4})\.(\d+)", b, re.I)
    if m and _vt(*m.groups()) < (2016, 74):
        add("MEDIUM", f"Dropbear SSH {m.group(1)}.{m.group(2)} is outdated, with known vulnerabilities - update the firmware")
    m = re.search(r"Apache/(\d+)\.(\d+)\.(\d+)", b)
    if m:
        v = _vt(*m.groups())
        if v in ((2, 4, 49), (2, 4, 50)):
            add("HIGH", f"Apache {'.'.join(map(str, v))}: path traversal / remote code execution "
                        "(CVE-2021-41773 / CVE-2021-42013) - update immediately")
        elif v < (2, 4, 0):
            add("HIGH", f"Apache {'.'.join(map(str, v))} - the 2.2 series and older have been end of life since 2017")
        elif v < (2, 4, 58):
            add("LOW", f"Apache {'.'.join(map(str, v))} - security fixes have been released since; update or "
                       "confirm your vendor back-ports them")
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", b)
    if m and _vt(*m.groups()) < (1, 24, 0):
        add("LOW", f"nginx {'.'.join(m.groups())} - this release branch no longer receives security fixes")
    m = re.search(r"Microsoft-IIS/(\d+)\.(\d+)", b)
    if m:
        v = _vt(*m.groups())
        if v <= (6, 0):
            add("HIGH", "IIS 6.0 (Windows Server 2003): end of life, remote code execution CVE-2017-7269")
        elif v < (10, 0):
            add("MEDIUM", f"IIS {v[0]}.{v[1]} runs on a Windows Server version that is out of support")
    m = re.search(r"vsFTPd (\d+\.\d+\.\d+)", b, re.I)
    if m and m.group(1) == "2.3.4":
        add("HIGH", "vsftpd 2.3.4 - the version number of the release that shipped with a backdoor (CVE-2011-2523)")
    m = re.search(r"ProFTPD (\d+)\.(\d+)\.(\d+)([a-z]?)", b)
    if m:
        v = _vt(*m.groups()[:3])
        if v == (1, 3, 3) and m.group(4) == "c":
            add("HIGH", "ProFTPD 1.3.3c - the version number of the release that shipped with a backdoor")
        elif v < (1, 3, 6):
            add("MEDIUM", f"ProFTPD {'.'.join(map(str, v))}{m.group(4)} - known remote vulnerabilities "
                          "(e.g. CVE-2015-3306) - update")
    m = re.search(r"Exim (\d+)\.(\d+)", b)
    if m and (4, 87) <= _vt(*m.groups()) <= (4, 91):
        add("HIGH", f"Exim {m.group(1)}.{m.group(2)}: remote command execution CVE-2019-10149 - update")
    m = re.search(r"OpenSSL/(\d+)\.(\d+)\.(\d+)([a-z]?)", b)
    if m:
        v = _vt(*m.groups()[:3])
        if v == (1, 0, 1) and (m.group(4) or "a") <= "f":
            add("HIGH", f"OpenSSL 1.0.1{m.group(4)}: Heartbleed (CVE-2014-0160) - leaks memory, keys and passwords")
        elif v < (3, 0, 0):
            add("MEDIUM", f"OpenSSL {'.'.join(map(str, v))}{m.group(4)} - end of life, no public security fixes")
    m = re.search(r"PHP/(\d+)\.(\d+)", b)
    if m and _vt(*m.groups()) < (8, 2):
        add("MEDIUM", f"PHP {m.group(1)}.{m.group(2)} - end of life, no security fixes any more")
    m = re.search(r"RomPager/(\d+)\.(\d+)", b)
    if m and _vt(*m.groups()) < (4, 34):
        add("HIGH", f"RomPager {m.group(1)}.{m.group(2)}: 'Misfortune Cookie' (CVE-2014-9222) - router takeover")
    if re.search(r"\bBoa/\d", b):
        add("MEDIUM", "Boa web server - abandoned since 2005, typical of old cameras/routers - update the firmware")
    if re.search(r"GoAhead-Webs", b):
        add("MEDIUM", "old GoAhead embedded web server - many known vulnerabilities - update the firmware")
    m = re.search(r"miniupnpd/(\d+)\.(\d+)", b, re.I)
    if m and _vt(*m.groups()) < (2, 0):
        add("MEDIUM", f"MiniUPnPd {m.group(1)}.{m.group(2)} - known remote vulnerabilities - update the router firmware")
    m = re.search(r"lighttpd/(\d+)\.(\d+)\.(\d+)", b, re.I)
    if m and _vt(*m.groups()) < (1, 4, 64):
        add("LOW", f"lighttpd {'.'.join(m.groups())} - security fixes have been released since; update or "
                   "confirm your vendor back-ports them")
    return out


# ============================================================ passive traffic analyzer ("packet inspector")
# A defensive, read-only network analyzer in the spirit of tcpdump / Wireshark: it listens to the traffic
# on a link you administer and tells you WHAT is on it - which protocols, which hosts are talking to which,
# how much, and whether anything plaintext or unexpected is flowing - so you can troubleshoot and spot
# trouble on your OWN network.
#
# Deliberate scope, enforced by the code itself, not just by intent:
#   * PASSIVE ONLY. It opens a listening socket and reads. It never transmits, injects, replays or spoofs a
#     single frame - there is no send path anywhere in here.
#   * HEADERS AND METADATA ONLY. A dissected packet keeps addresses, ports, protocol and flags, plus a few
#     structural fields that are routing metadata rather than message content (a DNS query name, an ICMP
#     type). Application payloads are parsed only transiently to derive that metadata and are NEVER stored
#     or returned - there is no stream reassembly, no "follow this conversation", no credential scraping.
#   * ADMIN-GATED BY THE OS. Raw capture needs root / administrator; where the OS will not grant it (or a
#     capture driver is missing), it says so plainly instead of pretending.
# This is the same thing a network administrator does with Wireshark on their own LAN - the standard way to
# diagnose a slow network or catch a misbehaving device.

ETH_IPV4, ETH_ARP, ETH_IPV6, ETH_VLAN, ETH_LLDP = 0x0800, 0x0806, 0x86DD, 0x8100, 0x88CC
IPPROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 47: "GRE"}
# well-known ports -> short service label for the one-line summary (the "info" column)
PKT_SERVICES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
                68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 119: "nntp", 123: "ntp", 135: "msrpc",
                137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 162: "snmp",
                389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "printer",
                520: "rip", 548: "afp", 587: "smtp", 631: "ipp", 636: "ldaps", 853: "dns-tls", 873: "rsync",
                993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1883: "mqtt",
                1900: "ssdp", 3306: "mysql", 3389: "rdp", 5060: "sip", 5222: "xmpp", 5353: "mdns",
                5355: "llmnr", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
                8443: "https-alt", 8883: "mqtt-tls", 9100: "jetdirect"}
# protocols that carry data in the clear - seeing them on the wire is itself worth flagging
PKT_PLAINTEXT = {21: "FTP", 23: "Telnet", 69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP", 143: "IMAP",
                 161: "SNMP", 389: "LDAP", 512: "rexec", 513: "rlogin", 514: "syslog", 515: "LPR/printer",
                 548: "AFP", 1883: "MQTT", 5900: "VNC", 9100: "raw-print"}
TCP_FLAG_BITS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                 (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]


def _mac_str(b):
    """Six raw bytes -> aa:bb:cc:dd:ee:ff."""
    return ":".join(f"{x:02x}" for x in b) if len(b) >= 6 else ""


def tcp_flag_str(flags):
    """A TCP flags byte -> Wireshark-style list, e.g. 0x12 -> 'SYN, ACK'."""
    return ", ".join(name for bit, name in TCP_FLAG_BITS if flags & bit)


def parse_ethernet(frame):
    """An Ethernet II frame header. Returns {dst, src, ethertype, vlan, payload} or None if too short.
    Handles a single 802.1Q VLAN tag (reports the VLAN id and unwraps to the inner ethertype)."""
    if len(frame) < 14:
        return None
    dst, src = _mac_str(frame[0:6]), _mac_str(frame[6:12])
    etype = int.from_bytes(frame[12:14], "big")
    vlan, off = None, 14
    if etype == ETH_VLAN and len(frame) >= 18:
        vlan = int.from_bytes(frame[14:16], "big") & 0x0FFF
        etype = int.from_bytes(frame[16:18], "big")
        off = 18
    return {"dst": dst, "src": src, "ethertype": etype, "vlan": vlan, "payload": frame[off:]}


def parse_arp(data):
    """An ARP packet. Returns {op, op_name, sender_mac, sender_ip, target_mac, target_ip} or None."""
    if len(data) < 28:
        return None
    op = int.from_bytes(data[6:8], "big")
    return {"op": op, "op_name": {1: "request", 2: "reply"}.get(op, f"op{op}"),
            "sender_mac": _mac_str(data[8:14]), "sender_ip": socket.inet_ntoa(data[14:18]),
            "target_mac": _mac_str(data[18:24]), "target_ip": socket.inet_ntoa(data[24:28])}


def parse_ipv4(data):
    """An IPv4 header. Returns {src, dst, proto, proto_name, ttl, length, payload} or None."""
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total = int.from_bytes(data[2:4], "big")
    proto = data[9]
    return {"src": socket.inet_ntoa(data[12:16]), "dst": socket.inet_ntoa(data[16:20]),
            "proto": proto, "proto_name": IPPROTO_NAMES.get(proto, f"IP/{proto}"),
            "ttl": data[8], "length": total or len(data), "payload": data[ihl:]}


def parse_ipv6(data):
    """An IPv6 fixed header (extension headers are not walked - the next-header value is reported as-is).
    Returns {src, dst, proto, proto_name, hop_limit, length, payload} or None."""
    if len(data) < 40 or (data[0] >> 4) != 6:
        return None
    plen = int.from_bytes(data[4:6], "big")
    nxt = data[6]
    return {"src": socket.inet_ntop(socket.AF_INET6, data[8:24]),
            "dst": socket.inet_ntop(socket.AF_INET6, data[24:40]),
            "proto": nxt, "proto_name": IPPROTO_NAMES.get(nxt, f"IP/{nxt}"),
            "hop_limit": data[7], "length": plen + 40, "payload": data[40:40 + plen] if plen else data[40:]}


def parse_tcp(data):
    """A TCP header. Returns {sport, dport, seq, ack, flags, flag_str, window, data_off, payload_len}."""
    if len(data) < 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", data[0:12])
    data_off = (data[12] >> 4) * 4
    flags = data[13]
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": flags,
            "flag_str": tcp_flag_str(flags), "window": int.from_bytes(data[14:16], "big"),
            "data_off": data_off, "payload_len": max(0, len(data) - data_off)}


def parse_udp(data):
    """A UDP header. Returns {sport, dport, length, payload_len} and KEEPS the payload only long enough
    for the caller to pull routing metadata (a DNS name); it is never stored on the record."""
    if len(data) < 8:
        return None
    sport, dport, length = struct.unpack("!HHH", data[0:6])
    return {"sport": sport, "dport": dport, "length": length, "payload_len": max(0, len(data) - 8),
            "_payload": data[8:]}


def parse_icmp(data):
    """An ICMP / ICMPv6 header (type + code)."""
    if len(data) < 2:
        return None
    t, c = data[0], data[1]
    names = {0: "echo reply", 8: "echo request", 3: "destination unreachable", 11: "time exceeded",
             5: "redirect", 128: "echo request", 129: "echo reply", 135: "neighbor solicitation",
             136: "neighbor advertisement", 134: "router advertisement", 133: "router solicitation"}
    return {"type": t, "code": c, "name": names.get(t, f"type {t}")}


def _dns_query_name(payload):
    """The first query name in a DNS/mDNS message, for the info column - metadata, not content. '' on any
    trouble. Reuses the engine's own compression-aware name decoder."""
    try:
        if len(payload) < 13:
            return ""
        qd = int.from_bytes(payload[4:6], "big")
        if qd < 1:
            return ""
        name, _ = _dns_name(payload, 12)
        return name
    except (IndexError, struct.error, ValueError, OSError):
        return ""


def dissect(frame, ts=None, linktype="ethernet"):
    """Turn one captured frame into a flat, render-ready record - the equivalent of a single row in
    Wireshark's packet list. linktype 'ethernet' starts at the Ethernet header (Linux AF_PACKET);
    'ipv4' starts at the IP header (Windows SIO_RCVALL hands us IP packets with no L2).

    The record holds only headers and derived metadata: {ts, length, l2, src, dst, proto, sport, dport,
    info}. No application payload is ever placed on it."""
    rec = {"ts": ts if ts is not None else time.time(), "length": len(frame), "l2": None,
           "src": "", "dst": "", "proto": "", "sport": None, "dport": None, "info": ""}
    if linktype == "ethernet":
        eth = parse_ethernet(frame)
        if not eth:
            rec["proto"], rec["info"] = "?", "runt frame"
            return rec
        rec["l2"] = {"src": eth["src"], "dst": eth["dst"], "vlan": eth["vlan"]}
        rec["src"], rec["dst"] = eth["src"], eth["dst"]
        etype, body = eth["ethertype"], eth["payload"]
        if etype == ETH_ARP:
            a = parse_arp(body)
            rec["proto"] = "ARP"
            if a:
                rec["info"] = (f"who has {a['target_ip']}? tell {a['sender_ip']}" if a["op"] == 1
                               else f"{a['sender_ip']} is at {a['sender_mac']}" if a["op"] == 2
                               else f"ARP {a['op_name']}")
            return rec
        if etype == ETH_LLDP:
            rec["proto"], rec["info"] = "LLDP", "link-layer discovery"
            return rec
        if etype == ETH_IPV4:
            return _dissect_ip(parse_ipv4(body), rec, 4)
        if etype == ETH_IPV6:
            return _dissect_ip(parse_ipv6(body), rec, 6)
        rec["proto"], rec["info"] = f"0x{etype:04x}", "non-IP"
        return rec
    # linktype == "ipv4": a bare IP packet (no Ethernet)
    ipv = parse_ipv4(frame)
    if ipv:
        return _dissect_ip(ipv, rec, 4)
    ipv = parse_ipv6(frame)
    if ipv:
        return _dissect_ip(ipv, rec, 6)
    rec["proto"], rec["info"] = "?", "unparsable"
    return rec


def _svc_label(a, b):
    """A real service name for whichever of the two ports is well-known, else '' (so an ephemeral port is
    never echoed back as if it were a service)."""
    return PKT_SERVICES.get(a) or PKT_SERVICES.get(b) or ""


def _dissect_ip(ip, rec, ver):
    """Fill a record from an already-parsed IPv4/IPv6 header dict `ip`."""
    if not ip:
        rec["proto"], rec["info"] = f"IPv{ver}", "truncated IP header"
        return rec
    rec["src"], rec["dst"], rec["proto"] = ip["src"], ip["dst"], ip["proto_name"]
    rec["length"] = ip.get("length", rec["length"])
    body, proto = ip["payload"], ip["proto"]
    if proto == 6:
        t = parse_tcp(body)
        if t:
            rec["sport"], rec["dport"], rec["proto"] = t["sport"], t["dport"], "TCP"
            label = _svc_label(t["dport"], t["sport"])
            flag = f" [{t['flag_str']}]" if t["flag_str"] else ""
            rec["info"] = (f"{t['sport']} → {t['dport']}{flag}" + (f" {label}" if label else "")).rstrip()
    elif proto == 17:
        u = parse_udp(body)
        if u:
            rec["sport"], rec["dport"], rec["proto"] = u["sport"], u["dport"], "UDP"
            if u["dport"] in (53, 5353) or u["sport"] in (53, 5353):
                qn = _dns_query_name(u.get("_payload", b""))
                rec["info"] = (f"DNS {u['sport']} → {u['dport']}" + (f"  {qn}" if qn else "")).rstrip()
            else:
                label = _svc_label(u["dport"], u["sport"])
                rec["info"] = (f"{u['sport']} → {u['dport']}" + (f" {label}" if label else "")).rstrip()
    elif proto in (1, 58):
        ic = parse_icmp(body)
        rec["proto"] = "ICMPv6" if proto == 58 else "ICMP"
        if ic:
            rec["info"] = ic["name"]
    else:
        rec["info"] = ip["proto_name"]
    return rec


def traffic_summary(records, window_secs=None):
    """Turn a list of dissected records into an analysis: protocol mix, who is talking to whom and how
    much, the busiest ports, and any plaintext protocols seen. Pure function - fully testable."""
    by_proto, talkers, convos, dports, plaintext = {}, {}, {}, {}, {}
    total_bytes = 0
    for r in records:
        total_bytes += r.get("length", 0) or 0
        by_proto[r["proto"]] = by_proto.get(r["proto"], 0) + 1
        s, d = r.get("src", ""), r.get("dst", "")
        for host in (s, d):
            if host:
                talkers[host] = talkers.get(host, 0) + (r.get("length", 0) or 0)
        if s and d:
            key = " ↔ ".join(sorted((s, d)))
            c = convos.setdefault(key, {"packets": 0, "bytes": 0})
            c["packets"] += 1
            c["bytes"] += r.get("length", 0) or 0
        dp = r.get("dport")
        if dp:
            dports[dp] = dports.get(dp, 0) + 1
            if dp in PKT_PLAINTEXT:
                plaintext[dp] = PKT_PLAINTEXT[dp]
        sp = r.get("sport")
        if sp in PKT_PLAINTEXT:
            plaintext[sp] = PKT_PLAINTEXT[sp]
    top_talkers = sorted(talkers.items(), key=lambda kv: kv[1], reverse=True)[:12]
    top_convos = sorted(convos.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:12]
    top_ports = sorted(dports.items(), key=lambda kv: kv[1], reverse=True)[:12]
    n = len(records)
    out = {"packets": n, "bytes": total_bytes, "by_protocol": by_proto,
           "top_talkers": top_talkers, "conversations": top_convos, "top_ports": top_ports,
           "plaintext": sorted(plaintext.items()), "window_secs": window_secs,
           "pps": (n / window_secs if window_secs else None),
           "bps": (total_bytes * 8 / window_secs if window_secs else None)}
    return out


def capture_capability():
    """Can this machine capture live traffic, and how? Honest, per-OS, before anything is attempted.
    Returns {ok, backend, linktype, detail, need}."""
    if OS == "Linux":
        ok = hasattr(socket, "AF_PACKET")
        root = hasattr(os, "geteuid") and os.geteuid() == 0
        return {"ok": ok, "backend": "AF_PACKET raw socket", "linktype": "ethernet",
                "detail": "Full Ethernet-level capture." if ok else "This kernel has no AF_PACKET support.",
                "need": "" if (ok and root) else "Run NetScout with sudo (raw capture needs root)."}
    if OS == "Windows":
        return {"ok": True, "backend": "SIO_RCVALL raw socket", "linktype": "ipv4",
                "detail": "Captures IPv4 at the IP layer (no Ethernet header is visible to a raw socket "
                          "on Windows).",
                "need": "Run NetScout as administrator (raw capture needs it); some third-party firewalls "
                        "also block raw sockets."}
    if OS == "Darwin":
        return {"ok": False, "backend": "BPF", "linktype": "ethernet",
                "detail": "macOS exposes capture through /dev/bpf* devices, which this stdlib build does "
                          "not open.",
                "need": "Use the built-in `tcpdump` (sudo tcpdump -i en0) for live capture on macOS."}
    return {"ok": False, "backend": "none", "linktype": "ethernet",
            "detail": f"Live capture is not supported on {OS} in this build.", "need": ""}


def capture_frames(seconds=5.0, count=None, iface_ip=None, cancel=None, log=print):
    """Listen PASSIVELY for up to `seconds` (and/or `count` packets) and return (records, error).

    Nothing is ever transmitted: the socket is opened for receive only. Raw capture needs root /
    administrator; capture_capability() reports that up front and this returns a plain message rather
    than failing obscurely. Linux captures whole Ethernet frames; Windows captures IPv4 packets."""
    cap = capture_capability()
    if not cap["ok"]:
        return [], (cap["detail"] + (" " + cap["need"] if cap["need"] else "")).strip()
    records, end = [], time.time() + max(0.2, float(seconds or 5))
    if OS == "Linux":
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL, receive
        except PermissionError:
            return [], "Live capture needs administrator rights (a raw packet socket). Run NetScout with sudo."
        except (AttributeError, OSError) as e:
            return [], f"Could not open a capture socket: {e}"
        try:
            s.settimeout(0.5)
            while time.time() < end:
                if cancel is not None and cancel.is_set():
                    break
                try:
                    frame = s.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                records.append(dissect(frame, linktype="ethernet"))
                if count and len(records) >= count:
                    break
        finally:
            s.close()
        return records, ""
    if OS == "Windows":
        ip = iface_ip or (net_info() or {}).get("ip", "")
        if not ip:
            return [], "Could not determine this machine's IP address to capture on."
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, 1)                     # promiscuous: receive all IP, send nothing
        except PermissionError:
            return [], "Live capture needs administrator rights. Right-click NetScout and 'Run as administrator'."
        except (AttributeError, OSError) as e:
            return [], f"Could not open a capture socket: {e}"
        try:
            s.settimeout(0.5)
            while time.time() < end:
                if cancel is not None and cancel.is_set():
                    break
                try:
                    pkt = s.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                records.append(dissect(pkt, linktype="ipv4"))
                if count and len(records) >= count:
                    break
        finally:
            try:
                s.ioctl(socket.SIO_RCVALL, 0)
            except OSError:
                pass
            s.close()
        return records, ""
    return [], cap["detail"]


def capture_lines(records, summary, limit=40):
    """Report-ready rendering: a Wireshark-style packet list (capped) followed by the traffic analysis."""
    out = []
    s = summary
    win = f" in {s['window_secs']:.0f}s" if s.get("window_secs") else ""
    out.append(f"CAPTURED {s['packets']} packet(s), {_human_bytes(s['bytes'])}{win}")
    if s.get("pps"):
        out.append(f"  rate: {s['pps']:.0f} packets/s, {_human_bits(s['bps'])}/s")
    out.append("")
    if records:
        out.append(f"{'NO.':>4}  {'TIME':>8}  {'SOURCE':<22} {'DEST':<22} {'PROTO':<7} {'LEN':>5}  INFO")
        t0 = records[0]["ts"]
        for i, r in enumerate(records[:limit], 1):
            out.append(f"{i:>4}  {r['ts'] - t0:>7.3f}s  {r['src'][:22]:<22} {r['dst'][:22]:<22} "
                       f"{r['proto'][:7]:<7} {r['length']:>5}  {r['info'][:60]}")
        if len(records) > limit:
            out.append(f"       ... {len(records) - limit} more (full counts are in the summary below)")
    out += ["", "PROTOCOLS:"]
    for proto, n in sorted(s["by_protocol"].items(), key=lambda kv: kv[1], reverse=True):
        out.append(f"  {proto:<10} {n:>6}  ({100 * n // max(1, s['packets'])}%)")
    out += ["", "TOP TALKERS (by bytes):"]
    for host, b in s["top_talkers"]:
        out.append(f"  {host:<40} {_human_bytes(b)}")
    out += ["", "TOP CONVERSATIONS:"]
    for key, c in s["conversations"]:
        out.append(f"  {key:<46} {c['packets']:>6} pkt  {_human_bytes(c['bytes'])}")
    if s["plaintext"]:
        out += ["", "PLAINTEXT PROTOCOLS SEEN (anyone on the path can read these - prefer the encrypted "
                "equivalent):"]
        for port, name in s["plaintext"]:
            out.append(f"  [!] {name} (port {port})")
    out += ["", "Passive capture: NetScout only listened, and kept packet headers and metadata - not the "
            "contents of any message. Capture your own network only."]
    return out


def _human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _human_bits(n):
    n = float(n or 0)
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if n < 1000 or unit == "Gbps":
            return f"{n:.0f} {unit}" if unit == "bps" else f"{n:.1f} {unit}"
        n /= 1000


SEV_RANK = {"": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def worst(sevs):
    return max(sevs, key=lambda s: SEV_RANK.get(s, 0)) if sevs else ""


# =========================================================== UPnP port-forward audit
_LAN_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # LAN calls never go via a proxy
IGD_SEARCH = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1",
              "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
              "urn:schemas-upnp-org:service:WANIPConnection:1", "upnp:rootdevice")


def _xesc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xunesc(s):
    return (s or "").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'") \
        .replace("&amp;", "&")


def ssdp_search(sts, bind_ip=None, wait=2.0):
    """[(ip, location)] answering any of the SSDP search targets `sts` (one string or several), all sent
    at once so the whole search costs a single `wait`."""
    if isinstance(sts, str):
        sts = [sts]
    out = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if bind_ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
            except OSError:
                pass
        s.settimeout(0.4)
        for st in sts:
            s.sendto((f'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                      f'MX: 2\r\nST: {st}\r\n\r\n').encode(), ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            m = re.search(r"(?im)^location:\s*(\S+)", data.decode(errors="ignore"))
            if m and (addr[0], m.group(1)) not in out:
                out.append((addr[0], m.group(1)))
    except OSError:
        pass
    finally:
        s.close()
    return out


def upnp_find_igds(gateway, bind_ip=None, wait=2.0):
    """Every UPnP description URL the router answered with, the likeliest gateway description first
    (a router often also serves a media-server description, which has no port-forwarding service)."""
    hits = [loc for ip, loc in ssdp_search(IGD_SEARCH, bind_ip, wait) if ip == gateway]
    return sorted(hits, key=lambda loc: 0 if re.search(r"igd|gateway|rootDesc|gatedesc", loc, re.I) else 1)


def upnp_find_igd(gateway, bind_ip=None, wait=2.0):
    hits = upnp_find_igds(gateway, bind_ip, wait)
    return hits[0] if hits else ""


def upnp_control(location, timeout=3.0):
    """(control_url, service_type) of the router's port-forwarding service, read from its description."""
    try:
        xml = _LAN_OPENER.open(urllib.request.Request(location, headers={"User-Agent": "NetScout"}),
                               timeout=timeout).read(300000).decode(errors="ignore")
    except Exception:
        return "", ""
    base = (re.search(r"<URLBase>\s*(.*?)\s*</URLBase>", xml, re.S | re.I) or [None, location])[1] or location
    for svc in re.findall(r"<service>(.*?)</service>", xml, re.S | re.I):
        st = (re.search(r"<serviceType>\s*(.*?)\s*</serviceType>", svc, re.S | re.I) or [None, ""])[1]
        cu = (re.search(r"<controlURL>\s*(.*?)\s*</controlURL>", svc, re.S | re.I) or [None, ""])[1]
        if cu and re.search(r"WAN(IP|PPP)Connection", st):
            return urllib.parse.urljoin(base, cu), st
    return "", ""


def upnp_soap(control_url, stype, action, args=None, timeout=3.0):
    """One UPnP SOAP call. Returns (fields, fault) - fields None when the router didn't answer at all."""
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{stype}">'
            + "".join(f"<{k}>{_xesc(v)}</{k}>" for k, v in (args or {}).items())
            + f"</u:{action}></s:Body></s:Envelope>")
    req = urllib.request.Request(control_url, data=body.encode(), method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{stype}#{action}"', "User-Agent": "NetScout"})
    fault = False
    try:
        resp = _LAN_OPENER.open(req, timeout=timeout).read(65536).decode(errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            resp = e.read(65536).decode(errors="ignore")
        except Exception:
            resp = ""
        fault = True
    except Exception:
        return None, True
    fields = {m.group(1): _xunesc(m.group(2).strip())
              for m in re.finditer(r"<(?:\w+:)?(New\w+|errorCode|errorDescription)>(.*?)</", resp, re.S)}
    return fields, fault or "errorCode" in fields


def _int(v, default=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def upnp_port_mappings(control, stype, limit=512, cancel=None):
    out = []
    for i in range(limit):
        if cancel is not None and cancel.is_set():
            break
        f, fault = upnp_soap(control, stype, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
        if f is None or fault or not f.get("NewExternalPort"):
            break
        out.append({"remote": f.get("NewRemoteHost", ""), "ext_port": _int(f.get("NewExternalPort")),
                    "proto": (f.get("NewProtocol") or "").upper(), "int_port": _int(f.get("NewInternalPort")),
                    "client": f.get("NewInternalClient", ""), "enabled": f.get("NewEnabled", "1") in ("1", "true"),
                    "desc": f.get("NewPortMappingDescription", ""), "lease": _int(f.get("NewLeaseDuration"))})
    return out


def upnp_audit(gateway, bind_ip=None, location=None, cancel=None):
    """Is UPnP on, and which ports has it opened from the internet into this network? Read-only: it
    lists port forwards, it never adds or removes one."""
    locs = [location] if location else upnp_find_igds(gateway, bind_ip)
    if not locs:
        return {"found": False}
    control, stype = "", ""
    for location in locs:
        control, stype = upnp_control(location)
        if control:
            break
    if not control:
        return {"found": True, "location": location, "control": "", "mappings": [], "external_ip": ""}
    ext = (upnp_soap(control, stype, "GetExternalIPAddress")[0] or {}).get("NewExternalIPAddress", "")
    return {"found": True, "location": location, "control": control, "external_ip": ext,
            "mappings": upnp_port_mappings(control, stype, cancel=cancel)}


def upnp_lines(a):
    """(lines, risky_count) - the plain-language read of upnp_audit()."""
    if not a.get("found"):
        return (["UPnP: the router did not answer. Programs on your network can't open ports to the internet "
                 "by themselves - that's the safer setting."], 0)
    lines = ["UPnP IS ON: any program or device on your network can open ports from the internet into it, "
             "without asking anyone."]
    ext = a.get("external_ip", "")
    if ext:
        note = ""
        try:
            ipobj = ipaddress.ip_address(ext)
            if ipobj in ipaddress.ip_network("100.64.0.0/10") or ipobj.is_private:
                note = "  (not a public address - your provider uses carrier-grade NAT, so forwards can't be reached from the internet)"
        except ValueError:
            pass
        lines.append(f"Router's internet address: {ext}{note}")
    maps, risky = a.get("mappings") or [], 0
    if not a.get("control"):
        lines.append("The router speaks UPnP but offers no port-forwarding service.")
    elif not maps:
        lines.append("Open port forwards: none right now.")
    else:
        lines.append(f"OPEN PORT FORWARDS ({len(maps)}) - each is a door from the internet into a device here:")
        for mp in maps:
            danger = RISKY_PORTS.get(mp["int_port"]) or RISKY_PORTS.get(mp["ext_port"])
            if danger:
                risky += 1
            lease = "permanent" if not mp["lease"] else f"expires in {mp['lease'] // 60} min"
            lines.append(f"  {'>> ' if danger else '   '}{mp['proto']:<4} internet:{mp['ext_port']:<6} -> "
                         f"{mp['client']}:{mp['int_port']:<6} '{mp['desc'][:30]}'  {lease}"
                         f"{'' if mp['enabled'] else '  (disabled)'}{'  RISK: ' + danger if danger else ''}")
    lines.append("Advice: if nothing here needs it (game consoles and some video apps do), switch UPnP off in the "
                 "router, and remove any forward you don't recognise.")
    return lines, risky


# =========================================================== ARP spoofing / man-in-the-middle
GW_FILE = os.path.join(os.path.expanduser("~"), ".netscout_gateways.json")


def _clean_arp(table):
    out = {}
    for ip, mac in (table or {}).items():
        m = norm_mac(mac) if mac else ""
        if not m or m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        try:
            if int(m[:2], 16) & 1:          # multicast address - never a real neighbour
                continue
        except ValueError:
            continue
        out[ip] = m
    return out


def arp_spoof_check(table, gateway, known_gw_mac=""):
    """Signs that someone is impersonating the router on this LAN (ARP spoofing - the standard way to
    put yourself in the middle of everyone's traffic). Returns [{"severity", "kind", "why"}]."""
    t = _clean_arp(table)
    out = []
    gw_mac = t.get(gateway, "")
    known = norm_mac(known_gw_mac) if known_gw_mac else ""
    if gw_mac and known and gw_mac != known:
        out.append({"severity": "HIGH", "kind": "ROUTER MAC CHANGED",
                    "why": f"the router {gateway} now answers as {gw_mac} (was {known}) - the classic sign of ARP "
                           "spoofing / man-in-the-middle, unless the router was just replaced"})
    if gw_mac:
        others = sorted((ip for ip, m in t.items() if m == gw_mac and ip != gateway),
                        key=lambda x: [int(p) if p.isdigit() else 0 for p in x.split(".")])
        if others:
            out.append({"severity": "HIGH" if len(others) == 1 else "MEDIUM", "kind": "ROUTER MAC SHARED",
                        "why": f"{', '.join(others[:6])} use{'s' if len(others) == 1 else ''} the router's hardware "
                               f"address {gw_mac} - another machine may be posing as the router (harmless only if "
                               "the router answers for several addresses itself, 'proxy ARP')"})
    by_mac = {}
    for ip, m in t.items():
        if m != gw_mac:
            by_mac.setdefault(m, []).append(ip)
    for m, ips in sorted(by_mac.items()):
        if len(ips) > 1:
            out.append({"severity": "LOW", "kind": "SHARED MAC",
                        "why": f"{m} answers for {', '.join(sorted(ips)[:6])} - fine for a machine with several "
                               "addresses, suspicious otherwise"})
    return out


def remember_gateway(key, mac):
    """Store the router's MAC per network and return the one stored before ('' the first time)."""
    if not mac:
        return ""
    data = _load_json(GW_FILE, {})
    if not isinstance(data, dict):
        data = {}
    prev = data.get(key, "")
    if prev != norm_mac(mac):
        data[key] = norm_mac(mac)
        try:
            _save_json_atomic(GW_FILE, data)
        except OSError:
            pass
    return prev


# =========================================================== traceroute
def _find_tool(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
        for d in ("/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/bin", "/usr/local/sbin"):
            cand = os.path.join(d, n)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return ""


def traceroute_cmd(host, max_hops=30, host_os=None):
    """(argv, error) for the OS's own traceroute - no admin rights needed on any of them."""
    host_os = host_os or OS
    if not re.fullmatch(r"[A-Za-z0-9._:\-]+", host or "") or host.startswith("-"):
        return None, "Enter a valid host name or IP address."
    try:
        m = max(1, min(int(max_hops), 64))
    except (TypeError, ValueError):
        m = 30
    if host_os == "Windows":
        return ["tracert", "-d", "-h", str(m), "-w", "1000", host], ""
    tr = _find_tool("traceroute")
    if tr:
        return [tr, "-n", "-q", "3", "-w", "2", "-m", str(m), host], ""
    tp = _find_tool("tracepath")
    if tp:
        return [tp, "-n", "-m", str(m), host], ""
    return None, ("No traceroute program found. Install one, e.g. 'sudo apt install traceroute' (Debian/Ubuntu), "
                  "'sudo dnf install traceroute' (Fedora).")


_IP4 = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
_IP6 = r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b"


def parse_trace_line(line):
    """One hop from tracert / traceroute / tracepath output: {"hop", "ips", "rtts", "lost"} or None."""
    m = re.match(r"\s*(\d{1,2})[?:]?\s+(.*)$", line or "")
    if not m:
        return None
    hop, rest = int(m.group(1)), m.group(2)
    if "[LOCALHOST]" in rest or "Resume" in rest:
        return None
    ips = re.findall(_IP4, rest) or [x for x in re.findall(_IP6, rest) if ":" in x and x.count(":") >= 2]
    rtts = []
    for x in re.findall(r"(<?\s*\d+(?:[.,]\d+)?)\s*ms", rest):
        x = x.replace(" ", "").replace(",", ".")
        rtts.append(0.5 if x.startswith("<") else float(x))
    lost = rest.count("*") + (1 if re.search(r"no reply", rest, re.I) else 0)
    if not ips and not lost:
        return None
    seen = []
    for ip in ips:
        if ip not in seen:
            seen.append(ip)
    return {"hop": hop, "ips": seen, "rtts": rtts, "lost": lost}


def merge_hops(hops):
    by = {}
    for h in hops:
        cur = by.setdefault(h["hop"], {"hop": h["hop"], "ips": [], "rtts": [], "lost": 0})
        cur["ips"] += [i for i in h["ips"] if i not in cur["ips"]]
        cur["rtts"] += h["rtts"]
        cur["lost"] += h["lost"]
    return [by[k] for k in sorted(by)]


def trace_lines(hops, target_ip="", names=None):
    """Hop table plus what it means: where your provider starts, where latency jumps, whether the target
    was reached."""
    names = names or {}
    hops = merge_hops(hops)
    out = [f"{'HOP':>3}  {'ADDRESS':<17}{'AVG ms':>8}  {'LOSS':<6} NAME / NOTE"]
    prev_avg, isp_marked = None, False
    for h in hops:
        ip = h["ips"][0] if h["ips"] else ""
        avg = sum(h["rtts"]) / len(h["rtts"]) if h["rtts"] else None
        tries = len(h["rtts"]) + h["lost"]
        loss = f"{h['lost']}/{tries}" if tries else "-"
        notes = []
        try:
            pub = bool(ip) and ipaddress.ip_address(ip).is_global
        except ValueError:
            pub = False
        if pub and not isp_marked:
            notes.append("<- internet provider starts here")
            isp_marked = True
        if avg is not None and prev_avg is not None and avg - prev_avg > 30 and avg > prev_avg * 2:
            notes.append(f"<- latency jumps +{avg - prev_avg:.0f} ms here")
        if not ip:
            notes.append("no answer (many routers ignore traceroute - only a problem if the trace stops here)")
        name = names.get(ip, "")
        out.append(f"{h['hop']:>3}  {ip or '*':<17}{'' if avg is None else f'{avg:.1f}':>8}  {loss:<6} "
                   f"{name}{'  ' if name and notes else ''}{'  '.join(notes)}")
        if avg is not None:
            prev_avg = avg
    reached = bool(target_ip) and any(target_ip in h["ips"] for h in hops)
    out.append("")
    if target_ip:
        out.append(f"Destination {target_ip} {'REACHED' if reached else 'NOT reached'} in {len(hops)} hop(s).")
    return out


# =========================================================== internet health / speed test
INET_TARGETS = (("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9"))
PUBLIC_IP_URLS = ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip")
CAPTIVE_URL = "http://connectivitycheck.gstatic.com/generate_204"
SPEED_DOWN_URL = "https://speed.cloudflare.com/__down?bytes={n}"
SPEED_UP_URL = "https://speed.cloudflare.com/__up"


def tcp_latency(host, port=443, n=5, timeout=2.0):
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                out.append((time.perf_counter() - t0) * 1000)
        except OSError:
            out.append(None)
    return out


def _lat_summary(samples):
    ok = [s for s in samples if s is not None]
    if not ok:
        return {"avg": None, "min": None, "jitter": None, "loss": 100}
    jit = sum(abs(a - b) for a, b in zip(ok, ok[1:])) / (len(ok) - 1) if len(ok) > 1 else 0.0
    return {"avg": sum(ok) / len(ok), "min": min(ok), "jitter": jit,
            "loss": round(100 * (len(samples) - len(ok)) / len(samples))}


def public_ip(timeout=4.0):
    for url in PUBLIC_IP_URLS:
        try:
            txt = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "NetScout"}),
                                         timeout=timeout).read(100).decode(errors="ignore").strip()
            ipaddress.ip_address(txt)
            return txt
        except Exception:
            continue
    return ""


def internet_health(cancel=None):
    """Is the internet reachable, how fast does it answer, and is anything in between tampering with it?"""
    h = {"latency": {}}
    for ip, name in INET_TARGETS:
        if cancel is not None and cancel.is_set():
            return h
        h["latency"][name] = _lat_summary(tcp_latency(ip))
    t0 = time.perf_counter()
    try:
        socket.getaddrinfo("www.example.com", 443)
        h["dns_ms"] = (time.perf_counter() - t0) * 1000
    except OSError:
        h["dns_ms"] = None
    bogus = "nxd-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(18)) + ".com"
    try:
        h["nx_hijack"] = sorted({a[4][0] for a in socket.getaddrinfo(bogus, 80)})[:3]
    except OSError:
        h["nx_hijack"] = []
    try:
        r = urllib.request.urlopen(urllib.request.Request(CAPTIVE_URL, headers={"User-Agent": "NetScout"}), timeout=4)
        h["captive"] = r.status != 204
    except urllib.error.HTTPError as e:
        h["captive"] = e.code != 204
    except Exception:
        h["captive"] = None
    h["public_ip"] = public_ip()
    return h


def health_lines(h):
    out = ["INTERNET CHECK", ""]
    lat = h.get("latency") or {}
    up = [v for v in lat.values() if v.get("avg") is not None]
    out.append("Internet: " + ("REACHABLE" if up else "NOT REACHABLE - check the router / cable / provider"))
    out.append(f"Public IP address: {h.get('public_ip') or 'unknown'}")
    for name, v in lat.items():
        if v["avg"] is None:
            out.append(f"  {name:<11} no answer")
        else:
            out.append(f"  {name:<11} {v['avg']:6.1f} ms avg   jitter {v['jitter']:5.1f} ms   loss {v['loss']}%")
    d = h.get("dns_ms")
    out.append(f"DNS lookup: {'failed - DNS is broken' if d is None else f'{d:.0f} ms'}"
               + ("  (slow - consider 1.1.1.1 or 9.9.9.9)" if d is not None and d > 150 else ""))
    if h.get("nx_hijack"):
        out.append("WARNING: your DNS answers for names that don't exist (" + ", ".join(h["nx_hijack"]) +
                   ") - your provider or something on the network redirects failed lookups (DNS hijacking).")
    if h.get("captive"):
        out.append("WARNING: web traffic is being intercepted (captive portal, login page or filtering proxy).")
    best = min((v["avg"] for v in up), default=None)
    if best is not None:
        q = ("excellent" if best < 20 else "good" if best < 50 else "fair" if best < 100 else "poor")
        out.append(f"Verdict: {q} connection quality ({best:.0f} ms to the nearest of the big networks).")
    return out


def speed_test(seconds=8.0, streams=4, cancel=None, progress=None, down_url=None, up_url=None):
    """Download then upload as fast as possible for `seconds` each, over several parallel connections
    (one connection alone rarely fills a fast line). Returns {"down_mbps", "up_mbps", "error"}."""
    down_url = down_url or SPEED_DOWN_URL
    up_url = up_url or SPEED_UP_URL
    res = {"down_mbps": None, "up_mbps": None, "error": ""}
    lock = threading.Lock()

    def run_phase(worker, label):
        total = [0]
        end = time.time() + seconds
        errs = []

        def w():
            while time.time() < end and not (cancel is not None and cancel.is_set()):
                try:
                    n = worker(end)
                except Exception as e:
                    errs.append(str(e))
                    time.sleep(0.2)
                    if len(errs) > 20:
                        return
                    continue
                with lock:
                    total[0] += n
        t0 = time.time()
        ts = [threading.Thread(target=w, daemon=True) for _ in range(max(1, streams))]
        for t in ts:
            t.start()
        while any(t.is_alive() for t in ts):
            time.sleep(0.25)
            if progress:
                el = max(0.001, time.time() - t0)
                progress(label, total[0] * 8 / el / 1e6)
        el = max(0.001, time.time() - t0)
        return (total[0] * 8 / el / 1e6 if total[0] else None), (errs[0] if errs and not total[0] else "")

    def down(end):
        got = 0
        r = urllib.request.urlopen(urllib.request.Request(down_url.format(n=25_000_000),
                                                          headers={"User-Agent": "NetScout"}), timeout=10)
        try:
            while time.time() < end:
                chunk = r.read(65536)
                if not chunk:
                    break
                got += len(chunk)
        finally:
            r.close()
        return got

    payload = os.urandom(2_000_000)

    def upl(end):
        urllib.request.urlopen(urllib.request.Request(up_url, data=payload, method="POST",
                                                      headers={"User-Agent": "NetScout",
                                                               "Content-Type": "application/octet-stream"}),
                               timeout=15).read(1024)
        return len(payload)
    res["down_mbps"], e1 = run_phase(down, "download")
    if cancel is not None and cancel.is_set():
        return res
    res["up_mbps"], e2 = run_phase(upl, "upload")
    res["error"] = e1 or e2
    return res


def speed_lines(r):
    d, u = r.get("down_mbps"), r.get("up_mbps")
    out = ["SPEED TEST (measured against Cloudflare's nearest server)", ""]
    out.append(f"  DOWNLOAD  {'failed' if d is None else f'{d:8.1f} Mbit/s'}")
    out.append(f"  UPLOAD    {'failed' if u is None else f'{u:8.1f} Mbit/s'}")
    if r.get("error") and (d is None or u is None):
        out.append(f"  ({r['error'][:120]})")
    if d is not None:
        out.append("")
        out.append("  What that's enough for: " + (
            "4K streaming on several screens, big downloads in seconds" if d >= 100 else
            "HD/4K streaming and video calls for a household" if d >= 25 else
            "HD streaming or video calls for one or two people" if d >= 8 else
            "basic browsing and email; video will struggle"))
    out.append("  Tip: test on a cable as well - if WiFi is much slower, the WiFi is the bottleneck, not the line.")
    return out


# =========================================================== desktop notifications
def _ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def notify(title, message):
    """A desktop notification, so an alert is seen while NetScout is minimised. Fire-and-forget; returns
    True when the OS's notifier was started."""
    clean = lambda s, n: re.sub(r"[\x00-\x1f]+", " ", str(s))[:n]
    t, m = clean(title, 64), clean(message, 240)
    try:
        if OS == "Windows":
            ps = ("Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
                  "$n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; "
                  "$n.Visible = $true; $n.ShowBalloonTip(10000, " + _ps_quote(t) + ", " + _ps_quote(m) +
                  ", [System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -Seconds 11; $n.Dispose()")
            argv = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-WindowStyle", "Hidden", "-Command", ps]
        elif OS == "Darwin":
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
            argv = ["osascript", "-e", f'display notification "{esc(m)}" with title "{esc(t)}" sound name "Basso"']
        else:
            if not shutil.which("notify-send"):
                return False
            argv = ["notify-send", "-u", "critical", "-a", "NetScout", t, m]
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **NOWIN)
        return True
    except OSError:
        return False


# =========================================================== HTML report
def _h(s):
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") \
        .replace('"', "&quot;")


def html_report(title, rows=None, cols=None, lines=None, info=None, sections=None):
    """A self-contained HTML report (no external files, prints cleanly) - for handing results to a
    colleague or attaching to a ticket. `sections` = [(heading, [text lines], is_warning)]."""
    info = info or {}
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    css = ("body{font-family:Segoe UI,Helvetica,Arial,sans-serif;margin:28px;color:#1a1a1a;background:#fff}"
           "h1{margin:0;font-size:24px;letter-spacing:2px}h1 span{color:#c01818}.meta{color:#666;margin:4px 0 18px}"
           "h2{color:#c01818;font-size:16px;border-bottom:2px solid #c01818;padding-bottom:3px;margin-top:26px}"
           ".cards{display:flex;flex-wrap:wrap;gap:10px}.card{border:1px solid #ddd;border-left:4px solid #c01818;"
           "padding:6px 12px;min-width:150px}.card b{display:block;font-size:11px;color:#888}"
           "table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}"
           "th{background:#c01818;color:#fff;text-align:left;padding:6px 8px;position:sticky;top:0}"
           "td{border-bottom:1px solid #eee;padding:5px 8px;vertical-align:top}tr:nth-child(even) td{background:#faf7f7}"
           ".warn{background:#fff3f3;border-left:4px solid #c01818;padding:8px 12px;margin:8px 0}"
           ".ok{background:#f4fbf4;border-left:4px solid #3a9a3a;padding:8px 12px;margin:8px 0}"
           "pre{background:#f6f3f3;padding:12px;border-left:3px solid #c01818;white-space:pre-wrap;font-size:12px}"
           "@media print{th{position:static}}")
    out = [f"<!doctype html><html><head><meta charset='utf-8'><title>{_h(title)}</title><style>{css}</style></head><body>",
           f"<h1><span>NET</span>SCOUT &mdash; {_h(title)}</h1>",
           f"<p class='meta'>Generated {stamp} on {_h(socket.gethostname())}</p>"]
    cards = [(k, info.get(v)) for k, v in (("Network", "network"), ("Your IP", "ip"), ("Subnet mask", "mask"),
                                           ("Gateway", "gateway"), ("DHCP", "dhcp"), ("DNS", "dns")) if info.get(v)]
    if cards:
        out.append("<div class='cards'>" + "".join(f"<div class='card'><b>{_h(k)}</b>{_h(v)}</div>" for k, v in cards)
                   + "</div>")
    for heading, body, warn in sections or []:
        out.append(f"<h2>{_h(heading)}</h2>")
        out.append(f"<div class='{'warn' if warn else 'ok'}'>" + "<br>".join(_h(x) for x in body) + "</div>")
    if rows and cols:
        out.append(f"<h2>Results ({len(rows)})</h2><table><tr>" + "".join(f"<th>{_h(t)}</th>" for _k, t in cols) + "</tr>")
        for r in rows:
            out.append("<tr>" + "".join(f"<td>{_h(r.get(k, ''))}</td>" for k, _t in cols) + "</tr>")
        out.append("</table>")
    if lines:
        out.append("<h2>Output</h2><pre>" + _h("\n".join(lines)) + "</pre>")
    out.append("</body></html>")
    return "\n".join(out)


def set_permissions(path, private=False):
    """Default: everyone can read the file. private=True: owner only."""
    try:
        if OS == "Windows":
            if private:
                run(["icacls", path, "/inheritance:r", "/grant:r", f"{os.environ.get('USERNAME', '')}:F"])
            else:
                run(["icacls", path, "/grant", "*S-1-1-0:R"])  # S-1-1-0 = "Everyone" in any language
        else:
            os.chmod(path, 0o600 if private else 0o644)
    except OSError:
        pass


def rows_to_csv(rows, cols):
    """cols: [(key, title), ...] in display order. Real CSV quoting (via the stdlib csv module) - a
    banner, label or note with a comma, quote or newline in it must not silently corrupt the column
    layout, which hand-joining strings with ',' would risk."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([title for _, title in cols])
    for d in rows:
        w.writerow(["" if d.get(key) is None else d.get(key) for key, _ in cols])
    return buf.getvalue()


def rows_to_json(rows, cols=None):
    """Full-fidelity JSON dump of the row dicts - one object per row. cols, given as [(key, title), ...],
    limits and orders the fields to match what a table shows; omitted, every field the engine collected
    is included (nested dicts like 'upnp'/'http' and all, which is more than any table column shows)."""
    if cols:
        keys = [k for k, _ in cols]
        rows = [{k: d.get(k) for k in keys} for d in rows]
    return json.dumps(rows, indent=1, sort_keys=True, default=str, ensure_ascii=False)


def save_rows(path, rows, cols, fmt, private=False):
    """Write rows as 'csv' or 'json' to path. Same ownership convention as emit()'s text saves."""
    text = rows_to_csv(rows, cols) if fmt == "csv" else rows_to_json(rows, cols)
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="" if fmt == "csv" else "\n") as f:
        f.write(text)
    set_permissions(path, private)
    return os.path.abspath(path)


def emit(lines, save=None, private=False):
    print("\n".join(lines))
    if save:
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        folder = os.path.dirname(os.path.abspath(save))
        os.makedirs(folder, exist_ok=True)
        with open(save, "w", encoding="utf-8") as f:
            f.write(f"NetScout report - {stamp}\n\n" + "\n".join(lines) + "\n")
        set_permissions(save, private)
        who = "owner only" if private else "readable by everyone"
        print(f"\nSaved to {os.path.abspath(save)}  ({who}, plain text)")


def menu():
    info = net_info()
    while True:
        print("\n=== NetScout ===\n1) Network info\n2) Scan devices\n3) Scan one device type\n"
              "4) Ping a device\n5) WiFi password\n6) Port scan\n7) Nearby WiFi + hotspots\n"
              "8) Bluetooth devices\n9) Network interfaces (MAC, IPv4, IPv6)\n0) Quit")
        c = input("> ").strip()
        save = None
        if c == "1":
            emit(info_lines(info))
        elif c == "9":
            if input("Save to txt? (y/N) ").lower() == "y":
                save = input("Filename [interfaces.txt]: ").strip() or "interfaces.txt"
            emit(iface_lines(list_interfaces()), save)
        elif c in ("2", "3"):
            kind = "all"
            if c == "3":
                kind = input("Type (camera/laptop/desktop/phone/router/printer/media/other): ").strip() or "all"
            devs = type_filter(scan(info), kind)
            if input("Save to txt? (y/N) ").lower() == "y":
                save = input("Filename [scan.txt]: ").strip() or "scan.txt"
            emit(scan_lines(devs), save)
        elif c == "4":
            ping_host(input("IP or hostname: ").strip())
        elif c == "5":
            lines, _ = wifi_report(info=info)
            if input("Save to txt? (y/N) ").lower() == "y":
                save = input("Filename [wifi.txt]: ").strip() or "wifi.txt"
            emit(lines, save)
        elif c == "6":
            try:
                targets = resolve_targets(input("Target (empty = whole network, IP, or 192.168.1.0/24): "), info)
                ports = parse_ports(input("Ports (common / 1-1024 / all / 22,80,8000-8100) [common]: "))
                print(f"Scanning {len(targets)} host(s) x {len(ports)} port(s)... only scan networks you own.")
                res = port_scan(targets, ports)
            except ValueError as e:
                print(f"Error: {e}")
                continue
            if input("Save to txt? (y/N) ").lower() == "y":
                save = input("Filename [ports.txt]: ").strip() or "ports.txt"
            emit(port_lines(res), save)
        elif c == "7":
            aps, err = wifi_scan(passes=3)
            if not aps:
                print(err)
                continue
            if input("Save to txt? (y/N) ").lower() == "y":
                save = input("Filename [nearby.txt]: ").strip() or "nearby.txt"
            emit(nearby_lines(aps), save)
        elif c == "8":
            devs, err = bluetooth_scan(duration=8.0)
            if err:
                print(err)
                continue
            if input("Save to txt? (y/N) ").lower() == "y":
                save = input("Filename [bluetooth.txt]: ").strip() or "bluetooth.txt"
            emit(bt_lines(devs), save)
        elif c == "0":
            break


def main():
    ap = argparse.ArgumentParser(description="NetScout - cross-platform network tool")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("info")
    s = sub.add_parser("scan")
    s.add_argument("--type", default="all", help="camera|laptop|desktop|phone|router|printer|media|other|all")
    s.add_argument("--no-ports", action="store_true", help="faster, less accurate type detection")
    s.add_argument("--no-vendor", action="store_true", help="skip MAC vendor lookup")
    s.add_argument("--save")
    s.add_argument("--private", action="store_true", help="save file readable by owner only")
    p = sub.add_parser("ping")
    p.add_argument("host")
    p.add_argument("-c", type=int, default=4)
    bt = sub.add_parser("bluetooth", help="passive BLE scan for nearby Bluetooth devices ('bleak' auto-installs)")
    bt.add_argument("--seconds", type=float, default=8.0)
    bt.add_argument("--save")
    bt.add_argument("--private", action="store_true", help="save file readable by owner only")
    nb = sub.add_parser("nearby", help="WiFi networks and hotspots in range (passive, nothing is joined)")
    nb.add_argument("--passes", type=int, default=3, help="look this many times and merge (catches weak networks)")
    nb.add_argument("--hotspots", action="store_true", help="only networks that look like hotspots")
    nb.add_argument("--save")
    nb.add_argument("--private", action="store_true", help="save file readable by owner only")
    pp = sub.add_parser("ports", help="TCP port scan of hosts on your own network")
    pp.add_argument("--target", default="", help="empty = whole network; IP, host name or internal CIDR range")
    pp.add_argument("--ports", default="common", help="common | 1-1024 | all | 22,80,443,8000-8100")
    pp.add_argument("--no-banners", action="store_true")
    pp.add_argument("--save")
    pp.add_argument("--private", action="store_true", help="save file readable by owner only")
    w = sub.add_parser("wifi")
    w.add_argument("--ssid")
    w.add_argument("--save")
    w.add_argument("--private", action="store_true", help="save file readable by owner only")
    ifp = sub.add_parser("interfaces", help="every network interface on this machine - MAC, IPv4, IPv6")
    ifp.add_argument("--save")
    ifp.add_argument("--private", action="store_true", help="save file readable by owner only")
    wr = sub.add_parser("wreport", help="weekly health report: scan, grade A-F, risks worst-first + what "
                                        "changed; save HTML and/or email it (for a scheduled task / cron)")
    wr.add_argument("--networks", default="", help="one or more CIDRs/ranges (default: your own network)")
    wr.add_argument("--save", help="write the HTML report here (default: a dated file in your home folder)")
    wr.add_argument("--email", action="store_true", help="email it using the saved Guardian SMTP settings")
    wr.add_argument("--no-snapshot", action="store_true", help="don't save a fresh snapshot afterwards")
    wr.add_argument("--private", action="store_true", help="save files readable by owner only")
    a = ap.parse_args()

    if a.cmd is None:
        menu()
    elif a.cmd == "info":
        emit(info_lines(net_info()))
    elif a.cmd == "interfaces":
        emit(iface_lines(list_interfaces()), a.save, a.private)
    elif a.cmd == "scan":
        info = net_info()
        devs = type_filter(scan(info, ports=not a.no_ports, vendors=not a.no_vendor), a.type)
        emit(scan_lines(devs), a.save, a.private)
    elif a.cmd == "ping":
        ping_host(a.host, a.c)
    elif a.cmd == "bluetooth":
        devs, err = bluetooth_scan(duration=max(1.0, a.seconds))
        if err:
            sys.exit(err)
        emit(bt_lines(devs), a.save, a.private)
    elif a.cmd == "nearby":
        print(f"Listening for WiFi networks ({max(1, a.passes)} pass(es))...")
        aps, err = wifi_scan(passes=a.passes)
        if not aps:
            sys.exit(err)
        emit(nearby_lines(aps, a.hotspots), a.save, a.private)
    elif a.cmd == "ports":
        try:
            targets = resolve_targets(a.target, net_info())
            ports = parse_ports(a.ports)
            print(f"Scanning {len(targets)} host(s) x {len(ports)} port(s)... only scan networks you own.")
            emit(port_lines(port_scan(targets, ports, grab_banners=not a.no_banners)), a.save, a.private)
        except ValueError as e:
            sys.exit(f"Error: {e}")
    elif a.cmd == "wifi":
        lines, _ = wifi_report(a.ssid, net_info())
        emit(lines, a.save, a.private)
    elif a.cmd == "wreport":
        info = net_info()
        print("Scanning for the weekly health report... only run this on networks you own.")
        if a.networks.strip():
            try:
                devs = scan_sites(info, parse_networks(a.networks))
            except ValueError as e:
                sys.exit(f"Error: {e}")
        else:
            devs = scan(info)
        snaps = list_snapshots()
        prev = load_snapshot(snaps[0]["stamp"]) if snaps else None    # last run's snapshot ~ a week ago
        rep = health_report(devs, info=info, prev_devs=prev)
        emit(health_report_lines(rep))
        html = health_report_html(rep)
        path = a.save or os.path.join(os.path.expanduser("~"),
                                      "netscout_health_%s.html" % datetime.datetime.now().strftime("%Y%m%d"))
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            if a.private:
                set_permissions(path, private=True)
            print(f"\nSaved HTML report: {path}")
        except OSError as e:
            print(f"Could not save the HTML report: {e}")
        if a.email:
            ok, msg = send_report_email(guardian_config_load(),
                                        f"NetScout weekly health report - grade {rep['grade']}",
                                        "\n".join(health_report_lines(rep)), html_body=html,
                                        attachment=html.encode("utf-8"), attachment_name="netscout_health.html")
            print("Email: " + ("sent." if ok else msg))
        if not a.no_snapshot:
            try:
                save_snapshot(devs, label="weekly report")
            except Exception:
                pass
        audit_log("weekly health report", target=info.get("network", ""), method="report",
                  command="wreport", ok=True, detail=f"grade {rep['grade']}, {rep['total']} device(s)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
