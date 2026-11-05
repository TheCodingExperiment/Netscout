# NetScout — Beginner's Guide

Welcome! This guide assumes you've **never used a tool like this before**. No technical
knowledge needed. We'll explain every word as we go.

---

## What is NetScout, in one sentence?

NetScout shows you **every device connected to your network** (your phones, laptops,
TV, printer, smart bulbs, and anything else) and helps you check that everything is
safe and working.

Think of it like a **guest list for your WiFi**: it tells you who's there, what they
are, and whether anyone looks out of place.

**You can't break anything just by looking.** Most of NetScout only *watches* — it
reads information, it doesn't change your devices. The few buttons that *do* change
something will always warn you first. So feel free to click around and explore.

> One rule: only use NetScout on **your own** network (your home or your company's),
> or one you're allowed to look after. Don't point it at networks that aren't yours.

---

## A few words you'll see (read this once, it'll save you confusion)

Don't memorise these — just glance at them. NetScout uses these words a lot:

- **Device** = anything connected to your network. Your phone is a device. So is your
  printer, your TV, your router.
- **Network** = your WiFi (and anything plugged in by cable). Everything in your home
  or office that's online.
- **IP address** = a device's **address on your network**, like `192.168.1.42`. Like a
  house number — it's how devices find each other. It can change over time.
- **MAC address** = a device's **permanent serial number**, like `a4:83:e7:1b:0c:9f`.
  Unlike the IP, this almost never changes, so it's the reliable way to recognise a
  device.
- **Router / Gateway** = the box from your internet provider that your WiFi comes from.
  It's the "front door" between your home and the internet.
- **Port** = think of a device as a building with many **doors**, each numbered. Some
  doors should be locked. An "open port" is an unlocked door — useful to know about,
  because open doors are how attackers get in.
- **Scan** = NetScout looking around and making a list. "Run a scan" just means "go
  look and tell me what you find."

That's it. If you forget one, come back here.

---

## Step 1 — Open NetScout

- **Easiest way:** double-click the **NetScout** icon (the skull). That's it — nothing
  to install.
  - **Windows** might show a blue box saying *"Windows protected your PC."* Don't worry —
    this is **not** a virus warning. It just means the app isn't from the Microsoft
    Store. Click **More info**, then **Run anyway**.
  - **Mac** might say it can't check the app. **Right-click** the icon → **Open** →
    **Open**. You only do this once.

- **If you only have files ending in `.py`:** those need a program called Python
  installed first. The skull icon version is much easier — if you're not sure, ask
  whoever gave you the files for the **NetScout app** (the one you just double-click).
  If you do want to run the `.py` files, the download links are at the end of this guide
  (see **Downloads**).

When it opens you'll see:

- a **skull** and a **list of buttons** down the **left side** — these are the tools;
- your own network info across the **top**;
- a big **empty space in the middle** — this is where results appear.

---

## Step 2 — Your very first scan

Let's find everything on your network. This is completely safe.

1. On the left, click **DEVICE SCAN**.
2. Click the big red **RUN** button.
3. Wait about 5–15 seconds.

A list fills the middle of the screen — **one row per device**. You'll probably
recognise most of them (your phone, your laptop, the printer…).

**What the columns mean (left to right, the important ones):**

- a dot and **ONLINE** — the device is switched on and responding.
- **IP ADDRESS** — its address right now (e.g. `192.168.1.42`).
- **TYPE / DEVICE** — NetScout's best guess at what it is (Phone, Printer, Camera…).
- **RISK** — a safety rating. Blank or "NONE" is fine. "LOW/MEDIUM/HIGH" means it's
  worth a closer look (click the row to see why at the bottom).

Above the list, a line like **"DETECTED 9 DEVICES: 3 phones, 2 laptops, 1 printer, 1 router…
BRANDS: Apple x3, Samsung…"** tells you at a glance **what NetScout found**. The same line
appears at the bottom of the screen while you look through the list.

The column **POWER OFF VIA** shows which devices could be switched off remotely (see
POWER CONTROL below). A dash just means that device can't be — phones, TVs and gadgets
never can.

**It finds more than ever:** while it scans, NetScout also listens for devices that
**announce themselves** (the same way your phone finds a printer or a Chromecast). That
catches devices that ignore the usual "are you there?" check — iPhones especially — and
tells it exactly what they are, often down to the model (e.g. *iPhone15,2*). Click a
device and the bottom line shows what it **announces** (AirPlay, printing, file
sharing…). If a device's web page runs **outdated, known-vulnerable software**, its RISK
says so.

It also asks the network the way **Windows' own "Network" folder** does (a standard called
*WS-Discovery*). Security **cameras, printers and Windows PCs** that ignore everything else
answer that — with what they are and often their **name and model** (*cam lobby,
DS-2CD2143G2-I*). And devices that have **left** the network are no longer listed by
mistake: your computer remembers recently-seen devices for a while, so NetScout now checks
each remembered one is really still there before showing it.

The four boxes above the list sum it up: **DEVICES**, **AT RISK** (red when anything is),
**NEW** (never seen before) and **SCAN TIME**.

**That's the heart of NetScout.** If you only ever use DEVICE SCAN, you're already
getting a lot of value.

---

## Step 3 — Finding your way around

The buttons you'll use most:

| Button | What it does |
|---|---|
| **Run** | Starts the tool you've selected. |
| **Stop** | Stops a tool that keeps running (like LIVE MONITOR). |
| **Back** | Go back to what you were looking at before. |
| **All / At risk / High** | Show every device, only the ones with a risk, or only HIGH risk. |
| **View ▾** | **Compare with last scan**, **Clear results**, **Zoom in / out / reset** (Ctrl + / Ctrl − / Ctrl 0) and **Fullscreen** (F11; Escape to shrink back). |
| **Save report** | Save a **nice-looking report** (a web page) of what's on screen — what was found, the risks, and the full list. Opens in any browser, prints well, easy to email to a colleague. |
| **Export ▾** | Save the current list as **TXT / CSV / JSON**, plus two settings: *TXT readable by everyone* and *Desktop alerts*. |
| **+ NEW TAB** (top) | Open another tab so you can run two things at once. |

**Scrolling:** if a list is too long or too wide to fit, red **scrollbars** appear on
the right and bottom edges — drag them, or use your mouse wheel (hold **Shift** while
scrolling to go sideways). If a scrollbar looks dark/dim, it just means there's nothing
more to scroll that way right now — that's normal.

**Tip:** You can **right-click a device** in the list for extra actions, and
**double-click a device** to quickly ping it (check it's reachable).

---

## Step 4 — The tools, explained simply

You don't need to learn all of these. Start with the ones marked **⭐**.

### The everyday ones

- **⭐ DEVICE SCAN** — lists everything on your network. Your main tool.
- **NETWORK INFO** — shows your own address details. A quick "is everything normal?" check.
  Two extra buttons:
    - **INTERNET CHECK** — is the internet working, how quickly does it answer, what's
      your public IP address, and is anything **tampering** with your connection (e.g. your
      provider redirecting mistyped web addresses, or a login page intercepting traffic).
    - **SPEED TEST** — measures your **download and upload speed** (takes about 20
      seconds) and tells you in plain words what that's enough for.
- **PING** — asks one device "are you there?" and times the reply. The **TRACE ROUTE**
  button shows **every stop on the way** to a website or device, with the delay at each
  one — it points out where your internet provider starts and where things get slow.
- **INTERFACES** — the network connections on *this* computer (WiFi, cable, etc.).
- **ROUTER SCAN** — a closer look at your router (the box your internet comes from). It also
  checks **"UPnP"**: a router setting that lets any program on your network open doors from
  the internet into your home without asking. NetScout lists every door that's open right
  now and flags the dangerous ones (like remote desktop). It also warns if the router's
  own software is outdated.

### Keeping an eye on things

- **⭐ BACKGROUND WATCH** — keeps scanning and **rings a bell the moment a new,
  unknown device joins your network.** Perfect for catching something that shouldn't
  be there. (You can mark your own devices as "approved" so it stops alerting on them —
  see Step 5.) If NetScout is minimised, you also get a **desktop notification** — untick
  **Desktop alerts** (in the **Export ▾** menu) if you don't want those.
- **LIVE MONITOR** — watches your devices continuously and shows if a connection is
  slow or dropping. Press **STOP** when you're done.
- **TOPOLOGY MAP** — draws a picture of your network: your router in the middle, every
  device around it.
- **PACKET INSPECTOR** — a simple version of the classic "Wireshark" / tcpdump tool, for
  seeing **what is actually travelling on your network**. Set how many **SECONDS** (and an
  optional **MAX PACKETS** cap) and press RUN; it **listens** and then shows a packet-by-packet
  list plus a summary: **which protocols** are in use, **which devices are talking to which**,
  the busiest ports, and — most useful — any **plaintext protocols** (like Telnet or plain
  HTTP) where someone on the same network could read the traffic, so you know to switch those
  to the encrypted version. It only ever **listens** (it never sends a thing) and keeps only
  packet **headers and summary** — never the actual contents of your messages. It needs
  **administrator / sudo** (press that way — see Step 6), and you should only ever use it on a
  network you own or run. *(On macOS, use the built-in `sudo tcpdump` instead — NetScout will
  say so.)*

### Looking more closely

- **⭐ SECURITY AUDIT** — the "how safe is my network?" button. Press RUN and it does a device
  scan, a WiFi check and a router/firewall check all at once, then gives you a **grade from A
  to F** and a **worst-first list of anything worth fixing** — each with a plain-English
  **FIX**. It only *reads* what a normal scan can see (open doors, WiFi encryption, risky
  devices, whether this computer's firewall is on); it changes nothing and it is **not** a
  "break-in test" — think of it as a checkup, not a stress test. A great place to start, and a
  good thing to re-run now and then.
- **SERVER SCAN** — the deep version of the audit, aimed at your **servers**. It finds the
  servers on your network (anything with a service running), then gives each one a thorough
  going-over: every open door, the software and version behind it, known-vulnerable versions,
  databases left open with no password, and the state of its security certificates — and
  grades each server **A–F** with a fix for every problem. Leave the SERVERS box empty to do
  all of them, or type specific IPs to check just those. It only reads; it never breaks in.
- **VULN SCAN** — the "**just show me everything that's vulnerable**" button. It deep-scans
  every device and gives you one list, worst first, of everything out-of-date, exposed, or
  mis-configured, each with a fix. (It spots *known* problems by version and exposure — it's a
  checkup, not a hacking tool.)
- **⭐ FULL REPORT** — the "**give me one report I can send to the boss**" button. Press RUN and
  it does the Security Audit, the Server Scan *and* the Vulnerability Scan in one go, then builds
  a single good-looking **web page** with the NetScout reaper and logo on it, an overall **A–F**
  grade, a summary, and every issue with its fix. When it's done it asks where to save it and
  opens it in your browser — and you can **print it to PDF** (Ctrl/Cmd + P → Save as PDF) to
  email or attach to a ticket. It only reads — it never touches anything.
- **PORT SCAN** — checks which "doors" (ports) are open on a device. Open doors can be
  a security risk, so this shows what's exposed. It also reads **which software and version**
  is behind each door and warns about **outdated or known-vulnerable** versions (with what
  to do), and checks **security certificates** — expired, about to expire, or self-made.
- **WIFI PASSWORD** — shows the password of the WiFi you're currently connected to.
- **BLUETOOTH** — lists Bluetooth gadgets nearby, nearest first, with a rough distance
  and a **likely range** (e.g. *~3 m, likely 2 – 5 m*). It reads what each gadget
  announces about itself, so even nameless ones are recognised: **AirPods**, **Apple
  Watch**, iPhones, **beacons** (with the web address an Eddystone beacon points to), and
  the maker from its Bluetooth ID.
    - **Item trackers are put at the top:** AirTags and other Find My items, **Tile**,
      **Samsung SmartTag**, **Chipolo** and **Google Find My Device** tags. A **red dot**
      means the tracker is **away from its owner**. A tracker near its owner is normal —
      but one marked *away from owner* that keeps turning up wherever you go (several
      scans, different places) is worth checking. Your phone's own tracker alerts
      (iPhone: Find My; Android: *Unknown tracker alerts*) can make it beep so you can
      find it.
    - It only **listens** — it never connects to or changes anything.

### Everyday network tools (new)

These three are classic IT utilities — handy day to day, and none of them touch other people's
devices.

- **SUBNET CALC** — the network-engineer's calculator. Type a network like `192.168.1.0/24`
  (or an IP with a mask, or a single address) and it instantly tells you the network and
  broadcast addresses, the usable host range, how many hosts fit, the netmask and wildcard —
  for IPv4 *and* IPv6. Put a number in **SPLIT /** to carve it into equal smaller subnets. It's
  pure maths — nothing is sent over the network.
- **DNS TOOLKIT** — looks up what DNS says about a name. Enter a hostname for its addresses, or
  an IP for the name behind it (reverse lookup). Set **TYPE** to a specific record (A, AAAA,
  **MX** for mail, **TXT**, **NS**, CNAME, SOA, PTR) or **ALL** for the common set, and
  optionally point it at a specific **RESOLVER**. It shows each record, its time-to-live, and
  how fast the resolver answered.
- **WEBSITE HEALTH** — a quick check-up for a website. Enter an address and it reports whether
  it's up, how fast it responds, any redirects it goes through, its **security certificate**
  (and when it expires), and whether the recommended **security headers** are set — graded A–F.
  It just makes a normal web request; it doesn't attack the site.

### WiFi

- **NETWORK SCAN** — all the WiFi networks your computer can hear. On **Windows** it now
  makes Windows do a **fresh scan** every time (no admin needed), so what you see is what
  is in the air *right now* — Windows on its own often shows a list that is a minute or
  more old. *(On Windows 11, Location must be switched on for any app to see WiFi
  networks: Settings › Privacy & security › Location.)*
- **ACCESS POINTS** — the WiFi "base stations" near you, **nearest first**, with their
  details. Pick one and press **LOCATE SELECTED AP**, then walk around: it says
  **WARMER** when you're getting closer and **COLDER** when you're moving away — handy
  for finding where a WiFi box actually is.
- **WIFI AUDIT** — a safety check of the WiFi around you: it flags open (unprotected)
  networks, old weak ones, and **fake copies of a network** set up to trick people.
  It only looks — it changes nothing.

### WiFi safety and coverage (new)

- **THREAT MONITOR** — a **burglar alarm for your WiFi**. Press RUN and leave it open; it
    keeps watching and rings a bell if it notices an attack in progress:
    - someone repeatedly **kicking devices off your WiFi** (a "deauth attack" — NetScout spots
      it from your computer's own record of disconnections);
    - a **fake copy of your network** appearing (an "evil twin");
    - a network suddenly **switching to weaker security**;
    - **your network vanishing** while others are still there (possible jamming);
    - a sudden **flood of fake networks**;
    - someone on your network **pretending to be your router** to read everyone's traffic
      (a "man-in-the-middle" attack) — NetScout also remembers your router between
      sessions, so it notices if it's suddenly a different one.

    It only listens — it never sends anything. If it says **ATTACK**, the fix it suggests is
    turning on **PMF** ("Protected Management Frames" / 802.11w) or **WPA3** in your router's
    settings — that makes those attacks stop working. Press **STOP** to end.

- **SPECTRUM** — shows how **crowded each WiFi channel** is where you're standing (think of
    channels as lanes on a motorway — fewer cars, faster trip). It marks each one CLEAR,
    LIGHT, BUSY or CONGESTED and tells you **the best channel to set on your router**.
- **COVERAGE SURVEY** — finds the **weak WiFi spots** in your home or office:
    1. Walk to a room (say, the kitchen).
    2. Type **Kitchen** in **SPOT NAME** and press **ADD SPOT**. Stand still a few seconds.
    3. Repeat in every room.
    4. You get a table with a signal bar for each room — **EXCELLENT, GOOD, FAIR, POOR**.
       Rooms marked POOR are where a mesh WiFi point or extra access point would help.

    The survey is remembered between sessions. **CLEAR SURVEY** starts a fresh one.

### Turning devices on and off (new)

- **POWER CONTROL** — press RUN to list your devices and how each can be powered. Pick one
    in the list, then:
    - **WAKE UP** — switches a computer **on** over the network ("Wake-on-LAN"). Works on most
      computers plugged in **by cable**, once Wake-on-LAN is switched on in their settings.
    - **CHECK IN USE** — asks the computer whether **someone is using it right now**.
    - **POWER OFF** / **RESTART** — shuts it down (or restarts it) after a short countdown
      (**DELAY**, 30 seconds by default). NetScout always checks whether it's in use first and
      asks you to confirm. Anyone at that computer gets a warning message.
    - **CANCEL OFF** — changed your mind? This stops a shutdown during the countdown.

    **Important:** this only works on computers **you're in charge of**:

    - **Windows PCs:** you need an administrator account on that PC (NetScout must be running
      on Windows too). Two routes: **WINDOWS** (classic) and **WINRM** — WINRM uses your current
      Windows login, so there's no password to type. **AUTO** picks the right one for you.
    - **Mac / Linux / servers:** pick **SSH**, type your user name on that machine in **SSH
      USER** (it needs SSH set up with a key — ask whoever manages it).
    - **Servers with a management controller (BMC):** pick **IPMI**. It talks to the server's
      *out-of-band* controller (a separate little computer on the motherboard), so it can power
      the server off or on even when the server itself is hung. It asks for the BMC's address and
      login when you use it — nothing is stored, and the password is never shown.

    Phones, TVs, cameras and smart gadgets can't be switched off over the network — no app
    can do that, and NetScout tells you so. The computer (or the BMC) itself checks your
    permission, so nobody can use this to switch off machines that aren't theirs. There is **no**
    "switch off any device" button, and there never will be — a tool that forced devices off
    without their permission would be an attack, not a defence.

- **SHUT DOWN ALL IDLE / ALL MANAGED** — shut down every computer in the list **that you
  administer** at once (the "PCs left on overnight waste power" case). *ALL IDLE* skips anyone
  still working; *ALL MANAGED* doesn't. Only Windows / WinRM / SSH machines are ever touched —
  phones, TVs, gadgets and this PC are left alone.

### Watching and steering your own cameras (new)

- **IP CAMERA** — shows the **live picture** from a security camera and lets you **move it**:
  **W** up, **S** down, **A** left, **D** right, **E** zoom in, **Q** zoom out (hold the key to keep
  moving, let go to stop).
    1. Type the camera's address in **CAMERA**.
    2. Type **the camera's own login** in **USER** and **PASSWORD** — the one set in the camera's web
       page or app (often under *Network › ONVIF*). This is not your Windows password.
    3. Press **RUN**. The picture appears; click it once if the keys don't respond.

    It works with any camera that supports **ONVIF** (most security cameras do). The camera checks
    the login itself on every picture and every move, so this only works on cameras you have the
    password for — running NetScout as administrator doesn't change that, and that's the point.
    For smooth full-quality video, the RTSP link shown under the picture opens in **VLC**.

### If an attack is happening — cut the attacker off (new)

You don't power the attacker's device off (you have no right to, and it may not even be a real
computer). You shut it **out**, two reversible ways:

- **Right-click the device → BLOCK … at THIS PC's firewall.** This adds a rule to **your own
  computer's** firewall so that machine can't reach it any more. It needs admin/root on *your*
  PC, works on Windows and Linux, affects **no other device**, and **UNBLOCK** removes it again.
  This is the one that always works — no special equipment needed.
- **Right-click the device → DISCONNECT (disable its switch port).** If you run a **managed
  switch**, this cuts that one device off the network entirely by switching off its port — the
  same thing a corporate "network access control" box does automatically. **RECONNECT** restores
  it. It needs the switch's SNMP password (see Step 7).

THREAT MONITOR and the ARP-spoofing check will point out a machine impersonating your router;
those are exactly the ones to block or disconnect.

### For bigger / office networks (need a special "managed" switch)
*A "switch" is a box that lots of network cables plug into. A "managed" one is a smarter,
usually business-grade version. If you don't have one, skip these three.*

- **SWITCH PORT** — tells you exactly which socket on the switch this computer is in.
- **CABLE TEST** — checks every network cable on the switch and flags any that are
  faulty — including the sneaky kind that still works but is **secretly running ten
  times too slow** because a wire inside is broken. Type the switch's address into the
  **SWITCH** box (leave it empty to ask your router).
- **DHCP CHECK** — makes sure only one box is handing out addresses on your network.
  Two is a problem and causes random connection failures.

### Protecting this computer

- **FIREWALL** — a firewall is like a **locked front door for your computer**. This tool
  shows whether yours is switched on, and **what doors are currently open to the
  outside**, with warnings about the risky ones. Buttons can turn the firewall on
  (needs admin — see Step 6).
- **MAC PRIVACY** — creates a random serial number for your computer so it's harder to
  track you by your device. (It changes how your computer appears on the network — it
  does **not** hide your internet address or make you invisible.)

---

## Step 5 — Right-clicking a device (handy extras)

In the DEVICE SCAN list, **right-click any device** for:

- **EDIT NOTE / TAG** — give it a nickname like *"Living room TV"* so you recognise it
  next time. The nickname sticks to the device even if its address changes.
- **MARK AS APPROVED** — tell BACKGROUND WATCH *"this one is fine, don't warn me about
  it."* Do this for all your own devices and the bell will only ring for genuine
  strangers.
- **DISCONNECT (disable its switch port)** — **kick a device off the network.** Use this
  if you spot something suspicious. **RECONNECT** puts it back. (This needs a managed
  switch and its password — see Step 7 — so not everyone can do it, which is the point.)
- **WAKE UP / CHECK IF IN USE / POWER OFF / RESTART / CANCEL** — the same power actions as
  the POWER CONTROL tool, right from the device list.

---

## Step 6 — When something asks for "administrator rights"

A couple of actions (turning the firewall on, changing your MAC address) actually change
your computer's settings, so your computer asks for permission first. This is normal and
good — it stops random apps changing important settings.

- **Windows:** close NetScout, **right-click its icon, choose "Run as administrator,"**
  then try again.
- **Mac / Linux:** you'll need to start it with `sudo` (ask whoever set it up if you're
  unsure).

If you don't do this, NetScout won't break — it'll just tell you politely that it needs
more permission.

---

## Step 7 — About the "switch" tools

**SWITCH PORT, CABLE TEST and DISCONNECT** only work if your network has a **managed
switch** (a business-grade box that cables plug into) with a setting called **SNMP**
turned on.

In plain terms: these are **office / IT tools**. On a normal home network you probably
don't have the right equipment for them, and that's completely fine — **everything else
in NetScout works without it.** If one of these says *"the switch did not answer,"* that's
all it means.

---

## Step 8 — If something doesn't work

- **"No WiFi networks found."** → Turn WiFi on. On Windows 11, also turn on Location
  (Settings → Privacy → Location). On a newer Mac, allow NetScout under Privacy →
  Location Services.
- **A switch tool says the switch didn't answer.** → See Step 7. You likely don't have
  a managed switch, or its SNMP setting is off. Nothing's broken.
- **The text is too small / window feels cramped.** → **View ▾ › Zoom in** (or Ctrl +), or
  **View ▾ › Fullscreen** (or the F11 key).
- **Can't find the DISCONNECT option.** → It's not a left-side button. **Right-click a
  device** in the DEVICE SCAN list.
- **A scrollbar won't move.** → That just means there's nothing to scroll in that
  direction — the list already fits. It'll work when there's more to show.
- **Windows says "Failed to load Python DLL", or asks for Python.** → Ask whoever gave you
  NetScout for the **NetScout-Folder** version (a .zip): unzip it and run **NetScout.exe**
  inside. That version works on PCs where antivirus or company settings block the
  single-file one. NetScout needs **64-bit Windows 10 or 11**.
- **POWER OFF says "Access denied".** → You need an administrator account on that PC. That's
  Windows protecting it — working as intended.
- **WAKE UP did nothing.** → Wake-on-LAN must be switched on in that computer's BIOS/UEFI
  and network settings, and it usually needs to be plugged in by cable.
- **THREAT MONITOR says it can't read the logs (Linux).** → Start NetScout with `sudo`, or
  ask your administrator to add you to the "adm" group.
- **TRACE ROUTE says no traceroute program was found (Linux).** → Install it once:
  `sudo apt install traceroute` (Debian/Ubuntu) or `sudo dnf install traceroute` (Fedora).
- **SPEED TEST or INTERNET CHECK fails at work.** → Company firewalls sometimes block speed
  tests. Try from home, or ask IT.
- **ROUTER SCAN says "UPnP IS ON".** → Not an emergency — game consoles and some apps use
  it. But if you don't need it, switch UPnP off in your router's settings, and remove any
  port forward you don't recognise.

---

## Step 9 — Good to know (honesty bit)

NetScout is a **protective** tool. It watches your network and only ever acts through
equipment you control. On purpose, it will **not** do sneaky attacker tricks — it won't
secretly knock devices off WiFi, fake your identity, or make you "untraceable" (that's
not a real thing, and the app will tell you so honestly rather than pretend). It can only
switch off computers whose owner gave you the rights to — the computer itself checks.

So: explore freely, it's safe. Only point it at networks that are yours to look after.

---

## The 30-second summary

1. **Double-click** NetScout to open it.
2. Click **DEVICE SCAN**, then **RUN** — see everything on your network.
3. Turn on **BACKGROUND WATCH** to get warned about new devices.
4. **Right-click** any device for notes, approval, or to disconnect it.
5. Everything that only *looks* is 100% safe — the few things that *change* something
   will warn you first.

That's really all you need. Welcome aboard. 🖤

---

## Downloads

You **don't need any of these** to use the NetScout app (the skull icon). They're only for
people running the `.py` files directly, or building the app themselves.

- **Python** (free) — <https://www.python.org/downloads/>
  - Windows: <https://www.python.org/downloads/windows/> — on the first installer screen,
    tick **"Add python.exe to PATH"**.
  - Mac: <https://www.python.org/downloads/macos/>
  - Linux: usually already installed; otherwise use your system's package manager.
- **bleak** (free, adds Bluetooth scanning) — <https://pypi.org/project/bleak/>
  - Install it by opening a terminal / Command Prompt and typing: `pip install bleak`
  - Its own documentation: <https://bleak.readthedocs.io/>
