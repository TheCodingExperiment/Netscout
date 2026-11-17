# NetScout — Seeing Downloads, Rough Location & Protecting Your Work

*A straight guide to what's possible, what isn't, and the honest way to do each one.*

---

## 1. How many people downloaded it (works today — free, no code)

You don't need to build anything for this; GitHub already counts it.

- **Release downloads (exact):** Repo → **Releases** → each file you attached shows **"Downloaded N times."**
  Via the API: `https://api.github.com/repos/TheCodingExperiment/Netscout/releases` → each asset has a
  `download_count`.
- **Repo traffic:** Repo → **Insights → Traffic** → clones, unique cloners, views, unique visitors, and
  the sites that referred people (rolling 14 days). This is the 84-clones / 201-views view you already saw.

That gives you real download and interest numbers with zero privacy risk.

---

## 2. Seeing *roughly where* downloads come from — the honest way

GitHub deliberately **does not** tell you who visited or where they are. To get rough location, measure it
**at the download link, not inside the app**:

- Point your download at a **counting link** — a URL shortener with analytics (Bitly and similar) or your
  own small download page — that then redirects to your release file. Those dashboards show **click counts
  and an approximate country** worked out from the request, exactly like any website's visitor stats.
- This is fair game because it measures a *web request to your download*, the same way every download page
  on the internet does — you're not reaching into anyone's computer.

### What I won't put *inside* the app — and why

I did **not** build location-reporting into NetScout itself (silent code that sends each user's location or
IP back to you), and I'd recommend strongly against it:

- NetScout runs with **admin rights** and its whole promise is *"defensive, private, nothing phones home."*
  Hiding location tracking inside it would make it the exact kind of spyware it's built to help people find —
  and if anyone noticed (antivirus and researchers do), your project's reputation is gone overnight.
- Collecting people's **location/IP without telling them** breaks privacy law (EU GDPR / Swiss FADP) and
  the trust that makes people install a security tool in the first place.

If you genuinely want in-app usage stats, the right version is **opt-in and disclosed**: on first run the app
asks *"Share your country anonymously so the author can see where NetScout is used? (yes / no)"*, and only on
**yes** sends a single country-level ping to a server you control, with a line about it in the README. That's
honest, legal, and I'm happy to build it **if** you want it and have somewhere to receive the ping.

---

## 3. "Protecting" it as open source — what AGPL v3 does and doesn't do

NetScout is now **open source under the GNU AGPL v3**, so the goal isn't to stop people copying it — open
source *invites* people to read, run and build on the code. What the licence protects is different, and for a
project you want your name on it's arguably stronger:

1. **Nobody can close it up.** Anyone who distributes NetScout — or runs a modified version as a network
   service — must release their **full source under the same AGPL v3**. So no company can take your code, make
   a closed, paid, proprietary version, and cut you out. Every version that exists stays open.
2. **Your authorship travels with it.** AGPL requires the copyright notices to be kept intact, and the header
   sits at the top of `netscout.py` and `netscout_gui.py`. A fork legally has to keep your name on it.
3. **They *can* use it, share it, even sell copies** — that's normal and fine for open source — **but only**
   while keeping it open and credited. Someone shipping a closed or re-badged version with your name stripped
   is a clear licence violation you can act on.
4. **You still can't make software uncopyable** — open or closed, anyone who can run it can copy it, and even a
   compiled app can be decompiled. AGPL doesn't try to prevent copying; it makes sure every copy stays free and
   keeps your name attached.

If you ever want the *opposite* — source kept private, nobody else allowed to use or sell it at all — that's
the proprietary route instead. Just say so and I'll switch it back; the two are opposites (open-and-credited,
or closed-and-controlled).

---

## What's already done for you

- **Open-source license (GNU AGPL v3)** replacing the earlier proprietary one: free to use, study, share and
  modify — on the one condition that any distributed or network-served version stays open under the same
  licence and keeps your name. (`LICENSE`, `NetScout_License.pdf`.)
- **Copyright + licence header** at the top of `netscout.py` and `netscout_gui.py`.
- **README** updated: the license badge and License section now state the AGPL terms.

*Not legal advice — I'm not a lawyer. For anything you'd actually enforce, have a professional glance at it.*
