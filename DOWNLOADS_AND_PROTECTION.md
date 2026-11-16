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

## 3. Stopping people copying it — the honest truth + the strongest realistic setup

Here's the part nobody likes but it's true: **you cannot make distributed software uncopyable.** Anyone who
can run it can copy it, and even a compiled app can be decompiled. No tool changes that. What you *can* do,
strongest to weakest:

1. **Don't publish the source.** Release only the **built app** (the PyInstaller `.exe` / `.app`) and keep
   `netscout.py` and `gui_template.py` private. People get a working program, not your code. *(Biggest single
   improvement you can make.)*
2. **Keep the repo private** (or make only a release/download page public). A **public** GitHub repo can be
   forked by anyone under GitHub's own terms — so "public source" and "no copying" pull against each other.
3. **The license (done).** It won't physically stop a copy, but it makes reselling or claiming it as theirs a
   clear violation you can act on.
4. **Copyright headers in the code (done).** Ownership now travels at the top of every main source file, so a
   copied file still carries your name.
5. **Obfuscation (weak, usually skip).** Tools like PyArmor make the Python harder to read — it *slows*
   copying, never stops it, and often trips antivirus. Rarely worth it for a free tool.

**Bottom line:** *license + copyright headers + release binaries only (private source)* is the realistic
"hard to copy, can't be resold or claimed" setup. True uncopyability doesn't exist for anyone — not for you,
not for Microsoft.

---

## What's already done for you

- **Proprietary license** replacing MIT: free to use, but no selling, no republishing as their own, no
  claiming authorship, no removing your name. (`LICENSE`, `NetScout_License.pdf`.)
- **Copyright header** at the top of `netscout.py` and `netscout_gui.py`.
- **README** updated: license badge and License section now state the terms.

*Not legal advice — I'm not a lawyer. For anything you'd actually enforce, have a professional glance at it.*
