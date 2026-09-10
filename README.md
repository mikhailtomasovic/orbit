# Orbit

<p align="center">
  <img src="assets/orbit-256.png" width="160" alt="Orbit icon"/>
</p>

<p align="center">
  <b>ProtonVPN rotator</b> — Levant, Eurasia, Stateside.<br/>
  Clock, hotkeys, sentinel. One Python file.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-c4a574?style=flat-square&labelColor=12110f" alt="Python"/>
  <img src="https://img.shields.io/badge/linux-KDE%20%2F%20GNOME-c4a574?style=flat-square&labelColor=12110f" alt="Linux"/>
  <img src="https://img.shields.io/badge/license-MIT-c4a574?style=flat-square&labelColor=12110f" alt="MIT"/>
</p>

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/mikhailtomasovic/orbit/main/install.sh | bash
```

That drops `~/.orbit`, the gold icon, a desktop launcher, and `~/.local/bin/orbit`. On a machine with a display it opens the GUI.

Manual:

```bash
curl -fsSL https://raw.githubusercontent.com/mikhailtomasovic/orbit/main/orbit.py -o orbit.py
python3 orbit.py
```

## What it does

| Trigger | Action |
|---|---|
| **Clock** | Timed hops — random 15s–15m or a set interval up to 30m. Manual hop resets the countdown. |
| **Keys** | `Ctrl+Alt+→` next · `←` prev · `D` disconnect · `1/2/3` pools |
| **Sentinel** | Probe URLs; hop on timeout / 403 / block-page copy |
| **GUI** | Live city, countdown, Hop / Prev / pools / Test timer |

US exits are opt-in and only **Los Angeles** or **Denver**. Iran is not on Proton; Russia is Moscow only.

## Pools

**Levant** — Beirut, Damascus, Cairo, Casablanca, Rabat, Dubai  
**Eurasia** — Warsaw, Bucharest, Skopje, Moscow, Minsk, Kyiv  
**Stateside** — Los Angeles, Denver

Hops call `protonvpn connect --city …` (Proton keeps a single NetworkManager profile).

## Commands

```bash
orbit                  # install + GUI
orbit gui              # window
orbit --dry-run gui    # no real VPN
orbit test-clock       # prove a GUI hop resets the timer
orbit start            # daemon, no window
orbit hop / hop --prev
orbit status
orbit nm               # UPLINK / VPN / LEAK
orbit stop
```

Sign in once: `protonvpn signin`

## Layout

```
~/.orbit/
  orbit.py
  orbit.yaml
  orbit.png
  venv/
  tunnels/          # optional WireGuard exports
```
