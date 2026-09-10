# Orbit

<p align="center">
  <img src="assets/orbit-256.png" width="160" alt="Orbit icon"/>
</p>

<p align="center">
  <b>ProtonVPN rotator</b> — Levant, Eurasia, Stateside.<br/>
  Clock, hotkeys, sentinel. One engine, a real app launcher.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-c4a574?style=flat-square&labelColor=12110f" alt="Python"/>
  <img src="https://img.shields.io/badge/linux-KDE%20%2F%20GNOME-c4a574?style=flat-square&labelColor=12110f" alt="Linux"/>
  <img src="https://img.shields.io/badge/license-MIT-c4a574?style=flat-square&labelColor=12110f" alt="MIT"/>
</p>

## Install

**One file, like a desktop IntuneWin** — compressed payload + setup, not for MDM:

```bash
curl -fL -o Orbit.run https://raw.githubusercontent.com/mikhailtomasovic/orbit/main/dist/Orbit-1.0.0.run
chmod +x Orbit.run
./Orbit.run
```

Or a Debian package:

```bash
curl -fL -O https://raw.githubusercontent.com/mikhailtomasovic/orbit/main/dist/orbit_1.0.0_all.deb
sudo apt install ./orbit_1.0.0_all.deb
```

Or from source:

```bash
curl -fsSL https://raw.githubusercontent.com/mikhailtomasovic/orbit/main/install.sh | bash
```

After that you **never type `python3 orbit.py`**. Launch **Orbit** from the app menu, or:

```bash
orbit
```

`orbit.py` is the engine. The `orbit` wrapper is the product: it finds the venv, opens the GUI, and keeps PATH/desktop consistent.

## Launch

| You click / type | What runs |
|---|---|
| **Orbit** in KDE/GNOME | `~/.local/bin/orbit` → GUI |
| `orbit` | GUI (sets up on first run) |
| `orbit hop` | next city |
| `orbit --dry-run gui` | window, no Proton |
| `orbit stop` | stop rotator |

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

## Layout

```
~/.local/bin/orbit     launcher (this is the app)
~/.orbit/
  orbit.py             engine
  orbit.yaml
  orbit.png
  venv/
```

Rebuild packages: `bash packaging/build.sh` → `dist/Orbit-1.0.0.run` and `dist/orbit_1.0.0_all.deb`.
