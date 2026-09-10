#!/usr/bin/env python3
"""Orbit — ProtonVPN rotator.

Three hop triggers share one mutexed rotator:

  CLOCK      interval timer, respects quiet hours
  KEYS       global hotkeys (optional; needs pynput)
  SENTINEL   HTTP probes; hop on consecutive failures or block pages

Backends are adapters. The rotator never talks to Proton directly.

    python orbit.py                # install to ~/.orbit and start
    python orbit.py bootstrap      # create folders, check backends, list tunnels
    python orbit.py start          # daemon: clock + keys + sentinel
    python orbit.py start --dry-run
    python orbit.py hop            # next server in the active pool
    python orbit.py hop --prev
    python orbit.py disconnect
    python orbit.py status
    python orbit.py probe
    python orbit.py stop           # signal a running daemon
    python orbit.py validate

Config: orbit.yaml beside this file, ~/.orbit/orbit.yaml, or bundled defaults.
Double-click Install-Orbit.bat (Windows) or Install-Orbit.command (macOS).
Requires Python 3.10+. pynput is optional and only needed for hotkeys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

APP = "orbit"
HOME = Path(os.environ.get("ORBIT_HOME", Path.home() / ".orbit"))
VENV = HOME / "venv"
LOCK_PATH = HOME / "orbit.pid"
STATUS_PATH = HOME / "status.json"
LOG_PATH = HOME / "orbit.log"

BUNDLED_YAML = r"""# Orbit — ProtonVPN rotator
# Cities verified against protonvpn countries/cities on Gotovuim.
# Iran is not on Proton. Russia is Moscow only. US opt-in: LA and Denver.

backend: auto
tunnels_dir: "~/.orbit/tunnels"
kill_switch: true
min_hop_seconds: 15
active_pool: "Levant"

pools:
  - name: "Levant"
    mode: round-robin
    servers:
      - id: "LB-BEY"
        city: "Beirut"
        country: "LB"
      - id: "SY-DAM"
        city: "Damascus"
        country: "SY"
      - id: "EG-CAI"
        city: "Cairo"
        country: "EG"
      - id: "MA-CAS"
        city: "Casablanca"
        country: "MA"
      - id: "MA-RAB"
        city: "Rabat"
        country: "MA"
      - id: "AE-DXB"
        city: "Dubai"
        country: "AE"
  - name: "Eurasia"
    mode: round-robin
    servers:
      - id: "PL-WAW"
        city: "Warsaw"
        country: "PL"
      - id: "RO-BUH"
        city: "Bucharest"
        country: "RO"
      - id: "MK-SKP"
        city: "Skopje"
        country: "MK"
      - id: "RU-MOW"
        city: "Moscow"
        country: "RU"
      - id: "BY-MSQ"
        city: "Minsk"
        country: "BY"
      - id: "UA-IEV"
        city: "Kyiv"
        country: "UA"
  - name: "Stateside"
    mode: round-robin
    servers:
      - id: "US-LAX"
        city: "Los Angeles"
        country: "US"
      - id: "US-DEN"
        city: "Denver"
        country: "US"

schedule:
  enabled: true
  mode: random
  interval_seconds: 900
  random_min_seconds: 15
  random_max_seconds: 900
  quiet_hours:
    enabled: false
    start: "23:00"
    end: "07:00"

hotkeys:
  enabled: true
  next: "ctrl+alt+arrowright"
  prev: "ctrl+alt+arrowleft"
  disconnect: "ctrl+alt+d"
  reconnect: "ctrl+alt+r"
  preset1: "ctrl+alt+1"
  preset2: "ctrl+alt+2"
  preset3: "ctrl+alt+3"

sentinel:
  enabled: true
  interval_seconds: 45
  fail_threshold: 2
  cooldown_minutes: 20
  probes:
    - url: "https://ifconfig.co/ip"
      timeout_ms: 8000
      required: true
    - url: "https://1.1.1.1"
      timeout_ms: 6000
      required: true
    - url: "https://example.com"
      timeout_ms: 8000
      required: false
  block_signatures:
    - "access denied"
    - "not available in your country"
    - "your ip has been blocked"
    - "vpn detected"
    - "please disable your vpn"
    - "captive portal"
    - "error 451"
"""


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _strip_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        if re.match(r"^\s*#", line):
            continue
        out.append(re.sub(r"\s+#.*$", "", line))
    return "\n".join(out)


def _parse_scalar(raw: str) -> Any:
    raw = raw.strip()
    if raw in ("true", "True", "yes"):
        return True
    if raw in ("false", "False", "no"):
        return False
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    return raw


def load_simple_yaml(text: str) -> dict[str, Any]:
    """Constrained YAML (maps, lists of maps/scalars, no anchors/tags)."""
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass

    lines = [ln.rstrip() for ln in _strip_comments(text).splitlines() if ln.strip()]
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any, Any | None, str | None]] = [(-1, root, None, None)]
    list_keys = {"pools", "servers", "probes", "block_signatures"}

    def current(indent: int) -> tuple[Any, Any | None, str | None]:
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        _, holder, parent, key = stack[-1]
        return holder, parent, key

    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        holder, parent, parent_key = current(indent)
        if stripped.startswith("- "):
            item = stripped[2:]
            if not isinstance(holder, list):
                lst: list[Any] = []
                if parent is not None and parent_key is not None:
                    parent[parent_key] = lst
                    stack[-1] = (stack[-1][0], lst, parent, parent_key)
                holder = lst
            if ":" in item:
                key, _, val = item.partition(":")
                node: dict[str, Any] = {}
                key = key.strip()
                val = val.strip()
                node[key] = _parse_scalar(val) if val else ( [] if key in list_keys else {} )
                holder.append(node)
                if not val:
                    stack.append((indent + 2, node[key], node, key))
                stack.append((indent + 1, node, holder, None))
            else:
                holder.append(_parse_scalar(item))
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()
        if not isinstance(holder, dict):
            # mapping keys after a list item belong to that item
            if isinstance(parent, list) and parent:
                last = parent[-1]
                if isinstance(last, dict):
                    holder = last
                else:
                    raise ValueError(f"mapping entry under non-map: {line}")
            else:
                raise ValueError(f"mapping entry under non-map: {line}")
        if not val:
            nxt: Any = [] if key in list_keys else {}
            holder[key] = nxt
            stack.append((indent, nxt, holder, key))
        else:
            holder[key] = _parse_scalar(val)

    # Promote empty maps that are actually lists: heuristic — if all children
    # were appended via '-' they already live as lists. Convert leftover {}
    # that should be lists when a later '-' arrived. Already handled.
    return _normalize_lists(root)


def _normalize_lists(obj: Any) -> Any:
    """Walk the tree; keys that look like lists in our schema stay as-is.

    The simple parser stores list parents as {} until the first '- ', which
    then fails. We instead detect list keys by rewriting on the fly in
    load_simple_yaml. Here we just recurse.
    """
    if isinstance(obj, dict):
        return {k: _normalize_lists(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_lists(v) for v in obj]
    return obj


def detect_platform() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def resolve_config_path(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("ORBIT_CONFIG")
    if env:
        return Path(env).expanduser()
    here = Path(__file__).resolve().parent / "orbit.yaml"
    if here.exists():
        return here
    home = HOME / "orbit.yaml"
    if home.exists():
        return home
    HOME.mkdir(parents=True, exist_ok=True)
    home.write_text(BUNDLED_YAML, encoding="utf-8")
    return home


@dataclass
class Server:
    id: str
    community: str = ""
    city: str = ""
    country: str = ""


CITY_BY_ID = {
    "LB#1": ("Beirut", "LB"),
    "LB#2": ("Beirut", "LB"),
    "LB-BEY": ("Beirut", "LB"),
    "SY#1": ("Damascus", "SY"),
    "SY-DAM": ("Damascus", "SY"),
    "EG#3": ("Cairo", "EG"),
    "EG-CAI": ("Cairo", "EG"),
    "MA#2": ("Casablanca", "MA"),
    "MA-CAS": ("Casablanca", "MA"),
    "MA#4": ("Rabat", "MA"),
    "MA-RAB": ("Rabat", "MA"),
    "AE#2": ("Dubai", "AE"),
    "AE-DXB": ("Dubai", "AE"),
    "PL#6": ("Warsaw", "PL"),
    "PL-WAW": ("Warsaw", "PL"),
    "RO#4": ("Bucharest", "RO"),
    "RO-BUH": ("Bucharest", "RO"),
    "MK#1": ("Skopje", "MK"),
    "MK-SKP": ("Skopje", "MK"),
    "RU#5": ("Moscow", "RU"),
    "RU-MOW": ("Moscow", "RU"),
    "BY#2": ("Minsk", "BY"),
    "BY-MSQ": ("Minsk", "BY"),
    "UA#7": ("Kyiv", "UA"),
    "UA-IEV": ("Kyiv", "UA"),
    "US#88": ("Los Angeles", "US"),
    "US-LAX": ("Los Angeles", "US"),
    "US#27": ("Denver", "US"),
    "US-DEN": ("Denver", "US"),
}

DROPPED_IDS = {"IR#1", "IR#2", "IR-THR", "RU#8", "RU-OVB"}


def is_allowed_exit(server: Server) -> bool:
    """US hops are opt-in: Los Angeles and Denver only. Iran is not on Proton."""
    if server.id.upper() in DROPPED_IDS:
        return False
    country = (server.country or "").upper()
    city = (server.city or "").lower()
    compact = f"{server.id} {server.community}".upper().replace(" ", "")
    looks_us = country in {"US", "USA"} or compact.startswith("US#") or compact.startswith("US-")
    if not looks_us:
        return True
    if city in {"los angeles", "denver"}:
        return True
    if server.id.upper() in {"US#88", "US#27", "US-LAX", "US-DEN"}:
        return True
    return "US-CA" in compact or "US-CO" in compact or "LOS ANGELES" in compact or "DENVER" in compact


@dataclass
class Pool:
    name: str
    mode: str
    servers: list[Server]


@dataclass
class Probe:
    url: str
    timeout_ms: int = 8000
    required: bool = True


@dataclass
class Config:
    backend: str
    platform: str
    tunnels_dir: Path
    kill_switch: bool
    min_hop_seconds: int
    active_pool: str
    pools: list[Pool]
    schedule_enabled: bool
    interval_mode: str
    interval_seconds: int
    random_min_seconds: int
    random_max_seconds: int
    quiet_enabled: bool
    quiet_start: str
    quiet_end: str
    hotkeys_enabled: bool
    hotkeys: dict[str, str]
    sentinel_enabled: bool
    sentinel_interval: int
    fail_threshold: int
    cooldown_minutes: int
    probes: list[Probe]
    block_signatures: list[str]


def _interval_seconds(schedule: dict[str, Any]) -> int:
    if schedule.get("interval_seconds") is not None:
        raw = int(schedule.get("interval_seconds") or 900)
    else:
        raw = int(schedule.get("interval_minutes") or 15) * 60
    return max(15, min(1800, raw))


def parse_config(raw: dict[str, Any]) -> Config:
    pools: list[Pool] = []
    for p in raw.get("pools") or []:
        servers = []
        for s in p.get("servers") or []:
            sid = str(s.get("id") or "")
            if sid.upper() in DROPPED_IDS:
                continue
            city = str(s.get("city") or "")
            country = str(s.get("country") or "")
            if not city or not country:
                mapped = CITY_BY_ID.get(sid.upper()) or CITY_BY_ID.get(sid)
                if mapped:
                    city = city or mapped[0]
                    country = country or mapped[1]
            servers.append(
                Server(
                    id=sid,
                    community=str(s.get("community") or sid),
                    city=city,
                    country=country,
                )
            )
        servers = [s for s in servers if is_allowed_exit(s)]
        pools.append(Pool(name=str(p.get("name")), mode=str(p.get("mode") or "round-robin"), servers=servers))
    schedule = raw.get("schedule") or {}
    quiet = schedule.get("quiet_hours") or {}
    hot = raw.get("hotkeys") or {}
    sent = raw.get("sentinel") or {}
    probes = [
        Probe(
            url=str(pr.get("url")),
            timeout_ms=int(pr.get("timeout_ms") or 8000),
            required=bool(pr.get("required", True)),
        )
        for pr in (sent.get("probes") or [])
    ]
    tunnels = str(raw.get("tunnels_dir") or "~/.orbit/tunnels")
    return Config(
        backend=str(raw.get("backend") or "auto"),
        platform=detect_platform(),
        tunnels_dir=Path(tunnels).expanduser(),
        kill_switch=bool(raw.get("kill_switch", True)),
        min_hop_seconds=max(15, int(raw.get("min_hop_seconds") or 15)),
        active_pool=str(raw.get("active_pool") or (pools[0].name if pools else "")),
        pools=pools,
        schedule_enabled=bool(schedule.get("enabled", True)),
        interval_mode="random" if str(schedule.get("mode") or "fixed") == "random" else "fixed",
        interval_seconds=_interval_seconds(schedule),
        random_min_seconds=max(15, min(900, int(schedule.get("random_min_seconds") or 15))),
        random_max_seconds=max(
            max(15, min(900, int(schedule.get("random_min_seconds") or 15))),
            min(900, int(schedule.get("random_max_seconds") or 900)),
        ),
        quiet_enabled=bool(quiet.get("enabled", False)),
        quiet_start=str(quiet.get("start") or "23:00"),
        quiet_end=str(quiet.get("end") or "07:00"),
        hotkeys_enabled=bool(hot.get("enabled", False)),
        hotkeys={
            k: str(hot.get(k) or "")
            for k in ("next", "prev", "disconnect", "reconnect", "preset1", "preset2", "preset3")
        },
        sentinel_enabled=bool(sent.get("enabled", True)),
        sentinel_interval=int(sent.get("interval_seconds") or 45),
        fail_threshold=int(sent.get("fail_threshold") or 2),
        cooldown_minutes=int(sent.get("cooldown_minutes") or 20),
        probes=probes,
        block_signatures=[str(s).lower() for s in (sent.get("block_signatures") or [])],
    )


# ---------------------------------------------------------------------------
# Logging / lock / status
# ---------------------------------------------------------------------------

_print_lock = threading.Lock()
_gui_queue: queue.Queue[str] | None = None


def log(kind: str, message: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    line = f"{stamp}  {kind.upper():<8}  {message}"
    with _print_lock:
        print(line, flush=True)
        HOME.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    if _gui_queue is not None:
        try:
            _gui_queue.put_nowait(line)
        except Exception:
            pass


def write_status(payload: dict[str, Any]) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def acquire_lock() -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    if LOCK_PATH.exists():
        try:
            pid = int(LOCK_PATH.read_text().strip())
            os.kill(pid, 0)
            raise SystemExit(f"Orbit already running as pid {pid}. Use: python orbit.py stop")
        except (ProcessLookupError, ValueError, OSError):
            pass
    LOCK_PATH.write_text(str(os.getpid()), encoding="utf-8")


def release_lock() -> None:
    try:
        if LOCK_PATH.exists() and LOCK_PATH.read_text().strip() == str(os.getpid()):
            LOCK_PATH.unlink()
    except OSError:
        pass


def stop_daemon() -> int:
    if not LOCK_PATH.exists():
        print("No running Orbit daemon.")
        return 1
    pid = int(LOCK_PATH.read_text().strip() or "0")
    if pid <= 0:
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Signaled pid {pid}.")
        return 0
    except ProcessLookupError:
        LOCK_PATH.unlink(missing_ok=True)
        print("Stale lock removed.")
        return 0


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

class Backend(Protocol):
    name: str

    def connect(self, server: Server) -> None: ...
    def disconnect(self) -> None: ...
    def status_text(self) -> str: ...


def which(cmd: str) -> str | None:
    from shutil import which as _which

    return _which(cmd)


def run(cmd: list[str], timeout: int = 45, quiet: bool = False) -> subprocess.CompletedProcess[str]:
    if not quiet:
        log("sys", " ".join(cmd))
    env = {**os.environ, "PAGER": "cat", "SYSTEMD_PAGER": "cat", "GIT_PAGER": "cat"}
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


@dataclass
class NmConn:
    name: str
    uuid: str
    type: str
    device: str = ""

    @property
    def role(self) -> str:
        n, d, t = self.name.lower(), self.device.lower(), self.type.lower()
        if n.startswith("pvpn-killswitch") or d.startswith("ipv6leakintrf"):
            return "LEAK"
        if t == "wireguard" and (d == "proton0" or n.startswith("protonvpn")):
            return "VPN"
        if t in {"802-11-wireless", "wifi", "802-3-ethernet", "ethernet", "gsm"}:
            return "UPLINK"
        return "OTHER"


def nmcli(*args: str, timeout: int = 20, quiet: bool = False) -> subprocess.CompletedProcess[str]:
    if not which("nmcli"):
        return subprocess.CompletedProcess(["nmcli", *args], 1, "", "nmcli missing")
    return run(["nmcli", "-t", "-c", "no", *args], timeout=timeout, quiet=quiet)


def _parse_nm_rows(text: str, nfields: int) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) < nfields:
            continue
        rows.append(parts[: nfields - 1] + [":".join(parts[nfields - 1 :])])
    return rows


def nm_connections(active: bool = False, quiet: bool = False) -> list[NmConn]:
    args = ["-f", "NAME,UUID,TYPE,DEVICE", "connection", "show"]
    if active:
        args.append("--active")
    r = nmcli(*args, quiet=quiet)
    if r.returncode != 0:
        return []
    out: list[NmConn] = []
    for parts in _parse_nm_rows(r.stdout, 4):
        name, uuid, typ, dev = (parts + ["", "", "", ""])[:4]
        out.append(NmConn(name=name, uuid=uuid, type=typ, device=dev))
    return out


def nm_active() -> list[NmConn]:
    return nm_connections(active=True, quiet=True)


def proton_nm_profiles() -> list[NmConn]:
    seen: set[str] = set()
    out: list[NmConn] = []
    for c in nm_connections():
        if c.type != "wireguard":
            continue
        if not (c.name.lower().startswith("protonvpn") or c.device == "proton0"):
            continue
        if c.uuid in seen:
            continue
        seen.add(c.uuid)
        out.append(c)
    return out


def get_active_proton_profile() -> NmConn | None:
    for c in nm_active():
        if c.role == "VPN":
            return c
    return None


def nm_profile_for(server: Server) -> NmConn | None:
    needles = {server.id.upper(), server.community.upper(), server.id.replace("#", "-").upper()}
    needles.discard("")
    for c in proton_nm_profiles():
        hay = c.name.upper()
        if any(n in hay for n in needles):
            return c
    return None


def wait_device(dev: str, timeout: float = 18) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(c.device == dev for c in nm_active()):
            return True
        time.sleep(0.35)
    return False


def default_route_dev() -> str:
    r = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True, timeout=5)
    text = r.stdout or ""
    if "dev " in text:
        return text.split("dev ", 1)[1].split()[0]
    return ""


def print_nm_state() -> None:
    if not which("nmcli"):
        print("nmcli         missing")
        return
    active = nm_active()
    print(f"nm_active     {len(active)}")
    for c in active:
        print(f"  {c.role:8} {c.name}  type={c.type}  dev={c.device or '-'}  {c.uuid[:8]}")
    profiles = proton_nm_profiles()
    print(f"nm_proton     {len(profiles)} saved WireGuard profiles")
    active_ids = {c.uuid for c in active}
    for p in profiles[:24]:
        mark = " *" if p.uuid in active_ids or p.device == "proton0" else ""
        print(f"  {p.name}{mark}")
    if len(profiles) > 24:
        print(f"  … {len(profiles) - 24} more")


class ProtonOfficial:
    name = "protonvpn"

    def _bin(self) -> str:
        return which("protonvpn") or which("protonvpn-cli") or "protonvpn"

    def connect(self, server: Server) -> None:
        profile = nm_profile_for(server)
        if profile:
            r = nmcli("connection", "up", "uuid", profile.uuid, timeout=45)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip() or r.stdout.strip() or f"nmcli up {profile.name} failed")
            log("link", f"nmcli up {profile.name}")
        else:
            cmd = [self._bin(), "connect"]
            if server.city:
                cmd += ["--city", server.city]
            elif server.country:
                cmd += ["--country", server.country]
            else:
                cmd.append(server.id)
            r = run(cmd, timeout=60)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip() or r.stdout.strip() or "connect failed")
        if which("nmcli") and not wait_device("proton0"):
            log("sys", "proton0 did not appear — tunnel may still be coming up")
        route = default_route_dev()
        if route and route != "proton0":
            log("sys", f"default route dev={route} (expected proton0)")
        active = get_active_proton_profile()
        if active:
            log("link", f"active {active.name} on {active.device}")

    def disconnect(self) -> None:
        active = get_active_proton_profile()
        if active:
            nmcli("connection", "down", "uuid", active.uuid)
        run([self._bin(), "disconnect"])

    def status_text(self) -> str:
        bits = []
        active = get_active_proton_profile()
        if active:
            bits.append(f"{active.name} dev={active.device}")
        r = run([self._bin(), "status"], timeout=20)
        cli = (r.stdout or r.stderr).strip()
        if cli:
            bits.append(cli)
        return " | ".join(bits) or "protonvpn idle"


class ProtonCommunity:
    name = "protonvpn-community"

    def connect(self, server: Server) -> None:
        binary = which("protonvpn") or "protonvpn"
        r = run([binary, "connect", server.community])
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or r.stdout.strip() or "connect failed")

    def disconnect(self) -> None:
        binary = which("protonvpn") or "protonvpn"
        run([binary, "disconnect"])

    def status_text(self) -> str:
        binary = which("protonvpn") or "protonvpn"
        r = run([binary, "status"], timeout=20)
        return (r.stdout or r.stderr).strip()


class WireGuard:
    name = "wireguard"

    def __init__(self, tunnels_dir: Path, platform: str) -> None:
        self.tunnels_dir = tunnels_dir
        self.platform = platform
        self._up: str | None = None

    def _conf(self, server: Server) -> Path:
        stem = server.id.replace("#", "-")
        candidates = [
            self.tunnels_dir / f"{stem}.conf",
            self.tunnels_dir / f"{server.community}.conf",
            self.tunnels_dir / f"{server.id}.conf",
        ]
        for path in candidates:
            if path.exists():
                return path
        raise FileNotFoundError(
            f"No WireGuard config for {server.id}. Export it from Proton and save as {candidates[0]}"
        )

    def connect(self, server: Server) -> None:
        conf = self._conf(server)
        self.disconnect()
        if self.platform == "windows" or os.name == "nt":
            wg = which("wireguard") or r"C:\Program Files\WireGuard\wireguard.exe"
            r = run([wg, "/installtunnelservice", str(conf)])
        else:
            r = run(["wg-quick", "up", str(conf)])
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or r.stdout.strip() or "wireguard up failed")
        self._up = conf.stem

    def disconnect(self) -> None:
        if self.platform == "windows" or os.name == "nt":
            wg = which("wireguard") or r"C:\Program Files\WireGuard\wireguard.exe"
            if self._up:
                run([wg, "/uninstalltunnelservice", self._up])
        else:
            if self._up:
                conf = self.tunnels_dir / f"{self._up}.conf"
                if conf.exists():
                    run(["wg-quick", "down", str(conf)])
        self._up = None

    def status_text(self) -> str:
        if which("wg"):
            r = run(["wg", "show"], timeout=10)
            return (r.stdout or "").strip() or "wireguard idle"
        return f"up={self._up}" if self._up else "wireguard idle"


class OpenVPN:
    name = "openvpn"

    def __init__(self, tunnels_dir: Path, platform: str) -> None:
        self.tunnels_dir = tunnels_dir
        self.platform = platform
        self._name: str | None = None

    def connect(self, server: Server) -> None:
        stem = server.id.replace("#", "-")
        for name in (f"{stem}.ovpn", f"{server.community}.ovpn"):
            path = self.tunnels_dir / name
            if path.exists():
                break
        else:
            raise FileNotFoundError(f"No OpenVPN profile for {server.id} in {self.tunnels_dir}")
        if self.platform == "windows" or os.name == "nt":
            gui = which("openvpn-gui") or r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe"
            run([gui, "--command", "disconnect_all"])
            r = run([gui, "--command", "connect", path.name])
        else:
            r = run(["openvpn", "--config", str(path), "--daemon", "orbit"])
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "openvpn connect failed")
        self._name = path.name

    def disconnect(self) -> None:
        if self.platform == "windows" or os.name == "nt":
            gui = which("openvpn-gui") or r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe"
            run([gui, "--command", "disconnect_all"])
        else:
            run(["pkill", "-f", "openvpn --config"])
        self._name = None

    def status_text(self) -> str:
        return self._name or "openvpn idle"


class DryRun:
    name = "dry-run"

    def connect(self, server: Server) -> None:
        log("link", f"dry-run connect {server.id}")

    def disconnect(self) -> None:
        log("link", "dry-run disconnect")

    def status_text(self) -> str:
        return "dry-run"


def has_tunnel_files(cfg: Config, suffix: str) -> bool:
    for pool in cfg.pools:
        for server in pool.servers:
            stem = server.id.replace("#", "-")
            for name in (f"{stem}{suffix}", f"{server.community}{suffix}", f"{server.id}{suffix}"):
                if (cfg.tunnels_dir / name).exists():
                    return True
    return False


def proton_cli() -> str | None:
    return which("protonvpn") or which("protonvpn-cli")


def proton_signed_in() -> bool:
    if get_active_proton_profile():
        return True
    binary = proton_cli()
    if not binary:
        return False
    r = subprocess.run([binary, "status"], capture_output=True, text=True, timeout=20)
    text = f"{r.stdout} {r.stderr}".lower()
    if any(s in text for s in ("signin", "sign in", "authentication required", "not logged", "please log")):
        return False
    return r.returncode == 0


def pick_backend(cfg: Config, dry: bool) -> Backend:
    if dry:
        return DryRun()
    kind = cfg.backend
    if kind == "auto":
        if proton_cli() or get_active_proton_profile() or proton_nm_profiles():
            if proton_signed_in() or get_active_proton_profile():
                kind = "protonvpn-cli"
            else:
                log("sys", f"{proton_cli() or 'protonvpn'} installed — sign in with: protonvpn signin")
                kind = ""
        elif (which("wg-quick") or which("wireguard")) and has_tunnel_files(cfg, ".conf"):
            kind = "wireguard"
        elif (which("openvpn") or which("openvpn-gui")) and has_tunnel_files(cfg, ".ovpn"):
            kind = "openvpn"
        else:
            kind = ""
        if not kind:
            log("sys", "no Proton tunnel yet — dry-run prototype (hops are logged, no VPN)")
            return DryRun()
    if kind in ("protonvpn-cli", "protonvpn"):
        return ProtonOfficial()
    if kind == "protonvpn-community":
        return ProtonCommunity()
    if kind == "wireguard":
        return WireGuard(cfg.tunnels_dir, cfg.platform)
    if kind == "openvpn":
        return OpenVPN(cfg.tunnels_dir, cfg.platform)
    raise SystemExit(f"Unknown backend: {kind}")


# ---------------------------------------------------------------------------
# Rotator
# ---------------------------------------------------------------------------

@dataclass
class Rotator:
    cfg: Config
    backend: Backend
    lock: threading.Lock = field(default_factory=threading.Lock)
    current: Server | None = None
    last_hop: float = 0.0
    next_due: float = 0.0
    skipped: dict[str, float] = field(default_factory=dict)
    stop: threading.Event = field(default_factory=threading.Event)
    clock_wake: threading.Event = field(default_factory=threading.Event)

    def pool(self) -> Pool:
        for p in self.cfg.pools:
            if p.name == self.cfg.active_pool:
                return p
        if not self.cfg.pools:
            raise RuntimeError("No pools in config")
        return self.cfg.pools[0]

    def live(self) -> list[Server]:
        now = time.monotonic()
        expired = [k for k, until in self.skipped.items() if until <= now]
        for k in expired:
            self.skipped.pop(k, None)
        servers = self.pool().servers
        live = [s for s in servers if s.id not in self.skipped and is_allowed_exit(s)]
        return live

    def pick(self, direction: int) -> Server:
        pool = self.pool()
        live = self.live()
        if not live:
            raise RuntimeError(f"Pool {pool.name} has no allowed servers")
        if pool.mode == "random":
            choices = [s for s in live if not self.current or s.id != self.current.id] or live
            return random.choice(choices)
        if pool.mode == "lowest-load":
            return live[0]
        servers = pool.servers
        if not servers:
            raise RuntimeError(f"Pool {pool.name} is empty")
        ids = [s.id for s in servers]
        idx = ids.index(self.current.id) if self.current and self.current.id in ids else -1
        for step in range(1, len(servers) + 1):
            nxt = servers[(idx + direction * step) % len(servers)]
            if nxt.id not in self.skipped and is_allowed_exit(nxt):
                return nxt
        return live[0]

    def hop(self, reason: str, direction: int = 1) -> Server | None:
        with self.lock:
            now = time.monotonic()
            if self.last_hop and now - self.last_hop < self.cfg.min_hop_seconds:
                log("sys", "hop held — min interval")
                return None
            try:
                target = self.pick(direction)
            except RuntimeError as exc:
                log("sys", str(exc))
                return None
            prev = self.current.city or self.current.id if self.current else "idle"
            dest = target.city or target.id
            log("hop", f"{prev} → {dest}  ({reason})")
            try:
                self.backend.connect(target)
            except Exception as exc:
                log("link", f"connect failed: {exc}")
                self.skipped[target.id] = now + self.cfg.cooldown_minutes * 60
                return None
            self.current = target
            self.last_hop = now
            if self.cfg.schedule_enabled:
                self.next_due = time.monotonic() + next_wait_seconds(self.cfg)
            if reason != "clock":
                self.clock_wake.set()
            write_status(
                {
                    "server": target.id,
                    "city": target.city,
                    "country": target.country,
                    "community": target.community,
                    "pool": self.pool().name,
                    "reason": reason,
                    "next_due": round(self.next_due, 1) if self.next_due else 0,
                    "at": datetime.now().isoformat(timespec="seconds"),
                    "backend": getattr(self.backend, "name", ""),
                }
            )
            log("link", f"up {target.id}")
            return target

    def disconnect(self) -> None:
        with self.lock:
            self.backend.disconnect()
            self.current = None
            log("link", "tunnel down")
            write_status({"server": None, "at": datetime.now().isoformat(timespec="seconds")})

    def cooldown(self, server_id: str) -> None:
        self.skipped[server_id] = time.monotonic() + self.cfg.cooldown_minutes * 60
        log("sentinel", f"{server_id} cooling {self.cfg.cooldown_minutes}m")


# ---------------------------------------------------------------------------
# Clock / sentinel / hotkeys
# ---------------------------------------------------------------------------

def in_quiet_hours(cfg: Config, when: datetime | None = None) -> bool:
    if not cfg.quiet_enabled:
        return False
    when = when or datetime.now()
    sh, sm = (int(x) for x in cfg.quiet_start.split(":"))
    eh, em = (int(x) for x in cfg.quiet_end.split(":"))
    now = when.hour * 60 + when.minute
    start, end = sh * 60 + sm, eh * 60 + em
    if start == end:
        return False
    if start < end:
        return start <= now < end
    return now >= start or now < end


def next_wait_seconds(cfg: Config) -> float:
    if cfg.interval_mode == "random":
        lo = float(cfg.random_min_seconds)
        hi = float(max(cfg.random_min_seconds, cfg.random_max_seconds))
        return random.uniform(lo, hi)
    return float(cfg.interval_seconds)


def clock_loop(rot: Rotator) -> None:
    log(
        "clock",
        f"mode={rot.cfg.interval_mode}  "
        + (
            f"{rot.cfg.random_min_seconds}s-{rot.cfg.random_max_seconds}s"
            if rot.cfg.interval_mode == "random"
            else f"{rot.cfg.interval_seconds}s"
        ),
    )
    while not rot.stop.is_set():
        if not rot.cfg.schedule_enabled:
            rot.next_due = 0.0
            if rot.stop.wait(0.4):
                break
            rot.clock_wake.wait(0.4)
            rot.clock_wake.clear()
            continue
        wait = next_wait_seconds(rot.cfg)
        rot.next_due = time.monotonic() + wait
        log("clock", f"next hop in {wait:.0f}s")
        aborted = False
        while time.monotonic() < rot.next_due:
            left = min(0.4, max(0.05, rot.next_due - time.monotonic()))
            if rot.stop.wait(left):
                return
            if rot.clock_wake.is_set():
                rot.clock_wake.clear()
                aborted = True
                break
            if not rot.cfg.schedule_enabled:
                aborted = True
                break
        if aborted:
            continue
        if in_quiet_hours(rot.cfg):
            log("clock", "quiet hours — skip")
            continue
        rot.hop("clock")


def fetch(probe: Probe, signatures: list[str]) -> tuple[bool, str]:
    req = urllib.request.Request(
        probe.url,
        headers={"User-Agent": "Orbit/1.0 (ProtonVPN rotator)", "Accept": "*/*"},
        method="GET",
    )
    timeout = max(1.0, probe.timeout_ms / 1000)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            body = resp.read(8192).decode("utf-8", errors="replace").lower()
            if status in (403, 451, 406) or status >= 500:
                return False, f"HTTP {status}"
            for sig in signatures:
                if sig and sig in body:
                    return False, f"blocked signature {sig!r}"
            return True, f"HTTP {status}"
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 451) or exc.code >= 500:
            return False, f"HTTP {exc.code}"
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, type(exc).__name__ + ": " + str(exc)


def sentinel_loop(rot: Rotator) -> None:
    fails = 0
    log("sentinel", f"every {rot.cfg.sentinel_interval}s  threshold={rot.cfg.fail_threshold}")
    while not rot.stop.wait(max(5, rot.cfg.sentinel_interval)):
        if not rot.current:
            continue
        round_ok = True
        detail = "ok"
        for probe in rot.cfg.probes:
            ok, detail = fetch(probe, rot.cfg.block_signatures)
            if not ok:
                log("sentinel", f"{probe.url}  {detail}")
                if probe.required:
                    round_ok = False
                    break
        if round_ok:
            fails = 0
            continue
        fails += 1
        log("sentinel", f"fail {fails}/{rot.cfg.fail_threshold}")
        if fails >= rot.cfg.fail_threshold:
            if rot.current:
                rot.cooldown(rot.current.id)
            fails = 0
            rot.hop("sentinel")


def chord_to_pynput(chord: str) -> str:
    parts = [p.strip().lower() for p in chord.split("+") if p.strip()]
    mapped = []
    keymap = {
        "ctrl": "<ctrl>",
        "control": "<ctrl>",
        "alt": "<alt>",
        "option": "<alt>",
        "shift": "<shift>",
        "meta": "<cmd>",
        "cmd": "<cmd>",
        "super": "<cmd>",
        "arrowright": "<right>",
        "arrowleft": "<left>",
        "arrowup": "<up>",
        "arrowdown": "<down>",
    }
    for p in parts:
        mapped.append(keymap.get(p, p if len(p) == 1 else f"<{p}>"))
    return "+".join(mapped)


def start_hotkeys(rot: Rotator) -> Any:
    try:
        from pynput.keyboard import GlobalHotKeys
    except ImportError as exc:
        log("sys", f"hotkeys off — {exc}. In the Orbit venv: pip install pynput")
        return None

    def bind(action: str):
        def _inner() -> None:
            if action == "next":
                rot.hop("key", 1)
            elif action == "prev":
                rot.hop("key", -1)
            elif action == "disconnect":
                rot.disconnect()
            elif action == "reconnect":
                rot.hop("key", 1)
            elif action.startswith("preset"):
                idx = int(action[-1]) - 1
                if 0 <= idx < len(rot.cfg.pools):
                    rot.cfg.active_pool = rot.cfg.pools[idx].name
                    log("key", f"pool {rot.cfg.active_pool}")
                    rot.hop("key", 1)

        return _inner

    mapping = {}
    for action, chord in rot.cfg.hotkeys.items():
        if not chord:
            continue
        mapping[chord_to_pynput(chord)] = bind(action)
    if not mapping:
        return None
    listener = GlobalHotKeys(mapping)
    listener.start()
    log("key", "global hotkeys armed")
    return listener


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_test_clock() -> int:
    """Dry-run: a GUI-style hop("key") must cancel the in-flight clock wait."""
    cfg = parse_config(load_simple_yaml(BUNDLED_YAML))
    cfg.min_hop_seconds = 0
    cfg.schedule_enabled = True
    cfg.interval_mode = "fixed"
    cfg.interval_seconds = 5
    cfg.sentinel_enabled = False
    cfg.hotkeys_enabled = False
    rot = Rotator(cfg=cfg, backend=DryRun())
    reasons: list[str] = []
    orig = Rotator.hop

    def tracked(reason: str, direction: int = 1) -> Server | None:
        reasons.append(reason)
        return orig(rot, reason, direction)

    rot.hop = tracked  # type: ignore[method-assign]
    worker = threading.Thread(target=clock_loop, args=(rot,), daemon=True, name="clock-test")
    worker.start()
    for _ in range(40):
        if rot.next_due:
            break
        time.sleep(0.05)
    if not rot.next_due:
        print("FAIL  clock never armed next_due")
        rot.stop.set()
        return 1
    original_due = rot.next_due
    time.sleep(1.0)
    rot.hop("key", 1)
    if reasons[:1] != ["key"]:
        print(f"FAIL  expected first hop reason 'key', got {reasons}")
        rot.stop.set()
        return 1
    time.sleep(0.5)
    if rot.next_due <= original_due:
        print(f"FAIL  next_due did not move forward ({original_due:.2f} -> {rot.next_due:.2f})")
        rot.stop.set()
        return 1
    leftover_window = original_due + 0.35
    while time.monotonic() < leftover_window:
        time.sleep(0.05)
    if "clock" in reasons:
        print(f"FAIL  clock hopped on leftover timer  reasons={reasons}")
        rot.stop.set()
        return 1
    rot.stop.set()
    rot.clock_wake.set()
    print("PASS  GUI hop('key') reset the clock")
    print(f"      reasons={reasons}  due {original_due:.2f} -> {rot.next_due:.2f}")
    return 0


def load_cfg(path: Path) -> Config:
    if not path.exists():
        raise SystemExit(f"Missing config: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        raw = json.loads(text)
    else:
        raw = load_simple_yaml(text)
    cfg = parse_config(raw)
    if not cfg.pools or not cfg.pools[0].servers:
        raise SystemExit("Config has no servers. Add a pool in orbit.yaml.")
    return cfg


def cmd_start(cfg: Config, dry: bool) -> int:
    rot, listener = spawn_rotator(cfg, dry)

    def shutdown(*_args: Any) -> None:
        teardown_rotator(rot, listener)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        while not rot.stop.wait(1):
            pass
    finally:
        shutdown()
    return 0


def spawn_rotator(cfg: Config, dry: bool) -> tuple[Rotator, Any]:
    acquire_lock()
    rot = Rotator(cfg=cfg, backend=pick_backend(cfg, dry))
    log("sys", f"backend={rot.backend.name}  pool={rot.pool().name}  n={len(rot.pool().servers)}")
    rot.hop("start")
    threading.Thread(target=clock_loop, args=(rot,), daemon=True, name="clock").start()
    if cfg.sentinel_enabled and cfg.probes:
        threading.Thread(target=sentinel_loop, args=(rot,), daemon=True, name="sentinel").start()
    listener = start_hotkeys(rot) if cfg.hotkeys_enabled else None
    return rot, listener


def teardown_rotator(rot: Rotator, listener: Any) -> None:
    log("sys", "stopping")
    rot.stop.set()
    try:
        rot.disconnect()
    except Exception as exc:
        log("sys", str(exc))
    if listener:
        try:
            listener.stop()
        except Exception:
            pass
    release_lock()


def want_gui() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def ensure_tk() -> None:
    try:
        import tkinter  # noqa: F401

        return
    except ImportError:
        pass
    if which("apt-get"):
        ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        sudo_run(["sudo", "apt-get", "install", "-y", "python3-tk", f"python{ver}-tk"])


def cmd_gui(cfg: Config, dry: bool) -> int:
    global _gui_queue
    ensure_tk()
    try:
        import tkinter as tk
        from tkinter import font as tkfont
        from tkinter import ttk
    except ImportError:
        print("deps          python3-tk missing — install it and re-run")
        return cmd_start(cfg, dry)

    if LOCK_PATH.exists():
        try:
            pid = int(LOCK_PATH.read_text().strip() or "0")
            if pid and pid != os.getpid():
                os.kill(pid, 0)
                stop_daemon()
                time.sleep(0.5)
        except (ProcessLookupError, ValueError, OSError):
            LOCK_PATH.unlink(missing_ok=True)

    _gui_queue = queue.Queue()
    rot, listener = spawn_rotator(cfg, dry)

    bg, raised, fg, muted, accent = "#12110f", "#1c1a17", "#ece8e1", "#9a9186", "#c4a574"
    root = tk.Tk()
    root.title("Orbit")
    root.configure(bg=bg)
    root.minsize(520, 560)
    root.geometry("640x720")
    try:
        root.tk.call("tk", "scaling", 1.15)
    except tk.TclError:
        pass

    family = "Noto Sans"
    available = set(tkfont.families())
    for candidate in ("IBM Plex Sans", "Noto Sans", "DejaVu Sans"):
        if candidate in available:
            family = candidate
            break

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("TFrame", background=bg)
    style.configure("Card.TFrame", background=raised)
    style.configure("TLabel", background=bg, foreground=fg, font=(family, 11))
    style.configure("Muted.TLabel", background=bg, foreground=muted, font=(family, 9))
    style.configure("Display.TLabel", background=bg, foreground=fg, font=(family, 22))
    style.configure("TButton", font=(family, 10), padding=8)
    style.configure("Accent.TButton", font=(family, 10, "bold"), padding=8)

    outer = ttk.Frame(root, style="TFrame")
    outer.pack(fill="both", expand=True, padx=20, pady=18)

    ttk.Label(outer, text="ORBIT", style="Muted.TLabel").pack(anchor="w")
    current_var = tk.StringVar(
        value=(f"{rot.current.city} ({rot.current.country})" if rot.current and rot.current.city else (rot.current.id if rot.current else "idle"))
    )
    ttk.Label(outer, textvariable=current_var, style="Display.TLabel").pack(anchor="w", pady=(4, 0))
    detail_var = tk.StringVar(value=f"{rot.backend.name} · {rot.pool().name}")
    eta_var = tk.StringVar(value="…")
    ttk.Label(outer, textvariable=detail_var, style="Muted.TLabel").pack(anchor="w", pady=(2, 0))
    ttk.Label(outer, textvariable=eta_var, style="Display.TLabel").pack(anchor="w", pady=(0, 14))

    btns = ttk.Frame(outer, style="TFrame")
    btns.pack(fill="x")

    def bg_call(fn: Any) -> None:
        threading.Thread(target=fn, daemon=True).start()

    ttk.Button(btns, text="Hop", style="Accent.TButton", command=lambda: bg_call(lambda: rot.hop("key", 1))).pack(
        side="left", padx=(0, 8)
    )
    ttk.Button(btns, text="Prev", command=lambda: bg_call(lambda: rot.hop("key", -1))).pack(side="left", padx=(0, 8))
    ttk.Button(btns, text="Disconnect", command=lambda: bg_call(rot.disconnect)).pack(side="left", padx=(0, 8))
    ttk.Button(btns, text="Reconnect", command=lambda: bg_call(lambda: rot.hop("key", 1))).pack(side="left")

    ttk.Label(outer, text="POOL", style="Muted.TLabel").pack(anchor="w", pady=(18, 6))
    pools = ttk.Frame(outer, style="TFrame")
    pools.pack(fill="x")

    def set_pool(name: str) -> None:
        rot.cfg.active_pool = name
        log("key", f"pool {name}")
        bg_call(lambda: rot.hop("key", 1))

    for pool in rot.cfg.pools:
        ttk.Button(pools, text=pool.name, command=lambda n=pool.name: set_pool(n)).pack(side="left", padx=(0, 8))

    ttk.Label(outer, text="CLOCK", style="Muted.TLabel").pack(anchor="w", pady=(18, 6))
    clock_row = ttk.Frame(outer, style="TFrame")
    clock_row.pack(fill="x")
    clock_on = tk.BooleanVar(value=rot.cfg.schedule_enabled)
    clock_mode = tk.StringVar(value=rot.cfg.interval_mode)
    style.configure("TCheckbutton", background=bg, foreground=fg, font=(family, 10))
    style.configure("TRadiobutton", background=bg, foreground=fg, font=(family, 10))

    def nudge_clock() -> None:
        rot.cfg.schedule_enabled = bool(clock_on.get())
        rot.cfg.interval_mode = "random" if clock_mode.get() == "random" else "fixed"
        rot.clock_wake.set()
        log(
            "clock",
            f"{'on' if rot.cfg.schedule_enabled else 'off'}  "
            + (
                f"random {rot.cfg.random_min_seconds}-{rot.cfg.random_max_seconds}s"
                if rot.cfg.interval_mode == "random"
                else f"set {rot.cfg.interval_seconds}s"
            ),
        )

    ttk.Checkbutton(clock_row, text="Timed hops", variable=clock_on, command=nudge_clock).pack(side="left", padx=(0, 12))
    ttk.Radiobutton(clock_row, text="Random 15s–15m", variable=clock_mode, value="random", command=nudge_clock).pack(
        side="left", padx=(0, 8)
    )
    ttk.Radiobutton(clock_row, text="Set interval", variable=clock_mode, value="fixed", command=nudge_clock).pack(
        side="left", padx=(0, 8)
    )

    def test_timer() -> None:
        def _run() -> None:
            if not rot.cfg.schedule_enabled:
                log("clock", "FAIL  turn Timed hops on first")
                return
            saved = rot.cfg.min_hop_seconds
            rot.cfg.min_hop_seconds = 0
            try:
                before = rot.next_due
                time.sleep(0.25)
                rot.hop("key", 1)
                time.sleep(0.55)
                after = rot.next_due
            finally:
                rot.cfg.min_hop_seconds = saved
            if after != before and after > time.monotonic():
                log("clock", f"PASS  GUI hop reset timer  {before:.1f} → {after:.1f}")
            else:
                log("clock", f"FAIL  timer did not reset  {before:.1f} → {after:.1f}")

        bg_call(_run)

    ttk.Button(clock_row, text="Test timer", command=test_timer).pack(side="left")

    scale_row = ttk.Frame(outer, style="TFrame")
    scale_row.pack(fill="x", pady=(6, 0))
    ttk.Label(scale_row, text="set", style="Muted.TLabel").pack(side="left")
    fixed_var = tk.IntVar(value=rot.cfg.interval_seconds)

    def on_fixed(_event: object | None = None) -> None:
        rot.cfg.interval_seconds = max(15, min(1800, int(float(fixed_var.get()))))

    ttk.Scale(scale_row, from_=15, to=1800, variable=fixed_var, command=lambda _v: on_fixed()).pack(
        side="left", fill="x", expand=True, padx=8
    )
    fixed_lbl = ttk.Label(scale_row, text=f"{rot.cfg.interval_seconds}s", style="Muted.TLabel")
    fixed_lbl.pack(side="left")

    def fmt_eta() -> str:
        if not rot.cfg.schedule_enabled:
            return "clock off"
        if not rot.next_due:
            return "arming…"
        left = max(0, int(rot.next_due - time.monotonic()))
        return f"next hop {left // 60}:{left % 60:02d}"

    ttk.Label(outer, text="LOG", style="Muted.TLabel").pack(anchor="w", pady=(18, 6))
    logbox = tk.Text(
        outer,
        height=18,
        bg=raised,
        fg=fg,
        insertbackground=fg,
        relief="flat",
        wrap="word",
        font=("IBM Plex Mono", 9) if "IBM Plex Mono" in available else ("monospace", 9),
        highlightthickness=0,
        padx=10,
        pady=10,
    )
    logbox.pack(fill="both", expand=True)
    logbox.tag_configure("muted", foreground=muted)

    def drain() -> None:
        moved = False
        while _gui_queue is not None:
            try:
                line = _gui_queue.get_nowait()
            except queue.Empty:
                break
            logbox.insert("end", line + "\n")
            moved = True
        if moved:
            logbox.see("end")
        if rot.current and rot.current.city:
            current_var.set(f"{rot.current.city} ({rot.current.country})")
        else:
            current_var.set(rot.current.id if rot.current else "idle")
        detail_var.set(f"{rot.backend.name} · {rot.pool().name}")
        eta_var.set(fmt_eta())
        fixed_lbl.configure(text=f"{int(fixed_var.get())}s")
        root.after(200, drain)

    def on_close() -> None:
        teardown_rotator(rot, listener)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(100, drain)
    log("sys", "GUI up")
    try:
        root.mainloop()
    finally:
        if not rot.stop.is_set():
            teardown_rotator(rot, listener)
        _gui_queue = None
    return 0


def cmd_konsole() -> int:
    py = venv_python() if venv_python().exists() else Path(sys.executable)
    script = HOME / "orbit.py" if (HOME / "orbit.py").exists() else Path(__file__).resolve()
    konsole = which("konsole")
    if not konsole:
        print("konsole not found")
        return 1
    cmd = [konsole, "--title", "Orbit", "-e", str(py), str(script), "gui"]
    print(" ".join(cmd))
    subprocess.Popen(cmd, start_new_session=True)
    return 0


def cmd_hop(cfg: Config, dry: bool, direction: int) -> int:
    rot = Rotator(cfg=cfg, backend=pick_backend(cfg, dry))
    rot.hop("cli", direction)
    return 0


def cmd_probe(cfg: Config) -> int:
    failed = 0
    for probe in cfg.probes:
        ok, detail = fetch(probe, cfg.block_signatures)
        print(f"{'ok  ' if ok else 'FAIL'}  {probe.url}  {detail}")
        if not ok and probe.required:
            failed += 1
    return 1 if failed else 0


def cmd_status(cfg: Config, dry: bool) -> int:
    if STATUS_PATH.exists():
        print(STATUS_PATH.read_text(encoding="utf-8"))
    backend = pick_backend(cfg, dry)
    print(backend.status_text())
    print_nm_state()
    return 0


def cmd_validate(cfg: Config) -> int:
    print(f"pools        {len(cfg.pools)}")
    for p in cfg.pools:
        print(f"  {p.name:16} {p.mode:12} {len(p.servers)} servers")
    print(f"active       {cfg.active_pool}")
    print(f"backend      {cfg.backend}")
    if cfg.interval_mode == "random":
        print(f"schedule     {cfg.schedule_enabled}  random  {cfg.random_min_seconds}s-{cfg.random_max_seconds}s")
    else:
        print(f"schedule     {cfg.schedule_enabled}  fixed  {cfg.interval_seconds}s")
    print(f"hotkeys      {cfg.hotkeys_enabled}")
    print(f"sentinel     {cfg.sentinel_enabled} every {cfg.sentinel_interval}s  n={len(cfg.probes)}")
    return 0


def _tunnel_candidates(cfg: Config, server: Server) -> list[Path]:
    stem = server.id.replace("#", "-")
    return [
        cfg.tunnels_dir / f"{stem}.conf",
        cfg.tunnels_dir / f"{server.community}.conf",
        cfg.tunnels_dir / f"{server.id}.conf",
        cfg.tunnels_dir / f"{stem}.ovpn",
        cfg.tunnels_dir / f"{server.community}.ovpn",
    ]


def cmd_bootstrap(cfg: Config) -> int:
    HOME.mkdir(parents=True, exist_ok=True)
    cfg.tunnels_dir.mkdir(parents=True, exist_ok=True)
    print("deps          installing missing packages (sudo may prompt)")
    ensure_system_packages()
    py = ensure_venv()
    ensure_pynput(py)
    print(f"home          {HOME}")
    print(f"config        {resolve_config_path(None)}")
    print(f"tunnels       {cfg.tunnels_dir}")
    print(f"python        {sys.version.split()[0]}  venv={py}")
    print(f"platform      {cfg.platform} (os={os.name})")
    print(f"protonvpn     {which('protonvpn') or 'missing'}")
    print(f"protonvpn-cli {which('protonvpn-cli') or 'missing'}")
    print(f"wg-quick      {which('wg-quick') or 'missing'}")
    print(f"openvpn       {which('openvpn') or which('openvpn-gui') or 'missing'}")
    pynput_ok = subprocess.run([str(py), "-c", "import pynput"], capture_output=True).returncode == 0
    print(f"pynput        {'ok' if pynput_ok else 'missing'}")
    if proton_cli() and not proton_signed_in():
        print("signin        run:  protonvpn signin")

    missing: list[str] = []
    seen: set[str] = set()
    for pool in cfg.pools:
        for server in pool.servers:
            if server.id in seen:
                continue
            seen.add(server.id)
            if any(path.exists() for path in _tunnel_candidates(cfg, server)):
                continue
            missing.append(f"{server.id.replace('#', '-')}.conf")
    if proton_cli():
        print("tunnels       CLI present — WireGuard files optional")
    elif which("wg-quick") and missing:
        print(f"tunnels       {len(missing)} Proton .conf files not in {cfg.tunnels_dir}")
        print("              export from account.protonvpn.com → WireGuard, or: protonvpn signin")
    elif missing:
        print(f"tunnels       {len(missing)} configs missing in {cfg.tunnels_dir}")
    else:
        print("tunnels       all configs present")
    print_nm_state()
    return 0


def desktop_dir() -> Path | None:
    home = Path.home()
    for path in (home / "Desktop", home / "OneDrive" / "Desktop"):
        if path.exists():
            return path
    return None


def sudo_run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    print(f"deps          {' '.join(cmd)}")
    return subprocess.run(cmd, env=env, timeout=timeout)


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def in_orbit_venv() -> bool:
    try:
        return Path(sys.prefix).resolve() == VENV.resolve()
    except OSError:
        return False


def ensure_venv() -> Path:
    py = venv_python()
    if py.exists():
        return py
    print(f"deps          creating venv {VENV}")
    r = subprocess.run([sys.executable, "-m", "venv", str(VENV)])
    if r.returncode != 0 or not py.exists():
        if which("apt-get"):
            ver = f"{sys.version_info.major}.{sys.version_info.minor}"
            sudo_run(["sudo", "apt-get", "install", "-y", "python3-venv", f"python{ver}-venv", "python3-pip"])
            subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=False)
        if not py.exists():
            raise SystemExit("Could not create a Python venv. Install python3-venv and retry.")
    return py


def ensure_pynput(py: Path) -> None:
    probe = subprocess.run([str(py), "-c", "import pynput"], capture_output=True)
    if probe.returncode == 0:
        print("deps          pynput ok")
        return
    print("deps          pip install pynput")
    r = subprocess.run([str(py), "-m", "pip", "install", "--quiet", "pynput"])
    if r.returncode != 0:
        print("deps          pynput install failed — hotkeys will stay off")


def download_file(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if which("curl"):
        r = subprocess.run(
            ["curl", "-fsSL", "-A", "Orbit/1.0", "-o", str(dest), url],
            timeout=120,
        )
        return r.returncode == 0 and dest.exists() and dest.stat().st_size > 0
    if which("wget"):
        r = subprocess.run(["wget", "-q", "-O", str(dest), url], timeout=120)
        return r.returncode == 0 and dest.exists() and dest.stat().st_size > 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Orbit/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.write_bytes(resp.read())
        return dest.exists() and dest.stat().st_size > 0
    except Exception as exc:
        print(f"deps          download failed: {exc}")
        return False


def ensure_proton_apt_repo() -> bool:
    lists = Path("/etc/apt/sources.list.d")
    if lists.exists() and any("protonvpn" in p.name for p in lists.glob("*")):
        return True
    url = "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.8_all.deb"
    expected = "0b14e71586b22e498eb20926c48c7b434b751149b1f2af9902ef1cfe6b03e180"
    dest = HOME / "protonvpn-stable-release_1.0.8_all.deb"
    print("deps          Proton apt repo")
    if not download_file(url, dest):
        return False
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest != expected:
        print(f"deps          repo checksum {digest[:16]}… — installing anyway if dpkg accepts it")
    r = sudo_run(["sudo", "dpkg", "-i", str(dest)])
    if r.returncode != 0:
        return False
    sudo_run(["sudo", "apt-get", "update"])
    return True


def ensure_system_packages() -> None:
    if os.name == "nt":
        print("deps          Windows: install WireGuard from https://www.wireguard.com/install/")
        return
    if proton_cli() and which("wg-quick"):
        print("deps          Proton CLI + WireGuard already present")
        return
    if which("apt-get"):
        ensure_proton_apt_repo()
        sudo_run(["sudo", "apt-get", "install", "-y", "wireguard"])
        sudo_run(["sudo", "apt-get", "install", "-y", "python3-tk", f"python{sys.version_info.major}.{sys.version_info.minor}-tk"])
        if not proton_cli():
            r = sudo_run(["sudo", "apt-get", "install", "-y", "proton-vpn-cli"])
            if r.returncode != 0 and which("snap"):
                sudo_run(["sudo", "snap", "install", "protonvpn"])
            if not proton_cli():
                print("deps          Proton CLI not installed. After sudo works, run: sudo apt install proton-vpn-cli")
        return
    if which("dnf"):
        pkgs = ["wireguard-tools"]
        if not proton_cli():
            pkgs.append("proton-vpn-cli")
        sudo_run(["sudo", "dnf", "install", "-y", *pkgs])
        return
    if which("pacman"):
        pkgs = ["wireguard-tools"]
        if not proton_cli():
            pkgs.append("proton-vpn-cli")
        sudo_run(["sudo", "pacman", "-S", "--noconfirm", *pkgs])
        return
    print("deps          unknown distro — install Proton CLI and WireGuard yourself")


def write_desktop_launcher(py_path: Path, interpreter: Path | None = None) -> Path | None:
    interp = str(interpreter) if interpreter else ("python" if os.name == "nt" else "python3")
    desk = desktop_dir()
    if os.name == "nt":
        if not desk:
            return None
        bat = desk / "Orbit.bat"
        bat.write_text(
            "\n".join(
                [
                    "@echo off",
                    "setlocal",
                    f'cd /d "{HOME}"',
                    f'"{interp}" "{py_path}"',
                    "if errorlevel 1 pause",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return bat
    if sys.platform == "darwin":
        target = (desk or Path.home()) / "Orbit.command"
        target.write_text(f'#!/bin/bash\ncd "{HOME}"\nexec "{interp}" "{py_path}"\n', encoding="utf-8")
        target.chmod(0o755)
        return target
    apps = Path.home() / ".local" / "share" / "applications"
    apps.mkdir(parents=True, exist_ok=True)
    desktop = apps / "orbit.desktop"
    desktop.write_text(
        "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                "Name=Orbit",
                "Comment=ProtonVPN rotator",
                f'Exec="{interp}" "{py_path}" gui',
                "Terminal=false",
                "Categories=Network;",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return desktop


def cmd_install(dry: bool) -> int:
    if sys.version_info < (3, 10):
        raise SystemExit("Orbit needs Python 3.10 or newer.")
    HOME.mkdir(parents=True, exist_ok=True)
    (HOME / "tunnels").mkdir(exist_ok=True)
    src = Path(__file__).resolve()
    dest_py = HOME / "orbit.py"
    if src != dest_py:
        shutil.copy2(src, dest_py)
    sibling = src.parent / "orbit.yaml"
    dest_yaml = HOME / "orbit.yaml"
    if sibling.exists() and sibling.resolve() != dest_yaml.resolve():
        shutil.copy2(sibling, dest_yaml)
    stale = True
    if dest_yaml.exists():
        text = dest_yaml.read_text(encoding="utf-8")
        stale = "city:" not in text or "IR#1" in text or "Tehran" in text
    if stale:
        dest_yaml.write_text(BUNDLED_YAML, encoding="utf-8")
        print("config        wrote city catalog (Proton live list)")
    os.environ["ORBIT_CONFIG"] = str(dest_yaml)

    ensure_system_packages()
    py = ensure_venv()
    ensure_pynput(py)
    if not in_orbit_venv():
        print(f"python        switching to {py}")
        os.execv(str(py), [str(py), str(dest_py), *sys.argv[1:]])

    shortcut = write_desktop_launcher(dest_py, py)
    if shortcut:
        print(f"shortcut      {shortcut}")
    cfg = load_cfg(dest_yaml)
    cmd_bootstrap(cfg)
    print()
    print(f"installed     {HOME}")
    if want_gui():
        if which("konsole") and not os.environ.get("KONSOLE_VERSION"):
            print("starting      Konsole")
            return cmd_konsole()
        print("starting      GUI")
        return cmd_gui(cfg, dry)
    print("starting      Ctrl+C stops")
    return cmd_start(cfg, dry)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orbit", description="ProtonVPN rotator — clock, hotkeys, sentinel")
    p.add_argument("--config", help="Path to orbit.yaml")
    p.add_argument("--dry-run", action="store_true", help="Log hops without calling a VPN backend")
    sub = p.add_subparsers(dest="cmd", required=False)
    sub.add_parser("install", help="Copy to ~/.orbit, make a shortcut, and start")
    sub.add_parser("gui", help="Open the Orbit window")
    sub.add_parser("konsole", help="Open Orbit in Konsole")
    sub.add_parser("start", help="Run the daemon")
    hop = sub.add_parser("hop", help="Hop once")
    hop.add_argument("--prev", action="store_true")
    sub.add_parser("disconnect", help="Tear down the tunnel")
    sub.add_parser("status", help="Show last hop + backend status")
    sub.add_parser("nm", help="Show NetworkManager Proton / uplink / leak roles")
    sub.add_parser("probe", help="Run sentinel probes once")
    sub.add_parser("test-clock", help="Dry-run: prove a GUI hop resets the timer")
    sub.add_parser("stop", help="Stop a running daemon")
    sub.add_parser("validate", help="Print parsed config")
    sub.add_parser("bootstrap", help="Create folders and report what the machine still needs")
    sub.add_parser("doctor", help="Alias for bootstrap")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "stop":
        return stop_daemon()
    if args.cmd == "test-clock":
        return cmd_test_clock()
    if args.cmd == "konsole":
        return cmd_konsole()
    if args.cmd in (None, "install"):
        return cmd_install(bool(args.dry_run))
    cfg = load_cfg(resolve_config_path(args.config))
    dry = bool(args.dry_run)
    if args.cmd == "gui":
        return cmd_gui(cfg, dry)
    if args.cmd == "start":
        return cmd_start(cfg, dry)
    if args.cmd == "hop":
        return cmd_hop(cfg, dry, -1 if args.prev else 1)
    if args.cmd == "disconnect":
        Rotator(cfg=cfg, backend=pick_backend(cfg, dry)).disconnect()
        return 0
    if args.cmd == "status":
        return cmd_status(cfg, dry)
    if args.cmd == "nm":
        print_nm_state()
        return 0
    if args.cmd == "probe":
        return cmd_probe(cfg)
    if args.cmd == "validate":
        return cmd_validate(cfg)
    if args.cmd in ("bootstrap", "doctor"):
        return cmd_bootstrap(cfg)
    return 2


if __name__ == "__main__":
    sys.exit(main())
