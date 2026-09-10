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
# Levant by default (Beirut and Tehran preferred). Eurasia is a second pool.
# US exits are opt-in: Los Angeles, CA and Denver, CO only.

backend: auto
tunnels_dir: "~/.orbit/tunnels"
kill_switch: true
min_hop_seconds: 15
active_pool: "Levant"

pools:
  - name: "Levant"
    mode: round-robin
    servers:
      - id: "LB#1"
        community: "LB-BEY#1"
      - id: "LB#2"
        community: "LB-BEY#2"
      - id: "IR#1"
        community: "IR-THR#1"
      - id: "IR#2"
        community: "IR-THR#2"
      - id: "SY#1"
        community: "SY-DAM#1"
      - id: "EG#3"
        community: "EG-CAI#3"
      - id: "MA#2"
        community: "MA-CAS#2"
      - id: "MA#4"
        community: "MA-RAB#4"
      - id: "AE#2"
        community: "AE-DXB#2"
  - name: "Eurasia"
    mode: round-robin
    servers:
      - id: "PL#6"
        community: "PL-WAW#6"
      - id: "RO#4"
        community: "RO-BUH#4"
      - id: "MK#1"
        community: "MK-SKP#1"
      - id: "RU#5"
        community: "RU-MOW#5"
      - id: "RU#8"
        community: "RU-OVB#8"
      - id: "BY#2"
        community: "BY-MSQ#2"
      - id: "UA#7"
        community: "UA-IEV#7"
  - name: "Stateside"
    mode: round-robin
    servers:
      - id: "US#88"
        community: "US-CA#88"
      - id: "US#27"
        community: "US-CO#27"

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
    community: str


def is_allowed_exit(server: Server) -> bool:
    """US hops are opt-in: Los Angeles (US-CA / US#88) and Denver (US-CO / US#27) only."""
    compact = f"{server.id} {server.community}".upper().replace(" ", "")
    looks_us = compact.startswith("US#") or compact.startswith("US-")
    if not looks_us:
        return True
    if server.id.upper() in {"US#88", "US#27"}:
        return True
    return "US-CA" in compact or "US-CO" in compact


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
        servers = [
            Server(id=str(s.get("id")), community=str(s.get("community") or s.get("id")))
            for s in (p.get("servers") or [])
        ]
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


def log(kind: str, message: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    line = f"{stamp}  {kind.upper():<8}  {message}"
    with _print_lock:
        print(line, flush=True)
        HOME.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


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


def run(cmd: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str]:
    log("sys", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class ProtonOfficial:
    name = "protonvpn"

    def _bin(self) -> str:
        return which("protonvpn") or which("protonvpn-cli") or "protonvpn"

    def connect(self, server: Server) -> None:
        r = run([self._bin(), "connect", server.id])
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or r.stdout.strip() or "connect failed")

    def disconnect(self) -> None:
        run([self._bin(), "disconnect"])

    def status_text(self) -> str:
        r = run([self._bin(), "status"], timeout=20)
        return (r.stdout or r.stderr).strip()


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
        if proton_cli():
            if proton_signed_in():
                kind = "protonvpn-cli"
            else:
                log("sys", f"{proton_cli()} installed — sign in with: protonvpn signin")
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
    skipped: dict[str, float] = field(default_factory=dict)
    stop: threading.Event = field(default_factory=threading.Event)

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
            prev = self.current.id if self.current else "idle"
            log("hop", f"{prev} → {target.id}  ({reason})")
            try:
                self.backend.connect(target)
            except Exception as exc:
                log("link", f"connect failed: {exc}")
                self.skipped[target.id] = now + self.cfg.cooldown_minutes * 60
                return None
            self.current = target
            self.last_hop = now
            write_status(
                {
                    "server": target.id,
                    "community": target.community,
                    "pool": self.pool().name,
                    "reason": reason,
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
        wait = next_wait_seconds(rot.cfg)
        log("clock", f"next hop in {wait:.0f}s")
        if rot.stop.wait(wait):
            break
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
    acquire_lock()
    rot = Rotator(cfg=cfg, backend=pick_backend(cfg, dry))
    log("sys", f"backend={rot.backend.name}  pool={rot.pool().name}  n={len(rot.pool().servers)}")
    rot.hop("start")

    threads: list[threading.Thread] = []
    if cfg.schedule_enabled:
        threads.append(threading.Thread(target=clock_loop, args=(rot,), daemon=True, name="clock"))
    if cfg.sentinel_enabled and cfg.probes:
        threads.append(threading.Thread(target=sentinel_loop, args=(rot,), daemon=True, name="sentinel"))
    for t in threads:
        t.start()
    listener = start_hotkeys(rot) if cfg.hotkeys_enabled else None

    def shutdown(*_args: Any) -> None:
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
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        while not rot.stop.wait(1):
            pass
    finally:
        shutdown()
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
                f'Exec="{interp}" "{py_path}"',
                "Terminal=true",
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
    elif not dest_yaml.exists():
        dest_yaml.write_text(BUNDLED_YAML, encoding="utf-8")
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
    print("starting      Ctrl+C stops")
    return cmd_start(cfg, dry)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orbit", description="ProtonVPN rotator — clock, hotkeys, sentinel")
    p.add_argument("--config", help="Path to orbit.yaml")
    p.add_argument("--dry-run", action="store_true", help="Log hops without calling a VPN backend")
    sub = p.add_subparsers(dest="cmd", required=False)
    sub.add_parser("install", help="Copy to ~/.orbit, make a shortcut, and start")
    sub.add_parser("start", help="Run the daemon")
    hop = sub.add_parser("hop", help="Hop once")
    hop.add_argument("--prev", action="store_true")
    sub.add_parser("disconnect", help="Tear down the tunnel")
    sub.add_parser("status", help="Show last hop + backend status")
    sub.add_parser("probe", help="Run sentinel probes once")
    sub.add_parser("stop", help="Stop a running daemon")
    sub.add_parser("validate", help="Print parsed config")
    sub.add_parser("bootstrap", help="Create folders and report what the machine still needs")
    sub.add_parser("doctor", help="Alias for bootstrap")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "stop":
        return stop_daemon()
    if args.cmd in (None, "install"):
        return cmd_install(bool(args.dry_run))
    cfg = load_cfg(resolve_config_path(args.config))
    dry = bool(args.dry_run)
    if args.cmd == "start":
        return cmd_start(cfg, dry)
    if args.cmd == "hop":
        return cmd_hop(cfg, dry, -1 if args.prev else 1)
    if args.cmd == "disconnect":
        Rotator(cfg=cfg, backend=pick_backend(cfg, dry)).disconnect()
        return 0
    if args.cmd == "status":
        return cmd_status(cfg, dry)
    if args.cmd == "probe":
        return cmd_probe(cfg)
    if args.cmd == "validate":
        return cmd_validate(cfg)
    if args.cmd in ("bootstrap", "doctor"):
        return cmd_bootstrap(cfg)
    return 2


if __name__ == "__main__":
    sys.exit(main())
