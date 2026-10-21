# macstalker

Brute-force scanner for **Stalker Portal** IPTV gateways. It generates random MAC addresses from the known prefix `00:1A:79:xx:xx:xx`, tests each one against the portal's STB handshake, and prints the account details (Xtream credentials, content counts, expiry) for every MAC that turns out to be a valid, subscribed STB.

## How it works

For each random MAC the scanner performs:

1. `portal.php … action=handshake` — the portal responds with a token for the MAC
2. `action=get_profile` with `Authorization: Bearer <token>` — the token is validated
3. `action=get_genres` — the genre list must contain **"All"**, which only subscribed accounts get
4. `action=get_main_info` — MAC + phone number of the account
5. `action=create_link` — generates a playback URL, from which the **Xtream username/password** are extracted
6. `player_api.php` — queries the Xtream user for expiry date, max connections and active connections
7. `get_ordered_list` for Live / VOD / Series — content counts for the summary

Workers run in parallel and stop once the requested number of MACs has been found (plus whatever overshoots while workers are mid-scan).

## Requirements

- `bash` 4+
- `curl`
- `jq`
- `flock` (util-linux — needed for the progress line locking)
- `nordvpn` CLI (installed via **nordvpn-gui**) — required, all traffic goes through it

## Usage

```
./macstalker.sh <portal-url>
```

Example:

```
./macstalker.sh http://1.2.3.4:8080
```

You will be asked two questions:

```
How many MACs do you want to find?   (stop after N valid MACs)
Parallel workers? [10]               (default: 10)
```

> **Note:** The portal rate-limits by IP. When your source IP gets blocked the
> scanner shows `connection failed, ratelimited?` and **automatically hops to a
> fresh NordVPN server** (any region) to get a new source IP — see below.

## Output

Every found MAC prints:

```
found:    00:1A:79:E9:2C:9D [+49123456789]
  -> http://1.2.3.4:8080/get.php?username=xt_user&password=xt_pass&type=m3u_plus [max=5 active=1]
```

- The `get.php` link is a ready-to-use **m3u_plus** playlist URL for that Xtream user.
- `max` / `active` are the connection limits from `player_api.php`.

When you hit the target (or press `Ctrl-C`), a summary is printed with all hits sorted by total content size:

```
Summary (sorted by total content):
  00:1A:79:E9:2C:9D  Live TV: 42  VOD: 17  Series: 5
  00:1A:79:87:30:AA  Live TV: 42  VOD: 17  Series: 5
```

## Options / behavior

- Requests use a very low per-request timeout (`SCAN_TIMEOUT=1`, editable at the top of the script) so blocked or ratelimited IPs fail fast instead of stalling workers.
- Accounts that connect but have no subscriptions (no "All" genre) are skipped automatically.

## NordVPN

All traffic runs through an active NordVPN tunnel — the scanner **never scans
without a VPN connection**:

- Before any workers start, `ensure_vpn` makes sure a tunnel is up (connecting
  to a server if needed).
- Whenever a handshake comes back blocked / ratelimited (non-200), the worker
  triggers a hop to a **different** NordVPN server (any region) so the next MACs
  are sent from a fresh source IP.
- The hop is **transparent**: it happens mid-scan, prints a single
  `blocked → new VPN: <country>` status line and immediately resumes scanning.
- **Blocked MACs are not lost** — a MAC whose handshake failed on the current
  endpoint is parked in a retry queue and retried as soon as a fresh VPN
  endpoint is up, so a geo-blocked MAC gets a fair second chance on a new IP
  before the scanner moves on to brand-new random MACs.

A switch happens **immediately** on every block — no waiting, no de-bouncing.
Hops are only **serialized** across workers (only one `nordvpn connect` runs at
a time) so parallel workers don't stack connections on each other.
