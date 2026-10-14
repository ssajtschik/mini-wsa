#!/bin/bash
#
# Generates random WAF security events, mixing background noise with "attack waves"
# (bursts from one IP hitting one path with one rule), and either POSTs them to the
# ingest API or writes the request bodies to a file.
#
# Usage: ./generate_data.sh [-n total] [-b batch_size] [-c config_count] [-H hours] [-u url] [-o file]
#   -n  number of events to generate          (default: 1000)
#   -b  events per ingest request             (default: 100)
#   -c  number of distinct configIds          (default: 3, starting at 14227)
#   -H  spread timestamps over the last N hours (default: 24)
#   -u  ingest endpoint                       (default: http://localhost:8080/v1/events/ingest)
#   -o  write one {"events": [...]} request body per line to this file instead of POSTing
#
# Replay a file later with:
#   while read -r body; do curl -s -X POST -H 'Content-Type: application/json' -d "$body" "$URL"; done < file

if ! command -v jq &> /dev/null; then
    echo "⚠️  'jq' is required but it is not installed."
    exit 1
fi

if ! command -v uuidgen &> /dev/null; then
    echo "⚠️  'uuidgen' is required but it is not installed."
    exit 1
fi

TOTAL_RECORDS=1000
CHUNK_SIZE=100
CONFIG_COUNT=3
HOURS=24
URL="http://localhost:8080/v1/events/ingest"
OUTPUT_FILE=""

while getopts "n:b:c:H:u:o:h" opt; do
    case $opt in
        n) TOTAL_RECORDS=$OPTARG ;;
        b) CHUNK_SIZE=$OPTARG ;;
        c) CONFIG_COUNT=$OPTARG ;;
        H) HOURS=$OPTARG ;;
        u) URL=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        *) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
    esac
done

# Realistic Data Pools for Random Selection
POLICIES=("pol_web1" "pol_api_gateway" "pol_internal" "pol_auth_service")
HOSTNAMES=("www.example.com" "api.example.com" "auth.example.com" "admin.example.com")
PATHS=("/api/v2/login" "/v1/payment/checkout" "/admin/config" "/users/profile/update" "/wp-login.php"
       "/api/v1/search" "/static/../../etc/passwd" "/graphql" "/api/v1/export" "/")
METHODS=("POST" "GET" "PUT" "DELETE")
STATUS_CODES=(200 403 401 500 404)
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
  "curl/7.81.0"
  "python-requests/2.28.1"
  "sqlmap/1.7.2#stable"
  "Googlebot/2.1 (+http://www.google.com/bot.html)"
)
ACTIONS=("DENY" "ALERT" "MONITOR")

# Rule catalog covering every category. Each rule has a pool of possible severities.
RULE_IDS=("942100" "941100" "932100" "930100" "920100" "913100" "912100" "912120")
RULE_NAMES=("SQL_INJECTION" "XSS_ATTACK" "REMOTE_CODE_EXECUTION" "PATH_TRAVERSAL" "INVALID_HTTP_REQUEST"
            "BAD_BOT" "HTTP_FLOOD" "RATE_LIMIT_EXCEEDED")
RULE_MSGS=("SQL Injection Attack Detected" "Cross-Site Scripting Detected" "RCE Exploit Attempted"
           "Directory Traversal Attempt" "Invalid HTTP Request Line" "Known Malicious Bot Detected"
           "HTTP Flood Detected" "Request Rate Limit Exceeded")
RULE_CATEGORIES=("INJECTION" "XSS" "INJECTION" "DATA_LEAKAGE" "PROTOCOL_VIOLATION" "BOT" "DOS" "RATE_LIMIT")
RULE_SEVERITY_POOLS=("HIGH CRITICAL" "MEDIUM HIGH" "CRITICAL" "MEDIUM HIGH" "LOW MEDIUM"
                     "LOW MEDIUM" "HIGH CRITICAL" "LOW MEDIUM")

# Paired GeoLocations (Country & City)
COUNTRIES=("CN" "US" "RU" "BR" "DE" "IL")
CITIES=("Beijing" "Ashburn" "Moscow" "Sao Paulo" "Frankfurt" "Jerusalem")

# A small set of attacker IPs that waves are drawn from, so they recur across waves
ATTACKER_IPS=("203.0.113.42" "198.51.100.7" "192.0.2.199" "45.33.32.156" "185.220.101.4" "91.240.118.22")

# Attack waves: chance (in %) that a new wave starts at any non-wave event, and its size range
WAVE_START_PCT=2
WAVE_MIN_SIZE=10
WAVE_MAX_SIZE=50

CONFIG_IDS=()
for ((c=0; c<CONFIG_COUNT; c++)); do CONFIG_IDS+=($((14227 + c))); done

NOW=$(date -u +%s)
WINDOW_SECS=$((HOURS * 3600))

random_ts() {  # random epoch second within the last $WINDOW_SECS
    echo $(( NOW - (RANDOM * 32768 + RANDOM) % WINDOW_SECS ))
}

pick_severity() {  # random severity from the pool of rule $R_IDX
    local sev_pool=(${RULE_SEVERITY_POOLS[$R_IDX]})
    R_SEV=${sev_pool[$RANDOM % ${#sev_pool[@]}]}
}

echo "🚀 Starting threat event generator..."
echo "📊 Total: $TOTAL_RECORDS | 📦 Chunk: $CHUNK_SIZE | 🗂  Configs: ${CONFIG_IDS[*]} | 🕒 Last ${HOURS}h"
if [ -n "$OUTPUT_FILE" ]; then
    echo "💾 Writing request bodies to $OUTPUT_FILE"
    : > "$OUTPUT_FILE"
fi
echo "--------------------------------------------------"

chunk_items=()

send_chunk() {
    local batch_size=${#chunk_items[@]}
    if [ $batch_size -eq 0 ]; then return; fi

    # Bundle individual object strings into an array wrapped inside an "events" root object
    local payload=$(jq -cn --jsonargs '{events: $ARGS.positional}' "${chunk_items[@]}")

    if [ -n "$OUTPUT_FILE" ]; then
        echo "$payload" >> "$OUTPUT_FILE"
        echo "💾 Wrote a chunk of $batch_size threat events"
    else
        echo "📡 Sending a wrapper chunk of $batch_size threat events..."
        local http_code=$(curl -X POST "$URL" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            --silent --output /dev/null --write-out "%{http_code}")
        echo "📥 Server Response: HTTP $http_code"
        sleep 0.2
    fi
    echo "--------------------------------------------------"

    chunk_items=()
}

wave_remaining=0
waves=0

# Main generation loop
for ((i=1; i<=TOTAL_RECORDS; i++))
do
   if [ $wave_remaining -eq 0 ] && [ $(( RANDOM % 100 )) -lt $WAVE_START_PCT ]; then
       # Start a new attack wave: same IP, path, rule, host and config for the whole burst
       waves=$((waves + 1))
       wave_remaining=$(( WAVE_MIN_SIZE + RANDOM % (WAVE_MAX_SIZE - WAVE_MIN_SIZE + 1) ))
       W_IP=${ATTACKER_IPS[$RANDOM % ${#ATTACKER_IPS[@]}]}
       W_PATH=${PATHS[$RANDOM % ${#PATHS[@]}]}
       W_HOST=${HOSTNAMES[$RANDOM % ${#HOSTNAMES[@]}]}
       W_CONFIG=${CONFIG_IDS[$RANDOM % ${#CONFIG_IDS[@]}]}
       W_UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
       G_IDX=$(( RANDOM % ${#COUNTRIES[@]} ))
       W_R_IDX=$(( RANDOM % ${#RULE_IDS[@]} ))
       # Leave room so the whole wave (up to 3s apart) stays in the past
       W_TS=$(( $(random_ts) - WAVE_MAX_SIZE * 3 ))
   fi

   if [ $wave_remaining -gt 0 ]; then
       wave_remaining=$((wave_remaining - 1))
       W_TS=$(( W_TS + 1 + RANDOM % 3 ))
       TS=$W_TS
       CLIENT_IP=$W_IP; PATH_STR=$W_PATH; HOSTNAME=$W_HOST; CONFIG_ID=$W_CONFIG; USER_AGENT=$W_UA
       R_IDX=$W_R_IDX
       pick_severity
       # Waves are mostly blocked
       if [ $(( RANDOM % 10 )) -lt 8 ]; then ACTION="DENY"; STATUS_CODE=403; else ACTION="ALERT"; STATUS_CODE=200; fi
       METHOD="POST"
   else
       # Background traffic: everything random
       TS=$(random_ts)
       CLIENT_IP="$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))"
       PATH_STR=${PATHS[$RANDOM % ${#PATHS[@]}]}
       HOSTNAME=${HOSTNAMES[$RANDOM % ${#HOSTNAMES[@]}]}
       CONFIG_ID=${CONFIG_IDS[$RANDOM % ${#CONFIG_IDS[@]}]}
       USER_AGENT=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
       G_IDX=$(( RANDOM % ${#COUNTRIES[@]} ))
       R_IDX=$(( RANDOM % ${#RULE_IDS[@]} ))
       pick_severity
       ACTION=${ACTIONS[$RANDOM % ${#ACTIONS[@]}]}
       STATUS_CODE=${STATUS_CODES[$RANDOM % ${#STATUS_CODES[@]}]}
       METHOD=${METHODS[$RANDOM % ${#METHODS[@]}]}
   fi

   POLICY=${POLICIES[$RANDOM % ${#POLICIES[@]}]}
   COUNTRY=${COUNTRIES[$G_IDX]}
   CITY=${CITIES[$G_IDX]}
   EVENT_ID="evt-$(uuidgen)"
   REQ_SIZE=$((RANDOM % 2000 + 512))
   RES_SIZE=$((RANDOM % 1000 + 64))

   # Construct single JSON item matching the ingest schema
   SINGLE_RECORD=$(jq -cn \
     --arg eid "$EVENT_ID" \
     --argjson ts "$TS" \
     --argjson cid "$CONFIG_ID" \
     --arg pol "$POLICY" \
     --arg ip "$CLIENT_IP" \
     --arg host "$HOSTNAME" \
     --arg path "$PATH_STR" \
     --arg meth "$METHOD" \
     --argjson sc "$STATUS_CODE" \
     --arg ua "$USER_AGENT" \
     --arg rid "${RULE_IDS[$R_IDX]}" \
     --arg rname "${RULE_NAMES[$R_IDX]}" \
     --arg rmsg "${RULE_MSGS[$R_IDX]}" \
     --arg rsev "$R_SEV" \
     --arg rcat "${RULE_CATEGORIES[$R_IDX]}" \
     --arg act "$ACTION" \
     --arg ctry "$COUNTRY" \
     --arg city "$CITY" \
     --argjson reqS "$REQ_SIZE" \
     --argjson resS "$RES_SIZE" \
     '{
       eventId: $eid,
       timestamp: ($ts | todate),
       configId: $cid,
       policyId: $pol,
       clientIp: $ip,
       hostname: $host,
       path: $path,
       method: $meth,
       statusCode: $sc,
       userAgent: $ua,
       rule: { id: $rid, name: $rname, message: $rmsg, severity: $rsev, category: $rcat },
       action: $act,
       geoLocation: { country: $ctry, city: $city },
       requestSize: $reqS,
       responseSize: $resS
     }')

   chunk_items+=("$SINGLE_RECORD")

   # Flush when the specified chunk window is reached
   if [ ${#chunk_items[@]} -eq $CHUNK_SIZE ]; then
       send_chunk
   fi
done

# Clear any leftovers
send_chunk

echo "✅ Script complete! Generated $TOTAL_RECORDS events including $waves attack wave(s)."
