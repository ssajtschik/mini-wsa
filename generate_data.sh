#!/bin/bash

if ! command -v jq &> /dev/null; then
    echo "⚠️  'jq' is required but it is not installed."
    exit 1
fi

if ! command -v uuidgen &> /dev/null; then
    echo "⚠️  'uuidgen' is required but it is not installed."
    exit 1
fi

# Target Endpoint (Should accept a JSON Array)
URL="http://localhost:8080/v1/events/ingest"

# Fallback defaults if arguments are omitted
TOTAL_RECORDS=${1:-1000}  # First argument (Default: 1000)
CHUNK_SIZE=${2:-100}      # Second argument (Default: 100)

# Dynamic Mock Data Pools
SEVERITIES=("LOW" "MEDIUM" "HIGH" "CRITICAL")
STATUSES=("NEW" "INVESTIGATING" "RESOLVED" "IGNORED")
ASSETS=("prod-db-01" "payment-gateway" "user-auth-service" "internal-hr-portal" "k8s-master-node")
MITRE_IDS=("T1110" "T1190" "T1059" "T1071" "T1567")
MITRE_NAMES=("Brute Force" "Exploit Public-Facing Application" "Command and Scripting Interpreter" "Application Layer Protocol" "Exfiltration Over Web Service")

# Realistic Data Pools for Random Selection
POLICIES=("pol_web1" "pol_api_gateway" "pol_internal" "pol_auth_service")
HOSTNAMES=("www.example.com" "api.example.com" "auth.example.com" "admin.example.com")
PATHS=("/api/v2/login" "/v1/payment/checkout" "/admin/config" "/users/profile/update" "/wp-login.php")
METHODS=("POST" "GET" "PUT" "DELETE")
STATUS_CODES=(200 403 401 500 404)
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
  "curl/7.81.0"
  "python-requests/2.28.1"
)
ACTIONS=("DENY" "ALERT" "MONITOR")

# Paired Threat Intelligence (Rules & Categories)
RULE_IDS=("950001" "942100" "933100" "920100")
RULE_NAMES=("SQL_INJECTION" "XSS_ATTACK" "REMOTE_CODE_EXECUTION" "PATH_TRAVERSAL")
RULE_MSGS=("SQL Injection Attack Detected" "Cross-Site Scripting Detected" "RCE Exploit Attempted" "Directory Traversal Attempt")
RULE_SEVERITIES=("HIGH" "MEDIUM" "CRITICAL" "LOW")
RULE_CATEGORIES=("INJECTION" "XSS" "PROTOCOL_VIOLATION" "DATA_LEAKAGE" "BOT" "DOS" "RATE_LIMIT")

# Paired GeoLocations (Country & City)
COUNTRIES=("CN" "US" "RU" "BR" "DE" "IL")
CITIES=("Beijing" "Ashburn" "Moscow" "Sao Paulo" "Frankfurt" "Jerusalem")

echo "🚀 Starting threat event generator..."
echo "📊 Total to generate: $TOTAL_RECORDS | 📦 Chunk Size: $CHUNK_SIZE"
echo "--------------------------------------------------"

chunk_items=()

send_chunk() {
    local batch_size=${#chunk_items[@]}
    if [ $batch_size -eq 0 ]; then return; fi

    echo "📡 Sending a wrapper chunk of $batch_size threat events..."

    # Bundle individual object strings into an array wrapped inside an "events" root object
    local payload=$(jq -n --jsonargs '$ARGS.positional' "${chunk_items[@]}" | jq '{events: .}')

    # Send POST command
    local http_code=$(curl -X POST "$URL" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        --silent --output /dev/null --write-out "%{http_code}")

    echo "📥 Server Response: HTTP $http_code"
    echo "--------------------------------------------------"

    chunk_items=()
}

# Main generation loop
for ((i=1; i<=TOTAL_RECORDS; i++))
do
   # 1. Random Selection
   POLICY=${POLICIES[$RANDOM % ${#POLICIES[@]}]}
   HOSTNAME=${HOSTNAMES[$RANDOM % ${#HOSTNAMES[@]}]}
   PATH_STR=${PATHS[$RANDOM % ${#PATHS[@]}]}
   METHOD=${METHODS[$RANDOM % ${#METHODS[@]}]}
   STATUS_CODE=${STATUS_CODES[$RANDOM % ${#STATUS_CODES[@]}]}
   USER_AGENT=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
   ACTION=${ACTIONS[$RANDOM % ${#ACTIONS[@]}]}

   # Paired Rule matching
   R_IDX=$(( RANDOM % ${#RULE_IDS[@]} ))
   R_ID=${RULE_IDS[$R_IDX]}
   R_NAME=${RULE_NAMES[$R_IDX]}
   R_MSG=${RULE_MSGS[$R_IDX]}
   R_SEV=${RULE_SEVERITIES[$R_IDX]}
   R_CAT=${RULE_CATEGORIES[$R_IDX]}

   # Paired Geo matching
   G_IDX=$(( RANDOM % ${#COUNTRIES[@]} ))
   COUNTRY=${COUNTRIES[$G_IDX]}
   CITY=${CITIES[$G_IDX]}

   # 2. Dynamic generation
#   EVENT_ID="evt-$(printf "%05d" $((RANDOM%100000)))"
   EVENT_ID="evt-$(uuidgen)"
   TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
   CONFIG_ID=$((RANDOM % 20000 + 10000))
   CLIENT_IP="$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))"
   REQ_SIZE=$((RANDOM % 2000 + 512))
   RES_SIZE=$((RANDOM % 1000 + 64))

   # 3. Construct single JSON item matching your schema exactly
   SINGLE_RECORD=$(jq -n \
     --arg eid "$EVENT_ID" \
     --arg ts "$TIMESTAMP" \
     --argjson cid "$CONFIG_ID" \
     --arg pol "$POLICY" \
     --arg ip "$CLIENT_IP" \
     --arg host "$HOSTNAME" \
     --arg path "$PATH_STR" \
     --arg meth "$METHOD" \
     --argjson sc "$STATUS_CODE" \
     --arg ua "$USER_AGENT" \
     --arg rid "$R_ID" \
     --arg rname "$R_NAME" \
     --arg rmsg "$R_MSG" \
     --arg rsev "$R_SEV" \
     --arg rcat "$R_CAT" \
     --arg act "$ACTION" \
     --arg ctry "$COUNTRY" \
     --arg city "$CITY" \
     --argjson reqS "$REQ_SIZE" \
     --argjson resS "$RES_SIZE" \
     '{
       eventId: $eid,
       timestamp: $ts,
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

   # Execute POST if the specified chunk window is reached
   if [ ${#chunk_items[@]} -eq $CHUNK_SIZE ]; then
       send_chunk
       sleep 0.2
   fi
done

# Clear any leftovers
send_chunk

echo "✅ Script complete!"