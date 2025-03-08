#!/usr/bin/env bash

# XSS Scanner Script v2.0
# Author: @Kdairatchi
# License: MIT

# Configuration
PAYLOAD_FILE="bxssMostUsed.txt"
TOOL_DIR="$HOME/go/bin"
INSTALL_DIR="/usr/local/bin"
TEMP_DIR=$(mktemp -d)
BOLD=$(tput bold)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
NC=$(tput sgr0)

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
    echo -e "\n${BOLD}Cleaned up temporary files${NC}"
}
trap cleanup EXIT

# Display usage message
display_usage() {
    echo -e "${BOLD}${GREEN}XSS Scanner Script v2.0${NC}"
    echo "Usage:"
    echo "  $0 [options] [target]"
    echo ""
    echo "Options:"
    echo "  -h               Display this help message"
    echo "  -d DOMAIN        Single domain scan"
    echo "  -l LIST_FILE     Multiple domains from file"
    echo "  -u URL           Single URL scan"
    echo "  -c               Install required tools"
    echo "  -i               Check tool dependencies"
    echo "  -v               Enable verbose output"
    echo ""
    echo "Examples:"
    echo "  $0 -d example.com"
    echo "  $0 -l domains.txt"
    echo "  $0 -u http://example.com/test?q=1"
    exit 0
}

# Error handling function
fatal() {
    echo -e "${BOLD}${RED}[-] ERROR: $1${NC}" >&2
    exit 1
}

# Check required tools
check_tools() {
    local tools=("anew" "qsreplace" "bxss" "urlfinder" "google-chrome")
    local missing=0

    echo -e "${BOLD}Checking required tools:${NC}"
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}[+]${NC} $tool: $(which $tool)"
        else
            echo -e "${RED}[-]${NC} $tool: Not installed"
            missing=$((missing+1))
        fi
    done
    
    [ $missing -gt 0 ] && fatal "$missing required tools missing"
    return 0
}

# Install required tools
install_tools() {
    echo -e "${BOLD}Installing required tools...${NC}"
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR" || fatal "Failed to enter temp directory"

    # Install Go tools
    for tool in qsreplace anew bxss urlfinder; do
        echo -e "\n${BOLD}Installing $tool...${NC}"
        go install "github.com/tomnomnom/$tool@latest" || \
        go install "github.com/ethicalhackingplayground/$tool@latest" || \
        go install "github.com/projectdiscovery/$tool@latest" || \
        fatal "Failed to install $tool"
    done

    # Install Google Chrome
    if ! command -v google-chrome &>/dev/null; then
        echo -e "\n${BOLD}Installing Google Chrome...${NC}"
        wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
            || fatal "Failed to download Chrome"
        sudo apt install -qq ./google-chrome-stable*.deb -y \
            || fatal "Failed to install Chrome"
    fi

    # Move binaries
    echo -e "\n${BOLD}Moving binaries...${NC}"
    [ -d "$TOOL_DIR" ] && sudo mv -v "$TOOL_DIR"/* "$INSTALL_DIR"/

    # Get payloads
    echo -e "\n${BOLD}Downloading payloads...${NC}"
    wget -q "https://raw.githubusercontent.com/haxshadow/payload/main/bxssMostUsed.txt" \
        && sudo mv bxssMostUsed.txt /usr/local/share/ \
        || fatal "Failed to download payloads"

    echo -e "\n${BOLD}${GREEN}Installation completed!${NC}"
}

# Process domain
process_domain() {
    local domain="$1"
    echo -e "\n${BOLD}Processing domain: ${GREEN}$domain${NC}"
    
    # Remove protocol and www prefix
    local clean_domain=$(echo "$domain" | sed -E 's,^(https?://)?(www\.)?,,i')

    urlfinder -d "$clean_domain" -fs fqdn -all \
        | grep -aviE "\.(js|css|json|ico|woff|woff2|svg|ttf|eot|png|jpg)([?#&]|$)" \
        | qsreplace "BXSS" \
        | grep -ai "BXSS" \
        | anew \
        | bxss -parameters -payloadFile "/usr/local/share/$PAYLOAD_FILE" \
        || fatal "Scan failed for $domain"
}

# Main scan functions
single_url_scan() {
    local url="$1"
    echo -e "\n${BOLD}Scanning single URL: ${GREEN}$url${NC}"
    echo "$url" | bxss -parameters -payloadFile "/usr/local/share/$PAYLOAD_FILE"
}

domain_scan() {
    local domain="$1"
    process_domain "$domain"
}

list_scan() {
    local file="$1"
    [ ! -f "$file" ] && fatal "File not found: $file"
    
    echo -e "\n${BOLD}Scanning multiple domains from: ${GREEN}$file${NC}"
    while IFS= read -r domain; do
        [ -n "$domain" ] && process_domain "$domain"
    done < "$file"
}

# Main script execution
while getopts ":hd:l:u:civ" opt; do
    case $opt in
        h) display_usage ;;
        d) target="$OPTARG"; mode="domain" ;;
        l) target="$OPTARG"; mode="list" ;;
        u) target="$OPTARG"; mode="url" ;;
        c) install_tools; exit 0 ;;
        i) check_tools; exit 0 ;;
        v) set -x ;;
        \?) fatal "Invalid option: -$OPTARG" ;;
        :) fatal "Option -$OPTARG requires an argument" ;;
    esac
done

# Validate input
[ -z "$target" ] && [ -z "$mode" ] && display_usage
check_tools

# Execute scan based on mode
case $mode in
    domain) domain_scan "$target" ;;
    list) list_scan "$target" ;;
    url) single_url_scan "$target" ;;
    *) display_usage ;;
esac

echo -e "\n${BOLD}${GREEN}Scan completed successfully!${NC}"
