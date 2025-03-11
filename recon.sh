#!/usr/bin/env bash
# Ultimate Reconnaissance Suite
# Author: [Your Name]
# Version: 2.0
# Date: $(date +%Y-%m-%d)

# Configuration
THREADS=50
WORDLIST="$HOME/tools/SecLists/Discovery/Web-Content/raft-medium-words.txt"
SCREENSHOT_DIR="screenshots"
REPORT_FILE="recon_report.html"
TOOLS=("amass" "subfinder" "assetfinder" "httprobe" "waybackurls" "nuclei" "gowitness" "gf" "hakrawler")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Initialization
DOMAIN=""
OUTPUT_DIR=""
MENU_OPTIONS=()

check_dependencies() {
    missing=()
    for tool in "${TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing dependencies:${NC}"
        for dep in "${missing[@]}"; do
            echo -e "  - $dep"
        done
        exit 1
    fi
}

init_environment() {
    OUTPUT_DIR="recon-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$OUTPUT_DIR/$SCREENSHOT_DIR"
    echo -e "${GREEN}[+] Created output directory: $OUTPUT_DIR${NC}"
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo " ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "██╔═══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "██║   ██║█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "██║   ██║██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "╚██████╔╝██║     ╚██████╗╚██████╔╝██║ ╚████║"
    echo " ╚═════╝ ╚═╝      ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Ultimate Reconnaissance Suite v2.0${NC}"
    echo -e "${BLUE}------------------------------------${NC}"
}

main_menu() {
    while true; do
        echo -e "\n${CYAN}Main Menu:${NC}"
        echo "1. Domain Reconnaissance"
        echo "2. URL Enumeration"
        echo "3. Vulnerability Scanning"
        echo "4. Visual Inspection"
        echo "5. Generate Report"
        echo "6. Exit"
        
        read -p "Select an option: " choice
        
        case $choice in
            1) domain_recon_menu ;;
            2) url_enum_menu ;;
            3) vuln_scan_menu ;;
            4) visual_inspection_menu ;;
            5) generate_report ;;
            6) exit 0 ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
    done
}

domain_recon_menu() {
    while true; do
        echo -e "\n${CYAN}Domain Reconnaissance:${NC}"
        echo "1. Full Subdomain Enumeration"
        echo "2. Find Related Domains"
        echo "3. Check DNS Records"
        echo "4. Back to Main Menu"
        
        read -p "Select an option: " choice
        
        case $choice in
            1) run_subdomain_enum ;;
            2) find_related_domains ;;
            3) check_dns_records ;;
            4) return ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
    done
}

run_subdomain_enum() {
    echo -e "\n${GREEN}[+] Starting subdomain enumeration...${NC}"
    amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt"
    subfinder -d "$DOMAIN" -o "$OUTPUT_DIR/subfinder.txt"
    assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/assetfinder.txt"
    
    sort -u "$OUTPUT_DIR/"*.txt -o "$OUTPUT_DIR/subdomains.txt"
    echo -e "${BLUE}[i] Found $(wc -l < "$OUTPUT_DIR/subdomains.txt") subdomains${NC}"
    
    MENU_OPTIONS+=("Subdomain Enumeration Completed")
}

find_related_domains() {
    echo -e "\n${GREEN}[+] Finding related domains...${NC}"
    amass intel -whois -d "$DOMAIN" -o "$OUTPUT_DIR/related_domains.txt"
    echo -e "${BLUE}[i] Related domains saved to related_domains.txt${NC}"
    MENU_OPTIONS+=("Related Domains Identified")
}

check_dns_records() {
    echo -e "\n${GREEN}[+] Checking DNS records...${NC}"
    amass enum -d "$DOMAIN" -src -ip -o "$OUTPUT_DIR/dns_records.txt"
    echo -e "${BLUE}[i] DNS records saved to dns_records.txt${NC}"
    MENU_OPTIONS+=("DNS Records Checked")
}

url_enum_menu() {
    while true; do
        echo -e "\n${CYAN}URL Enumeration:${NC}"
        echo "1. Find URLs from Wayback Machine"
        echo "2. Crawl Existing URLs"
        echo "3. Parameter Mining"
        echo "4. Back to Main Menu"
        
        read -p "Select an option: " choice
        
        case $choice in
            1) wayback_urls ;;
            2) crawl_urls ;;
            3) parameter_mining ;;
            4) return ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
    done
}

wayback_urls() {
    echo -e "\n${GREEN}[+] Gathering URLs from Wayback Machine...${NC}"
    waybackurls "$DOMAIN" > "$OUTPUT_DIR/wayback_urls.txt"
    echo -e "${BLUE}[i] Found $(wc -l < "$OUTPUT_DIR/wayback_urls.txt") URLs${NC}"
    MENU_OPTIONS+=("Wayback URLs Collected")
}

crawl_urls() {
    echo -e "\n${GREEN}[+] Crawling URLs...${NC}"
    hakrawler -url "$DOMAIN" -depth 3 -scope subs -js -forms -plain > "$OUTPUT_DIR/crawled_urls.txt"
    echo -e "${BLUE}[i] Crawling completed. Results saved to crawled_urls.txt${NC}"
    MENU_OPTIONS+=("URL Crawling Completed")
}

parameter_mining() {
    echo -e "\n${GREEN}[+] Mining interesting parameters...${NC}"
    cat "$OUTPUT_DIR/wayback_urls.txt" "$OUTPUT_DIR/crawled_urls.txt" | gf xss | tee "$OUTPUT_DIR/xss_params.txt"
    gf sqli "$OUTPUT_DIR/wayback_urls.txt" > "$OUTPUT_DIR/sqli_params.txt"
    echo -e "${BLUE}[i] Parameter mining completed${NC}"
    MENU_OPTIONS+=("Parameter Mining Done")
}

vuln_scan_menu() {
    while true; do
        echo -e "\n${CYAN}Vulnerability Scanning:${NC}"
        echo "1. Run Nuclei Scan"
        echo "2. Check for Open Redirects"
        echo "3. Test for XSS"
        echo "4. Back to Main Menu"
        
        read -p "Select an option: " choice
        
        case $choice in
            1) run_nuclei ;;
            2) check_open_redirects ;;
            3) test_xss ;;
            4) return ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
    done
}

run_nuclei() {
    echo -e "\n${GREEN}[+] Running Nuclei scan...${NC}"
    nuclei -l "$OUTPUT_DIR/subdomains.txt" -t cves -t vulnerabilities -o "$OUTPUT_DIR/nuclei_results.txt"
    echo -e "${BLUE}[i] Nuclei results saved to nuclei_results.txt${NC}"
    MENU_OPTIONS+=("Nuclei Scan Completed")
}

visual_inspection_menu() {
    while true; do
        echo -e "\n${CYAN}Visual Inspection:${NC}"
        echo "1. Take Screenshots"
        echo "2. Generate Directory Map"
        echo "3. Back to Main Menu"
        
        read -p "Select an option: " choice
        
        case $choice in
            1) take_screenshots ;;
            2) generate_directory_map ;;
            3) return ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
    done
}

take_screenshots() {
    echo -e "\n${GREEN}[+] Taking screenshots...${NC}"
    gowitness file -f "$OUTPUT_DIR/subdomains.txt" -P "$OUTPUT_DIR/$SCREENSHOT_DIR"
    echo -e "${BLUE}[i] Screenshots saved to $SCREENSHOT_DIR${NC}"
    MENU_OPTIONS+=("Screenshots Taken")
}

generate_directory_map() {
    echo -e "\n${GREEN}[+] Generating directory map...${NC}"
    gospider -S "$OUTPUT_DIR/subdomains.txt" -o "$OUTPUT_DIR/gospider" --js --sitemap
    echo -e "${BLUE}[i] Directory map generated in gospider folder${NC}"
    MENU_OPTIONS+=("Directory Map Generated")
}

generate_report() {
    echo -e "\n${GREEN}[+] Generating HTML report...${NC}"
    
    echo "<html><head><title>Recon Report for $DOMAIN</title>" > "$OUTPUT_DIR/$REPORT_FILE"
    echo "<style>body{font-family:Arial,sans-serif} h1{color:#333} .section{margin:20px 0} .finding{padding:10px; border-left:4px solid #007bff; margin:10px 0} .critical{border-color:#dc3545} .warning{background-color:#fff3cd} table{width:100%; border-collapse:collapse} td,th{padding:8px; border:1px solid #ddd}</style></head>" >> "$OUTPUT_DIR/$REPORT_FILE"
    echo "<body><h1>Recon Report for $DOMAIN</h1>" >> "$OUTPUT_DIR/$REPORT_FILE"
    
    # Subdomains Section
    echo "<div class='section'>" >> "$OUTPUT_DIR/$REPORT_FILE"
    echo "<h2>Subdomains Found ($(wc -l < "$OUTPUT_DIR/subdomains.txt"))</h2>" >> "$OUTPUT_DIR/$REPORT_FILE"
    echo "<pre>$(head -n 10 "$OUTPUT_DIR/subdomains.txt")</pre>" >> "$OUTPUT_DIR/$REPORT_FILE"
    echo "</div>" >> "$OUTPUT_DIR/$REPORT_FILE"
    
    # Vulnerabilities Section
    if [ -s "$OUTPUT_DIR/nuclei_results.txt" ]; then
        echo "<div class='section'>" >> "$OUTPUT_DIR/$REPORT_FILE"
        echo "<h2>Critical Vulnerabilities</h2>" >> "$OUTPUT_DIR/$REPORT_FILE"
        echo "<table><tr><th>Severity</th><th>Vulnerability</th><th>URL</th></tr>" >> "$OUTPUT_DIR/$REPORT_FILE"
        grep -i critical "$OUTPUT_DIR/nuclei_results.txt" | head -n 5 | while read -r line; do
            echo "<tr><td style='color:red'>CRITICAL</td><td>${line#* }</td><td>${line%% *}</td></tr>" 
        done >> "$OUTPUT_DIR/$REPORT_FILE"
        echo "</table></div>" >> "$OUTPUT_DIR/$REPORT_FILE"
    fi
    
    # Screenshots Section
    echo "<div class='section'>" >> "$OUTPUT_DIR/$REPORT_FILE"
    echo "<h2>Screenshots</h2>" >> "$OUTPUT_DIR/$REPORT_FILE"
    find "$OUTPUT_DIR/$SCREENSHOT_DIR" -name "*.png" | head -n 5 | while read -r img; do
        echo "<img src='$img' style='max-width:300px; margin:10px; border:1px solid #ddd'>" 
    done >> "$OUTPUT_DIR/$REPORT_FILE"
    echo "</div></body></html>" >> "$OUTPUT_DIR/$REPORT_FILE"
    
    echo -e "${BLUE}[i] Report generated: $OUTPUT_DIR/$REPORT_FILE${NC}"
}

# Main Execution
check_dependencies
show_banner

if [ $# -eq 0 ]; then
    read -p "Enter target domain: " DOMAIN
else
    DOMAIN="$1"
fi

init_environment
main_menu