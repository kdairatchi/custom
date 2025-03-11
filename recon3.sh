#!/usr/bin/env bash
# Ultimate Reconnaissance Suite
# Author: Your Name
# Version: 3.0
# Date: $(date +%Y-%m-%d)
#
# Description:
#   Fully integrated, multi-tool recon framework that:
#     - Collects URLs using urlfinder, waymore, katana, and subenum.sh for subdomains.
#     - Deduplicates and filters URLs for interesting file types.
#     - Extracts query parameters (BXSS candidates) using grep/sed and gf for XSS patterns.
#     - Runs httpx for full JSON scanning (including sensitive paths detection).
#     - Captures full-page screenshots with gowitness.
#     - Performs deep analysis (subjs, subjack, nuclei).
#     - Generates a custom dashboard aggregating key info from the httpx JSON output.
#     - Provides an interactive menu for selecting tasks (easy to add up to 25 custom tasks).
#
# Requirements:
#   urlfinder, waymore, katana, subenum.sh, anew, grep, sed, gf, httpx, gowitness,
#   subjs, subjack, nuclei, parallel, jq
#
########################################
# ///   You can edit your configuration here   \\\
#
# aquatoneThreads=5
# subdomainThreads=10
# dirsearchThreads=50
# dirsearchWordlist=~/tools/dirsearch/db/dicc.txt
# massdnsWordlist=~/tools/SecLists/Discovery/DNS/clean-jhaddix-dns.txt
# chromiumPath=/snap/bin/chromium
########################################
# Happy Hunting
########################################

# -------------------------
# Color Codes
# -------------------------
BOLD_WHITE="\033[1;37m"
BOLD_BLUE="\033[1;34m"
BOLD_YELLOW="\033[1;33m"
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
NC="\033[0m"

# -------------------------
# Configuration
# -------------------------
THREADS=50
SCREENSHOT_DIR="/home/anom/ai/scripts/custom/output/screenshot/"
HTTPX_FLAGS="-sc -ss -cl -title -location -tech-detect -favicon -json -sr -server -td -t $THREADS"
SENSITIVE_PATHS="--path /robots.txt,/sitemap.xml,/env,.git/HEAD"
base_dir="scan_results_$(date +%F_%H-%M-%S)"
mkdir -p "$base_dir" || { echo "Failed to create base directory"; exit 1; }
SUBJACK_FP="${SUBJACK_FP:-$HOME/.config/subjack/fingerprints.json}"
TOOLS=(urlfinder waymore katana subenum.sh anew gf httpx gowitness subjs subjack nuclei jq parallel)

# -------------------------
# Global Functions
# -------------------------
show_progress() {
  echo -e "${BOLD_WHITE}[+] $1${NC}"
}
error_exit() {
  echo -e "${RED}[!] Error: $1${NC}"
  exit 1
}
display_usage() {
  echo -e "${BOLD_YELLOW}Ultimate Reconnaissance Suite v3.0${NC}"
  echo -e "Author: Your Name\n"
  echo -e "${BOLD_YELLOW}Usage:${NC}"
  echo "  $0 [-d domain.com] [-l domains.txt] [-i] [-h]"
  echo -e "\nOptions:"
  echo "  -d    Single domain scan (e.g. example.com)"
  echo "  -l    File with a list of domains (one per line)"
  echo "  -i    Check required tools"
  echo "  -h    Display this help message"
}

check_tools() {
  local missing=0
  for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      echo -e "${RED}[✖]${NC} $tool"
      missing=1
    else
      echo -e "${GREEN}[✔]${NC} $tool ($(which $tool))"
    fi
  done
  (( missing == 1 )) && error_exit "Some required tools are missing. Please install them and try again."
}

# -------------------------
# Custom Dashboard Function
# -------------------------
generate_dashboard() {
  local infile="$base_dir/httpx_results.json"
  local dashfile="$base_dir/dashboard.txt"
  if [ ! -f "$infile" ]; then
    echo "httpx JSON output not found." > "$dashfile"
    return
  fi
  {
    echo -e "\n${BOLD_YELLOW}=== Custom Dashboard ===${NC}\n"
    total=$(jq 'length' "$infile")
    waf_count=$(jq '[.[] | select(.cdn_type=="waf")] | length' "$infile")
    echo -e "${CYAN}Total Targets:${NC} $total"
    echo -e "${CYAN}WAF Detected:${NC} $waf_count\n"
    printf "%-50s %-8s %-40s %-15s %-5s %-30s %-10s\n" "URL" "Status" "Title" "CDN" "WAF" "Technology" "Time"
    printf "%-50s %-8s %-40s %-15s %-5s %-30s %-10s\n" "--------------------------------------------------" "--------" "----------------------------------------" "---------------" "-----" "------------------------------" "----------"
    jq -r '
      .[] | [
          (.url // "N/A"),
          (.status_code|tostring),
          (.title // "N/A"),
          (.cdn_name // "N/A"),
          (if .cdn_type=="waf" then "Yes" else "No" end),
          ((.tech | join(", ")) // "N/A"),
          (.time // "N/A")
      ] | @tsv' "$infile" | while IFS=$'\t' read -r url status title cdn waf tech time; do
            url_disp=$(echo "$url" | cut -c1-50)
            title_disp=$(echo "$title" | cut -c1-40)
            tech_disp=$(echo "$tech" | cut -c1-30)
            printf "%-50s %-8s %-40s %-15s %-5s %-30s %-10s\n" "$url_disp" "$status" "$title_disp" "$cdn" "$waf" "$tech_disp" "$time"
         done
  } | tee "$dashfile"
  show_progress "Dashboard saved to: ${BOLD_BLUE}$dashfile${NC}"
}

# -------------------------
# Interactive Menu Function
# -------------------------
interactive_view() {
  if [ -t 0 ]; then
    echo -e "\n${BOLD_YELLOW}Would you like to view the interactive menu? (y/n)${NC}"
    read -r ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      PS3="Select an option: "
      options=("View Full JSON Output" "View Dashboard" "View 200 Responses" "View 403 Responses" "View 500 Errors" "View Technology Stack" "View Potential Takeovers" "View JavaScript Analysis" "View Sensitive Paths" "View GF XSS URLs" "Open Screenshot Directory" "Exit")
      select opt in "${options[@]}"; do
        case $REPLY in
          1) less "$base_dir/httpx_results.json" ;;
          2) generate_dashboard; less "$base_dir/dashboard.txt" ;;
          3) less "$base_dir/200_responses.txt" ;;
          4) less "$base_dir/403_forbidden.txt" ;;
          5) less "$base_dir/500_errors.txt" ;;
          6) less "$base_dir/tech_stack.txt" ;;
          7) less "$base_dir/potential_takeovers.txt" ;;
          8) less "$base_dir/javascript_files.txt" ;;
          9) less "$base_dir/sensitive_paths.txt" ;;
          10) less "$base_dir/gf_xss.txt" ;;
          11)
             if command -v xdg-open &>/dev/null; then
               xdg-open "$base_dir/$SCREENSHOT_DIR" || echo "Open manually: $base_dir/$SCREENSHOT_DIR"
             else
               echo "Screenshot directory: $base_dir/$SCREENSHOT_DIR"
             fi
             ;;
          12) break ;;
          *) echo "Invalid option. Try again." ;;
        esac
      done
    fi
  fi
}

# -------------------------
# Modular Task Functions
# -------------------------
collect_urls() {
  show_progress "Collecting URLs for: ${BOLD_BLUE}$domain_Without_Protocol${NC}"
  {
    # Run subenum.sh for subdomain enumeration (active)
    ./subenum.sh -f "$domain_Without_Protocol" -o "$base_dir/subs.txt"
  } &
  {
    ./subenum.sh -d "$domain_Without_Protocol" -o "$base_dir/subs.txt"
  } &
  {
    urlfinder -all -d "$domain_Without_Protocol" -o "$base_dir/urlfinder.txt"
  } &
  {
    waymore -i "$domain_Without_Protocol" -mode U --providers wayback,otx,urlscan,virustotal -oU "$base_dir/waymore.txt"
  } &
  {
    katana -u "$domain_Without_Protocol" -rl 170 -timeout 5 -retry 2 -aff -d 4 -duc -ps -pss waybackarchive,commoncrawl,alienvault -o "$base_dir/katana.txt"
  } &
  wait
}
deduplicate_and_filter() {
  show_progress "Merging and filtering URLs"
  cat "$base_dir/urlfinder.txt" "$base_dir/waymore.txt" "$base_dir/katana.txt" | anew "$base_dir/all_urls.txt" || error_exit "Error merging URLs."
  cat "$base_dir/all_urls.txt" | grep -aE '\.xls|\.xml|\.xlsx|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.tar|\.deb|\.rpm|\.iso|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc' | anew "$base_dir/all_unique_urls.txt"
  cat "$base_dir/all_unique_urls.txt" | grep -aE '\.pdf$' | anew "$base_dir/all_pdf.txt"
}
extract_parameters() {
  show_progress "Extracting query parameters (BXSS candidates)"
  cat "$base_dir/all_urls.txt" | grep "?" | sed -E 's/^[^?]*\?//' | grep -iE "id=|page=|search=|query=|bxss" | anew "$base_dir/get_params_bxss.txt"
}
run_gf_scans() {
  show_progress "Running GF for XSS patterns"
  gf xss "$base_dir/all_urls.txt" | anew "$base_dir/gf_xss.txt"
  show_progress "Running GF with custom patterns"
  local patterns=(
    "allin1gf" "allonegf" "allparam" "api-keys" "asymmetric-keys_secrets" "auth" "aws-keys" "aws-keys_secrets" "aws-mws-key" "aws-s3_secrets" "aws-secret-key" "badwords" "base64" "blacklist" "bufferoverflow" "ccode" "cors" "crypto" "debug-pages" "debug_logic" "domxss" "endpoints" "execs" "facebook-access-token" "facebook-oauth" "facebook-oauth_secrets" "facebook-token_secrets" "firebase" "firebase_secrets" "fw" "github" "github_secrets" "go-functions" "google-keys_secrets" "google-oauth_secrets" "google-service-account_secrets" "google-token_secrets" "heroku-keys_secrets" "http-auth" "idor" "img-traversal" "insubs" "interestingEXT" "interestingparams" "interestingsubs" "inurls" "ip" "js-interesting" "js-sinks" "json-sec" "jsvar" "jwt" "lfi" "mailchimp-keys_secrets" "mailgun-keys_secrets" "meg-headers" "or" "parsers" "paypal-token_secrets" "php-callbacks" "php-codeexec" "php-commandexec" "php-curl" "php-errors" "php-informationdisclosure" "php-open-filesystem-handler" "php-read-filesystem" "php-serialized" "php-sinks" "php-sources" "php-write-filesystem" "picatic-keys_secrets" "rce-2" "rce" "redirect" "s3-buckets" "sec" "secret-ext" "secret-urls" "secrets" "serial" "servers" "slack-token" "slack-token_secrets" "slack-webhook" "slack-webhook_secrets" "sqli-error" "sqli" "square-keys_secrets" "square-secret" "ssrf" "ssti" "strings" "stripe-keys_secrets" "swearwords" "takeovers" "truffle" "twilio-key" "twilio-keys_secrets" "twitter-oauth" "twitter-oauth_secrets" "twitter-secret" "twitter-token_secrets" "typos" "upload-fields" "urlparams" "urls" "urls_params" "xml" "xpath" "xss" "xxe"
  )
  for pattern in "${patterns[@]}"; do
    gf "$pattern" "$base_dir/all_urls.txt"
  done | anew "$base_dir/gf_all.txt"
  local gf_all_count
  gf_all_count=$(wc -l < "$base_dir/gf_all.txt")
  echo -e "${BOLD_YELLOW}GF All patterns results (${RED}$gf_all_count${NC}): ${BOLD_BLUE}$base_dir/gf_all.txt${NC}"
}
run_httpx() {
  show_progress "Scanning URLs with httpx"
  httpx -l "$base_dir/all_unique_urls.txt" $HTTPX_FLAGS -o "$base_dir/httpx_results.json" || error_exit "httpx scan failed."
  {
    jq -r '. | select(.status_code == 200) | .url' "$base_dir/httpx_results.json" > "$base_dir/200_responses.txt"
  } &
  {
    jq -r '. | select(.status_code == 403) | .url' "$base_dir/httpx_results.json" > "$base_dir/403_forbidden.txt"
  } &
  {
    jq -r '. | select(.status_code == 500) | .url' "$base_dir/httpx_results.json" > "$base_dir/500_errors.txt"
  } &
  wait
  jq -r '. | select(.technology != null) | .url + " => " + (.technology | join(", "))' "$base_dir/httpx_results.json" > "$base_dir/tech_stack.txt"
}
capture_screenshots() {
  show_progress "Capturing screenshots with gowitness"
  gowitness scan file -f "$base_dir/200_responses.txt" --screenshot-fullpage --write-screenshots "$base_dir/$SCREENSHOT_DIR" --write-jsonl || show_progress "Screenshot capture warning."
}
deep_analysis() {
  show_progress "Performing deep analysis"
  subjs -i "$base_dir/200_responses.txt" > "$base_dir/javascript_files.txt" &
  if [[ -f "$SUBJACK_FP" ]]; then
    subjack -w "$base_dir/200_responses.txt" -t 50 -ssl -c "$SUBJACK_FP" -v -o "$base_dir/potential_takeovers.txt" &
  else
    echo "No subjack fingerprints file found. Skipping takeover check." > "$base_dir/potential_takeovers.txt"
  fi
  nuclei -l "$base_dir/200_responses.txt" -t ~/nuclei-customs/ -o "$base_dir/nuclei_results.txt" &
  httpx -l "$base_dir/200_responses.txt" $SENSITIVE_PATHS -sr -o "$base_dir/sensitive_paths.txt" &
  wait
}
generate_report() {
  show_progress "Generating final report"
  {
    echo -e "${BOLD_YELLOW}Scan Report for ${domain_Without_Protocol}${NC}"
    echo "========================================"
    echo -e "${CYAN}Total URLs Found:${NC} $(wc -l < "$base_dir/all_urls.txt")"
    echo -e "${GREEN}Live Sites (200):${NC} $(wc -l < "$base_dir/200_responses.txt")"
    echo -e "${RED}Forbidden (403):${NC} $(wc -l < "$base_dir/403_forbidden.txt")"
    echo -e "${RED}Server Errors (500):${NC} $(wc -l < "$base_dir/500_errors.txt")"
    echo -e "\nKey Findings:"
    echo -e "Screenshots: ${BOLD_BLUE}$base_dir/$SCREENSHOT_DIR${NC}"
    echo -e "Technology Stack: ${BOLD_BLUE}$base_dir/tech_stack.txt${NC}"
    echo -e "Potential Takeovers: ${BOLD_BLUE}$base_dir/potential_takeovers.txt${NC}"
    echo -e "Nuclei Results: ${BOLD_BLUE}$base_dir/nuclei_results.txt${NC}"
    echo -e "JS Analysis: ${BOLD_BLUE}$base_dir/javascript_files.txt${NC}"
    echo -e "Sensitive Paths: ${BOLD_BLUE}$base_dir/sensitive_paths.txt${NC}"
    echo -e "\nAdditional URL Data:"
    echo -e "All URLs: ${BOLD_BLUE}$base_dir/all_unique_urls.txt${NC}"
    echo -e "Document URLs: ${BOLD_BLUE}$base_dir/all_pdf.txt${NC}"
    echo -e "BXSS Params URLs: ${BOLD_BLUE}$base_dir/get_params_bxss.txt${NC}"
    echo -e "GF XSS URLs: ${BOLD_BLUE}$base_dir/gf_xss.txt${NC}"
    echo -e "GF All Patterns: ${BOLD_BLUE}$base_dir/gf_all.txt${NC}"
  } > "$base_dir/report.txt"
  generate_dashboard
}
full_scan() {
  collect_urls
  deduplicate_and_filter
  extract_parameters
  run_gf_scans
  run_httpx
  capture_screenshots
  deep_analysis
  generate_report
  interactive_view
}

# -------------------------
# Main Interactive Menu
# -------------------------
main_menu() {
  while true; do
    echo -e "\n${BOLD_YELLOW}=== Ultimate Recon Scanner Menu ===${NC}"
    echo "1) Collect URLs"
    echo "2) Deduplicate & Filter URLs"
    echo "3) Extract Query Parameters (BXSS candidates)"
    echo "4) Run GF for XSS Patterns"
    echo "5) Run GF for Custom Patterns"
    echo "6) Run httpx Scan & Categorize"
    echo "7) Capture Screenshots with Gowitness"
    echo "8) Perform Deep Analysis (subjs, subjack, nuclei, sensitive paths)"
    echo "9) Generate Report & Dashboard"
    echo "10) Run Full Scan (All Steps)"
    echo "11) Exit"
    read -p "Enter your choice [1-11]: " choice
    case $choice in
      1) 
         read -p "Enter domain: " domain_input
         domain_Without_Protocol=$(echo "$domain_input" | sed 's~http[s]\?://~~')
         collect_urls
         ;;
      2) deduplicate_and_filter ;;
      3) extract_parameters ;;
      4) 
         gf xss "$base_dir/all_urls.txt" | anew "$base_dir/gf_xss.txt"
         echo -e "${BOLD_YELLOW}GF XSS results saved to:${NC} ${BOLD_BLUE}$base_dir/gf_xss.txt${NC}"
         ;;
      5) run_gf_scans ;;
      6) run_httpx ;;
      7) capture_screenshots ;;
      8) deep_analysis ;;
      9) generate_report ;;
      10) full_scan ;;
      11) echo "Exiting."; break ;;
      *) echo -e "${RED}Invalid option, try again.${NC}" ;;
    esac
  done
}

# -------------------------
# Main Execution Logic
# -------------------------
while getopts "d:l:ih" opt; do
  case "$opt" in
    d) domain="$OPTARG" ; MODE="single" ;;
    l) domain_list="$OPTARG" ; MODE="list" ;;
    i) check_tools; exit 0 ;;
    h) display_usage; exit 0 ;;
    *) display_usage; exit 1 ;;
  esac
done

if [[ -n "$domain" ]]; then
  check_tools
  scan_domain "$domain"
elif [[ -n "$domain_list" ]]; then
  if [[ ! -f "$domain_list" ]]; then
    error_exit "Domain list file '$domain_list' not found."
  fi
  check_tools
  show_progress "Starting multi-domain scan from list: $domain_list"
  while IFS= read -r d || [[ -n "$d" ]]; do
    [[ -z "$d" || "$d" =~ ^# ]] && continue
    scan_domain "$d" &
  done < "$domain_list"
  wait
  show_progress "All domain scans completed!"
else
  check_tools
  main_menu
fi