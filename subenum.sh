#!/bin/bash

# Check for input arguments
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 -f <file_with_domains> or <single_domain>"
  exit 1
fi

# Parse arguments
if [[ $1 == "-f" ]]; then
  input_file=$2
  mode="file"
elif [[ $1 == "-d" ]]; then
  domain=$2
  mode="domain"
else
  echo "Invalid option. Use -f for file or -d for single domain."
  exit 1
fi

# Function to process a single domain
process_domain() {
  local domain=$1

  echo "Running subdomain enumeration for: $domain"

  # Subfinder: Find subdomains and save to subfinder.txt
  subfinder -d "$domain" -o "${domain}_subfinder.txt"

  # ShodanX: Retrieve subdomains and save to shodax.txt
#  shodanx subdomain -d "$domain" -ra -o "${domain}_shodax.txt"

  # crt.sh: Fetch subdomains from certificate transparency logs
  curl -s https://crt.sh/\?q\=\%.$domain\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee -a "${domain}_crt.txt"

  # AlienVault OTX: Fetch subdomains from passive DNS
  curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/passive_dns" | jq -r '.passive_dns[]?.hostname' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" | sort -u | tee "${domain}_alienvault_subs.txt"

  # urlscan.io: Fetch subdomains from URL scan results
  curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" | jq -r '.results[]?.page?.domain' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" | sort -u | tee "${domain}_urlscan_subs.txt"

  # Web Archive: Fetch subdomains from Wayback Machine
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&collapse=urlkey" | jq -r '.[1:][] | .[2]' | grep -Eo "([a-zA-Z0-9._-]+\.)?${domain}" | sed 's/^2F//g' | sort -u | tee "${domain}_webarchive_subs.txt"

  # Amass: Perform active enumeration and save to amass.txt
  amass enum -active -norecursive -noalts -d "$domain" -o "${domain}_amass.txt"

  # Merge all subdomain results
  cat "${domain}_subfinder.txt" "${domain}_shodax.txt" "${domain}_subs_domain.txt" \
      "${domain}_alienvault_subs.txt" "${domain}_urlscan_subs.txt" "${domain}_webarchive_subs.txt" \
      "${domain}_amass.txt" | anew "${domain}.txt"

  # Clean up subdomains in the merged file
  sed -i -E 's/^(www\.|https?:\/\/|[_\.-])//g' "${domain}.txt"

  # Extract live subdomains using httpx
  httpx -silent -list "${domain}.txt" -o "live_subdomains.txt"

  echo "Extracted live subdomains and saved to live_subdomains.txt"

  # Generate permutations of subdomains using altdns
  # altdns -i "${domain}_live_subdomains.txt" -o "${domain}_subdomains.txt" -w words.txt -r -s results_output.txt

  echo "Generated subdomain permutations and saved to ${domain}_subdomains.txt"

  # Remove intermediate files
  rm -f "${domain}_subfinder.txt" "${domain}_shodax.txt" "${domain}_crt.txt" \
        "${domain}_alienvault_subs.txt" "${domain}_urlscan_subs.txt" "${domain}_webarchive_subs.txt" \
        "${domain}_amass.txt" "${domain}.txt"

}

# Process input based on mode
if [[ $mode == "file" ]]; then
  while read -r domain; do
    process_domain "$domain"
  done < "$input_file"
elif [[ $mode == "domain" ]]; then
  process_domain "$domain"
fi

echo "Subdomain enumeration completed."
