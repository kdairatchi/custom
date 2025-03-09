#!/usr/bin/env python3
import os
import time
import json
import random
import argparse
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor
from googlesearch import search
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from urllib.parse import urlparse

console = Console()

# 🔥 Default Dork Categories (if no custom file is used)
DEFAULT_DORKS = {
    "PHP Extensions": "site: ext:php inurl:?",
    "API Endpoints": "site: inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3",
    "Juicy Extensions": "site: ext:log | ext:txt | ext:conf | ext:ini | ext:env",
    "Cloud Storage": 'site:s3.amazonaws.com | site:googleapis.com | site:onedrive.live.com',
    "Wayback Archive": "wayback"
}

PROXY_FILE = "proxies.txt"
BURP_URL = "http://127.0.0.1:8080"

# 🌍 Load Proxies
def load_proxies():
    if not os.path.exists(PROXY_FILE):
        return None
    with open(PROXY_FILE, "r") as f:
        return [line.strip() for line in f.readlines()]

# 🌍 Load Custom Dork File
def load_dorks(file_path):
    """Loads dorks from a given file and returns them as a list."""
    dorks = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  # Ignore empty lines and comments
                dorks.append(line)
    return dorks

# Example usage:
dork_file = "dorks.txt"
dork_list = load_dorks(dork_file)

print(f"Loaded {len(dork_list)} dorks!")
for dork in dork_list[:5]:  # Print first 5 dorks for verification
    print(dork)

# 🌍 Use Wayback Machine to Find Old URLs
def wayback_search(domain):
    console.print(f"\n[bold cyan]🔍 Fetching Wayback Machine URLs for {domain}...[/]")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            urls = [entry[0] for entry in response.json()[1:]]
            return urls
    except Exception as e:
        console.print(f"[bold red]❌ Wayback Error:[/bold red] {e}")
    return []

# 🔍 Google Dorking Function
def google_dork(dork_query, num_results, delay):
    """Performs Google Dorking and returns results."""
    results = []
    try:
        for url in search(dork_query, num=num_results, pause=delay, lang="en"):
            results.append(url)
            console.print(f"[bold green]✔ Found:[/bold green] {url}")
    except Exception as e:
        console.print(f"[bold red]❌ Google Dork Error:[/bold red] {str(e)}")
    return results

# 📡 Send URLs to Burp Suite
def send_to_burp(urls):
    console.print("\n[bold cyan]🦠 Sending URLs to Burp Suite...[/]")
    for url in urls:
        try:
            requests.post(f"{BURP_URL}/burp", json={"url": url})
            console.print(f"[bold green]✔ Sent to Burp:[/bold green] {url}")
        except Exception as e:
            console.print(f"[bold red]❌ Burp Error:[/bold red] {e}")

# 🛠️ Validate URLs with HTTPX
def validate_urls(urls, output_file):
    with open("temp_urls.txt", "w") as f:
        f.write("\n".join(urls))

    console.print("\n[bold cyan]🔍 Running HTTPX to validate URLs...[/]")
    subprocess.run(["httpx", "-l", "temp_urls.txt", "-status-code", "-o", output_file])

    console.print(f"[bold green]✔ Valid URLs saved to:[/bold green] {output_file}")
    os.remove("temp_urls.txt")

# 🚀 Main Function
def start_dorking(args):
    """Main function to perform Google Dorking."""
    console.print("\n[bold cyan]🔎 Google Dorking Multitool[/]\n")

    if args.dork_file:
        dork_queries = load_dork_file(args.dork_file)
    else:
        dork_queries = DEFAULT_DORKS.values()

    if not dork_queries:
        console.print("[bold red]❌ No dorks found! Exiting...[/]")
        return

    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    for dork_query in dork_queries:
        category_name = dork_query.split(":")[0].strip().replace(" ", "_")
        if args.domain and "wayback" not in dork_query:
            dork_query = f"{dork_query} site:{args.domain}"

        console.print(f"\n[bold yellow]🔥 Starting Google Dorking for: {dork_query}[/]\n")

        if "wayback" in dork_query:
            results = wayback_search(args.domain)
        else:
            results = google_dork(dork_query, args.num_results, args.delay)

        if not results:
            console.print(f"[bold red]❌ No results found for {category_name}![/]")
            continue

        category_file = f"{results_dir}/{category_name}.txt"
        with open(category_file, "w") as f:
            f.write("\n".join(results))

        console.print(f"\n[bold green]✔ Results saved to:[/bold green] {category_file}")

        if args.burp:
            send_to_burp(results)

        validate_urls(results, category_file.replace(".txt", "_valid.txt"))

    console.print("\n[bold green]✅ Google Dorking Complete![/]\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔎 Ultimate Multi-Google Dorking Tool 🚀")
    parser.add_argument("-f", "--dork-file", help="Path to custom dork file (default: built-in categories)")
    parser.add_argument("-n", "--num-results", type=int, default=10, help="Number of results to fetch (default: 10)")
    parser.add_argument("-d", "--delay", type=int, default=5, help="Pause between requests (default: 5 seconds)")
    parser.add_argument("--domain", help="Specific domain to search (e.g., example.com)")
    parser.add_argument("--proxy", action="store_true", help="Use proxies from proxies.txt")
    parser.add_argument("--burp", action="store_true", help="Send results to Burp Suite")

    args = parser.parse_args()
    start_dorking(args)