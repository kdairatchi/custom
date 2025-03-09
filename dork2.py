#!/usr/bin/env python3
import os
import time
import json
import random
import argparse
import requests
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from googlesearch import search
from urllib.parse import urlparse
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from threading import Event

console = Console()

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# 🛠️ CONFIGURATION CONSTANTS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DEFAULT_DORKS = {
    "PHP Extensions": "site: ext:php inurl:?",
    "API Endpoints": "site: inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3",
    "Juicy Extensions": "site: ext:log | ext:txt | ext:conf | ext:ini | ext:env",
    "Cloud Storage": 'site:s3.amazonaws.com | site:googleapis.com | site:onedrive.live.com',
    "Wayback Archive": "wayback"
}

PROXY_FILE = "proxies.txt"
BURP_URL = "http://127.0.0.1:8080"
TOOL_BANNER = """
[bold cyan]
▓█████▄  ▒█████   ██▀███   ▄████▄  ▓█████ 
▒██▀ ██▌▒██▒  ██▒▓██ ▒ ██▒▒██▀ ▀█  ▓█   ▀ 
░██   █▌▒██░  ██▒▓██ ░▄█ ▒▒▓█    ▄ ▒███   
░▓█▄   ▌▒██   ██░▒██▀▀█▄  ▒▓▓▄ ▄██▒▒▓█  ▄ 
░▒████▓ ░ ████▓▒░░██▓ ▒██▒▒ ▓███▀ ░░▒████▒
 ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░░ ▒░ ░
 ░ ▒  ▒   ░ ▒ ▒░   ░▒ ░ ▒░  ░  ▒    ░ ░  ░
 ░ ░  ░ ░ ░ ░ ▒    ░░   ░ ░           ░   
   ░        ░ ░     ░     ░ ░         ░  ░
 ░                     ░                  
[/bold cyan]
"""

DASHBOARD_LAYOUT = """
[bold green]
┌───────────────────────────[ [blink]Monitoring Panel[/] ]─────────────────────────────┐
│ [cyan]                                                                             [/cyan]│
│  [ [yellow]Discovered URLs[/] ]                [ [red]Vulnerability Feed[/] ]                 │
│  ───────────────────                ──────────────────────                 │
│  {urls:<55}  {vulns:<55} 
│ [cyan]                                                                             [/cyan]│
│  [ [magenta]Scan Statistics[/] ]                                                        │
│  ────────────────                                                           │
│  • Targets: [bold]{total_urls}[/] ✔ [green]Valid: {valid_urls}[/] ❌ [red]Dead: {dead_urls}[/]       │
│  • [white]Critical:[/] [bold red]{critical}[/] 🚨 [bright_red]High: {high}[/] ⚠ [yellow]Med: {medium}[/] ℹ [blue]Info: {low}[/] │
│  • [cyan]Active Threads:[/] {threads} ⏱ [bold]{elapsed}[/]                                │
│ [cyan]                                                                             [/cyan]│
└─────────────────────────────────────────────────────────────────────────────┘
[/bold green]
"""

# ~~~~~~~~~~~~~~~~~~~~~
# 🕹️ DASHBOARD CLASS
# ~~~~~~~~~~~~~~~~~~~~~
class ReconDashboard:
    def __init__(self):
        self.live = None
        self.stats = {
            'total_urls': 0,
            'valid_urls': 0,
            'dead_urls': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'threads': 0,
            'start_time': time.time(),
            'recent_urls': [],
            'recent_vulns': []
        }
        self.stop_event = Event()
        
    def update_stat(self, key, value):
        self.stats[key] = value
        
    def add_url(self, url):
        self.stats['recent_urls'].append(url)
        if len(self.stats['recent_urls']) > 5:
            self.stats['recent_urls'].pop(0)
        self.stats['total_urls'] += 1
            
    def add_vuln(self, vuln):
        self.stats['recent_vulns'].append(vuln)
        if len(self.stats['recent_vulns']) > 5:
            self.stats['recent_vulns'].pop(0)
            
    def elapsed_time(self):
        return time.strftime("%H:%M:%S", time.gmtime(time.time() - self.stats['start_time']))
        
    def generate_layout(self):
        return DASHBOARD_LAYOUT.format(
            urls="\n  ".join(self.stats['recent_urls'][-5:] or ["Scanning..."],
            vulns="\n  ".join(self.stats['recent_vulns'][-5:] or ["Clean so far!"],
            total_urls=self.stats['total_urls'],
            valid_urls=self.stats['valid_urls'],
            dead_urls=self.stats['dead_urls'],
            critical=self.stats['critical'],
            high=self.stats['high'],
            medium=self.stats['medium'],
            low=self.stats['low'],
            threads=threading.active_count(),
            elapsed=self.elapsed_time()
        )
        
    def start(self):
        def live_loop():
            with Live(auto_refresh=False, screen=True) as live:
                self.live = live
                while not self.stop_event.is_set():
                    live.update(Panel.fit(self.generate_layout(), 
                                        border_style="cyan"))
                    live.refresh()
                    time.sleep(0.25)
                    
        threading.Thread(target=live_loop, daemon=True).start()
        
    def stop(self):
        self.stop_event.set()

# ~~~~~~~~~~~~~~~~
# 🧰 CORE FUNCTIONS
# ~~~~~~~~~~~~~~~~
def show_banner():
    """Display awesome ASCII art banner"""
    console.print(Panel.fit(TOOL_BANNER, title="[blink]DORK ENGINE v3.0[/]", 
                         subtitle="by Cyber Ninja", border_style="cyan"))
    console.print(Panel.fit("[bold yellow]🔥 Ultimate Bug Bounty Reconnaissance Suite[/]", 
                         border_style="red"))

def load_proxies():
    """Load validated proxies from file"""
    if not os.path.exists(PROXY_FILE):
        return None
    with open(PROXY_FILE, "r") as f:
        return [line.strip() for line in f if line.strip() and line.startswith(('http', 'socks5'))]

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

def wayback_search(domain, proxies=None, dashboard=None):
    """Fetch historical data from Wayback Machine"""
    console.print(f"\n[bold cyan]🔍 Fetching Wayback URLs for {domain}...[/]")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        proxy = random.choice(proxies) if proxies else None
        response = requests.get(url, proxies={"http": proxy, "https": proxy} if proxy else None)
        if response.status_code == 200:
            urls = [entry[0] for entry in response.json()[1:]]
            if dashboard:
                for url in urls:
                    dashboard.add_url(url)
            return urls
    except Exception as e:
        console.print(f"[bold red]❌ Wayback Error: {e}[/]")
    return []

# ~~~~~~~~~~~~~~~~~~
# 🚀 MAIN OPERATIONS
# ~~~~~~~~~~~~~~~~~~
def execute_recon(args):
    """Main recon workflow controller"""
    show_banner()
    dashboard = ReconDashboard() if args.dashboard else None
    if dashboard: dashboard.start()

    try:
        proxies = load_proxies() if args.proxy else None
        session = requests.Session()
        if proxies:
            session.proxies.update({"http": random.choice(proxies), "https": random.choice(proxies)})

        results_dir = f"recon_{args.domain}"
        os.makedirs(results_dir, exist_ok=True)

        dork_source = load_dork_file(args.dork_file) if args.dork_file else DEFAULT_DORKS
        recon_data = {}

        for category, dork in dork_source.items():
            console.rule(f"[bold yellow]🔥 Processing {category}", style="red")
            
            if "wayback" in dork.lower():
                results = wayback_search(args.domain, proxies, dashboard)
            else:
                augmented_dork = f"{dork} site:{args.domain}"
                with Progress(
                    SpinnerColumn(),
                    BarColumn(),
                    TimeElapsedColumn(),
                    transient=True,
                ) as progress:
                    task = progress.add_task(f"[cyan]Dorking {category}", total=args.num_results)
                    results = []
                    try:
                        for url in search(
                            augmented_dork, 
                            num=args.num_results, 
                            pause=args.delay, 
                            lang="en",
                            proxies=proxies
                        ):
                            results.append(url)
                            if dashboard: dashboard.add_url(url)
                            progress.update(task, advance=1)
                    except Exception as e:
                        console.print(f"[bold red]❌ Search Failed: {e}[/]")

            if not results:
                console.print(f"[bold red]⛔ No results for {category}[/]")
                continue

            # Save results
            report_path = os.path.join(results_dir, f"{category.replace(' ', '_')}.txt")
            with open(report_path, "w") as f:
                f.write("\n".join(results))
            
            # Burp Integration
            if args.burp:
                with console.status("[red]🕷️ Sending to Burp...[/]"):
                    send_to_burp(results, session, dashboard)

            # Validation
            valid_path = report_path.replace(".txt", "_valid.txt")
            validate_targets(results, valid_path, dashboard)
            
            # Vulnerability Scanning
            if args.nuclei:
                run_nuclei_scan(valid_path, dashboard)
            
            # Directory Bruteforce
            if args.ffuf:
                run_ffuf_scan(valid_path, args.wordlist, dashboard)
            
            recon_data[category] = {
                "total": len(results),
                "valid": sum(1 for _ in open(valid_path)),
                "report": report_path
            }

        generate_summary(recon_data, dashboard)

    finally:
        if dashboard: dashboard.stop()

# ~~~~~~~~~~~~~~~~~~~~~
# 🛡️ SECURITY FEATURES
# ~~~~~~~~~~~~~~~~~~~~~
def send_to_burp(urls, session, dashboard=None):
    """Proxy results through Burp Suite"""
    console.print("\n[bold cyan]🕷️ Sending URLs to Burp Suite...[/]")
    for url in urls:
        try:
            session.post(f"{BURP_URL}/burp", json={"url": url}, timeout=3)
            if dashboard: dashboard.add_url(f"[dim]Burp: {url}[/]")
        except Exception as e:
            console.print(f"[bold red]❌ Burp Error: {e}[/]")

def validate_targets(urls, output_file, dashboard=None):
    """Validate URLs with HTTPX"""
    with console.status(f"[cyan]🔬 Validating {len(urls)} targets..."):
        with open("temp_targets.txt", "w") as f:
            f.write("\n".join(urls))
        
        result = subprocess.run(
            ["httpx", "-l", "temp_targets.txt", "-status-code", "-o", output_file],
            capture_output=True, text=True
        )
        valid_count = len(open(output_file).readlines())
        if dashboard:
            dashboard.update_stat('valid_urls', valid_count)
            dashboard.update_stat('dead_urls', len(urls) - valid_count)
        os.remove("temp_targets.txt")

def run_nuclei_scan(target_file, dashboard=None):
    """Execute Nuclei vulnerability scan"""
    console.print(f"\n[bold cyan]🛡️ Launching Nuclei Scan...[/]")
    report_file = target_file.replace("_valid.txt", "_nuclei.txt")
    try:
        result = subprocess.run(
            ["nuclei", "-l", target_file, "-severity", "critical,high", "-o", report_file],
            capture_output=True, text=True
        )
        vulns = [line for line in result.stdout.split("\n") if line]
        if dashboard:
            for vuln in vulns:
                if "critical" in vuln.lower():
                    dashboard.update_stat('critical', dashboard.stats['critical'] + 1)
                    dashboard.add_vuln(f"🚨 [red]{vuln}[/]")
                elif "high" in vuln.lower():
                    dashboard.update_stat('high', dashboard.stats['high'] + 1)
                    dashboard.add_vuln(f"⚠️ [yellow]{vuln}[/]")
        console.print(f"[green]✅ Found {len(vulns)} vulnerabilities[/]")
    except Exception as e:
        console.print(f"[red]❌ Nuclei Failed: {e}[/]")

def run_ffuf_scan(target_file, wordlist, dashboard=None):
    """Perform directory brute-forcing"""
    if not os.path.exists(wordlist):
        console.print(f"[red]⛔ Wordlist missing: {wordlist}[/]")
        return
    
    console.print(f"\n[cyan]💥 Starting FFUF Assault...[/]")
    with open(target_file) as f:
        targets = [line.strip() for line in f]
    
    for target in targets:
        report_file = target_file.replace("_valid.txt", f"_ffuf_{urlparse(target).netloc}.json")
        try:
            subprocess.run(
                ["ffuf", "-w", wordlist, "-u", f"{target}/FUZZ", "-recursion", "-t", "50", "-o", report_file],
                check=True
            )
            if dashboard:
                dashboard.add_vuln(f"🔍 Found directories on {urlparse(target).netloc}")
        except Exception as e:
            console.print(f"[red]❌ FFUF Failed: {e}[/]")

# ~~~~~~~~~~~~~~~~~~~~~
# 📊 REPORTING SYSTEM
# ~~~~~~~~~~~~~~~~~~~~~
def generate_summary(data, dashboard=None):
    """Generate final mission report"""
    console.print("\n[bold cyan]📊 MISSION SUMMARY[/]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan")
    table.add_column("Total", justify="center")
    table.add_column("Valid", justify="center")
    table.add_column("Critical", justify="center")
    table.add_column("High Risk", justify="center")
    table.add_column("Report", style="dim")
    
    for category, stats in data.items():
        table.add_row(
            category,
            str(stats['total']),
            str(stats['valid']),
            str(dashboard.stats['critical'] if dashboard else "N/A"),
            str(dashboard.stats['high'] if dashboard else "N/A"),
            stats['report']
        )
    
    console.print(table)
    console.print(Panel.fit("[bold green]✅ RECON MISSION COMPLETE![/]", 
                         title="STATUS", border_style="green"))

# ~~~~~~~~~~~~~~
# 🚀 LAUNCH PAD
# ~~~~~~~~~~~~~~
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🕵️ Next-Gen Web Reconnaissance Toolkit")
    parser.add_argument("-d", "--domain", required=True, help="🌐 Target domain")
    parser.add_argument("-f", "--dork-file", help="📁 Custom dork patterns")
    parser.add_argument("-n", "--num-results", type=int, default=25, help="🎯 Results per dork")
    parser.add_argument("--delay", type=int, default=5, help="⏳ Request delay")
    parser.add_argument("--proxy", action="store_true", help="🔒 Proxy rotation")
    parser.add_argument("--burp", action="store_true", help="🕷️ Burp integration")
    parser.add_argument("--nuclei", action="store_true", help="🛡️ Nuclei scanning")
    parser.add_argument("--ffuf", help="💥 FFUF with wordlist")
    parser.add_argument("--dashboard", action="store_true", help="📈 Real-time dashboard")
    
    args = parser.parse_args()
    
    try:
        execute_recon(args)
    except KeyboardInterrupt:
        console.print("\n[bold red]🛑 MISSION ABORTED![/]")
    except Exception as e:
        console.print(f"[bold red]❌ CRASH: {str(e)}[/]")