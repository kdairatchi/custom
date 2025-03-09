#!/usr/bin/env python3
import os
import sys
import time
import argparse
import tempfile
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.tree import Tree

console = Console()

# ASCII Art Banner
BANNER = r"""
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
"""

# Configuration
REQUIRED_TOOLS = ["gau", "uro", "httpx", "nuclei", "ffuf", "qsreplace"]
SEVERITY_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "info": "cyan"
}

VULNERABILITY_TESTS = {
    "xss": {
        "payloads": ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"],
        "matchers": ["reflected_xss", "xss"]
    },
    "sqli": {
        "payloads": ["' OR 1=1--", "SLEEP(5)"],
        "matchers": ["sql_injection", "sqli"]
    },
    "ssti": {
        "payloads": ["{{7*7}}", "${7*7}"],
        "matchers": ["ssti", "template_injection"]
    },
    "lfi": {
        "payloads": ["../../../../etc/passwd", "....//....//etc/passwd"],
        "matchers": ["lfi", "path_traversal"]
    }
}

def show_banner():
    """Display animated banner"""
    console.print(Panel.fit(f"[cyan]{BANNER}[/]", 
                        title="[blink]ULTRA-NUCLEI PRO[/]", 
                        subtitle="by ~/.coffinxp@lostsec",
                        border_style="cyan"))

def check_tools():
    """Verify required tools are installed"""
    missing = []
    for tool in REQUIRED_TOOLS:
        if not subprocess.run(["which", tool], capture_output=True).stdout:
            missing.append(tool)
    
    if missing:
        console.print(f"\n[bold red]✗ Missing required tools: {', '.join(missing)}[/]")
        sys.exit(1)

def run_command(cmd, description=None, capture=True):
    """Execute command with progress tracking"""
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]{description}", total=1)
        try:
            result = subprocess.run(cmd, shell=True, check=True, 
                                  capture_output=capture, text=True)
            progress.update(task, advance=1)
            return result.stdout.strip().split('\n') if capture else True
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]❌ Command failed: {cmd}[/]")
            console.print(f"[red]{e.stderr}[/]")
            return []

def enhanced_gathering(target):
    """Advanced URL gathering with multiple sources"""
    console.print(f"\n[bold yellow]🔍 Deep Scanning: {target}[/]")
    urls = []
    
    # Wayback Machine
    urls += run_command(f"waybackurls {target}", "Fetching historical URLs")
    
    # GitHub endpoints
    urls += run_command(f"github-endpoints {target}", "Finding GitHub endpoints")
    
    # Common crawl
    urls += run_command(f"commoncrawl {target}", "Checking Common Crawl")
    
    return list(set(urls))

def parameter_analysis(urls):
    """Identify sensitive parameters in URLs"""
    sensitive_params = {
        'auth': ['token', 'key', 'secret', 'password'],
        'sql': ['query', 'id', 'select', 'where'],
        'rce': ['cmd', 'exec', 'command', 'run'],
        'ssrf': ['url', 'callback', 'proxy', 'request']
    }
    
    found_params = []
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for category, keywords in sensitive_params.items():
                if any(kw in param.lower() for kw in keywords):
                    found_params.append({
                        'url': url,
                        'parameter': param,
                        'category': category
                    })
    return found_params

def run_fuzzing(base_url, wordlist):
    """Perform directory and parameter fuzzing"""
    console.print(f"\n[bold yellow]💥 Fuzzing: {base_url}[/]")
    results = []
    
    # Directory fuzzing
    dir_output = tempfile.NamedTemporaryFile(delete=False)
    run_command(f"ffuf -w {wordlist} -u {base_url}/FUZZ -o {dir_output.name} -of json", 
               "Directory Fuzzing")
    results += json.load(open(dir_output.name))['results']
    
    # Parameter fuzzing
    param_output = tempfile.NamedTemporaryFile(delete=False)
    run_command(f"ffuf -w {wordlist} -u {base_url}?FUZZ=test -o {param_output.name} -of json",
               "Parameter Fuzzing")
    results += json.load(open(param_output.name))['results']
    
    return results

def active_testing(url, test_type):
    """Perform active vulnerability testing"""
    console.print(f"\n[bold yellow]⚡ Testing: {url}[/]")
    findings = []
    
    # XSS Testing
    if test_type == "xss":
        for payload in VULNERABILITY_TESTS['xss']['payloads']:
            modified = run_command(f"echo {url} | qsreplace '{payload}'", "Generating payload")
            response = requests.get(modified[0])
            if payload in response.text:
                findings.append({
                    'type': 'XSS',
                    'payload': payload,
                    'evidence': response.text[:100]
                })
    
    # SQLi Testing
    elif test_type == "sqli":
        for payload in VULNERABILITY_TESTS['sqli']['payloads']:
            modified = run_command(f"echo {url} | qsreplace '{payload}'", "Generating payload")
            start_time = time.time()
            requests.get(modified[0])
            if time.time() - start_time > 5:  # Time-based detection
                findings.append({
                    'type': 'SQLi',
                    'payload': payload,
                    'evidence': 'Delayed response'
                })
    
    return findings

def enhanced_nuclei_scan(target_file, config):
    """Advanced Nuclei scanning with custom workflows"""
    console.rule("[bold yellow]☢️ Advanced Nuclei Scanning")
    
    # Custom template scanning
    if config['templates']:
        run_command(f"nuclei -l {target_file} -t {config['templates']} "
                   f"-severity {config['severity']} -j -o {config['output']}/nuclei_results.json",
                   "Custom Template Scan")
    
    # Full passive scan
    run_command(f"nuclei -l {target_file} -tags misc -severity {config['severity']} "
               f"-j -o {config['output']}/passive_scan.json",
               "Passive Vulnerability Scan")
    
    # Active exploitation checks
    run_command(f"nuclei -l {target_file} -tags exploitation -severity {config['severity']} "
               f"-j -o {config['output']}/active_scan.json",
               "Active Exploitation Checks")

def generate_interactive_report(work_dir):
    """Create rich interactive report"""
    report_tree = Tree(f"Scan Results: [link file://{work_dir}]{work_dir}[/]")
    
    # Nuclei Findings
    nuclei_branch = report_tree.add("🔍 Nuclei Results")
    nuclei_files = [f for f in os.listdir(work_dir) if f.startswith('nuclei')]
    for nf in nuclei_files:
        nuclei_branch.add(f"[bold cyan]{nf}[/]")
    
    # Fuzzing Results
    fuzz_branch = report_tree.add("💥 Fuzzing Results")
    fuzz_files = [f for f in os.listdir(work_dir) if f.startswith('fuzz')]
    for ff in fuzz_files:
        fuzz_branch.add(f"[bold yellow]{ff}[/]")
    
    # Parameter Analysis
    param_branch = report_tree.add("🔑 Sensitive Parameters")
    with open(f"{work_dir}/parameters.json") as f:
        params = json.load(f)
        for param in params:
            param_branch.add(f"[bold red]{param['parameter']}[/] in [dim]{param['url']}[/]")
    
    console.print(Panel.fit(report_tree, title="[bold green]Scan Report[/]", border_style="blue"))

def main():
    show_banner()
    check_tools()

    parser = argparse.ArgumentParser(description="Ultra Nuclei Pro Scanner")
    parser.add_argument("target", help="Domain or file containing domains")
    parser.add_argument("-o", "--output", default="scans", help="Output directory")
    parser.add_argument("-t", "--templates", nargs="+", help="Nuclei templates/directories")
    parser.add_argument("-s", "--severity", default="critical,high,medium", 
                      help="Severity levels to include")
    parser.add_argument("-c", "--concurrency", type=int, default=50, 
                      help="Nuclei concurrency level")
    parser.add_argument("-w", "--wordlist", default="SecLists/Discovery/Web-Content/common.txt",
                      help="Fuzzing wordlist path")
    parser.add_argument("-a", "--active", action="store_true",
                      help="Enable active vulnerability testing")
    
    args = parser.parse_args()

    # Process targets
    targets = [args.target]
    if os.path.isfile(args.target):
        with open(args.target) as f:
            targets = [line.strip() for line in f]

    # Create workspace
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    work_dir = os.path.join(args.output, f"scan-{timestamp}")
    os.makedirs(work_dir, exist_ok=True)

    # Enhanced gathering
    all_urls = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(enhanced_gathering, target): target for target in targets}
        for future in futures:
            all_urls += future.result()

    # Parameter analysis
    sensitive_params = parameter_analysis(all_urls)
    with open(f"{work_dir}/parameters.json", "w") as f:
        json.dump(sensitive_params, f)

    # Fuzzing
    fuzz_results = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(run_fuzzing, url, args.wordlist): url for url in all_urls[:5]}
        for future in futures:
            fuzz_results += future.result()

    # Nuclei scanning
    nuclei_config = {
        'templates': ','.join(args.templates) if args.templates else None,
        'severity': args.severity,
        'output': work_dir
    }
    enhanced_nuclei_scan(f"{work_dir}/live_urls.txt", nuclei_config)

    # Active testing
    if args.active:
        active_findings = []
        for url in all_urls[:10]:  # Limit to first 10 for demo
            active_findings += active_testing(url, "xss")
            active_findings += active_testing(url, "sqli")
        with open(f"{work_dir}/active_findings.json", "w") as f:
            json.dump(active_findings, f)

    # Generate report
    generate_interactive_report(work_dir)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]✖ Scan aborted![/]")
        sys.exit(1)