import subprocess
import socket
import sys
import platform
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.progress import track
from rich.theme import Theme
from time import sleep
import requests
import shutil
import re
from bs4 import BeautifulSoup
import networkx as nx
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed for unverified HTTPS requests
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Custom hacker/professional theme
custom_theme = Theme({
    "primary": "bold green",
    "secondary": "bold cyan",
    "danger": "bold red",
    "info": "bold magenta",
    "highlight": "bold yellow",
    "dim": "dim white"
})
console = Console(theme=custom_theme)

# --- Existing Features ---
def check_internet_connection():
    console.print("[secondary]Checking internet connection...[/secondary]")
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        console.print("[primary]Internet connection is active![/primary]")
    except Exception:
        console.print("[danger]No internet connection detected.[/danger]")

def test_internet_speed():
    console.print("[secondary]Testing internet speed...[/secondary]")
    try:
        import speedtest
    except ImportError:
        console.print("[highlight]speedtest module not found. Installing...[/highlight]")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "speedtest-cli"])
        import speedtest
    st = speedtest.Speedtest()
    for step in track(["Download", "Upload"], description="[primary]Running speed test...[/primary]"):
        if step == "Download":
            download = st.download() / 1_000_000
        else:
            upload = st.upload() / 1_000_000
    ping = st.results.ping
    table = Table(title="[primary]Internet Speed Test Results[/primary]", style="dim")
    table.add_column("Metric", style="secondary", no_wrap=True)
    table.add_column("Value", style="highlight")
    table.add_row("Download", f"{download:.2f} Mbps")
    table.add_row("Upload", f"{upload:.2f} Mbps")
    table.add_row("Ping", f"{ping:.2f} ms")
    console.print(table)

# --- New Features ---
def public_ip_lookup():
    console.print("[secondary]Looking up your public IP address...[/secondary]")
    try:
        ip = requests.get("https://api.ipify.org").text
        console.print(Panel(f"[primary]{ip}[/primary]", title="[highlight]Your Public IP[/highlight]", expand=False))
    except Exception as e:
        console.print(f"[danger]Failed to retrieve public IP: {e}[/danger]")

def dns_lookup():
    domain = Prompt.ask("[info]Enter a domain to resolve (e.g. google.com)")
    try:
        ip = socket.gethostbyname(domain)
        console.print(Panel(f"[primary]{domain}[/primary] resolves to [highlight]{ip}[/highlight]", title="[highlight]DNS Lookup[/highlight]", expand=False))
        # Optionally show more records (A, MX, etc.)
    except Exception as e:
        console.print(f"[danger]DNS lookup failed: {e}[/danger]")

def ensure_command(cmd, package_name):
    """Check if a command exists, and if not, ask to install it."""
    if shutil.which(cmd) is not None:
        return True
    console.print(f"[danger]'{cmd}' is not installed.[/danger]")
    if Confirm.ask(f"[highlight]Do you want to install '{package_name}' now?[/highlight]", default=True):
        try:
            subprocess.check_call(["sudo", "apt", "update"])  # update first
            subprocess.check_call(["sudo", "apt", "install", package_name, "-y"])
            console.print(f"[primary]{package_name} installed successfully![/primary]")
            return True
        except Exception as e:
            console.print(f"[danger]Failed to install {package_name}: {e}[/danger]")
            return False
    else:
        console.print(f"[info]Skipping {cmd} feature.[/info]")
        return False

def traceroute():
    if platform.system().lower() == "windows":
        cmd_name = "tracert"
        package = None  # Not installable via apt
    else:
        cmd_name = "traceroute"
        package = "traceroute"
    if package and not ensure_command(cmd_name, package):
        return
    host = Prompt.ask("[info]Enter a host to traceroute (e.g. google.com)")
    console.print(f"[secondary]Running traceroute to [primary]{host}[/primary]...[/secondary]")
    try:
        cmd = [cmd_name, host]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(Panel(f"[dim]{result.stdout}[/dim]", title="[highlight]Traceroute Results[/highlight]", expand=False))
        else:
            console.print(f"[danger]Traceroute failed: {result.stderr}[/danger]")
    except Exception as e:
        console.print(f"[danger]Traceroute error: {e}[/danger]")

def whois_lookup():
    if not ensure_command("whois", "whois"):
        return
    domain = Prompt.ask("[info]Enter a domain for WHOIS lookup (e.g. google.com)")
    console.print(f"[secondary]Performing WHOIS lookup for [primary]{domain}[/primary]...[/secondary]")
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            display = "\n".join(lines[:30]) + ("\n..." if len(lines) > 30 else "")
            console.print(Panel(f"[dim]{display}[/dim]", title="[highlight]WHOIS Results[/highlight]", expand=False))
        else:
            console.print(f"[danger]WHOIS failed: {result.stderr}[/danger]")
    except Exception as e:
        console.print(f"[danger]WHOIS error: {e}[/danger]")

def local_network_info():
    console.print("[secondary]Gathering local network interface info...[/secondary]")
    try:
        result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
        if result.returncode == 0:
            # Show only the first 40 lines for brevity
            lines = result.stdout.splitlines()
            display = "\n".join(lines[:40]) + ("\n..." if len(lines) > 40 else "")
            console.print(Panel(f"[dim]{display}[/dim]", title="[highlight]Network Interfaces[/highlight]", expand=False))
        else:
            console.print(f"[danger]Failed to get network info: {result.stderr}[/danger]")
    except Exception as e:
        console.print(f"[danger]Network info error: {e}[/danger]")

def web_crawler_graph():
    console.print(Panel("[primary]Automated Web Crawler with Network Graph Output[/primary]", subtitle="[dim]Cybersecurity Recon[/dim]", expand=False, style="bold green"))
    start_url = Prompt.ask("[info]Enter the base URL to crawl (e.g. https://example.com)")
    max_depth = int(Prompt.ask("[info]Max crawl depth? (e.g. 2)", default="2"))
    use_hidden = Confirm.ask("[highlight]Attempt to discover hidden directories?[/highlight]", default=True)
    wordlist = ["admin", "login", "dashboard", ".git", ".env", "backup", "test", "dev", "config", "uploads", "private", "hidden"]
    visited = set()
    G = nx.DiGraph()
    session = requests.Session()
    def crawl(url, depth):
        if depth > max_depth or url in visited or not url.startswith(start_url):
            return
        visited.add(url)
        try:
            resp = session.get(url, timeout=5, allow_redirects=True, verify=False)
            G.add_node(url)
            if 'text/html' in resp.headers.get('Content-Type', ''):
                soup = BeautifulSoup(resp.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    link = a['href']
                    if link.startswith('/'):
                        link = start_url.rstrip('/') + link
                    elif not link.startswith('http'):
                        continue
                    if link not in visited:
                        G.add_edge(url, link)
                        crawl(link, depth+1)
            # Try hidden directories
            if use_hidden and depth < max_depth:
                for word in wordlist:
                    hidden_url = url.rstrip('/') + '/' + word
                    if hidden_url not in visited:
                        r = session.get(hidden_url, timeout=3, allow_redirects=True, verify=False)
                        if r.status_code < 400:
                            G.add_edge(url, hidden_url)
                            crawl(hidden_url, depth+1)
        except Exception as e:
            pass  # Ignore errors for robustness
    # Start crawling
    with console.status("[secondary]Crawling... This may take a while.[/secondary]"):
        crawl(start_url, 0)
    # Visualize the graph
    if G.number_of_nodes() == 0:
        console.print("[danger]No links found or crawl failed.[/danger]")
        return
    from rich.tree import Tree
    def build_tree(node, G, seen=None):
        if seen is None:
            seen = set()
        seen.add(node)
        tree = Tree(f"[primary]{node}[/primary]")
        for child in G.successors(node):
            if child not in seen:
                tree.add(build_tree(child, G, seen))
        return tree
    root = build_tree(start_url, G)
    console.print(Panel("[highlight]Crawl Network Graph[/highlight]", style="bold green"))
    console.print(root)
    console.print(f"[info]Crawl complete. {G.number_of_nodes()} unique URLs found.[/info]")

# --- Main Menu ---
def main_menu():
    while True:
        console.print(Panel("[primary]Network Tool[/primary]", subtitle="[dim]by AI Assistant[/dim]", expand=False, style="bold green"))
        console.print("[highlight]1.[/highlight] [primary]Check Internet Connection[/primary]")
        console.print("[highlight]2.[/highlight] [primary]Test Internet Speed[/primary]")
        console.print("[highlight]3.[/highlight] [primary]Public IP Address Lookup[/primary]")
        console.print("[highlight]4.[/highlight] [primary]DNS Lookup[/primary]")
        console.print("[highlight]5.[/highlight] [primary]Traceroute[/primary]")
        console.print("[highlight]6.[/highlight] [primary]Whois Lookup[/primary]")
        console.print("[highlight]7.[/highlight] [primary]Local Network Interface Info[/primary]")
        console.print("[highlight]8.[/highlight] [primary]Automated Web Crawler with Network Graph Output[/primary]")
        console.print("[highlight]9.[/highlight] [primary]Exit[/primary]")
        choice = Prompt.ask("[info]Choose an option[/info]", choices=[str(i) for i in range(1,10)])
        if choice == "1":
            check_internet_connection()
        elif choice == "2":
            test_internet_speed()
        elif choice == "3":
            public_ip_lookup()
        elif choice == "4":
            dns_lookup()
        elif choice == "5":
            traceroute()
        elif choice == "6":
            whois_lookup()
        elif choice == "7":
            local_network_info()
        elif choice == "8":
            web_crawler_graph()
        elif choice == "9":
            console.print("[primary]Goodbye! Stay secure.[/primary]")
            break
        console.print("\n")

if __name__ == "__main__":
    main_menu() 