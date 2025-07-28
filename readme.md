# Network Tool

A stunning, hacker-themed command-line network utility for WSL (Ubuntu) with the following features:

- **Check Internet Connection**: Instantly verify if your system is online.
- **Test Internet Speed**: Measure your download, upload, and ping using speedtest.net.
- **Public IP Address Lookup**: Instantly see your public-facing IP address.
- **DNS Lookup**: Resolve any domain to its IP address.
- **Traceroute**: Visualize the network path to any host.
- **Whois Lookup**: Get domain registration and ownership info.
- **Local Network Interface Info**: Display all local network interfaces and their IPs.
- **Automated Web Crawler with Network Graph Output**: Crawl a website, discover all reachable and hidden links/directories, and visualize the structure as a  CLI network graph for cybersecurity recon.

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt --break-system-packages
   ```

2. Run the tool:
   ```bash
   python3 network_tool.py
   ```

## Requirements
- Python 3.7+
- WSL (Ubuntu recommended)
- `pip` for installing dependencies
- Internet connection for some features

## Notes
- Some features may require administrative privileges.
- Use responsibly and only on networks/devices you own or have permission to scan.
- The tool uses a custom hacker/professional color theme for a stunning CLI experience.

## Automated Web Crawler with Network Graph Output
- Enter a base URL and the tool will recursively crawl all reachable links up to a specified depth.
- Optionally, it will attempt to discover hidden directories using a built-in wordlist (for cybersecurity recon).
- The discovered site structure is visualized as a beautiful ASCII/Unicode network graph in the terminal.
- Useful for web reconnaissance, bug bounty, and understanding site architecture.

---

Enjoy your network exploration with a beautiful CLI experience! 