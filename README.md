# NEONSCAN

**NEONSCAN** is a futuristic pentesting tool designed for Kali Linux. This advanced version includes the following features:

- **Futuristic Banner:** Displays the "NEONSCAN" ASCII art banner at startup using pyfiglet.
- **Ping Scan:** Sends ICMP packets to verify the target's reachability.
- **Port Scan:** Scans a range of ports (default: 20-1024) using threaded scanning for increased speed.
- **Banner Grabbing:** Attempts to retrieve the service banner on open ports.
- **DNS Lookup:** Resolves a domain, displaying the hostname, any aliases, and IP addresses.
- **Traceroute:** Performs a traceroute to map the path that packets take to reach the target.
- **Subnet Scan:** If the target is specified in CIDR format (e.g., `192.168.1.0/24`), it performs a ping sweep to identify active hosts on the network.

## Requirements

- Python 3.6 or higher
- [pyfiglet](https://pypi.org/project/pyfiglet/)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your_username/neonscan.git
