# Network Scanner

A Python-based network scanner that detects active devices on a network, performs port scanning, resolves hostnames, and provides basic OS detection.

## Features
- **ARP Scanning**: Discovers devices in a network by sending ARP requests.
- **Port Scanning**: Identifies open ports on target devices.
- **Hostname Resolution**: Resolves IP addresses to hostnames.
- **Basic OS Detection**: Attempts to detect the operating system of target devices.

## Requirements
- Python 3.x
- Scapy library

Install Scapy:
```bash
pip install scapy
```

## Usage
1. Make the script executable (Linux/Mac):
    ```bash
    chmod +x scanner.py
    ```

2. Run the script:
    ```bash
    ./scanner.py -t <target>
    ```
   or:
    ```bash
    python3 scanner.py -t <target>
    ```

### Note for Windows Users
If you are running the script on Windows, you can remove the first line (`#!/usr/bin/env python`) from the script to avoid errors.

## Examples
- Scan a single IP:
    ```bash
    python3 scanner.py -t 192.168.1.1
    ```

- Scan an IP range:
    ```bash
    python3 scanner.py -t 192.168.1.0/24
    ```

## How It Works
1. **ARP Requests**: Sends ARP requests to discover devices on the network.
2. **Port Scanning**: Uses TCP SYN scans to check for open ports.
3. **Hostname Resolution**: Uses reverse DNS lookups to resolve hostnames.
4. **OS Detection**: Analyzes responses for hints about the target's operating system.

## Output Example
```
IP Address       MAC Address           Hostname          Open Ports       OS
192.168.1.1      00:11:22:33:44:55    router.local      22, 80           Linux
192.168.1.10     66:77:88:99:AA:BB    desktop.local     135, 445         Windows
```

## Disclaimer
This tool is for educational purposes only. Use it responsibly and only on networks you own or have permission to scan.

