
#!/usr/bin/env python
import scapy.all as scapy
import argparse
import csv
import ipaddress
import sys
import socket

def get_args():
    """Get command-line arguments."""
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP or IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", dest="output", help="File to save the results (e.g., results.csv)")
    parser.add_argument("-p", "--ports", dest="ports", type=str, help="Ports to scan (e.g., 22,80,443 or 1-1000)")
    parser.add_argument("--os", action="store_true", help="Enable OS detection")
    parser.add_argument("--resolve", action="store_true", help="Resolve hostnames")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed output")
    options = parser.parse_args()

    # Validate the target input
    try:
        ipaddress.ip_network(options.target, strict=False)
    except ValueError:
        print("Error: Invalid IP address or range.")
        sys.exit(1)

    return options

def scan(ip, verbose):
    """Scan the network and return a list of clients."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_brd = broadcast / arp_request
    answered_list = scapy.srp(arp_req_brd, timeout=1, verbose=verbose)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def port_scan(ip, ports, verbose):
    """Scan specified ports on a given IP address."""
    open_ports = []
    port_range = []
    
    # Parse the ports argument
    if '-' in ports:
        start, end = map(int, ports.split('-'))
        port_range = range(start, end + 1)
    else:
        port_range = map(int, ports.split(','))

    for port in port_range:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                if verbose:
                    print(f"Port {port} is open on {ip}")
            sock.close()
        except Exception as e:
            if verbose:
                print(f"Error scanning port {port} on {ip}: {e}")

    return open_ports

def os_detection(ip):
    """Detect the operating system (basic)."""
    try:
        ans, _ = scapy.sr(scapy.IP(dst=ip) / scapy.ICMP(), timeout=1, verbose=False)
        if ans:
            return "Likely Linux/Unix" if "ttl=64" in str(ans[0]) else "Likely Windows" if "ttl=128" in str(ans[0]) else "Unknown"
        return "Unknown"
    except Exception:
        return "Unknown"

def resolve_hostname(ip):
    """Resolve hostname for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def printer(result_lists):
    """Print the results in a table format."""
    print("IP Address\t\tMAC Address\t\tHostname\t\tOS\t\tOpen Ports\n" + "-" * 80)
    for client in result_lists:
        print(f"{client['ip']}\t\t{client['mac']}\t\t{client['hostname']}\t\t{client['os']}\t\t{', '.join(map(str, client['ports']))}")

def save_to_csv(result_lists, output_file):
    """Save the scan results to a CSV file."""
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "MAC Address", "Hostname", "OS", "Open Ports"])
        for client in result_lists:
            writer.writerow([client["ip"], client["mac"], client["hostname"], client["os"], ', '.join(map(str, client["ports"]))])
    print(f"Results saved to {output_file}")

# Main execution
if __name__ == "__main__":
    opts = get_args()
    if opts.verbose:
        print("[*] Starting scan...")

    scan_list = scan(opts.target, opts.verbose)
    if not scan_list:
        print("No devices found on the network.")
        sys.exit()

    # Enhanced features: hostname resolution, OS detection, and port scanning
    for client in scan_list:
        if opts.resolve:
            client["hostname"] = resolve_hostname(client["ip"])
        else:
            client["hostname"] = "N/A"

        if opts.os:
            client["os"] = os_detection(client["ip"])
        else:
            client["os"] = "N/A"

        if opts.ports:
            client["ports"] = port_scan(client["ip"], opts.ports, opts.verbose)
        else:
            client["ports"] = []

    printer(scan_list)

    # Save results if output file is specified
    if opts.output:
        save_to_csv(scan_list, opts.output)
