import time
from collections import defaultdict
from ids.utils import notify_ui, save_alert
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP
from datetime import datetime
import threading
import requests

# Thresholds and timeframes
BRUTE_FORCE_THRESHOLD = 10  # Number of failed attempts
DNS_THRESHOLD = 50          # Number of DNS queries
ARP_THRESHOLD = 20          # Number of ARP requests
DOS_THRESHOLD = 1000        # Number of packets from a single IP
PORT_SCAN_THRESHOLD = 100   # Number of ports accessed
TIMEFRAME = 60              # Timeframe in seconds

# Data structures for tracking
login_attempts = defaultdict(list)
dns_queries = defaultdict(list)
arp_requests = {}
dos_detect = defaultdict(int)
port_scan_detect = defaultdict(list)
malicious_ips = set()
malicious_domains = set()

def load_malicious_lists():
    global malicious_ips, malicious_domains
    print("Loading malicious IPs and domains from threat intelligence feeds...")
    # URLs of publicly available threat intelligence feeds
    ip_feeds = [
        'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'https://www.spamhaus.org/drop/drop.txt',
    ]
    domain_feeds = [
        'https://mirror.cedia.org.ec/malwaredomains/justdomains',
        'https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt',
    ]
    # Load malicious IPs
    for feed in ip_feeds:
        try:
            response = requests.get(feed, timeout=10)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ip = line.split()[0]
                        malicious_ips.add(ip)
            else:
                print(f"Failed to fetch IP feed: {feed}")
        except Exception as e:
            print(f"Error fetching IP feed {feed}: {e}")

    # Load malicious domains
    for feed in domain_feeds:
        try:
            response = requests.get(feed, timeout=10)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domain = line.strip('.')
                        malicious_domains.add(domain)
            else:
                print(f"Failed to fetch domain feed: {feed}")
        except Exception as e:
            print(f"Error fetching domain feed {feed}: {e}")

    print(f"Loaded {len(malicious_ips)} malicious IPs and {len(malicious_domains)} malicious domains.")

load_malicious_lists()

def detect_port_scan(packet):
    if TCP in packet or UDP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        current_time = time.time()
        port_scan_detect[src_ip].append((dst_port, current_time))

        # Remove old entries
        port_scan_detect[src_ip] = [(port, t) for port, t in port_scan_detect[src_ip] if current_time - t < TIMEFRAME]

        if len(set([port for port, t in port_scan_detect[src_ip]])) > PORT_SCAN_THRESHOLD:
            alert = f"Port scan detected from {src_ip}"
            notify_ui(alert)
            save_alert('Port Scan', src_ip, alert)
            port_scan_detect[src_ip] = []

def detect_dos(packet):
    src_ip = packet[IP].src
    dos_detect[src_ip] += 1

    # Reset counts periodically
    if dos_detect[src_ip] == 1:
        def reset_count():
            time.sleep(TIMEFRAME)
            dos_detect[src_ip] = 0
        threading.Thread(target=reset_count).start()

    if dos_detect[src_ip] > DOS_THRESHOLD:
        alert = f"DoS attack detected from {src_ip}"
        notify_ui(alert)
        save_alert('DoS Attack', src_ip, alert)
        dos_detect[src_ip] = 0

def detect_brute_force(packet):
    # Simulate detection of failed login attempts
    pass  # Implement if applicable

def detect_dns_tunneling(packet):
    if DNS in packet and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode().strip('.')
        src_ip = packet[IP].src
        current_time = time.time()
        dns_queries[src_ip].append((domain, current_time))
        # Clean up old entries
        dns_queries[src_ip] = [
            (d, t) for d, t in dns_queries[src_ip] if current_time - t < TIMEFRAME
        ]
        if len(dns_queries[src_ip]) > DNS_THRESHOLD:
            alert = f"DNS tunneling suspected from {src_ip}"
            notify_ui(alert)
            save_alert('DNS Tunneling', src_ip, alert)
            dns_queries[src_ip] = []

def detect_arp_spoofing(packet):
    if ARP in packet and packet[ARP].op == 2:  # ARP reply
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in arp_requests:
            if arp_requests[src_ip] != src_mac:
                alert = f"ARP spoofing detected: {src_ip} is claimed by {src_mac}"
                notify_ui(alert)
                save_alert('ARP Spoofing', src_ip, alert)
        else:
            arp_requests[src_ip] = src_mac

def detect_malware_communication(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Check for malicious IPs
        if src_ip in malicious_ips or dst_ip in malicious_ips:
            alert = f"Communication with malicious IP detected: {src_ip} <-> {dst_ip}"
            notify_ui(alert)
            save_alert('Malware Communication', src_ip, alert)
        # Check for malicious domains
        if DNS in packet and packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode().strip('.')
            if domain in malicious_domains:
                alert = f"DNS request to malicious domain detected: {domain}"
                notify_ui(alert)
                save_alert('Malware Communication', packet[IP].src, alert)
