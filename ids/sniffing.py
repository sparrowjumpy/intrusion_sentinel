from scapy.all import sniff, AsyncSniffer, IP, ARP
from ids.detectors import (
    detect_port_scan,
    detect_dos,
    detect_dns_tunneling,
    detect_arp_spoofing,
    detect_malware_communication,
    detect_icmp_flood,
    detect_ssh_brute_force,
    detect_ftp_brute_force,
    detect_http_sql_injection,
    detect_smtp_spam,
)
import threading

def packet_handler(packet):
    try:
        if IP in packet:
            detect_port_scan(packet)
            detect_dos(packet)
            detect_dns_tunneling(packet)
            detect_malware_communication(packet)
            detect_icmp_flood(packet)
            detect_ssh_brute_force(packet)
            detect_ftp_brute_force(packet)
            detect_http_sql_injection(packet)
            detect_smtp_spam(packet)
        if ARP in packet:
            detect_arp_spoofing(packet)
    except Exception as e:
        print(f"Error in packet_handler: {e}")

def start_sniffing():
    sniffer = AsyncSniffer(prn=packet_handler, store=False, iface="eth0")
    sniffer.start()
