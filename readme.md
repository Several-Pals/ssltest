```bash
sudo python3 sniff.py 192.168.5.187 -i eth0 -f "port 80" -o output.pcap -t tap0

sudo python3 sniffer.py 192.168.5.187 eth0
```

https://github.com/l0v3c0d3r/Packet-Sniffer-in-Python-using-Scapy-and-SSLstrip