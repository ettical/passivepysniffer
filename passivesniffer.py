from scapy.all import *

def packet_sniffer(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        data = packet[TCP].payload
       
        print(f"Source IP: {src_ip}\tSource Port: {src_port}\n"
              f"Destination IP: {dst_ip}\tDestination Port: {dst_port}\n"
              f"Data: {data}\n")

# Sniff packets on the network interface
sniff(filter="tcp", prn=packet_sniffer)
