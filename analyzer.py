from scapy.all import rdpcap, ARP
from collections import Counter
import os

PCAP_FILE = "pcap/arp-storm.pcap"

print("=" * 60)
print("          Wi-Fi Security Threat Analyzer")
print("=" * 60)

if not os.path.exists(PCAP_FILE):
    print("ERROR: PCAP file not found!")
    exit()

packets = rdpcap(PCAP_FILE)

total_packets = len(packets)
arp_packets = 0
arp_requests = 0
arp_replies = 0

sender_ips = Counter()
target_ips = Counter()

for packet in packets:

    if packet.haslayer(ARP):

        arp_packets += 1
        arp = packet[ARP]

        if arp.op == 1:
            arp_requests += 1
            target_ips[arp.pdst] += 1

        elif arp.op == 2:
            arp_replies += 1

        sender_ips[arp.psrc] += 1


arp_percentage = (arp_packets / total_packets) * 100

print(f"Total Packets    : {total_packets}")
print(f"ARP Packets      : {arp_packets}")
print(f"ARP Percentage   : {arp_percentage:.2f}%")
print(f"ARP Requests     : {arp_requests}")
print(f"ARP Replies      : {arp_replies}")

print("\nTop ARP Senders:")
for ip, count in sender_ips.most_common(5):
    print(f"{ip} -> {count} packets")

print("\nMost Requested IPs:")
for ip, count in target_ips.most_common(5):
    print(f"{ip} -> {count} requests")

print("\nSecurity Assessment:")

if arp_packets > 500:
    print("⚠️ HIGH ARP ACTIVITY")
    print("Repeated ARP traffic requires investigation.")
elif arp_packets > 100:
    print("⚠️ MODERATE ARP ACTIVITY")
else:
    print("✅ LOW ARP ACTIVITY")

print("=" * 60)