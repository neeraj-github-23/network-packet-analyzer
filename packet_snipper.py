from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "Unknown"

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"

        print(f"\n[+] Packet Captured")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {proto}")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"    Payload Data   : {payload[:50]}")  # Show first 50 bytes

print("Starting Packet Sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
