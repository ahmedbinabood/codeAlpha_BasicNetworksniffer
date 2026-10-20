from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    if IP not in packet:
        return

    print("-" * 40)
    print("Source IP:", packet[IP].src)
    print("Destination IP:", packet[IP].dst)

    if TCP in packet:
        print("Protocol: TCP")
    elif UDP in packet:
        print("Protocol: UDP")
    elif ICMP in packet:
        print("Protocol: ICMP")
    else:
        print("Protocol: Other IP")

    print("Packet size:", len(packet), "bytes")
    print("Summary:", packet.summary())

print("Basic Network Sniffer Started")
print("Capturing 20 packets...")

sniff(
    filter="ip",
    prn=analyze_packet,
    count=20,
    store=False
)

print("Capture completed!")