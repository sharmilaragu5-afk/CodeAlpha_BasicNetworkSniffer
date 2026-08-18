from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


packet_count = 0
MAX_PACKETS = 20


def process_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Identify protocol and ports
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"
        source_port = "-"
        destination_port = "-"

    else:
        protocol = "Other"
        source_port = "-"
        destination_port = "-"

    print("\n" + "=" * 65)
    print(f"Packet Number   : {packet_count}")
    print(f"Time            : {timestamp}")
    print(f"Source IP       : {source_ip}")
    print(f"Destination IP  : {destination_ip}")
    print(f"Protocol        : {protocol}")
    print(f"Source Port     : {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Packet Size     : {packet_size} bytes")

    # Display limited payload information
    if Raw in packet:
        payload = packet[Raw].load
        preview = payload[:50]

        try:
            print(f"Payload Preview : {preview.decode(errors='replace')}")
        except Exception:
            print(f"Payload Preview : {preview}")

    if packet_count >= MAX_PACKETS:
        print("\n" + "=" * 65)
        print(f"Capture completed. {MAX_PACKETS} packets analyzed.")
        print("=" * 65)


print("=" * 65)
print("       CodeAlpha - Basic Network Sniffer")
print("=" * 65)
print(f"Capturing up to {MAX_PACKETS} packets...")
print("Generate some network activity using your browser.")
print("=" * 65)

sniff(
    prn=process_packet,
    store=False,
    stop_filter=lambda packet: packet_count >= MAX_PACKETS
)

print("\nSniffer stopped successfully.")
