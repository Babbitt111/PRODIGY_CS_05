from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        print(f"\n📦 Packet Captured:")
        print(f"🔹 Source IP: {src}")
        print(f"🔸 Destination IP: {dst}")

        if packet.haslayer(TCP):
            print("🔧 Protocol: TCP")
        elif packet.haslayer(UDP):
            print("🔧 Protocol: UDP")
        elif packet.haslayer(ICMP):
            print("🔧 Protocol: ICMP")
        else:
            print(f"🔧 Protocol: {proto}")

        if packet.haslayer(Raw):
            try:
                print(f"📨 Payload: {packet[Raw].load.decode(errors='ignore')}")
            except:
                print("📨 Payload: (unreadable binary data)")

print("🔍 Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=process_packet, store=False)