import pyshark
import sys

capture = pyshark.LiveCapture(interface='eth0')

protocol_counts   = {}
total_packets     = 0
selected_protocol = None

# check for a protocol filter
if len(sys.argv) == 2:
    selected_protocol = sys.argv[1].upper()
elif len(sys.argv) > 2:
    print("Usage: python analyzer.py [protocol]")
    sys.exit(1)

try:
    for i, packet in enumerate(capture.sniff_continuously(packet_count=5), start=1):
        packet_protocol = packet.highest_layer.upper()

        # display packets only if they match the selected protocol filter
        if selected_protocol is None or packet_protocol == selected_protocol:
            if packet_protocol in protocol_counts:
                protocol_counts[packet_protocol] += 1
            else:
                protocol_counts[packet_protocol] = 1

            print(f"Packet {i}")
            print(f"Protocol: {packet_protocol}")
            print(f"Length: {packet.length}")

            if hasattr(packet, 'ip'):
                print(f"Source IP: {packet.ip.src}")
                print(f"Destination IP: {packet.ip.dst}")
            else:
                print("No IPv4 layer found")

            total_packets += 1
            print("----------------------------------")

except KeyboardInterrupt:
    print("\nCapture interrupted.") #triggered on ctrl+c

finally:
    capture.close() #always cleanup

print("--- Protocol Statistics ---")

for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")

print(f"Total matching packets: {total_packets}")
