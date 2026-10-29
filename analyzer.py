import argparse
import csv
import re
from contextlib import nullcontext

import pyshark

# Restrict CSV output to simple filenames in the current directory.
CSV_FILENAME_PATTERN = r"[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\.csv"
CSV_COLUMN_NAMES = ["Packet", "Protocol", "Length", "Source IP", "Destination IP"]

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Capture and analyze network packets."
    )

    parser.add_argument(
        "--protocol", type=str, default=None,
        help="Display only this protocol"
    )
    parser.add_argument(
        "--count", type=int, default=5,
        help="Number of packets to capture (default: 5)"
    )
    parser.add_argument(
        "--interface", type=str, default="eth0",
        help="Capture interface (default: eth0)"
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Optional CSV output filename"
    )

    args = parser.parse_args()

    if args.count <= 0:
        parser.error("Packet count must be greater than zero.")

    if args.output is not None:
        if not re.fullmatch(CSV_FILENAME_PATTERN, args.output, re.IGNORECASE):
            parser.error("Invalid output filename. Use a valid .csv filename.")

    if args.protocol is not None:
        args.protocol = args.protocol.upper()

    return args

def get_ip_addresses(packet):
    """Extract IPv4 addresses, returning empty strings when unavailable."""

    # Not all captured packets contain an IPv4 layer, like ARP for example.
    if hasattr(packet, "ip"):
        return packet.ip.src, packet.ip.dst

    return "", ""

def display_packet(number, protocol, length, src_ip, dst_ip): # Displays all the information about the current packet 
    print(f"Packet {number}")
    print(f"Protocol: {protocol}")
    print(f"Length: {length}")

    if src_ip or dst_ip:
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
    else:
        print("No IPv4 layer found")

    print("----------------------------------")

def display_statistics(protocol_counts, total_packets, matching_packets, selected_protocol): # Displays some stats about collected packets
    print("--- Protocol Statistics ---")

    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count}")

    print(f"Total captured packets: {total_packets}")

    if selected_protocol is not None:
        print(f"Total matching packets: {matching_packets}")

def main():
    args = parse_arguments()

    protocol_counts = {}
    total_packets = 0
    matching_packets = 0
    capture = None

    try:
        # nullcontext allows the same 'with' block to work without CSV output.
        file_context = (
            open(args.output, "w", newline="", encoding="utf-8")
            if args.output else nullcontext()
        )

        # Automatically close the output file when capture finishes.
        with file_context as csv_file:
            writer = csv.writer(csv_file) if csv_file is not None else None

            if writer is not None:
                writer.writerow(CSV_COLUMN_NAMES)

            capture = pyshark.LiveCapture(interface=args.interface)

            # Process packets as they arrive instead of storing them in memory.
            for number, packet in enumerate(
                capture.sniff_continuously(packet_count=args.count), start=1
            ):
                total_packets += 1
                protocol = packet.highest_layer.upper()

                # Skip nonmatching packets while still counting all captured traffic.
                if args.protocol is not None and protocol != args.protocol:
                    print(f"Packet {number} captured, does not match filter")
                    print("----------------------------------")
                    continue

                matching_packets += 1
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

                src_ip, dst_ip = get_ip_addresses(packet)

                display_packet(number, protocol, packet.length, src_ip, dst_ip)

                # Only export packets that pass the protocol filter.
                if writer is not None:
                    writer.writerow([
                        number,
                        protocol,
                        packet.length,
                        src_ip,
                        dst_ip
                    ])

    except KeyboardInterrupt:
        # Allow Ctrl+C to stop capture without an unhandled traceback.
        print("\nCapture interrupted.")

    finally:
        # Release the live capture even if execution is interrupted.
        if capture is not None:
            capture.close()

    display_statistics(
        protocol_counts,
        total_packets,
        matching_packets,
        args.protocol
    )


# Only run the CLI when executed directly, not when imported for testing.
if __name__ == "__main__":
    main()
