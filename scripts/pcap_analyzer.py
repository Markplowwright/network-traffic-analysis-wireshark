import datetime
import argparse
import sys
import dpkt


def parse_args():
    parser = argparse.ArgumentParser(description="PCAP Analyzer (learning building script)")
    parser.add_argument("pcap", help="Path to the PCAP file to analyze")
    return parser.parse_args()

def main():
    args = parse_args()

    packet_count = 0
    tcp_count = 0
    udp_count = 0
    other_count = 0

    first_ts = None
    last_ts = None

    try:
        with open(args.pcap, "rb") as f:
            reader = dpkt.pcap.Reader(f)

            for ts, buf in reader:
                packet_count += 1

                # Track capture start/end timestamps
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                # Decode Ethernet frame
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except (dpkt.dpkt.UnpackError, ValueError):
                    other_count += 1
                    continue

                l3 = eth.data  # usually IPv4, IPv6, ARP, etc.

                # PASS 3: classify IPv4 packets by L4 protocol
                if isinstance(l3, dpkt.ip.IP):
                    if l3.p == dpkt.ip.IP_PROTO_TCP:
                        tcp_count += 1
                    elif l3.p == dpkt.ip.IP_PROTO_UDP:
                        udp_count += 1
                    else:
                        other_count += 1
                else:
                    other_count += 1

    except FileNotFoundError:
        print(f"Error: File not found: {args.pcap}", file=sys.stderr)
        return 2
    except (dpkt.dpkt.NeedData, ValueError) as e:
        print(f"Could not parse PCAP file: {e}", file=sys.stderr)
        return 2

    print("PCAP Analyzer starting...")
    print(f"PCAP file: {args.pcap}")
    print(f"Total packets: {packet_count}")

    if first_ts is not None and last_ts is not None:
        start = datetime.datetime.fromtimestamp(first_ts)
        end = datetime.datetime.fromtimestamp(last_ts)
        duration = max(last_ts - first_ts, 0.0)
        print(f"Capture start: {start}")
        print(f"Capture end:   {end}")
        print(f"Duration (s):  {duration:.2f}")

    print("Protocol breakdown (PASS 3):")
    print(f"  TCP:   {tcp_count}")
    print(f"  UDP:   {udp_count}")
    print(f"  Other: {other_count}")

    return 0

if __name__ == "__main__":
    sys.exit(main())