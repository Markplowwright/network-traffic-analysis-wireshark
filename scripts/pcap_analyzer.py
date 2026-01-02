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
    try: 
        with open(args.pcap, 'rb') as f:
            reader = dpkt.pcap.Reader(f)
            for _ts, _buf in reader: 
                packet_count += 1
        
    except FileNotFoundError:
        print(f"Error: File not found: {args.pcap}", file=sys.stderr)
        return 2
    except (dpkt.dpkt.NeedData, ValueError) as e:
        print(f"Could not parse PCAP file:{e}", file=sys.stderr)
        return 2

    print ("PCAP Analyzer starting...")
    print (f"PCAP file: {args.pcap}")
    print (f"Total packets: {packet_count}")
    return 0

if __name__ == "__main__":
    sys.exit(main())