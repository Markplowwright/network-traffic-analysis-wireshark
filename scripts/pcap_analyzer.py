import argparse
import sys
import datetime
import hashlib
import ipaddress

import dpkt


def parse_args():
    parser = argparse.ArgumentParser(description="PCAP Analyzer (learning building script)")
    parser.add_argument("pcap", help="Path to the PCAP file to analyze")
    return parser.parse_args()


def ip_bytes_to_str(addr_bytes: bytes) -> str:
    """Convert IPv4/IPv6 raw bytes to a printable IP string."""
    try:
        if len(addr_bytes) == 4:
            return str(ipaddress.IPv4Address(addr_bytes))
        if len(addr_bytes) == 16:
            return str(ipaddress.IPv6Address(addr_bytes))
    except Exception:
        pass
    return "unknown"


def main():
    args = parse_args()

    # PASS 2/3 counters
    packet_count = 0
    tcp_count = 0
    udp_count = 0
    other_count = 0

    # PASS 3 timing
    first_ts = None
    last_ts = None

    # PASS 4 DNS counters + matching sets
    dns_queries = 0
    dns_responses = 0
    dns_query_keys = set()     # (client_ip, dns_server_ip, dns_id, qname_hash)
    dns_response_keys = set()  # stored reversed to match query direction

    try:
        with open(args.pcap, "rb") as f:
            reader = dpkt.pcap.Reader(f)

            for ts, buf in reader:
                packet_count += 1

                # Track capture start/end timestamps (PASS 3)
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                # Decode Ethernet frame
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except (dpkt.dpkt.UnpackError, ValueError):
                    other_count += 1
                    continue

                l3 = eth.data  # could be IPv4, IPv6, ARP, etc.

                # ---------- IPv4 ----------
                if isinstance(l3, dpkt.ip.IP):
                    src_ip = ip_bytes_to_str(l3.src)
                    dst_ip = ip_bytes_to_str(l3.dst)

                    if l3.p == dpkt.ip.IP_PROTO_TCP:
                        tcp_count += 1

                    elif l3.p == dpkt.ip.IP_PROTO_UDP:
                        udp_count += 1
                        udp = l3.data

                        # DNS over UDP/53
                        if isinstance(udp, dpkt.udp.UDP) and (udp.sport == 53 or udp.dport == 53):
                            try:
                                dns = dpkt.dns.DNS(udp.data)

                                qname = ""
                                if dns.qd and len(dns.qd) > 0 and hasattr(dns.qd[0], "name"):
                                    qname = dns.qd[0].name or ""

                                # Stable qname hash (avoid Python randomized hash seed)
                                qhash = int(hashlib.md5(qname.encode("utf-8")).hexdigest()[:8], 16)

                                if dns.qr == dpkt.dns.DNS_Q:  # query
                                    dns_queries += 1
                                    dns_query_keys.add((src_ip, dst_ip, dns.id, qhash))
                                else:  # response
                                    dns_responses += 1
                                    dns_response_keys.add((dst_ip, src_ip, dns.id, qhash))

                            except Exception:
                                pass
                    else:
                        other_count += 1

                # ---------- IPv6 ----------
                elif isinstance(l3, dpkt.ip6.IP6):
                    src_ip = ip_bytes_to_str(l3.src)
                    dst_ip = ip_bytes_to_str(l3.dst)

                    # In IPv6, "next header" is l3.nxt
                    if l3.nxt == dpkt.ip.IP_PROTO_TCP:
                        tcp_count += 1

                    elif l3.nxt == dpkt.ip.IP_PROTO_UDP:
                        udp_count += 1
                        udp = l3.data

                        # DNS over UDP/53
                        if isinstance(udp, dpkt.udp.UDP) and (udp.sport == 53 or udp.dport == 53):
                            try:
                                dns = dpkt.dns.DNS(udp.data)

                                qname = ""
                                if dns.qd and len(dns.qd) > 0 and hasattr(dns.qd[0], "name"):
                                    qname = dns.qd[0].name or ""

                                qhash = int(hashlib.md5(qname.encode("utf-8")).hexdigest()[:8], 16)

                                if dns.qr == dpkt.dns.DNS_Q:  # query
                                    dns_queries += 1
                                    dns_query_keys.add((src_ip, dst_ip, dns.id, qhash))
                                else:  # response
                                    dns_responses += 1
                                    dns_response_keys.add((dst_ip, src_ip, dns.id, qhash))

                            except Exception:
                                pass
                    else:
                        other_count += 1

                # ---------- Non-IP (ARP, etc.) ----------
                else:
                    other_count += 1

    except FileNotFoundError:
        print(f"Error: File not found: {args.pcap}", file=sys.stderr)
        return 2
    except (dpkt.dpkt.NeedData, ValueError) as e:
        print(f"Could not parse PCAP file: {e}", file=sys.stderr)
        return 2

    # PASS 4: DNS unanswered estimate (best-effort)
    dns_unanswered = len(dns_query_keys - dns_response_keys)
    dns_unanswered_ratio = (dns_unanswered / dns_queries) if dns_queries else 0.0

    # Output
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

    print("Protocol breakdown (PASS 3/4):")
    print(f"  TCP:   {tcp_count}")
    print(f"  UDP:   {udp_count}")
    print(f"  Other: {other_count}")

    print("DNS breakdown (PASS 4):")
    print(f"  DNS queries:        {dns_queries}")
    print(f"  DNS responses:      {dns_responses}")
    print(f"  Unanswered queries: {dns_unanswered}")
    print(f"  Unanswered ratio:   {dns_unanswered_ratio:.2f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
