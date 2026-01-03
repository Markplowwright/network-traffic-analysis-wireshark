import argparse
import sys
import datetime
import hashlib
import ipaddress
from collections import Counter

import dpkt


def parse_args():
    parser = argparse.ArgumentParser(description="PCAP Analyzer (learning building script)")
    parser.add_argument("pcap", help="Path to the PCAP file to analyze")
    parser.add_argument(
        "--dns-unanswered-threshold",
        type=float,
        default=0.30,
        help="Flag DNS risk if unanswered DNS ratio >= this threshold (default: 0.30)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many top DNS query domains to show (default: 10)",
    )
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


def stable_qname_hash(qname: str) -> int:
    """Stable hash for DNS qname (avoid Python's randomized hash())."""
    return int(hashlib.md5(qname.encode("utf-8")).hexdigest()[:8], 16)


def dns_rcode_name(rcode: int) -> str:
    """Best-effort DNS RCODE name mapping."""
    mapping = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    return mapping.get(rcode, f"RCODE_{rcode}")


def process_dns_packet(
    udp_payload: bytes,
    src_ip: str,
    dst_ip: str,
    dns_query_keys: set,
    dns_response_keys: set,
    dns_domain_counts: Counter,
    dns_rcode_counts: Counter,
):
    """
    Parse DNS payload and update:
      - query/response matching sets
      - top domain counts (queries only)
      - rcode counts (responses only)

    Best-effort: if parsing fails, do nothing.
    """
    try:
        dns = dpkt.dns.DNS(udp_payload)

        # Extract qname (best effort)
        qname = ""
        if dns.qd and len(dns.qd) > 0 and hasattr(dns.qd[0], "name"):
            qname = dns.qd[0].name or ""

        qhash = stable_qname_hash(qname)

        if dns.qr == dpkt.dns.DNS_Q:  # query
            dns_domain_counts[qname if qname else "(empty)"] += 1
            dns_query_keys.add((src_ip, dst_ip, dns.id, qhash))
        else:  # response
            dns_rcode_counts[dns_rcode_name(dns.rcode)] += 1
            # reverse direction so it matches the query-key format
            dns_response_keys.add((dst_ip, src_ip, dns.id, qhash))

    except Exception:
        return


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

    # PASS 4/5 DNS tracking
    dns_queries = 0
    dns_responses = 0
    dns_query_keys = set()     # (client_ip, dns_server_ip, dns_id, qname_hash)
    dns_response_keys = set()  # stored reversed to match query direction

    # PASS 5 DNS depth
    dns_domain_counts = Counter()  # qname -> count (queries)
    dns_rcode_counts = Counter()   # rcode name -> count (responses)

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
                            # Count query vs response (best effort)
                            # We'll infer query/response by parsing. If parse fails, no increment.
                            before_q = len(dns_query_keys)
                            before_r = len(dns_response_keys)

                            process_dns_packet(
                                udp_payload=udp.data,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                dns_query_keys=dns_query_keys,
                                dns_response_keys=dns_response_keys,
                                dns_domain_counts=dns_domain_counts,
                                dns_rcode_counts=dns_rcode_counts,
                            )

                            if len(dns_query_keys) > before_q:
                                dns_queries += 1
                            if len(dns_response_keys) > before_r:
                                dns_responses += 1
                    else:
                        other_count += 1

                # ---------- IPv6 ----------
                elif isinstance(l3, dpkt.ip6.IP6):
                    src_ip = ip_bytes_to_str(l3.src)
                    dst_ip = ip_bytes_to_str(l3.dst)

                    if l3.nxt == dpkt.ip.IP_PROTO_TCP:
                        tcp_count += 1

                    elif l3.nxt == dpkt.ip.IP_PROTO_UDP:
                        udp_count += 1
                        udp = l3.data

                        # DNS over UDP/53
                        if isinstance(udp, dpkt.udp.UDP) and (udp.sport == 53 or udp.dport == 53):
                            before_q = len(dns_query_keys)
                            before_r = len(dns_response_keys)

                            process_dns_packet(
                                udp_payload=udp.data,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                dns_query_keys=dns_query_keys,
                                dns_response_keys=dns_response_keys,
                                dns_domain_counts=dns_domain_counts,
                                dns_rcode_counts=dns_rcode_counts,
                            )

                            if len(dns_query_keys) > before_q:
                                dns_queries += 1
                            if len(dns_response_keys) > before_r:
                                dns_responses += 1
                    else:
                        other_count += 1

                # ---------- Non-IP ----------
                else:
                    other_count += 1

    except FileNotFoundError:
        print(f"Error: File not found: {args.pcap}", file=sys.stderr)
        return 2
    except (dpkt.dpkt.NeedData, ValueError) as e:
        print(f"Could not parse PCAP file: {e}", file=sys.stderr)
        return 2

    # PASS 4/5: DNS unanswered estimate (best-effort)
    dns_unanswered = len(dns_query_keys - dns_response_keys)
    dns_unanswered_ratio = (dns_unanswered / dns_queries) if dns_queries else 0.0
    dns_risk_flag = (dns_queries > 0) and (dns_unanswered_ratio >= args.dns_unanswered_threshold)

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

    print("Protocol breakdown (PASS 3/4/5):")
    print(f"  TCP:   {tcp_count}")
    print(f"  UDP:   {udp_count}")
    print(f"  Other: {other_count}")

    print("DNS breakdown (PASS 4/5):")
    print(f"  DNS queries:        {dns_queries}")
    print(f"  DNS responses:      {dns_responses}")
    print(f"  Unanswered queries: {dns_unanswered}")
    print(f"  Unanswered ratio:   {dns_unanswered_ratio:.2f}")
    print(f"  DNS risk flag:      {'YES' if dns_risk_flag else 'NO'} (threshold={args.dns_unanswered_threshold})")

    # PASS 5 depth: RCODEs + Top domains
    if dns_rcode_counts:
        print("DNS response codes (PASS 5):")
        for name, cnt in dns_rcode_counts.most_common():
            print(f"  {name:<8} {cnt}")

    if dns_domain_counts:
        print(f"Top DNS queried domains (PASS 5) (top {args.top}):")
        for qname, cnt in dns_domain_counts.most_common(args.top):
            print(f"  {qname:<45} {cnt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
