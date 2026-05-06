from scapy.all import rdpcap, TCP, UDP, ICMP, DNS, ARP, IP
import statistics

def extract_features(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception:
        packets = []
    
    if not packets:
        return {
        "total_packets":         0,
        "protocol_counts":       {},
        "protocol_distribution": {},
        "packet_sizes":          [],
        "mean_packet_size":      0.0,
        "min_packet_size":       0,
        "max_packet_size":       0,
        "unique_dest_ips":       [],
        "dns_queries":           [],
        "total_bytes":           0,
        "inter_arrival_times":   [],
        "packet_timestamps":     [],
        "size_buckets":          {"0-100":0,"101-500":0,"501-1000":0,"1001-1500":0,"1500+":0},
        "bytes_per_second":      {},
    }

    total_bytes = 0
    protocol_counts = {"TCP": 0, "UDP": 0, "DNS": 0, "HTTPS": 0, "Other": 0}
    unique_ips = set()
    dns_queries = set()
    packet_sizes = []
    timestamps = []

    for pkt in packets:
        size = len(pkt)
        total_bytes += size
        packet_sizes.append(size)
        if hasattr(pkt, 'time'):
            timestamps.append(float(pkt.time))

        if IP in pkt:
            unique_ips.add(pkt[IP].dst)

        # Better Protocol Detection
        if TCP in pkt:
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                protocol_counts["HTTPS"] += 1
            else:
                protocol_counts["TCP"] += 1
        elif UDP in pkt:
            if DNS in pkt:
                protocol_counts["DNS"] += 1
                if pkt[DNS].qr == 0: 
                    try:
                        qname = pkt[DNS].qd[0].qname.decode('utf-8')
                        dns_queries.add(qname)
                    except: pass
            else:
                protocol_counts["UDP"] += 1
        else:
            protocol_counts["Other"] += 1
    size_buckets = {
        "0-100":    0,
        "101-500":  0,
        "501-1000": 0,
        "1001-1500":0,
        "1500+":    0,
    }

    for s in packet_sizes:
        if s <= 100:
            size_buckets["0-100"] += 1
        elif s <= 500:
            size_buckets["101-500"] += 1
        elif s <= 1000:
            size_buckets["501-1000"] += 1
        elif s <= 1500:
            size_buckets["1001-1500"] += 1
        else:
            size_buckets["1500+"] += 1
    bytes_per_second = {}
    if timestamps:
        start_time = timestamps[0]
        for t, s in zip(timestamps, packet_sizes):
            sec = int(t - start_time)
            bytes_per_second[sec] = bytes_per_second.get(sec, 0) + s

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "protocol_counts": protocol_counts,
        "unique_ips": list(unique_ips),
        "dns_queries": list(dns_queries),
        "packet_sizes": packet_sizes,
        "size_buckets": size_buckets,
        "bytes_per_second": bytes_per_second,
        "mean_packet_size": statistics.mean(packet_sizes) if packet_sizes else 0,
        "max_packet_size": max(packet_sizes) if packet_sizes else 0
    }