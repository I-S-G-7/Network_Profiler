
def classify_behavior(fingerprint):
    if "error" in fingerprint:
        return "Unknown", 0

    total_bytes      = fingerprint.get("total_bytes", 0)
    total_packets    = fingerprint.get("total_packets", 0)
    mean_packet_size = fingerprint.get("mean_packet_size", 0)
    unique_ips       = fingerprint.get("unique_ips", 0)
    dns_queries      = fingerprint.get("dns_queries", 0)
    top_protocol     = fingerprint.get("top_protocol", "Unknown")
    protocol_dist    = fingerprint.get("protocol_distribution", {})
    size_buckets     = fingerprint.get("size_buckets", {})
    small_packets    = size_buckets.get("0-100", 0)
    large_packets    = (size_buckets.get("1001-1500", 0) +
                        size_buckets.get("1500+", 0))

    # Guard — not enough data to classify
    if total_packets < 5:
        return "Unknown", 0

    tcp_share = protocol_dist.get("TCP", 0) + protocol_dist.get("HTTPS", 0)
    protocols_in_mix = sum(1 for share in protocol_dist.values() if share > 5)

    # (1) Streaming - high byte volume, large average packet size
    # Dropped strict TCP requirement because modern video (e.g. YouTube) uses HTTP/3 QUIC (UDP)
    if total_bytes > 3000000 and mean_packet_size > 800 and total_packets > 2500:
        return "Streaming", 85

    # (4) API-Heavy - very small packets, rapid request-response cycles, HTTPS dominant
    # Checked early so clean APIs don't mistakenly fall into Static Content
    if mean_packet_size < 500 and top_protocol == "HTTPS" and protocol_dist.get("HTTPS", 0) > 80 and total_bytes < 500000:
        return "API-Heavy", 80

    # (2) Social Media - frequent small packets, many unique IPs, mix of protocols
    if small_packets > 400 and unique_ips >= 10 and protocols_in_mix >= 2:
        return "Social Media", 75

    # (3) Static Content - low packet count, short session duration, minimal DNS queries
    if total_packets <= 3000 and dns_queries <= 35:
        return "Static Content", 85

    # (5) Unknown - does not match any pattern
    return "Unknown", 0


def enrich_fingerprint(fingerprint):
    if "error" not in fingerprint:
        label, conf = classify_behavior(fingerprint)
        fingerprint["behavior_label"] = label
        fingerprint["confidence"] = conf
    return fingerprint