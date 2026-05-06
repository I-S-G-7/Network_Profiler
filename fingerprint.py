import time

def generate_fingerprint(url, features):
    if features.get("total_packets", 0) == 0:
        return {
            "site_url": url,
            "capture_timestamp": time.time(),
            "error": "No packets captured or could not reach destination."
        }

    total = features["total_packets"]
    protocol_distribution = {}
    for proto, count in features["protocol_counts"].items():
        if count > 0:
            protocol_distribution[proto] = round((count / total) * 100, 2)

    top_protocol = max(protocol_distribution, key=protocol_distribution.get) if protocol_distribution else "Unknown"

    fingerprint = {
        "site_url": url,
        "capture_timestamp": time.time(),
        "total_packets": features["total_packets"],
        "total_bytes": features["total_bytes"],
        "top_protocol": top_protocol,
        "unique_ips": len(features["unique_ips"]),
        "dns_queries": len(features["dns_queries"]),
        "mean_packet_size": round(features["mean_packet_size"], 2),
        "max_packet_size": features["max_packet_size"],
        "protocol_distribution": protocol_distribution,
        "size_buckets": features.get("size_buckets", {}),
        "bytes_per_second": features.get("bytes_per_second", {}),
        "packet_sizes": features["packet_sizes"]
    }
    return fingerprint
