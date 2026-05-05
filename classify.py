
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

    # Rule 1: Streaming
    # Video streaming is characterized by sustained bulk data transfer.
    # It has very high volume, many large packets, and a high mean packet size.
    if total_bytes > 2500000 and large_packets > 1200 and mean_packet_size > 800:
        return "Streaming", 85

    # Rule 2: Social Media / Heavy Web App
    # Sites like Facebook, LinkedIn, GitHub load lots of resources (JS/Images),
    # resulting in high packet counts, but their mean packet size is lower
    # due to many small requests, ACKs, and APIs.
    if total_packets > 300 and total_bytes > 300000 and small_packets > 100:
        return "Social Media", 75

    # Rule 3: API-Heavy
    # api.github.com: 38 pkts, 13KB, mean 365B
    # Threshold: small mean size + low total bytes
    if mean_packet_size < 400 and total_bytes < 50000 and total_packets < 100:
        return "API-Heavy", 80

    # Rule 4: Static Content
    # wikipedia: 70 pkts, 60KB
    # bbc:       164 pkts, 142KB
    # reddit:    45 pkts, 31KB
    # python:    29 pkts, 20KB
    # stackoverflow: 152 pkts, 127KB
    # anthropic: 114 pkts, 93KB
    # twitch:    182 pkts, 166KB
    # Threshold: covers all of these
    if total_packets < 250 and total_bytes < 250000:
        return "Static Content", 85

    return "Unknown", 0


def enrich_fingerprint(fingerprint):
    if "error" not in fingerprint:
        label, conf = classify_behavior(fingerprint)
        fingerprint["behavior_label"] = label
        fingerprint["confidence"] = conf
    return fingerprint