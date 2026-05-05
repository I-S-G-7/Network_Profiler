def classify_behavior(fingerprint):

    total_bytes      = fingerprint.get("total_bytes", 0)
    total_packets    = fingerprint.get("total_packets", 0)
    mean_packet_size = fingerprint.get("mean_packet_size", 0)
    unique_ips       = len(fingerprint.get("unique_ips", []))
    dns_queries      = len(fingerprint.get("dns_queries", []))
    top_protocol     = fingerprint.get("top_protocol", "Unknown")
    protocol_dist    = fingerprint.get("protocol_distribution", {})
    size_buckets     = fingerprint.get("size_buckets", {})
    small_packets    = size_buckets.get("0-100", 0)
    large_packets    = (size_buckets.get("1001-1500", 0) +
                        size_buckets.get("1500+", 0))

    # Guard — not enough data to classify
    if total_packets < 5:
        return {"label": "Unknown", "confidence": 0}

    # Rule 1: Streaming
    # claude.com/product: 1225 pkts, 1.2MB, 646 large packets
    # Threshold: very high bytes + very high packet count + many large packets
    if total_bytes > 800000 and total_packets > 800 and large_packets > 400:
        return {"label": "Streaming", "confidence": 85}

    # Rule 2: Social Media
    # instagram: 341 pkts, 330KB, 138 small
    # github:    303 pkts, 302KB, 136 small
    # gemini:    317 pkts, 283KB, 154 small
    # Threshold: high packet count + high bytes + many small packets
    if total_packets > 250 and total_bytes > 250000 and small_packets > 100:
        return {"label": "Social Media", "confidence": 75}

    # Rule 3: API-Heavy
    # api.github.com: 38 pkts, 13KB, mean 365B
    # Threshold: small mean size + low total bytes
    if mean_packet_size < 400 and total_bytes < 50000 and total_packets < 100:
        return {"label": "API-Heavy", "confidence": 80}

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
        return {"label": "Static Content", "confidence": 85}

    return {"label": "Unknown", "confidence": 0}


 # Test against all real data
sites = [
        ("claude.com/product",  {"total_bytes": 1243327, "total_packets": 1225, "mean_packet_size": 1014, "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 560, "101-500": 9,  "501-1000": 10, "1001-1500": 539, "1500+": 107}}),
        ("anthropic.com",       {"total_bytes": 93103,   "total_packets": 114,  "mean_packet_size": 816,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 42,  "101-500": 8,  "501-1000": 8,  "1001-1500": 54,  "1500+": 2  }}),
        ("twitch.tv",           {"total_bytes": 166102,  "total_packets": 182,  "mean_packet_size": 912,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 84,  "101-500": 5,  "501-1000": 5,  "1001-1500": 69,  "1500+": 19 }}),
        ("instagram.com",       {"total_bytes": 330831,  "total_packets": 341,  "mean_packet_size": 970,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 138, "101-500": 16, "501-1000": 13, "1001-1500": 144, "1500+": 30 }}),
        ("reddit.com",          {"total_bytes": 31444,   "total_packets": 45,   "mean_packet_size": 698,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 25,  "101-500": 6,  "501-1000": 4,  "1001-1500": 7,   "1500+": 3  }}),
        ("linkedin.com",        {"total_bytes": 0,       "total_packets": 0,    "mean_packet_size": 0,    "unique_ips": [],        "dns_queries": [], "top_protocol": "Unknown","protocol_distribution": {},             "size_buckets": {"0-100": 0,   "101-500": 0,  "501-1000": 0,  "1001-1500": 0,   "1500+": 0  }}),
        ("wikipedia.org",       {"total_bytes": 60656,   "total_packets": 70,   "mean_packet_size": 866,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 31,  "101-500": 8,  "501-1000": 3,  "1001-1500": 22,  "1500+": 6  }}),
        ("bbc.com/news",        {"total_bytes": 142496,  "total_packets": 164,  "mean_packet_size": 868,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 72,  "101-500": 6,  "501-1000": 4,  "1001-1500": 73,  "1500+": 9  }}),
        ("python.org",          {"total_bytes": 20288,   "total_packets": 29,   "mean_packet_size": 699,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 17,  "101-500": 3,  "501-1000": 2,  "1001-1500": 6,   "1500+": 1  }}),
        ("github.com",          {"total_bytes": 302218,  "total_packets": 303,  "mean_packet_size": 997,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 136, "101-500": 20, "501-1000": 4,  "1001-1500": 118, "1500+": 25 }}),
        ("stackoverflow.com",   {"total_bytes": 127090,  "total_packets": 152,  "mean_packet_size": 836,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 62,  "101-500": 12, "501-1000": 12, "1001-1500": 59,  "1500+": 7  }}),
        ("api.github.com",      {"total_bytes": 13886,   "total_packets": 38,   "mean_packet_size": 365,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 22,  "101-500": 10, "501-1000": 2,  "1001-1500": 2,   "1500+": 2  }}),
        ("youtube.com",         {"total_bytes": 0,       "total_packets": 0,    "mean_packet_size": 0,    "unique_ips": [],        "dns_queries": [], "top_protocol": "Unknown","protocol_distribution": {},             "size_buckets": {"0-100": 0,   "101-500": 0,  "501-1000": 0,  "1001-1500": 0,   "1500+": 0  }}),
        ("gemini.google.com",   {"total_bytes": 283601,  "total_packets": 317,  "mean_packet_size": 894,  "unique_ips": ["x","y"], "dns_queries": [], "top_protocol": "HTTPS", "protocol_distribution": {"HTTPS": 100}, "size_buckets": {"0-100": 154, "101-500": 11, "501-1000": 11, "1001-1500": 106, "1500+": 35 }}),
    ]

print(f"{'Site':<25} {'Label':<18} {'Confidence'}")
print("-" * 55)
for name, fp in sites:
    result = classify_behavior(fp)
    print(f"{name:<25} {result['label']:<18} {result['confidence']}%")