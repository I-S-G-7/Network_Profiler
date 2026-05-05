import json
from classify import classify_behavior

test_cases = [
    {
        "name": "YouTube",
        "fingerprint": {
            "site_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "mean_packet_size": 200,   
            "total_bytes": 50000,      
            "total_packets": 100,
            "unique_ips": 3,
            "protocol_distribution": {"HTTPS": 60, "UDP": 40}
        }
    },
    {
        "name": "GitHub",
        "fingerprint": {
            "site_url": "https://github.com/torvalds/linux",
            "mean_packet_size": 150,
            "total_bytes": 80000,
            "total_packets": 120,
            "unique_ips": 2,
            "protocol_distribution": {"HTTPS": 100}
        }
    },
    {
        "name": "Generic Streaming",
        "fingerprint": {
            "site_url": "https://netflix.com",
            "mean_packet_size": 950,
            "total_bytes": 1000000,
            "total_packets": 1000,
            "unique_ips": 4,
            "protocol_distribution": {"HTTPS": 95, "Other": 5}
        }
    },
    {
        "name": "Social Media",
        "fingerprint": {
            "site_url": "https://twitter.com",
            "mean_packet_size": 500,
            "total_bytes": 300000,
            "total_packets": 600,
            "unique_ips": 8,
            "protocol_distribution": {"HTTPS": 90, "DNS": 10}
        }
    },
    {
        "name": "Static Content",
        "fingerprint": {
            "site_url": "http://example.com",
            "mean_packet_size": 400,
            "total_bytes": 50000,
            "total_packets": 120,
            "unique_ips": 2,
            "protocol_distribution": {"TCP": 100}
        }
    },
    {
        "name": "API-Heavy",
        "fingerprint": {
            "site_url": "https://api.weather.gov",
            "mean_packet_size": 300,
            "total_bytes": 200000,
            "total_packets": 600,
            "unique_ips": 1,
            "protocol_distribution": {"HTTPS": 95, "TCP": 5}
        }
    },
    {
        "name": "Unknown",
        "fingerprint": {
            "site_url": "https://random-blog.com",
            "mean_packet_size": 500,    
            "total_bytes": 200000,      
            "total_packets": 400,
            "unique_ips": 2,
            "protocol_distribution": {"TCP": 50, "UDP": 50} 
        }
    }
]

for tc in test_cases:
    label, conf = classify_behavior(tc["fingerprint"])
    print(f"Test Case: {tc['name']}")
    print(f"Result: {label} (Confidence: {conf})")
    print("-" * 30)
