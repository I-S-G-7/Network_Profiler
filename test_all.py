import requests
import json
import time

urls = [
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://api.github.com",
    "https://www.wikipedia.org"
]

results = {}
for url in urls:
    print(f"Testing {url}...")
    try:
        response = requests.post("http://127.0.0.1:5000/api/analyze", json={"url": url})
        res_json = response.json()
        results[url] = {
            "total_bytes": res_json.get("total_bytes"),
            "total_packets": res_json.get("total_packets"),
            "mean_packet_size": res_json.get("mean_packet_size"),
            "unique_ips": res_json.get("unique_ips"),
            "dns_queries": res_json.get("dns_queries"),
            "top_protocol": res_json.get("top_protocol"),
            "protocol_dist": res_json.get("protocol_distribution"),
            "small_packets": res_json.get("size_buckets", {}).get("0-100", 0),
            "large_packets": res_json.get("size_buckets", {}).get("1500+", 0) + res_json.get("size_buckets", {}).get("1001-1500", 0),
            "label": res_json.get("behavior_label")
        }
    except Exception as e:
        results[url] = {"error": str(e)}

with open("test_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("Done. Results saved to test_results.json")
