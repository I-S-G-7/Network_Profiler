from flask import Flask, request, jsonify
import os
import time
from capture import capture_traffic
from extract import extract_features
from fingerprint import generate_fingerprint
from classify import enrich_fingerprint

app = Flask(__name__)

def run_pipeline(url, duration=12): # Reduced to 12s for faster comparison
    unique_id = int(time.time() * 1000)
    pcap_file = f"capture_{unique_id}.pcap"
    
    try:
        # Step 1: Capture
        capture_traffic(url, duration=duration, output_pcap=pcap_file)
        
        # Step 2: Extract
        features = extract_features(pcap_file)
        
        # Step 3: Fingerprint & Classify
        fingerprint = generate_fingerprint(url, features)
        return enrich_fingerprint(fingerprint)
        
    except Exception as e:
        print(f"Error: {e}")
        return {"error": str(e), "site_url": url}
    finally:
        if os.path.exists(pcap_file):
            os.remove(pcap_file)

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    url = request.json.get('url')
    return jsonify(run_pipeline(url))

@app.route('/api/compare', methods=['POST'])
def compare():
    data = request.json
    url1 = data.get('url1')
    url2 = data.get('url2')
    
    if not url1 or not url2:
        return jsonify({"error": "Missing URLs"}), 400

    # Execute sequentially to avoid traffic bleeding
    print(f"[*] Analyzing first URL: {url1}")
    result1 = run_pipeline(url1)
    
    # Small pause to let the network "settle"
    time.sleep(2) 
    
    print(f"[*] Analyzing second URL: {url2}")
    result2 = run_pipeline(url2)
    
    diffs = {}
    if "error" not in result1 and "error" not in result2:
        diffs = {
            "total_bytes_diff": result1.get("total_bytes", 0) - result2.get("total_bytes", 0),
            "unique_ips_diff": result1.get("unique_ips", 0) - result2.get("unique_ips", 0),
            "mean_size_diff": result1.get("mean_packet_size", 0) - result2.get("mean_packet_size", 0)
        }
        
    return jsonify({
        "site1": result1,
        "site2": result2,
        "diffs": diffs
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)