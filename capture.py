import threading
import time
from playwright.sync_api import sync_playwright
from scapy.all import sniff, wrpcap

def capture_traffic(url, duration=12, output_pcap="capture.pcap"):
    captured_packets = []
    
    # We use a broad filter but we rely on SEQUENTIAL timing to separate data
    filter_expr = "tcp or udp" 

    def run_sniffer():
        # The timeout here is the "hard stop" for the sniffer
        pkts = sniff(filter=filter_expr, timeout=duration + 2) 
        captured_packets.extend(pkts)

    sniffer_thread = threading.Thread(target=run_sniffer)
    sniffer_thread.start()

    # Give sniffer a moment to hook into the interface
    time.sleep(2)

    try:
        with sync_playwright() as p:
            # We use a short headless browser session
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            # Go to the URL and wait for it to be somewhat stable
            page.goto(url, wait_until="load", timeout=15000)
            
            # Let it run for the remaining duration
            time.sleep(duration - 3 if duration > 3 else 1)
            browser.close()
    except Exception as e:
        print(f"Browser error for {url}: {e}")

    # Ensure the sniffer thread finishes
    sniffer_thread.join(timeout=duration + 5)
    
    wrpcap(output_pcap, captured_packets)
    print(f"[*] Saved {len(captured_packets)} packets for {url}")