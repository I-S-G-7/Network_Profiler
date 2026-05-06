import requests
import time
import json

url = "http://127.0.0.1:5000/api/analyze"
data = {"url": "https://www.python.org"}

try:
    response = requests.post(url, json=data)
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
