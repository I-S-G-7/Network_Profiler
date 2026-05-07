# Network Traffic Profiler

A lightweight, web‑based educational tool that captures network traffic for a given URL, extracts behavioural features, generates a fingerprint, and classifies the traffic.

---

## Features
- **Capture** live network traffic using **Scapy** (or underlying OS capture utilities).
- **Extract** key metrics: total bytes, unique IPs, mean packet size, etc.
- **Fingerprint** generation in a deterministic JSON format.
- **Simple classification** (static, streaming, social, unknown) based on rule‑based heuristics.
- **Compare** two sites side‑by‑side with a diff of core metrics.
- **Responsive UI** built with vanilla HTML/CSS/JavaScript (no heavy frameworks).

---

## Architecture Overview
```
+-----------------+      +-------------------+      +-------------------+
|   Frontend UI   | ---> |   Flask API (app) | ---> |   Capture (Scapy) |
+-----------------+      +-------------------+      +-------------------+
                               |                         |
                               v                         v
                      +------------------------+      +------------------------------+
                      |   Extract (extract.py) |      | Fingerprint (fingerprint.py) |
                      +------------------------+      +------------------------------+
                               |
                               v
                      +-------------------------------+
                      |  Classification (classify.py) |
                      +-------------------------------+
```

---

## Prerequisites
- **Python 3.10+**
- **pip** (for installing dependencies)
- **Windows** (or Linux/macOS with appropriate permissions for packet capture)

---

## Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/network_profiler.git
cd network_profiler

# (Optional) create a virtual environment
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

---

## Usage
1. **Start the server**
   ```bash
   python app.py
   ```
   The app will run on `http://127.0.0.1:5000`.

2. **Open the UI** in a browser and enter a URL to analyse.

3. **API endpoints** (JSON requests):
   - `POST /api/analyze` – Analyze a single URL.
   - `POST /api/compare` – Compare two URLs and receive a diff of key metrics.

   Example cURL request:
   ```bash
   curl -X POST http://127.0.0.1:5000/api/analyze \
        -H "Content-Type: application/json" \
        -d '{"url": "https://example.com"}'
   ```

---

## Testing
A basic pytest suite is provided:
```bash
pytest test_*.py
```
The tests cover capture stubs, feature extraction, fingerprint generation, and API responses.

---

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feat/your-feature`).
3. Make your changes and ensure tests pass.
4. Open a pull request with a clear description of the changes.

---

## License
This project is licensed under the MIT License – see the `LICENSE` file for details.

---

## Acknowledgements
- **Scapy** – powerful packet manipulation library.
- **Flask** – lightweight web framework.
- **Chart.js** – used for visualising traffic metrics on the frontend.

---


