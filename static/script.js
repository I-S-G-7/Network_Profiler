let protocolChartInstance = null;
let sizeChartInstance = null;

function validateUrl(url, errorId) {
    const errorDiv = document.getElementById(errorId);
    if (!url) {
        errorDiv.innerText = "URL cannot be empty.";
        return false;
    }
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        errorDiv.innerText = "URL must start with http:// or https://";
        return false;
    }
    errorDiv.innerText = "";
    return true;
}

async function analyzeSingle() {
    const url = document.getElementById('url1').value;
    if (!validateUrl(url, 'url1-error')) return;

    showLoading(true);
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        
        if (data.error) {
            alert("Error: " + data.error);
        } else {
            displayResults(data, null);
        }
    } catch (e) {
        alert("Request failed: " + e.message);
    }
    showLoading(false);
}

async function compareUrls() {
    const url1 = document.getElementById('url1').value;
    const url2 = document.getElementById('url2').value;
    
    const valid1 = validateUrl(url1, 'url1-error');
    const valid2 = validateUrl(url2, 'url2-error');
    if (!valid1 || !valid2) return;

    showLoading(true);
    try {
        const response = await fetch('/api/compare', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url1, url2 })
        });
        const data = await response.json();
        
        if (data.error) {
            alert("Error: " + data.error);
        } else {
            displayResults(data.site1, data.site2);
        }
    } catch (e) {
        alert("Request failed: " + e.message);
    }
    showLoading(false);
}

function showLoading(isLoading) {
    document.getElementById('loading').style.display = isLoading ? 'block' : 'none';
    document.getElementById('analyze-btn').disabled = isLoading;
    document.getElementById('compare-btn').disabled = isLoading;
}

function displayResults(site1, site2) {
    document.getElementById('results').style.display = 'flex';
    document.getElementById('charts').style.display = 'flex';
    
    renderCard('site1', site1);
    
    if (site2) {
        document.getElementById('site2-card').style.display = 'block';
        renderCard('site2', site2);
        renderCharts(site1, site2);
    } else {
        document.getElementById('site2-card').style.display = 'none';
        renderCharts(site1, null);
    }
}

function renderCard(prefix, data) {
    if (data.error) {
        document.getElementById(`${prefix}-url`).innerText = data.site_url;
        document.getElementById(`${prefix}-stats`).innerHTML = `<p style="color:red;">Error: ${data.error}</p>`;
        return;
    }
    
    document.getElementById(`${prefix}-url`).innerText = data.site_url;
    let html = `
        <p><strong>Behavior Label:</strong> ${data.behavior_label} (${data.confidence}%)</p>
        <p><strong>Total Packets:</strong> ${data.total_packets}</p>
        <p><strong>Total Bytes:</strong> ${data.total_bytes}</p>
        <p><strong>Mean Packet Size:</strong> ${data.mean_packet_size} bytes</p>
        <p><strong>Unique IPs Contacted:</strong> ${data.unique_ips}</p>
        <p><strong>DNS Queries:</strong> ${data.dns_queries}</p>
        <p><strong>Top Protocol:</strong> ${data.top_protocol}</p>
    `;
    document.getElementById(`${prefix}-stats`).innerHTML = html;
}

function renderCharts(site1, site2) {
    renderProtocolChart(site1, site2);
    renderSizeChart(site1, site2);
}

function renderProtocolChart(site1, site2) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    if (protocolChartInstance) protocolChartInstance.destroy();

    if (!site2) {
        const labels = Object.keys(site1.protocol_distribution || {});
        const data = Object.values(site1.protocol_distribution || {});
        
        protocolChartInstance = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40']
                }]
            }
        });
    } else {
        const allLabels = new Set([...Object.keys(site1.protocol_distribution || {}), ...Object.keys(site2.protocol_distribution || {})]);
        const labels = Array.from(allLabels);
        
        const data1 = labels.map(l => site1.protocol_distribution?.[l] || 0);
        const data2 = labels.map(l => site2.protocol_distribution?.[l] || 0);
        
        protocolChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    { label: 'Site 1 %', data: data1, backgroundColor: '#36A2EB' },
                    { label: 'Site 2 %', data: data2, backgroundColor: '#FF6384' }
                ]
            }
        });
    }
}

function createHistogramBins(sizes) {
    let bins = {"0-100": 0, "101-500": 0, "501-1000": 0, "1001-1500": 0, "1500+": 0};
    if (!sizes) return Object.values(bins);
    sizes.forEach(size => {
        if (size <= 100) bins["0-100"]++;
        else if (size <= 500) bins["101-500"]++;
        else if (size <= 1000) bins["501-1000"]++;
        else if (size <= 1500) bins["1001-1500"]++;
        else bins["1500+"]++;
    });
    return Object.values(bins);
}

function renderSizeChart(site1, site2) {
    const ctx = document.getElementById('sizeChart').getContext('2d');
    if (sizeChartInstance) sizeChartInstance.destroy();

    const labels = ["0-100", "101-500", "501-1000", "1001-1500", "1500+"];
    const data1 = createHistogramBins(site1.packet_sizes);

    const datasets = [{
        label: 'Site 1 (Count)',
        data: data1,
        backgroundColor: '#36A2EB'
    }];

    if (site2) {
        datasets.push({
            label: 'Site 2 (Count)',
            data: createHistogramBins(site2.packet_sizes),
            backgroundColor: '#FF6384'
        });
    }

    sizeChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}
