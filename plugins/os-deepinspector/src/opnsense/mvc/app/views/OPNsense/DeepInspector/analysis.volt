{# analysis.volt - Deep Packet Inspector Analysis #}
<div class="content-box">
    <div class="analysis-header">
        <div class="analysis-controls">
            <button class="btn btn-secondary" id="refreshAnalysis">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
            <button class="btn btn-primary" id="exportAnalysis">
                <i class="fa fa-download"></i> {{ lang._('Export') }}
            </button>
        </div>
    </div>

    <div class="analysis-filters">
        <div class="row">
            <div class="col-md-3">
                <label for="analysisTimeRange">{{ lang._('Time Range') }}</label>
                <select class="form-control" id="analysisTimeRange">
                    <option value="1h">{{ lang._('Last Hour') }}</option>
                    <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                    <option value="7d">{{ lang._('Last Week') }}</option>
                    <option value="30d">{{ lang._('Last Month') }}</option>
                    <option value="all">{{ lang._('All Time') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="analysisProtocol">{{ lang._('Protocol') }}</label>
                <select class="form-control" id="analysisProtocol">
                    <option value="all">{{ lang._('All Protocols') }}</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                    <option value="http">HTTP</option>
                    <option value="https">HTTPS</option>
                    <option value="dns">DNS</option>
                    <option value="smtp">SMTP</option>
                    <option value="ftp">FTP</option>
                    <option value="ssh">SSH</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="analysisInterface">{{ lang._('Interface') }}</label>
                <select class="form-control" id="analysisInterface">
                    <option value="all">{{ lang._('All Interfaces') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="analysisType">{{ lang._('Analysis Type') }}</label>
                <select class="form-control" id="analysisType">
                    <option value="traffic">{{ lang._('Traffic Analysis') }}</option>
                    <option value="protocol">{{ lang._('Protocol Distribution') }}</option>
                    <option value="anomaly">{{ lang._('Anomaly Detection') }}</option>
                    <option value="top">{{ lang._('Top Talkers') }}</option>
                </select>
            </div>
        </div>
    </div>

    <div class="analysis-results">
        <div class="row">
            <div class="col-md-8">
                <div class="card analysis-chart">
                    <div class="card-header">
                        {{ lang._('Traffic Chart') }}
                    </div>
                    <div class="card-body">
                        <canvas id="trafficChart" height="300"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card analysis-summary">
                    <div class="card-header">
                        {{ lang._('Summary') }}
                    </div>
                    <div class="card-body">
                        <ul class="list-group" id="analysisSummaryList">
                            <li class="list-group-item">{{ lang._('Total Packets') }}: <span id="totalPackets">0</span></li>
                            <li class="list-group-item">{{ lang._('Total Bytes') }}: <span id="totalBytes">0</span></li>
                            <li class="list-group-item">{{ lang._('Unique IPs') }}: <span id="uniqueIPs">0</span></li>
                            <li class="list-group-item">{{ lang._('Unique Ports') }}: <span id="uniquePorts">0</span></li>
                        </ul>
                    </div>
                </div>
                <div class="card analysis-protocols mt-3">
                    <div class="card-header">
                        {{ lang._('Protocols') }}
                    </div>
                    <div class="card-body">
                        <canvas id="protocolChart" height="200"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-3">
            <div class="col-md-6">
                <div class="card analysis-anomalies">
                    <div class="card-header">
                        {{ lang._('Detected Anomalies') }}
                    </div>
                    <div class="card-body">
                        <table class="table table-sm table-striped" id="anomaliesTable">
                            <thead>
                                <tr>
                                    <th>{{ lang._('Timestamp') }}</th>
                                    <th>{{ lang._('Type') }}</th>
                                    <th>{{ lang._('Description') }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr><td colspan="3" class="text-center text-muted">{{ lang._('No anomalies detected') }}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card analysis-top">
                    <div class="card-header">
                        {{ lang._('Top Talkers') }}
                    </div>
                    <div class="card-body">
                        <table class="table table-sm table-striped" id="topTalkersTable">
                            <thead>
                                <tr>
                                    <th>{{ lang._('IP Address') }}</th>
                                    <th>{{ lang._('Packets') }}</th>
                                    <th>{{ lang._('Bytes') }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr><td colspan="3" class="text-center text-muted">{{ lang._('No data available') }}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
let trafficChart = null;
let protocolChart = null;

$(document).ready(function() {
    loadInterfaces();
    loadAnalysisData();

    $('#refreshAnalysis').click(function() {
        loadAnalysisData();
    });

    $('#exportAnalysis').click(function() {
        exportAnalysis();
    });

    $('#analysisTimeRange, #analysisProtocol, #analysisInterface, #analysisType').change(function() {
        loadAnalysisData();
    });

    // Auto-refresh ogni 60 secondi
    setInterval(loadAnalysisData, 60000);
});

function loadInterfaces() {
    ajaxCall(
        '/api/deepinspector/interfaces',
        {},
        function(response) {
            const select = $('#analysisInterface');
            select.find('option:not(:first)').remove();

            if (response && response.status === 'ok' && Array.isArray(response.data)) {
                response.data.forEach(function(iface) {
                    select.append(`<option value="${iface.name}">${iface.description}</option>`);
                });
            }
        }
    );
}

function loadAnalysisData() {
    const filters = {
        timeRange: $('#analysisTimeRange').val(),
        protocol: $('#analysisProtocol').val(),
        interface: $('#analysisInterface').val(),
        type: $('#analysisType').val()
    };

    console.log('Loading data with filters:', filters);

    ajaxCall(
        '/api/deepinspector/analysis',
        filters,
        function(response) {
            if (response && response.status === 'ok') {
                updateAnalysisResults(response.data);
            } else {
                showNotification('{{ lang._("Error loading analysis data") }}', 'danger');
            }
        },
        function(xhr, status, error) {
            console.error('AJAX error:', error);
            showNotification('{{ lang._("Failed to load analysis data") }}', 'danger');
        }
    );
}

function updateAnalysisResults(data) {
    updateTrafficChart(data.traffic);
    updateProtocolChart(data.protocols);
    updateSummary(data.summary);
    updateAnomaliesTable(data.anomalies);
    updateTopTalkersTable(data.topTalkers);
}

function updateTrafficChart(traffic) {
    const ctx = document.getElementById('trafficChart').getContext('2d');

    if (trafficChart) {
        trafficChart.destroy();
    }

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: traffic.labels,
            datasets: [
                {
                    label: '{{ lang._("Packets") }}',
                    data: traffic.packets,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    fill: false
                },
                {
                    label: '{{ lang._("Bytes") }}',
                    data: traffic.bytes,
                    borderColor: 'rgba(153, 102, 255, 1)',
                    fill: false
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                x: { display: true },
                y: { display: true }
            }
        }
    });
}

function updateProtocolChart(protocols) {
    const ctx = document.getElementById('protocolChart').getContext('2d');

    if (protocolChart) {
        protocolChart.destroy();
    }

    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(protocols),
            datasets: [{
                data: Object.values(protocols),
                backgroundColor: [
                    '#FF6384', '#36A2EB', '#FFCE56',
                    '#4BC0C0', '#9966FF', '#FF9F40',
                    '#C9CBCF', '#E7E9ED'
                ]
            }]
        },
        options: {
            responsive: true
        }
    });
}

function updateSummary(summary) {
    $('#totalPackets').text(summary.packets);
    $('#totalBytes').text(summary.bytes);
    $('#uniqueIPs').text(summary.unique_ips);
    $('#uniquePorts').text(summary.unique_ports);
}

function updateAnomaliesTable(anomalies) {
    const tbody = $('#anomaliesTable tbody');
    tbody.empty();

    if (!anomalies || anomalies.length === 0) {
        tbody.html(`<tr><td colspan="3" class="text-center text-muted">{{ lang._('No anomalies detected') }}</td></tr>`);
        return;
    }

    anomalies.forEach(function(anomaly) {
        const row = `
            <tr>
                <td>${new Date(anomaly.timestamp).toLocaleString()}</td>
                <td>${anomaly.type}</td>
                <td>${anomaly.description}</td>
            </tr>
        `;
        tbody.append(row);
    });
}

function updateTopTalkersTable(topTalkers) {
    const tbody = $('#topTalkersTable tbody');
    tbody.empty();

    if (!topTalkers || topTalkers.length === 0) {
        tbody.html(`<tr><td colspan="3" class="text-center text-muted">{{ lang._('No data available') }}</td></tr>`);
        return;
    }

    topTalkers.forEach(function(talker) {
        const row = `
            <tr>
                <td><code>${talker.ip}</code></td>
                <td>${talker.packets}</td>
                <td>${talker.bytes}</td>
            </tr>
        `;
        tbody.append(row);
    });
}

function exportAnalysis() {
    const filters = {
        timeRange: $('#analysisTimeRange').val(),
        protocol: $('#analysisProtocol').val(),
        interface: $('#analysisInterface').val(),
        type: $('#analysisType').val(),
        format: 'csv'
    };

    ajaxCall("/api/deepinspector/analysis/export", filters, function(data) {
        if (data.status === 'ok') {
            const blob = new Blob([data.data], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `dpi_analysis_${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            showNotification('{{ lang._("Analysis exported successfully") }}', 'success');
        } else {
            showNotification('{{ lang._("Failed to export analysis") }}', 'error');
        }
    });
}
</script>
