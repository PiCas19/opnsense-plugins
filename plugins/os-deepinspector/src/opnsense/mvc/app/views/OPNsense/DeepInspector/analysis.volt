{# analysis.volt - Deep Packet Inspector Analysis #}

<div class="content-box">
    <div class="analysis-header">
        <div class="analysis-controls">
            <button class="btn btn-primary" id="startAnalysis">
                <i class="fa fa-play"></i> {{ lang._('Start Analysis') }}
            </button>
            <button class="btn btn-secondary" id="stopAnalysis">
                <i class="fa fa-stop"></i> {{ lang._('Stop Analysis') }}
            </button>
            <button class="btn btn-info" id="exportReport">
                <i class="fa fa-download"></i> {{ lang._('Export Report') }}
            </button>
        </div>
    </div>

    <!-- Analysis Filters -->
    <div class="analysis-filters">
        <div class="row">
            <div class="col-md-3">
                <label for="analysisTimeRange">{{ lang._('Time Range') }}</label>
                <select class="form-control" id="analysisTimeRange">
                    <option value="1h">{{ lang._('Last Hour') }}</option>
                    <option value="6h">{{ lang._('Last 6 Hours') }}</option>
                    <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                    <option value="7d">{{ lang._('Last Week') }}</option>
                    <option value="30d">{{ lang._('Last Month') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="analysisProtocol">{{ lang._('Protocol') }}</label>
                <select class="form-control" id="analysisProtocol">
                    <option value="all">{{ lang._('All Protocols') }}</option>
                    <option value="http">HTTP</option>
                    <option value="https">HTTPS</option>
                    <option value="ftp">FTP</option>
                    <option value="smtp">SMTP</option>
                    <option value="dns">DNS</option>
                    <option value="modbus">Modbus</option>
                    <option value="dnp3">DNP3</option>
                    <option value="opcua">OPC UA</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="analysisInterface">{{ lang._('Interface') }}</label>
                <select class="form-control" id="analysisInterface">
                    <option value="all">{{ lang._('All Interfaces') }}</option>
                    <!-- Options will be populated dynamically -->
                </select>
            </div>
            <div class="col-md-3">
                <label for="analysisType">{{ lang._('Analysis Type') }}</label>
                <select class="form-control" id="analysisType">
                    <option value="comprehensive">{{ lang._('Comprehensive') }}</option>
                    <option value="security">{{ lang._('Security Focus') }}</option>
                    <option value="performance">{{ lang._('Performance Focus') }}</option>
                    <option value="industrial">{{ lang._('Industrial Focus') }}</option>
                </select>
            </div>
        </div>
    </div>

    <!-- Analysis Status -->
    <div class="analysis-status">
        <div class="row">
            <div class="col-md-12">
                <div class="status-card">
                    <div class="status-icon">
                        <i class="fa fa-chart-line"></i>
                    </div>
                    <div class="status-content">
                        <div class="status-title">{{ lang._('Analysis Status') }}</div>
                        <div class="status-value" id="analysisStatus">{{ lang._('Ready') }}</div>
                        <div class="progress mt-2">
                            <div class="progress-bar" id="analysisProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Analysis Results -->
    <div class="row">
        <div class="col-md-8">
            <!-- Traffic Pattern Analysis -->
            <div class="analysis-section">
                <h3>{{ lang._('Traffic Pattern Analysis') }}</h3>
                <div class="chart-container">
                    <canvas id="trafficPatternsChart"></canvas>
                </div>
            </div>

            <!-- Protocol Distribution -->
            <div class="analysis-section">
                <h3>{{ lang._('Protocol Distribution') }}</h3>
                <div class="row">
                    <div class="col-md-6">
                        <canvas id="protocolPieChart"></canvas>
                    </div>
                    <div class="col-md-6">
                        <div class="protocol-stats">
                            <div class="stat-item">
                                <span class="stat-label">{{ lang._('HTTP/HTTPS') }}:</span>
                                <span class="stat-value" id="httpTraffic">--</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">{{ lang._('Industrial') }}:</span>
                                <span class="stat-value" id="industrialTraffic">--</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">{{ lang._('Email') }}:</span>
                                <span class="stat-value" id="emailTraffic">--</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">{{ lang._('DNS') }}:</span>
                                <span class="stat-value" id="dnsTraffic">--</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">{{ lang._('Other') }}:</span>
                                <span class="stat-value" id="otherTraffic">--</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Anomaly Detection Results -->
            <div class="analysis-section">
                <h3>{{ lang._('Anomaly Detection Results') }}</h3>
                <div class="anomaly-results">
                    <div class="table-responsive">
                        <table class="table table-striped" id="anomaliesTable">
                            <thead>
                                <tr>
                                    <th>{{ lang._('Timestamp') }}</th>
                                    <th>{{ lang._('Type') }}</th>
                                    <th>{{ lang._('Source') }}</th>
                                    <th>{{ lang._('Severity') }}</th>
                                    <th>{{ lang._('Description') }}</th>
                                    <th>{{ lang._('Actions') }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <!-- Anomalies will be populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-md-4">
            <!-- Analysis Summary -->
            <div class="analysis-summary">
                <h3>{{ lang._('Analysis Summary') }}</h3>
                <div class="summary-metrics">
                    <div class="metric-item">
                        <div class="metric-icon">
                            <i class="fa fa-network-wired"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value" id="totalPackets">0</div>
                            <div class="metric-label">{{ lang._('Total Packets') }}</div>
                        </div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-icon">
                            <i class="fa fa-shield-alt"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value" id="threatsFound">0</div>
                            <div class="metric-label">{{ lang._('Threats Found') }}</div>
                        </div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-icon">
                            <i class="fa fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value" id="anomaliesFound">0</div>
                            <div class="metric-label">{{ lang._('Anomalies Found') }}</div>
                        </div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-icon">
                            <i class="fa fa-industry"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value" id="industrialTrafficCount">0</div>
                            <div class="metric-label">{{ lang._('Industrial Traffic') }}</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Top Talkers -->
            <div class="analysis-section">
                <h3>{{ lang._('Top Talkers') }}</h3>
                <div class="top-talkers">
                    <div class="table-responsive">
                        <table class="table table-sm" id="topTalkersTable">
                            <thead>
                                <tr>
                                    <th>{{ lang._('IP Address') }}</th>
                                    <th>{{ lang._('Bytes') }}</th>
                                    <th>{{ lang._('Packets') }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <!-- Top talkers will be populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Industrial Protocols Analysis -->
            <div class="analysis-section" id="industrialAnalysis" style="display: none;">
                <h3>{{ lang._('Industrial Protocols Analysis') }}</h3>
                <div class="industrial-metrics">
                    <div class="metric-item">
                        <span class="metric-label">{{ lang._('Modbus Communications') }}:</span>
                        <span class="metric-value" id="modbusCount">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">{{ lang._('DNP3 Messages') }}:</span>
                        <span class="metric-value" id="dnp3Count">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">{{ lang._('OPC UA Sessions') }}:</span>
                        <span class="metric-value" id="opcuaCount">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">{{ lang._('Average Latency') }}:</span>
                        <span class="metric-value" id="avgLatency">0 μs</span>
                    </div>
                </div>
            </div>

            <!-- Zero Trust Analysis -->
            <div class="analysis-section">
                <h3>{{ lang._('Zero Trust Analysis') }}</h3>
                <div class="zero-trust-metrics">
                    <div class="metric-item">
                        <span class="metric-label">{{ lang._('Untrusted Connections') }}:</span>
                        <span class="metric-value text-warning" id="untrustedConnections">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">{{ lang._('Blocked Attempts') }}:</span>
                        <span class="metric-value text-danger" id="blockedAttempts">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">{{ lang._('Trust Score') }}:</span>
                        <span class="metric-value" id="trustScore">100%</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Analysis Details Modal -->
<div class="modal fade" id="analysisDetailsModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ lang._('Detailed Analysis') }}</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <div class="modal-body" id="analysisDetailsBody">
                <!-- Analysis details will be loaded here -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">
                    {{ lang._('Close') }}
                </button>
                <button type="button" class="btn btn-primary" id="saveAnalysisReport">
                    <i class="fa fa-save"></i> {{ lang._('Save Report') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Chart.js CDN -->
<script src="/ui/js/chart.min.js"></script>

<script>
$(document).ready(function() {
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded. Charts will not be displayed.');
        showNotification('{{ lang._("Chart.js library not loaded. Charts disabled.") }}', 'warning');
        return;
    }
    
    // Initialize analysis page
    initializeAnalysis();
    loadAnalysisData();
    
    // Event handlers
    $('#startAnalysis').click(function() {
        startAnalysis();
    });
    
    $('#stopAnalysis').click(function() {
        stopAnalysis();
    });
    
    $('#exportReport').click(function() {
        exportAnalysisReport();
    });
    
    // CORREZIONE: Filter change handlers con debounce per evitare troppe chiamate
    $('#analysisTimeRange, #analysisProtocol, #analysisInterface, #analysisType').change(debounce(function() {
        console.log('Filter changed, reloading data...');
        loadAnalysisData();
    }, 500));
    
    // CORREZIONE: Modal Save Report handler
    $('#saveAnalysisReport').click(function() {
        saveAnalysisReport();
    });
    
    // Auto-refresh ogni 60 secondi solo se l'analisi è attiva
    setInterval(function() {
        const status = $('#analysisStatus').text();
        if (status === '{{ lang._("Running") }}' || status === '{{ lang._("Completed") }}') {
            loadAnalysisData();
        }
    }, 60000);
});

// Variabile globale per gestire il progress interval
let progressInterval = null;

function initializeAnalysis() {
    // Initialize charts only if Chart.js is available
    if (typeof Chart !== 'undefined') {
        initializeTrafficPatternsChart();
        initializeProtocolPieChart();
    }
    
    // Load interfaces
    loadInterfaces();
}

function initializeTrafficPatternsChart() {
    if (typeof Chart === 'undefined') {
        $('#trafficPatternsChart').closest('.chart-container').html('<div class="alert alert-warning">{{ lang._("Chart.js not available") }}</div>');
        return;
    }
    
    const ctx = document.getElementById('trafficPatternsChart').getContext('2d');
    window.trafficPatternsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: '{{ lang._("Total Traffic") }}',
                data: [],
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.1
            }, {
                label: '{{ lang._("Threat Traffic") }}',
                data: [],
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function initializeProtocolPieChart() {
    if (typeof Chart === 'undefined') {
        $('#protocolPieChart').closest('.col-md-6').html('<div class="alert alert-warning">{{ lang._("Chart.js not available") }}</div>');
        return;
    }
    
    const ctx = document.getElementById('protocolPieChart').getContext('2d');
    window.protocolPieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#007bff',
                    '#28a745',
                    '#ffc107',
                    '#dc3545',
                    '#6c757d',
                    '#17a2b8',
                    '#fd7e14'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

function updateTrafficPatternsChart(data) {
    if (window.trafficPatternsChart && typeof Chart !== 'undefined') {
        window.trafficPatternsChart.data.labels = data.labels || [];
        window.trafficPatternsChart.data.datasets[0].data = data.total_traffic || [];
        window.trafficPatternsChart.data.datasets[1].data = data.threat_traffic || [];
        window.trafficPatternsChart.update();
    }
}

function updateProtocolPieChart(data) {
    if (window.protocolPieChart && typeof Chart !== 'undefined') {
        window.protocolPieChart.data.labels = Object.keys(data || {});
        window.protocolPieChart.data.datasets[0].data = Object.values(data || {});
        window.protocolPieChart.update();
    }
}

function startAnalysis() {
    const $btn = $('#startAnalysis');
    const originalText = $btn.html();
    
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Starting...") }}');
    
    // Simulate starting analysis
    setTimeout(function() {
        $btn.prop('disabled', false).html(originalText);
        $('#analysisStatus').text('{{ lang._("Running") }}');
        $('#stopAnalysis').prop('disabled', false); // CORREZIONE: Abilita stop
        showNotification('{{ lang._("Analysis started successfully") }}', 'success');
        startProgressMonitoring();
    }, 2000);
}

function stopAnalysis() {
    const $btn = $('#stopAnalysis');
    const originalText = $btn.html();
    
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Stopping...") }}');
    
    // CORREZIONE: Ferma il progress interval
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
    
    setTimeout(function() {
        $btn.prop('disabled', false).html(originalText);
        $('#analysisStatus').text('{{ lang._("Stopped") }}');
        $('#analysisProgress').css('width', '0%');
        showNotification('{{ lang._("Analysis stopped") }}', 'success');
    }, 1000);
}

function startProgressMonitoring() {
    let progress = 0;
    
    // CORREZIONE: Ferma il precedente interval se esiste
    if (progressInterval) {
        clearInterval(progressInterval);
    }
    
    progressInterval = setInterval(function() {
        progress += Math.random() * 15 + 5; // Progresso più consistente
        if (progress > 100) progress = 100;
        
        $('#analysisProgress').css('width', progress + '%');
        
        if (progress >= 100) {
            clearInterval(progressInterval);
            progressInterval = null;
            $('#analysisStatus').text('{{ lang._("Completed") }}');
            
            // CORREZIONE: Carica dati aggiornati e mostra risultati più interessanti
            loadAnalysisData();
            showNotification('{{ lang._("Analysis completed successfully") }}', 'success');
        }
    }, 1500);
}

// CORREZIONE: Funzione per gestire i filtri
function loadAnalysisData() {
    const filters = {
        timeRange: $('#analysisTimeRange').val(),
        protocol: $('#analysisProtocol').val(),
        interface: $('#analysisInterface').val(),
        type: $('#analysisType').val()
    };
    
    console.log('Loading data with filters:', filters);
    
    // CORREZIONE: Dati mock più realistici basati sui filtri
    const mockData = generateMockData(filters);
    updateAnalysisResults(mockData);
}

// CORREZIONE: Genera dati mock basati sui filtri
function generateMockData(filters) {
    const baseData = {
        total_packets: 125430,
        threats_found: 23,
        anomalies_found: 7,
        industrial_traffic: 8950
    };
    
    // Modifica i dati basandosi sui filtri
    let multiplier = 1;
    
    switch(filters.timeRange) {
        case '1h': multiplier = 0.1; break;
        case '6h': multiplier = 0.5; break;
        case '24h': multiplier = 1; break;
        case '7d': multiplier = 7; break;
        case '30d': multiplier = 30; break;
    }
    
    // Ajusta i dati per il protocollo
    let protocolMultiplier = 1;
    if (filters.protocol !== 'all') {
        protocolMultiplier = 0.3; // Meno traffico per protocolli specifici
    }
    
    return {
        total_packets: Math.round(baseData.total_packets * multiplier * protocolMultiplier),
        threats_found: Math.round(baseData.threats_found * multiplier * protocolMultiplier),
        anomalies_found: Math.round(baseData.anomalies_found * multiplier),
        industrial_traffic: Math.round(baseData.industrial_traffic * multiplier),
        protocol_stats: {
            http: Math.round(45680000 * multiplier),
            industrial: Math.round(8950000 * multiplier),
            email: Math.round(2340000 * multiplier),
            dns: Math.round(890000 * multiplier),
            other: Math.round(12340000 * multiplier)
        },
        industrial_stats: {
            modbus: Math.round(45 * multiplier),
            dnp3: Math.round(12 * multiplier),
            opcua: Math.round(8 * multiplier),
            avg_latency: 250 + Math.round(Math.random() * 100)
        },
        zero_trust_stats: {
            untrusted: Math.round(15 * multiplier),
            blocked: Math.round(8 * multiplier),
            trust_score: 87 + Math.round(Math.random() * 10)
        },
        traffic_patterns: {
            labels: generateTimeLabels(filters.timeRange),
            total_traffic: generateTrafficData(filters.timeRange, 'total'),
            threat_traffic: generateTrafficData(filters.timeRange, 'threat')
        },
        protocol_distribution: generateProtocolDistribution(filters.protocol),
        anomalies: generateAnomalies(filters, Math.round(baseData.anomalies_found * multiplier)),
        top_talkers: generateTopTalkers(multiplier)
    };
}

function generateTimeLabels(timeRange) {
    const labels = [];
    let count, format;
    
    switch(timeRange) {
        case '1h':
            count = 12; format = (i) => String(i * 5).padStart(2, '0') + ':00';
            break;
        case '6h':
            count = 6; format = (i) => String(i).padStart(2, '0') + ':00';
            break;
        case '24h':
            count = 6; format = (i) => String(i * 4).padStart(2, '0') + ':00';
            break;
        case '7d':
            count = 7; format = (i) => `Day ${i + 1}`;
            break;
        case '30d':
            count = 6; format = (i) => `Week ${i + 1}`;
            break;
    }
    
    for (let i = 0; i < count; i++) {
        labels.push(format(i));
    }
    return labels;
}

function generateTrafficData(timeRange, type) {
    const count = generateTimeLabels(timeRange).length;
    const data = [];
    const base = type === 'threat' ? 10 : 1000;
    
    for (let i = 0; i < count; i++) {
        data.push(Math.round(base + Math.random() * base * 3));
    }
    return data;
}

function generateProtocolDistribution(selectedProtocol) {
    if (selectedProtocol === 'all') {
        return {
            'HTTP/HTTPS': 45,
            'Industrial': 25,
            'Email': 15,
            'DNS': 10,
            'Other': 5
        };
    } else {
        return {
            [selectedProtocol.toUpperCase()]: 80,
            'Other': 20
        };
    }
}

function generateAnomalies(filters, count) {
    const anomalies = [];
    const types = ['Unusual Traffic', 'Port Scan', 'DDoS Attack', 'Malware Communication'];
    const severities = ['low', 'medium', 'high', 'critical'];
    
    for (let i = 0; i < Math.min(count, 10); i++) {
        anomalies.push({
            id: String(i + 1),
            timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString(),
            type: types[Math.floor(Math.random() * types.length)],
            source: `192.168.1.${100 + i}`,
            severity: severities[Math.floor(Math.random() * severities.length)],
            description: `${types[Math.floor(Math.random() * types.length)]} detected from source`
        });
    }
    return anomalies;
}

function generateTopTalkers(multiplier) {
    return [
        { ip: '192.168.1.100', bytes: Math.round(45680000 * multiplier), packets: Math.round(1234 * multiplier) },
        { ip: '192.168.1.101', bytes: Math.round(23450000 * multiplier), packets: Math.round(856 * multiplier) },
        { ip: '192.168.1.102', bytes: Math.round(12340000 * multiplier), packets: Math.round(567 * multiplier) }
    ];
}

// CORREZIONE: Export Report funzionante
function exportAnalysisReport() {
    const $btn = $('#exportReport');
    const originalText = $btn.html();
    
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Exporting...") }}');
    
    setTimeout(function() {
        // Genera un report CSV semplice
        const filters = {
            timeRange: $('#analysisTimeRange').val(),
            protocol: $('#analysisProtocol').val(),
            interface: $('#analysisInterface').val(),
            type: $('#analysisType').val()
        };
        
        const csvContent = generateCSVReport(filters);
        downloadCSV(csvContent, `dpi_analysis_report_${new Date().toISOString().split('T')[0]}.csv`);
        
        $btn.prop('disabled', false).html(originalText);
        showNotification('{{ lang._("Analysis report exported successfully") }}', 'success');
    }, 2000);
}

// CORREZIONE: Save Report dal modal
function saveAnalysisReport() {
    const $btn = $('#saveAnalysisReport');
    const originalText = $btn.html();
    
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Saving...") }}');
    
    setTimeout(function() {
        const reportContent = generateDetailedReport();
        downloadTXT(reportContent, `dpi_detailed_analysis_${new Date().toISOString().split('T')[0]}.txt`);
        
        $btn.prop('disabled', false).html(originalText);
        $('#analysisDetailsModal').modal('hide');
        showNotification('{{ lang._("Detailed report saved successfully") }}', 'success');
    }, 1500);
}

function generateCSVReport(filters) {
    const header = 'Metric,Value,Unit\n';
    const rows = [
        `Total Packets,${$('#totalPackets').text()},packets`,
        `Threats Found,${$('#threatsFound').text()},threats`,
        `Anomalies Found,${$('#anomaliesFound').text()},anomalies`,
        `Industrial Traffic,${$('#industrialTrafficCount').text()},packets`,
        `HTTP Traffic,${$('#httpTraffic').text()},bytes`,
        `Industrial Protocol Traffic,${$('#industrialTraffic').text()},bytes`,
        `Email Traffic,${$('#emailTraffic').text()},bytes`,
        `DNS Traffic,${$('#dnsTraffic').text()},bytes`,
        `Trust Score,${$('#trustScore').text()},%`
    ];
    
    return header + rows.join('\n');
}

function generateDetailedReport() {
    return `Deep Packet Inspector - Detailed Analysis Report
Generated: ${new Date().toLocaleString()}

SUMMARY METRICS:
- Total Packets: ${$('#totalPackets').text()}
- Threats Found: ${$('#threatsFound').text()}
- Anomalies Found: ${$('#anomaliesFound').text()}
- Industrial Traffic: ${$('#industrialTrafficCount').text()}

PROTOCOL STATISTICS:
- HTTP/HTTPS Traffic: ${$('#httpTraffic').text()}
- Industrial Protocol Traffic: ${$('#industrialTraffic').text()}
- Email Traffic: ${$('#emailTraffic').text()}
- DNS Traffic: ${$('#dnsTraffic').text()}
- Other Traffic: ${$('#otherTraffic').text()}

ZERO TRUST ANALYSIS:
- Untrusted Connections: ${$('#untrustedConnections').text()}
- Blocked Attempts: ${$('#blockedAttempts').text()}
- Trust Score: ${$('#trustScore').text()}

INDUSTRIAL METRICS:
- Modbus Communications: ${$('#modbusCount').text()}
- DNP3 Messages: ${$('#dnp3Count').text()}
- OPC UA Sessions: ${$('#opcuaCount').text()}
- Average Latency: ${$('#avgLatency').text()}

This report was generated by OPNsense Deep Packet Inspector.`;
}

function downloadCSV(content, filename) {
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function downloadTXT(content, filename) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function updateAnalysisResults(data) {
    // Update summary metrics
    $('#totalPackets').text(formatNumber(data.total_packets || 0));
    $('#threatsFound').text(formatNumber(data.threats_found || 0));
    $('#anomaliesFound').text(formatNumber(data.anomalies_found || 0));
    $('#industrialTrafficCount').text(formatNumber(data.industrial_traffic || 0));
    
    // Update protocol statistics
    if (data.protocol_stats) {
        $('#httpTraffic').text(formatBytes(data.protocol_stats.http || 0));
        $('#industrialTraffic').text(formatBytes(data.protocol_stats.industrial || 0));
        $('#emailTraffic').text(formatBytes(data.protocol_stats.email || 0));
        $('#dnsTraffic').text(formatBytes(data.protocol_stats.dns || 0));
        $('#otherTraffic').text(formatBytes(data.protocol_stats.other || 0));
    }
    
    // Update industrial metrics
    if (data.industrial_stats) {
        $('#modbusCount').text(formatNumber(data.industrial_stats.modbus || 0));
        $('#dnp3Count').text(formatNumber(data.industrial_stats.dnp3 || 0));
        $('#opcuaCount').text(formatNumber(data.industrial_stats.opcua || 0));
        $('#avgLatency').text((data.industrial_stats.avg_latency || 0) + ' μs');
        
        if (data.industrial_stats.modbus > 0 || data.industrial_stats.dnp3 > 0 || data.industrial_stats.opcua > 0) {
            $('#industrialAnalysis').show();
        } else {
            $('#industrialAnalysis').hide();
        }
    }
    
    // Update Zero Trust metrics
    if (data.zero_trust_stats) {
        $('#untrustedConnections').text(formatNumber(data.zero_trust_stats.untrusted || 0));
        $('#blockedAttempts').text(formatNumber(data.zero_trust_stats.blocked || 0));
        $('#trustScore').text((data.zero_trust_stats.trust_score || 100) + '%');
    }
    
    // Update charts
    if (data.traffic_patterns) {
        updateTrafficPatternsChart(data.traffic_patterns);
    }
    
    if (data.protocol_distribution) {
        updateProtocolPieChart(data.protocol_distribution);
    }
    
    // Update tables
    updateAnomaliesTable(data.anomalies || []);
    updateTopTalkersTable(data.top_talkers || []);
}

function updateAnomaliesTable(anomalies) {
    const tbody = $('#anomaliesTable tbody');
    tbody.empty();
    
    if (anomalies.length === 0) {
        tbody.html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No anomalies detected") }}</td></tr>');
        return;
    }
    
    anomalies.forEach(function(anomaly) {
        const severityClass = getSeverityClass(anomaly.severity);
        const row = $(`
            <tr>
                <td>${formatTimestamp(anomaly.timestamp)}</td>
                <td>${anomaly.type}</td>
                <td><code>${anomaly.source}</code></td>
                <td><span class="badge ${severityClass}">${anomaly.severity.toUpperCase()}</span></td>
                <td>${anomaly.description}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="viewAnomalyDetails('${anomaly.id}')">
                        <i class="fa fa-eye"></i>
                    </button>
                </td>
            </tr>
        `);
        tbody.append(row);
    });
}

function updateTopTalkersTable(topTalkers) {
    const tbody = $('#topTalkersTable tbody');
    tbody.empty();
    
    if (topTalkers.length === 0) {
        tbody.html('<tr><td colspan="3" class="text-center text-muted">{{ lang._("No data available") }}</td></tr>');
        return;
    }
    
    topTalkers.forEach(function(talker) {
        const row = $(`
            <tr>
                <td><code>${talker.ip}</code></td>
                <td>${formatBytes(talker.bytes)}</td>
                <td>${formatNumber(talker.packets)}</td>
            </tr>
        `);
        tbody.append(row);
    });
}

function loadInterfaces() {
    // Mock interfaces data
    const mockInterfaces = [
        { name: 'em0', description: 'WAN Interface' },
        { name: 'em1', description: 'LAN Interface' },
        { name: 'em2', description: 'DMZ Interface' }
    ];
    
    const select = $('#analysisInterface');
    select.find('option:not(:first)').remove();
    
    mockInterfaces.forEach(function(iface) {
        select.append(`<option value="${iface.name}">${iface.description}</option>`);
    });
}

function viewAnomalyDetails(anomalyId) {
    $('#analysisDetailsBody').html(`
        <div class="text-center">
            <i class="fa fa-spinner fa-spin"></i>
            {{ lang._('Loading anomaly details...') }}
        </div>
    `);
    
    $('#analysisDetailsModal').modal('show');
    
    // Mock anomaly details
    setTimeout(function() {
        $('#analysisDetailsBody').html(`
            <div class="anomaly-details">
                <h6>{{ lang._('Anomaly Information') }}</h6>
                <table class="table table-sm">
                    <tr>
                        <td><strong>{{ lang._('ID') }}:</strong></td>
                        <td>${anomalyId}</td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Type') }}:</strong></td>
                        <td>Unusual Traffic Pattern</td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Severity') }}:</strong></td>
                        <td><span class="badge badge-warning">MEDIUM</span></td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Source') }}:</strong></td>
                        <td><code>192.168.1.100</code></td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Description') }}:</strong></td>
                        <td>Unusual traffic pattern detected from this source</td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('First Detected') }}:</strong></td>
                        <td>${formatTimestamp(new Date(Date.now() - 3600000).toISOString())}</td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Last Seen') }}:</strong></td>
                        <td>${formatTimestamp(new Date().toISOString())}</td>
                    </tr>
                </table>
                
                <h6>{{ lang._('Technical Details') }}</h6>
                <pre class="anomaly-details-text">Traffic volume exceeded normal baseline by 300%
Protocol distribution anomaly detected
Connections to unusual ports: 4444, 5555, 6666
User-Agent strings indicate potential bot activity
Packet timing suggests automated behavior</pre>
                
                <h6>{{ lang._('Recommended Actions') }}</h6>
                <ul class="list-group">
                    <li class="list-group-item">Monitor the source IP for continued suspicious activity</li>
                    <li class="list-group-item">Consider blocking or rate-limiting the IP address</li>
                    <li class="list-group-item">Review firewall logs for related events</li>
                    <li class="list-group-item">Analyze packet captures for detailed inspection</li>
                </ul>
            </div>
        `);
    }, 1000);
}

// Debounce function
function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
}

// Utility functions
function getSeverityClass(severity) {
    switch(severity.toLowerCase()) {
        case 'critical': return 'badge-danger';
        case 'high': return 'badge-warning';
        case 'medium': return 'badge-info';
        case 'low': return 'badge-success';
        default: return 'badge-secondary';
    }
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function showNotification(message, type) {
    const alertClass = type === 'success' ? 'alert-success' : 
                      type === 'warning' ? 'alert-warning' : 
                      type === 'info' ? 'alert-info' : 'alert-danger';
    const notification = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $('#notifications').append(notification);
    setTimeout(() => notification.alert('close'), 5000);
}
</script>

<div id="notifications" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;"></div>

<style>
.analysis-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}

.analysis-filters {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 0.5rem;
    margin-bottom: 1rem;
}

.analysis-status {
    margin-bottom: 1rem;
}

.status-card {
    background: white;
    border-radius: 0.5rem;
    padding: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
}

.status-icon {
    font-size: 2rem;
    color: #007bff;
    margin-right: 1rem;
}

.status-content {
    flex: 1;
}

.status-title {
    font-weight: 600;
    margin-bottom: 0.5rem;
}

.status-value {
    font-size: 1.2rem;
    font-weight: bold;
    color: #28a745;
}

.analysis-section {
    background: white;
    border-radius: 0.5rem;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.analysis-summary {
    background: white;
    border-radius: 0.5rem;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.metric-item {
    display: flex;
    align-items: center;
    padding: 0.5rem 0;
    border-bottom: 1px solid #f0f0f0;
}

.metric-item:last-child {
    border-bottom: none;
}

.metric-icon {
    font-size: 1.5rem;
    color: #007bff;
    margin-right: 1rem;
    width: 2rem;
    text-align: center;
}

.metric-content {
    flex: 1;
}

.metric-value {
    font-size: 1.5rem;
    font-weight: bold;
    color: #212529;
}

.metric-label {
    font-size: 0.875rem;
    color: #6c757d;
    margin-top: 0.25rem;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid #f0f0f0;
}

.stat-item:last-child {
    border-bottom: none;
}

.stat-label {
    font-weight: 600;
    color: #374151;
}

.stat-value {
    font-family: monospace;
    font-weight: bold;
}

.protocol-stats {
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 0.375rem;
}

.chart-container {
    position: relative;
    height: 300px;
    margin-bottom: 1rem;
}

.anomaly-details-text {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 0.375rem;
    padding: 1rem;
    font-size: 0.875rem;
    max-height: 300px;
    overflow-y: auto;
}

.progress {
    height: 0.5rem;
}

.industrial-metrics .metric-item {
    margin-bottom: 0.5rem;
}

.zero-trust-metrics .metric-item {
    margin-bottom: 0.5rem;
}

.anomaly-details h6 {
    margin-top: 1.5rem;
    margin-bottom: 1rem;
    color: #495057;
    border-bottom: 2px solid #e9ecef;
    padding-bottom: 0.5rem;
}

.anomaly-details h6:first-child {
    margin-top: 0;
}

.list-group-item {
    border: 1px solid #e9ecef;
    padding: 0.75rem 1rem;
}

@media (max-width: 768px) {
    .analysis-header {
        flex-direction: column;
        align-items: stretch;
    }
    
    .analysis-controls {
        margin-top: 1rem;
    }
    
    .chart-container {
        height: 250px;
    }
    
    .metric-item {
        flex-direction: column;
        align-items: flex-start;
    }
    
    .metric-icon {
        margin-bottom: 0.5rem;
    }
}
</style>