<!-- Aggiungi Chart.js CDN prima del tuo script -->
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
    
    // Filter change handlers
    $('#analysisTimeRange, #analysisProtocol, #analysisInterface, #analysisType').change(function() {
        loadAnalysisData();
    });
    
    // Auto-refresh every 60 seconds
    setInterval(loadAnalysisData, 60000);
});

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

// Resto delle funzioni rimangono uguali...
function loadAnalysisData() {
    const filters = {
        timeRange: $('#analysisTimeRange').val(),
        protocol: $('#analysisProtocol').val(),
        interface: $('#analysisInterface').val(),
        type: $('#analysisType').val()
    };
    
    // Per ora, dati mock dato che non abbiamo l'API ancora
    updateAnalysisResults({
        total_packets: 125430,
        threats_found: 23,
        anomalies_found: 7,
        industrial_traffic: 8950,
        protocol_stats: {
            http: 45680000,
            industrial: 8950000,
            email: 2340000,
            dns: 890000,
            other: 12340000
        },
        industrial_stats: {
            modbus: 45,
            dnp3: 12,
            opcua: 8,
            avg_latency: 250
        },
        zero_trust_stats: {
            untrusted: 15,
            blocked: 8,
            trust_score: 87
        },
        traffic_patterns: {
            labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
            total_traffic: [1200, 1800, 3400, 4200, 3800, 2100],
            threat_traffic: [12, 18, 34, 42, 38, 21]
        },
        protocol_distribution: {
            'HTTP/HTTPS': 45,
            'Industrial': 25,
            'Email': 15,
            'DNS': 10,
            'Other': 5
        },
        anomalies: [
            {
                id: '1',
                timestamp: new Date().toISOString(),
                type: 'Unusual Traffic',
                source: '192.168.1.100',
                severity: 'medium',
                description: 'Unusual traffic pattern detected'
            }
        ],
        top_talkers: [
            { ip: '192.168.1.100', bytes: 45680000, packets: 1234 },
            { ip: '192.168.1.101', bytes: 23450000, packets: 856 },
            { ip: '192.168.1.102', bytes: 12340000, packets: 567 }
        ]
    });
}

function startAnalysis() {
    const $btn = $('#startAnalysis');
    const originalText = $btn.html();
    
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Starting...") }}');
    
    // Simulate starting analysis
    setTimeout(function() {
        $btn.prop('disabled', false).html(originalText);
        $('#analysisStatus').text('{{ lang._("Running") }}');
        showNotification('{{ lang._("Analysis started successfully") }}', 'success');
        startProgressMonitoring();
    }, 2000);
}

function stopAnalysis() {
    const $btn = $('#stopAnalysis');
    const originalText = $btn.html();
    
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Stopping...") }}');
    
    // Simulate stopping analysis
    setTimeout(function() {
        $btn.prop('disabled', false).html(originalText);
        $('#analysisStatus').text('{{ lang._("Stopped") }}');
        $('#analysisProgress').css('width', '0%');
        showNotification('{{ lang._("Analysis stopped") }}', 'success');
    }, 1000);
}

function startProgressMonitoring() {
    let progress = 0;
    const progressInterval = setInterval(function() {
        progress += Math.random() * 20;
        if (progress > 100) progress = 100;
        
        $('#analysisProgress').css('width', progress + '%');
        
        if (progress >= 100) {
            clearInterval(progressInterval);
            $('#analysisStatus').text('{{ lang._("Completed") }}');
            loadAnalysisData();
        }
    }, 2000);
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
                </table>
                
                <h6>{{ lang._('Technical Details') }}</h6>
                <pre class="anomaly-details-text">Traffic volume exceeded normal baseline by 300%
Protocol distribution anomaly detected
Connections to unusual ports: 4444, 5555, 6666</pre>
            </div>
        `);
    }, 1000);
}

function exportAnalysisReport() {
    showNotification('{{ lang._("Report export functionality will be implemented") }}', 'info');
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
                      type === 'warning' ? 'alert-warning' : 'alert-danger';
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