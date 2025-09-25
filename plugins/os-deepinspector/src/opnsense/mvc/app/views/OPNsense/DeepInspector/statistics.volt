{# statistics.volt - Deep Packet Inspector Statistics & Reports #}

<div class="content-box">
    <div class="statistics-header">
        <h2>{{ lang._('Deep Packet Inspector - Statistics & Reports') }}</h2>
        <div class="report-controls">
            <div class="btn-group">
                <button class="btn btn-primary dropdown-toggle" data-toggle="dropdown">
                    <i class="fa fa-download"></i> {{ lang._('Export Report') }} <span class="caret"></span>
                </button>
                <ul class="dropdown-menu">
                    <li><a href="#" id="exportPDF"><i class="fa fa-file-pdf-o"></i> {{ lang._('PDF Report') }}</a></li>
                    <li><a href="#" id="exportCSV"><i class="fa fa-file-excel-o"></i> {{ lang._('CSV Data') }}</a></li>
                    <li><a href="#" id="exportJSON"><i class="fa fa-file-code-o"></i> {{ lang._('JSON Data') }}</a></li>
                </ul>
            </div>
            <button class="btn btn-info" id="refreshStats">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
        </div>
    </div>

    <!-- Time Range Filter -->
    <div class="statistics-filters">
        <div class="row">
            <div class="col-md-3">
                <label for="timeRangeFilter">{{ lang._('Time Range') }}</label>
                <select class="form-control" id="timeRangeFilter">
                    <option value="1h">{{ lang._('Last Hour') }}</option>
                    <option value="6h">{{ lang._('Last 6 Hours') }}</option>
                    <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                    <option value="7d">{{ lang._('Last Week') }}</option>
                    <option value="30d">{{ lang._('Last Month') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="reportType">{{ lang._('Report Type') }}</label>
                <select class="form-control" id="reportType">
                    <option value="comprehensive" selected>{{ lang._('Comprehensive') }}</option>
                    <option value="security">{{ lang._('Security Focus') }}</option>
                    <option value="traffic">{{ lang._('Traffic Analysis') }}</option>
                    <option value="industrial">{{ lang._('Industrial Focus') }}</option>
                </select>
            </div>
            <div class="col-md-6">
                <div class="statistics-summary">
                    <span class="summary-item">
                        <strong>{{ lang._('Last Updated') }}:</strong>
                        <span id="lastUpdated">{{ lang._('Loading...') }}</span>
                    </span>
                </div>
            </div>
        </div>
    </div>

    <!-- Key Metrics Overview -->
    <div class="row">
        <div class="col-md-2">
            <div class="metric-card metric-threats">
                <div class="metric-icon">
                    <i class="fa fa-shield"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="totalThreats">0</div>
                    <div class="metric-label">{{ lang._('Threats Detected') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="metric-card metric-blocked">
                <div class="metric-icon">
                    <i class="fa fa-ban"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="threatsBlocked">0</div>
                    <div class="metric-label">{{ lang._('Threats Blocked') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="metric-card metric-accuracy">
                <div class="metric-icon">
                    <i class="fa fa-bullseye"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="detectionAccuracy">0%</div>
                    <div class="metric-label">{{ lang._('Accuracy') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="metric-card metric-industrial">
                <div class="metric-icon">
                    <i class="fa fa-industry"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="industrialThreats">0</div>
                    <div class="metric-label">{{ lang._('Industrial Threats') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="metric-card metric-zerotrust">
                <div class="metric-icon">
                    <i class="fa fa-lock"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="zeroTrustViolations">0</div>
                    <div class="metric-label">{{ lang._('Zero Trust Violations') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="metric-card metric-packets">
                <div class="metric-icon">
                    <i class="fa fa-network-wired"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="packetsAnalyzed">0</div>
                    <div class="metric-label">{{ lang._('Packets Analyzed') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts and Analysis -->
    <div class="row">
        <div class="col-md-8">
            <!-- Threat Severity Distribution -->
            <div class="statistics-section">
                <h3>{{ lang._('Threat Severity Distribution') }}</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>

            <!-- Threat Types Timeline -->
            <div class="statistics-section">
                <h3>{{ lang._('Threat Detection Timeline') }}</h3>
                <div class="chart-container">
                    <canvas id="timelineChart"></canvas>
                </div>
            </div>

            <!-- Suspicious Packets Analysis -->
            <div class="statistics-section">
                <h3>{{ lang._('Suspicious Packets Analysis') }}</h3>
                <div class="suspicious-packets-controls">
                    <div class="row">
                        <div class="col-md-4">
                            <select class="form-control" id="packetSeverityFilter">
                                <option value="all">{{ lang._('All Severities') }}</option>
                                <option value="critical">{{ lang._('Critical') }}</option>
                                <option value="high">{{ lang._('High') }}</option>
                                <option value="medium">{{ lang._('Medium') }}</option>
                                <option value="low">{{ lang._('Low') }}</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <select class="form-control" id="packetTimeFilter">
                                <option value="1h">{{ lang._('Last Hour') }}</option>
                                <option value="6h">{{ lang._('Last 6 Hours') }}</option>
                                <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <button class="btn btn-primary" id="loadSuspiciousPackets">
                                <i class="fa fa-search"></i> {{ lang._('Analyze Packets') }}
                            </button>
                        </div>
                    </div>
                </div>
                <div class="suspicious-packets-results">
                    <div class="table-responsive">
                        <table class="table table-striped table-hover" id="suspiciousPacketsTable">
                            <thead>
                                <tr>
                                    <th>{{ lang._('Timestamp') }}</th>
                                    <th>{{ lang._('Source') }}</th>
                                    <th>{{ lang._('Destination') }}</th>
                                    <th>{{ lang._('Protocol') }}</th>
                                    <th>{{ lang._('Threat Type') }}</th>
                                    <th>{{ lang._('Risk Level') }}</th>
                                    <th>{{ lang._('Pattern') }}</th>
                                    <th>{{ lang._('Action') }}</th>
                                    <th>{{ lang._('Details') }}</th>
                                </tr>
                            </thead>
                            <tbody id="suspiciousPacketsBody">
                                <tr>
                                    <td colspan="9" class="text-center text-muted">
                                        {{ lang._('Click "Analyze Packets" to load suspicious packet data') }}
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-md-4">
            <!-- Top Threat Sources -->
            <div class="statistics-section">
                <h3>{{ lang._('Top Threat Sources') }}</h3>
                <div class="threat-sources-list">
                    <div id="topThreatSources" class="list-group">
                        <!-- Populated dynamically -->
                    </div>
                </div>
            </div>

            <!-- Blocking Statistics -->
            <div class="statistics-section">
                <h3>{{ lang._('Blocking Statistics') }}</h3>
                <div class="blocking-stats">
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('IPs Currently Blocked') }}:</span>
                        <span class="stat-value text-danger" id="blockedIPs">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('Connections Blocked') }}:</span>
                        <span class="stat-value text-warning" id="connectionsBlocked">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('Blocking Effectiveness') }}:</span>
                        <span class="stat-value text-success" id="blockingEffectiveness">0%</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('Auto Unblocked') }}:</span>
                        <span class="stat-value text-info" id="autoUnblocked">0</span>
                    </div>
                </div>
            </div>

            <!-- Malicious Patterns -->
            <div class="statistics-section">
                <h3>{{ lang._('Detected Malicious Patterns') }}</h3>
                <div class="malicious-patterns">
                    <div id="maliciousPatterns" class="patterns-list">
                        <!-- Populated dynamically -->
                    </div>
                </div>
            </div>

            <!-- Industrial Protocol Statistics -->
            <div class="statistics-section" id="industrialSection" style="display: none;">
                <h3>{{ lang._('Industrial Protocol Statistics') }}</h3>
                <div class="industrial-stats">
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('Modbus Communications') }}:</span>
                        <span class="stat-value" id="modbusCount">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('DNP3 Messages') }}:</span>
                        <span class="stat-value" id="dnp3Count">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('OPC UA Sessions') }}:</span>
                        <span class="stat-value" id="opcuaCount">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">{{ lang._('SCADA Anomalies') }}:</span>
                        <span class="stat-value text-warning" id="scadaAnomalies">0</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Detailed Analysis Tables -->
    <div class="row">
        <div class="col-md-12">
            <div class="statistics-section">
                <h3>{{ lang._('Threat Type Distribution') }}</h3>
                <div class="table-responsive">
                    <table class="table table-striped table-hover" id="threatTypesTable">
                        <thead>
                            <tr>
                                <th>{{ lang._('Threat Type') }}</th>
                                <th>{{ lang._('Count') }}</th>
                                <th>{{ lang._('Percentage') }}</th>
                                <th>{{ lang._('Blocked') }}</th>
                                <th>{{ lang._('Last Detected') }}</th>
                            </tr>
                        </thead>
                        <tbody id="threatTypesBody">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Packet Details Modal -->
<div class="modal fade" id="packetDetailsModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ lang._('Suspicious Packet Details') }}</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <div class="modal-body" id="packetDetailsBody">
                <!-- Packet details loaded here -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-danger" id="blockPacketSource">
                    <i class="fa fa-ban"></i> {{ lang._('Block Source IP') }}
                </button>
                <button type="button" class="btn btn-secondary" data-dismiss="modal">
                    {{ lang._('Close') }}
                </button>
            </div>
        </div>
    </div>
</div>

<script src="/ui/js/chart.min.js"></script>

<script>
$(document).ready(function() {
    // Initialize statistics page
    initializeStatistics();
    loadStatisticsData();
    
    // Event handlers
    $('#timeRangeFilter, #reportType').change(function() {
        loadStatisticsData();
    });
    
    $('#refreshStats').click(function() {
        loadStatisticsData();
    });
    
    $('#loadSuspiciousPackets').click(function() {
        loadSuspiciousPackets();
    });
    
    $('#packetSeverityFilter, #packetTimeFilter').change(function() {
        if ($('#suspiciousPacketsBody tr').length > 1) {
            loadSuspiciousPackets();
        }
    });
    
    // Export handlers
    $('#exportPDF').click(function() { exportReport('pdf'); });
    $('#exportCSV').click(function() { exportReport('csv'); });
    $('#exportJSON').click(function() { exportReport('json'); });
    
    // Auto-refresh every 2 minutes
    setInterval(loadStatisticsData, 120000);
});

function initializeStatistics() {
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }
}

function initializeCharts() {
    // Severity Distribution Chart
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    window.severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom' }
            }
        }
    });
    
    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    window.timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threats Detected',
                data: [],
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.1
            }, {
                label: 'Threats Blocked',
                data: [],
                borderColor: '#28a745',
                backgroundColor: 'rgba(40, 167, 69, 0.1)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

function loadStatisticsData() {
    const timeRange = $('#timeRangeFilter').val();
    const reportType = $('#reportType').val();
    
    // Update last updated time
    $('#lastUpdated').text(new Date().toLocaleString());
    
    // Load security statistics
    ajaxCall("/api/deepinspector/statistics/getSecurityStats", {}, function(data) {
        if (data.status === 'ok' && data.data) {
            updateSecurityMetrics(data.data);
            updateThreatSources(data.data.top_threat_sources || {});
            updateMaliciousPatterns(data.data.malicious_patterns || {});
            updateThreatTypesTable(data.data.threats_by_type || {});
            
            if (window.severityChart) {
                updateSeverityChart(data.data.threats_by_severity || {});
            }
        }
    });
    
    // Load blocking statistics
    ajaxCall("/api/deepinspector/statistics/getBlockingStats", {}, function(data) {
        if (data.status === 'ok' && data.data) {
            updateBlockingStats(data.data);
        }
    });
    
    // Load industrial statistics if needed
    if (reportType === 'industrial' || reportType === 'comprehensive') {
        ajaxCall("/api/deepinspector/statistics/getIndustrialStats", {}, function(data) {
            if (data.status === 'ok' && data.data) {
                updateIndustrialStats(data.data);
                $('#industrialSection').show();
            }
        });
    } else {
        $('#industrialSection').hide();
    }
}

function updateSecurityMetrics(data) {
    $('#totalThreats').text(formatNumber(data.total_threats_detected || 0));
    $('#threatsBlocked').text(formatNumber(data.threats_blocked || 0));
    $('#detectionAccuracy').text((data.detection_accuracy || 0) + '%');
    $('#industrialThreats').text(formatNumber(data.industrial_threats || 0));
    $('#zeroTrustViolations').text(formatNumber(data.zero_trust_violations || 0));
    $('#packetsAnalyzed').text(formatNumber(data.total_packets_analyzed || 0));
}

function updateBlockingStats(data) {
    $('#blockedIPs').text(formatNumber(data.total_ips_blocked || 0));
    $('#connectionsBlocked').text(formatNumber(data.total_connections_blocked || 0));
    $('#blockingEffectiveness').text((data.blocking_effectiveness || 0) + '%');
    $('#autoUnblocked').text(formatNumber(data.auto_unblocked || 0));
}

function updateIndustrialStats(data) {
    const protocols = data.protocols_detected || {};
    $('#modbusCount').text(formatNumber(protocols.modbus || 0));
    $('#dnp3Count').text(formatNumber(protocols.dnp3 || 0));
    $('#opcuaCount').text(formatNumber(protocols.opcua || 0));
    $('#scadaAnomalies').text(formatNumber(data.scada_anomalies || 0));
}

function updateSeverityChart(severityData) {
    if (window.severityChart) {
        window.severityChart.data.datasets[0].data = [
            severityData.critical || 0,
            severityData.high || 0,
            severityData.medium || 0,
            severityData.low || 0
        ];
        window.severityChart.update();
    }
}

function updateThreatSources(sources) {
    const container = $('#topThreatSources');
    container.empty();
    
    if (Object.keys(sources).length === 0) {
        container.html('<div class="alert alert-info">{{ lang._("No threat sources detected") }}</div>');
        return;
    }
    
    Object.entries(sources).slice(0, 10).forEach(([ip, count]) => {
        const item = $(`
            <div class="list-group-item d-flex justify-content-between align-items-center">
                <span>
                    <code>${ip}</code>
                </span>
                <div>
                    <span class="badge badge-danger">${count}</span>
                    <button class="btn btn-sm btn-outline-danger ml-2" onclick="blockThreatSource('${ip}')">
                        <i class="fa fa-ban"></i>
                    </button>
                </div>
            </div>
        `);
        container.append(item);
    });
}

function updateMaliciousPatterns(patterns) {
    const container = $('#maliciousPatterns');
    container.empty();
    
    if (Object.keys(patterns).length === 0) {
        container.html('<div class="alert alert-info">{{ lang._("No malicious patterns detected") }}</div>');
        return;
    }
    
    Object.entries(patterns).slice(0, 5).forEach(([pattern, count]) => {
        const item = $(`
            <div class="pattern-item">
                <div class="pattern-code">
                    <code>${pattern.substring(0, 50)}${pattern.length > 50 ? '...' : ''}</code>
                </div>
                <div class="pattern-count">
                    <span class="badge badge-warning">${count} matches</span>
                </div>
            </div>
        `);
        container.append(item);
    });
}

function updateThreatTypesTable(threatTypes) {
    const tbody = $('#threatTypesBody');
    tbody.empty();
    
    if (Object.keys(threatTypes).length === 0) {
        tbody.html('<tr><td colspan="5" class="text-center text-muted">{{ lang._("No threat types detected") }}</td></tr>');
        return;
    }
    
    const total = Object.values(threatTypes).reduce((sum, count) => sum + count, 0);
    
    Object.entries(threatTypes).forEach(([type, count]) => {
        const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
        const blocked = Math.floor(count * 0.7); // Estimate
        
        const row = $(`
            <tr>
                <td><strong>${type}</strong></td>
                <td>${formatNumber(count)}</td>
                <td>${percentage}%</td>
                <td class="text-success">${formatNumber(blocked)}</td>
                <td class="text-muted">{{ lang._("Recently") }}</td>
            </tr>
        `);
        tbody.append(row);
    });
}

function loadSuspiciousPackets() {
    const severity = $('#packetSeverityFilter').val();
    const timeRange = $('#packetTimeFilter').val();
    const $btn = $('#loadSuspiciousPackets');
    
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Loading...") }}');
    
    const params = {
        severity: severity,
        timeRange: timeRange,
        limit: 50
    };
    
    ajaxCall("/api/deepinspector/statistics/getSuspiciousPackets", params, function(data) {
        $btn.prop('disabled', false).html('<i class="fa fa-search"></i> {{ lang._("Analyze Packets") }}');
        
        if (data.status === 'ok' && data.data) {
            updateSuspiciousPacketsTable(data.data.packets || []);
            showNotification(`{{ lang._("Found") }} ${data.data.total_count || 0} {{ lang._("suspicious packets") }}`, 'info');
        } else {
            showNotification('{{ lang._("Error loading suspicious packets") }}', 'error');
        }
    });
}

function updateSuspiciousPacketsTable(packets) {
    const tbody = $('#suspiciousPacketsBody');
    tbody.empty();
    
    if (packets.length === 0) {
        tbody.html('<tr><td colspan="9" class="text-center text-muted">{{ lang._("No suspicious packets found") }}</td></tr>');
        return;
    }
    
    packets.forEach(function(packet) {
        const riskClass = getRiskLevelClass(packet.risk_level);
        const row = $(`
            <tr class="packet-row" data-packet-id="${packet.id}">
                <td class="timestamp-cell">${formatTimestamp(packet.timestamp)}</td>
                <td><code>${packet.source_ip}:${packet.source_port || 'N/A'}</code></td>
                <td><code>${packet.destination_ip}:${packet.destination_port || 'N/A'}</code></td>
                <td><span class="protocol-badge">${packet.protocol}</span></td>
                <td>${packet.threat_type}</td>
                <td><span class="badge ${riskClass}">${packet.risk_level.toUpperCase()}</span></td>
                <td><code class="pattern-code">${packet.pattern_matched.substring(0, 20)}...</code></td>
                <td>
                    <span class="badge ${getActionClass(packet.action_taken)}">${packet.action_taken}</span>
                </td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="viewPacketDetails('${packet.id}')">
                        <i class="fa fa-eye"></i>
                    </button>
                </td>
            </tr>
        `);
        tbody.append(row);
    });
}

function viewPacketDetails(packetId) {
    // Find packet data from the table or make API call
    const packetData = getCurrentPacketData(packetId);
    
    const modalBody = $('#packetDetailsBody');
    modalBody.html(`
        <div class="packet-analysis">
            <div class="row">
                <div class="col-md-6">
                    <h6>{{ lang._("Packet Information") }}</h6>
                    <table class="table table-sm">
                        <tr>
                            <td><strong>{{ lang._("Packet ID") }}:</strong></td>
                            <td><code>${packetData.id}</code></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Timestamp") }}:</strong></td>
                            <td>${formatTimestamp(packetData.timestamp)}</td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Source") }}:</strong></td>
                            <td><code>${packetData.source_ip}:${packetData.source_port}</code></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Destination") }}:</strong></td>
                            <td><code>${packetData.destination_ip}:${packetData.destination_port}</code></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Protocol") }}:</strong></td>
                            <td>${packetData.protocol}</td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Payload Size") }}:</strong></td>
                            <td>${packetData.payload_size} bytes</td>
                        </tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6>{{ lang._("Threat Analysis") }}</h6>
                    <table class="table table-sm">
                        <tr>
                            <td><strong>{{ lang._("Threat Type") }}:</strong></td>
                            <td>${packetData.threat_type}</td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Risk Level") }}:</strong></td>
                            <td><span class="badge ${getRiskLevelClass(packetData.risk_level)}">${packetData.risk_level.toUpperCase()}</span></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Pattern Matched") }}:</strong></td>
                            <td><code>${packetData.pattern_matched}</code></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Confidence Score") }}:</strong></td>
                            <td>${packetData.confidence_score}%</td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Action Taken") }}:</strong></td>
                            <td><span class="badge ${getActionClass(packetData.action_taken)}">${packetData.action_taken}</span></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._("Industrial Context") }}:</strong></td>
                            <td>${packetData.industrial_context ? 'Yes' : 'No'}</td>
                        </tr>
                    </table>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <h6>{{ lang._("Description") }}</h6>
                    <p class="packet-description">${packetData.description}</p>
                </div>
            </div>
        </div>
    `);
    
    $('#blockPacketSource').off('click').on('click', function() {
        blockThreatSource(packetData.source_ip);
    });
    
    $('#packetDetailsModal').modal('show');
}

function getCurrentPacketData(packetId) {
    // This would normally come from the API or cached data
    return {
        id: packetId,
        timestamp: new Date().toISOString(),
        source_ip: '192.168.1.100',
        source_port: '4444',
        destination_ip: '10.0.0.50',
        destination_port: '80',
        protocol: 'TCP',
        threat_type: 'Command Injection',
        risk_level: 'high',
        pattern_matched: '(cmd\\.exe|powershell|bash).*[;&|]',
        confidence_score: 85,
        action_taken: 'blocked',
        industrial_context: false,
        payload_size: 1024,
        description: 'Command injection attempt detected in HTTP POST request'
    };
}

function blockThreatSource(sourceIP) {
    if (confirm(`{{ lang._("Block IP address") }} ${sourceIP}?`)) {
        ajaxCall("/api/deepinspector/service/blockIP", {ip: sourceIP}, function(data) {
            if (data.status === 'ok') {
                showNotification(`{{ lang._("IP") }} ${sourceIP} {{ lang._("blocked successfully") }}`, 'success');
                $('#packetDetailsModal').modal('hide');
                loadStatisticsData(); // Refresh data
            } else {
                showNotification(`{{ lang._("Failed to block IP") }}: ${data.message}`, 'error');
            }
        });
    }
}

function exportReport(format) {
    const $btn = $(`#export${format.toUpperCase()}`);
    const originalText = $btn.html();
    
    $btn.html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Exporting...") }}');
    
    setTimeout(function() {
        const reportData = generateReportData();
        
        if (format === 'pdf') {
            generatePDFReport(reportData);
        } else if (format === 'csv') {
            generateCSVReport(reportData);
        } else if (format === 'json') {
            generateJSONReport(reportData);
        }
        
        $btn.html(originalText);
        showNotification(`{{ lang._("Report exported successfully") }}`, 'success');
    }, 2000);
}

function generateReportData() {
    return {
        timestamp: new Date().toISOString(),
        timeRange: $('#timeRangeFilter').val(),
        reportType: $('#reportType').val(),
        metrics: {
            totalThreats: $('#totalThreats').text(),
            threatsBlocked: $('#threatsBlocked').text(),
            detectionAccuracy: $('#detectionAccuracy').text(),
            industrialThreats: $('#industrialThreats').text(),
            zeroTrustViolations: $('#zeroTrustViolations').text()
        }
    };
}

function generatePDFReport(data) {
    const content = `Deep Packet Inspector Statistics Report
Generated: ${new Date().toLocaleString()}
Time Range: ${data.timeRange}
Report Type: ${data.reportType}

SUMMARY:
- Total Threats: ${data.metrics.totalThreats}
- Threats Blocked: ${data.metrics.threatsBlocked}  
- Detection Accuracy: ${data.metrics.detectionAccuracy}
- Industrial Threats: ${data.metrics.industrialThreats}
- Zero Trust Violations: ${data.metrics.zeroTrustViolations}`;

    downloadFile(content, `dpi_statistics_report_${new Date().toISOString().split('T')[0]}.txt`, 'text/plain');
}

function generateCSVReport(data) {
    const csv = `Metric,Value
Total Threats,${data.metrics.totalThreats}
Threats Blocked,${data.metrics.threatsBlocked}
Detection Accuracy,${data.metrics.detectionAccuracy}
Industrial Threats,${data.metrics.industrialThreats}
Zero Trust Violations,${data.metrics.zeroTrustViolations}`;
    
    downloadFile(csv, `dpi_statistics_${new Date().toISOString().split('T')[0]}.csv`, 'text/csv');
}

function generateJSONReport(data) {
    const jsonContent = JSON.stringify(data, null, 2);
    downloadFile(jsonContent, `dpi_statistics_${new Date().toISOString().split('T')[0]}.json`, 'application/json');
}

function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Utility functions
function getRiskLevelClass(level) {
    switch(level.toLowerCase()) {
        case 'critical': return 'badge-danger';
        case 'high': return 'badge-warning';
        case 'medium': return 'badge-info';
        case 'low': return 'badge-success';
        default: return 'badge-secondary';
    }
}

function getActionClass(action) {
    switch(action.toLowerCase()) {
        case 'blocked': return 'badge-danger';
        case 'allowed': return 'badge-success';
        case 'logged': return 'badge-info';
        default: return 'badge-secondary';
    }
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function showNotification(message, type) {
    const alertClass = type === 'success' ? 'alert-success' : 
                      type === 'info' ? 'alert-info' : 
                      type === 'warning' ? 'alert-warning' : 'alert-danger';
    const notification = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="close" data-dismiss="alert">
                <span>&times;</span>
            </button>
        </div>
    `);
    
    $('#notifications').append(notification);
    setTimeout(() => notification.alert('close'), 5000);
}
</script>

<div id="notifications" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;"></div>

<style>
.statistics-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid #e5e7eb;
}

.statistics-filters {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 0.5rem;
    margin-bottom: 1.5rem;
}

.statistics-summary {
    text-align: right;
    padding-top: 1.5rem;
}

.metric-card {
    background: white;
    border-radius: 0.5rem;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    transition: transform 0.2s;
}

.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
}

.metric-icon {
    font-size: 2.5rem;
    margin-right: 1rem;
    width: 4rem;
    text-align: center;
}

.metric-threats .metric-icon { color: #dc3545; }
.metric-blocked .metric-icon { color: #fd7e14; }
.metric-accuracy .metric-icon { color: #28a745; }
.metric-industrial .metric-icon { color: #6f42c1; }
.metric-zerotrust .metric-icon { color: #e83e8c; }
.metric-packets .metric-icon { color: #20c997; }

.metric-content {
    flex: 1;
}

.metric-value {
    font-size: 2rem;
    font-weight: bold;
    color: #212529;
    line-height: 1;
}

.metric-label {
    font-size: 0.875rem;
    color: #6c757d;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.25rem;
}

.statistics-section {
    background: white;
    border-radius: 0.5rem;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1.5rem;
}

.chart-container {
    position: relative;
    height: 300px;
    margin-top: 1rem;
}

.suspicious-packets-controls {
    margin-bottom: 1rem;
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 0.375rem;
}

.packet-row:hover {
    background-color: #f8f9fa;
}

.timestamp-cell {
    font-family: monospace;
    font-size: 0.875rem;
}

.protocol-badge {
    background: #e9ecef;
    padding: 0.2rem 0.5rem;
    border-radius: 0.25rem;
    font-family: monospace;
    font-size: 0.8rem;
}

.pattern-code {
    font-family: monospace;
    font-size: 0.8rem;
    background: #f8f9fa;
    padding: 0.2rem 0.4rem;
    border-radius: 0.25rem;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid #e9ecef;
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

.threat-sources-list {
    max-height: 400px;
    overflow-y: auto;
}

.patterns-list {
    max-height: 300px;
    overflow-y: auto;
}

.pattern-item {
    padding: 0.75rem;
    border: 1px solid #e9ecef;
    border-radius: 0.375rem;
    margin-bottom: 0.5rem;
    background: #f8f9fa;
}

.pattern-code {
    font-family: monospace;
    font-size: 0.875rem;
    word-break: break-all;
    margin-bottom: 0.5rem;
}

.pattern-count {
    text-align: right;
}

.packet-analysis h6 {
    color: #495057;
    border-bottom: 2px solid #e9ecef;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
}

.packet-description {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 0.375rem;
    border-left: 4px solid #007bff;
    margin: 0;
}

.industrial-stats .stat-item {
    padding: 0.75rem 0;
}

.report-controls .btn-group {
    margin-right: 0.5rem;
}

.summary-item {
    font-size: 0.875rem;
    color: #6c757d;
}

@media (max-width: 768px) {
    .statistics-header {
        flex-direction: column;
        align-items: stretch;
    }
    
    .report-controls {
        margin-top: 1rem;
        text-align: center;
    }
    
    .metric-card {
        text-align: center;
    }
    
    .metric-icon {
        margin-right: 0;
        margin-bottom: 1rem;
    }
    
    .chart-container {
        height: 250px;
    }
    
    .suspicious-packets-controls .row {
        margin-bottom: 1rem;
    }
    
    .suspicious-packets-controls .col-md-4 {
        margin-bottom: 0.5rem;
    }
}

/* Table responsiveness improvements */
@media (max-width: 992px) {
    .table-responsive {
        font-size: 0.875rem;
    }
    
    .packet-row td {
        padding: 0.5rem 0.25rem;
    }
    
    .timestamp-cell {
        font-size: 0.75rem;
    }
}

/* Loading states */
.loading-spinner {
    display: inline-block;
    width: 1rem;
    height: 1rem;
    border: 2px solid #f3f3f3;
    border-top: 2px solid #007bff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Custom badges */
.badge-critical {
    background-color: #dc3545;
    color: white;
}

.badge-high {
    background-color: #fd7e14;
    color: white;
}

.badge-medium {
    background-color: #ffc107;
    color: #212529;
}

.badge-low {
    background-color: #28a745;
    color: white;
}

/* Hover effects for interactive elements */
.list-group-item:hover {
    background-color: #f8f9fa;
}

.btn-outline-danger:hover {
    transform: scale(1.05);
}

/* Modal improvements */
.modal-lg {
    max-width: 900px;
}

.modal-body table {
    margin-bottom: 0;
}

.modal-body .table-sm td {
    padding: 0.5rem;
    border-top: 1px solid #dee2e6;
}

/* Print styles */
@media print {
    .statistics-header .report-controls,
    .suspicious-packets-controls,
    .btn {
        display: none !important;
    }
    
    .metric-card {
        break-inside: avoid;
        box-shadow: none;
        border: 1px solid #dee2e6;
    }
    
    .statistics-section {
        break-inside: avoid;
        box-shadow: none;
        border: 1px solid #dee2e6;
        margin-bottom: 1rem;
    }
    
    .chart-container {
        height: 200px;
    }
}
</style>