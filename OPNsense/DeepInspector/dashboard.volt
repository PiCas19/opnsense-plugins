{# dashboard.volt - Deep Packet Inspector Dashboard #}
<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <h1>{{ lang._('Deep Packet Inspector Dashboard') }}</h1>
                <div class="service-status">
                    <span id="serviceStatus" class="badge badge-secondary">{{ lang._('Loading...') }}</span>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-search"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="packetsAnalyzed">0</div>
                    <div class="metric-label">{{ lang._('Packets Analyzed') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-shield"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="threatsDetected">0</div>
                    <div class="metric-label">{{ lang._('Threats Detected') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-exclamation-triangle"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="criticalAlerts">0</div>
                    <div class="metric-label">{{ lang._('Critical Alerts') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-percent"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="detectionRate">0%</div>
                    <div class="metric-label">{{ lang._('Detection Rate') }}</div>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-6">
            <div class="chart-container">
                <h3>{{ lang._('Threat Detection Timeline') }}</h3>
                <canvas id="threatTimelineChart"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="chart-container">
                <h3>{{ lang._('Protocol Analysis') }}</h3>
                <canvas id="protocolChart"></canvas>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-8">
            <div class="table-container">
                <h3>{{ lang._('Recent Threats') }}</h3>
                <table class="table table-striped" id="recentThreats">
                    <thead>
                        <tr>
                            <th>{{ lang._('Timestamp') }}</th>
                            <th>{{ lang._('Source IP') }}</th>
                            <th>{{ lang._('Threat Type') }}</th>
                            <th>{{ lang._('Severity') }}</th>
                            <th>{{ lang._('Protocol') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="threatTableBody">
                        <!-- Dynamic content -->
                    </tbody>
                </table>
            </div>
        </div>
        <div class="col-md-4">
            <div class="system-info">
                <h3>{{ lang._('System Information') }}</h3>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Engine Status') }}:</span>
                    <span id="engineStatus" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Uptime') }}:</span>
                    <span id="uptime" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Memory Usage') }}:</span>
                    <span id="memoryUsage" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('CPU Usage') }}:</span>
                    <span id="cpuUsage" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Signatures Version') }}:</span>
                    <span id="signaturesVersion" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
            </div>

            <div class="service-controls">
                <h3>{{ lang._('Service Controls') }}</h3>
                <div class="btn-group-vertical" style="width: 100%;">
                    <button class="btn btn-success" id="startService">
                        <i class="fa fa-play"></i> {{ lang._('Start Service') }}
                    </button>
                    <button class="btn btn-warning" id="restartService">
                        <i class="fa fa-refresh"></i> {{ lang._('Restart Service') }}
                    </button>
                    <button class="btn btn-danger" id="stopService">
                        <i class="fa fa-stop"></i> {{ lang._('Stop Service') }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    // Initialize dashboard
    loadDashboardData();
    checkServiceStatus();
    
    // Set up periodic updates
    setInterval(loadDashboardData, 30000); // Update every 30 seconds
    setInterval(checkServiceStatus, 10000); // Check service every 10 seconds
    
    // Service control buttons
    $('#startService').click(function() {
        controlService('start');
    });
    
    $('#restartService').click(function() {
        controlService('restart');
    });
    
    $('#stopService').click(function() {
        controlService('stop');
    });
});

function loadDashboardData() {
    ajaxCall("/api/deepinspector/settings/stats", {}, function(data) {
        if (data.status === 'ok' && data.data) {
            updateMetrics(data.data);
            updateRecentThreats(data.data.recent_threats || []);
        }
    });
}

function updateMetrics(data) {
    $('#packetsAnalyzed').text(formatNumber(data.packets_analyzed || 0));
    $('#threatsDetected').text(formatNumber(data.threats_detected || 0));
    $('#criticalAlerts').text(formatNumber(data.critical_alerts || 0));
    
    const detectionRate = data.packets_analyzed > 0 
        ? ((data.threats_detected / data.packets_analyzed) * 100).toFixed(2)
        : 0;
    $('#detectionRate').text(detectionRate + '%');
}

function updateRecentThreats(threats) {
    const tbody = $('#threatTableBody');
    tbody.empty();
    
    threats.forEach(function(threat) {
        const severityClass = getSeverityClass(threat.severity);
        const row = $(`
            <tr>
                <td>${formatTimestamp(threat.timestamp)}</td>
                <td><code>${threat.source_ip}</code></td>
                <td>${threat.threat_type}</td>
                <td><span class="badge ${severityClass}">${threat.severity}</span></td>
                <td>${threat.protocol}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="viewThreatDetails('${threat.id}')">
                        <i class="fa fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="blockSource('${threat.source_ip}')">
                        <i class="fa fa-ban"></i>
                    </button>
                </td>
            </tr>
        `);
        tbody.append(row);
    });
}

function checkServiceStatus() {
    ajaxCall("/api/deepinspector/service/status", {}, function(data) {
        if (data.status && data.status.running) {
            $('#serviceStatus').removeClass('badge-secondary badge-danger')
                             .addClass('badge-success')
                             .text('{{ lang._("Running") }}');
            $('#engineStatus').text('{{ lang._("Active") }}');
            $('#uptime').text(data.status.uptime || '{{ lang._("Unknown") }}');
            $('#memoryUsage').text(data.status.memory_usage || '{{ lang._("Unknown") }}');
            $('#cpuUsage').text(data.status.cpu_usage || '{{ lang._("Unknown") }}');
        } else {
            $('#serviceStatus').removeClass('badge-secondary badge-success')
                             .addClass('badge-danger')
                             .text('{{ lang._("Stopped") }}');
            $('#engineStatus').text('{{ lang._("Inactive") }}');
        }
    });
}

function controlService(action) {
    const button = $(`#${action}Service`);
    const originalText = button.text();
    
    button.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Processing...") }}');
    
    ajaxCall(`/api/deepinspector/service/${action}`, {}, function(data) {
        button.prop('disabled', false).html(originalText);
        
        if (data.status) {
            showNotification(`{{ lang._("Service ${action} completed successfully") }}`, 'success');
            setTimeout(checkServiceStatus, 2000);
        } else {
            showNotification(`{{ lang._("Service ${action} failed") }}`, 'error');
        }
    });
}

function viewThreatDetails(threatId) {
    // Open modal with threat details
    const modal = $(`
        <div class="modal fade" id="threatModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ lang._("Threat Details") }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p>{{ lang._("Loading threat details...") }}</p>
                    </div>
                </div>
            </div>
        </div>
    `);
    
    $('body').append(modal);
    $('#threatModal').modal('show');
    
    // Load threat details
    ajaxCall(`/api/deepinspector/alerts/threatDetails/${threatId}`, {}, function(data) {
        if (data.status === 'ok') {
            const details = data.data;
            $('#threatModal .modal-body').html(`
                <div class="row">
                    <div class="col-md-6">
                        <h6>{{ lang._("Basic Information") }}</h6>
                        <p><strong>{{ lang._("Threat ID") }}:</strong> ${details.threat_id}</p>
                        <p><strong>{{ lang._("Status") }}:</strong> ${details.status}</p>
                        <p><strong>{{ lang._("First Seen") }}:</strong> ${formatTimestamp(details.first_seen)}</p>
                        <p><strong>{{ lang._("Last Seen") }}:</strong> ${formatTimestamp(details.last_seen)}</p>
                    </div>
                    <div class="col-md-6">
                        <h6>{{ lang._("Analysis Results") }}</h6>
                        <div id="analysisResults">
                            <!-- Analysis results will be populated here -->
                        </div>
                    </div>
                </div>
            `);
        }
    });
}

function blockSource(sourceIP) {
    if (confirm(`{{ lang._("Are you sure you want to block IP") }} ${sourceIP}?`)) {
        ajaxCall("/api/deepinspector/service/blockIP", {ip: sourceIP}, function(data) {
            if (data.status === 'ok') {
                showNotification(`{{ lang._("IP blocked successfully") }}`, 'success');
            } else {
                showNotification(`{{ lang._("Failed to block IP") }}`, 'error');
            }
        });
    }
}

function getSeverityClass(severity) {
    switch(severity) {
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

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function showNotification(message, type) {
    const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
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
.dpi-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid #e5e7eb;
}

.metric-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
}

.metric-icon {
    font-size: 2rem;
    color: #2563eb;
    margin-right: 1rem;
}

.metric-content {
    flex: 1;
}

.metric-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
}

.metric-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.chart-container {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.table-container {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.system-info {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.info-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid #f3f4f6;
}

.info-item:last-child {
    border-bottom: none;
}

.info-label {
    font-weight: 600;
    color: #374151;
}

.info-value {
    color: #6b7280;
    font-family: monospace;
}

.service-controls {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.service-controls .btn {
    margin-bottom: 0.5rem;
}

.service-controls .btn:last-child {
    margin-bottom: 0;
}
</style>