{# dashboard.volt - Deep Packet Inspector Dashboard #}
<style>
.metric-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    border-radius: 15px;
    padding: 20px;
    color: white;
    box-shadow: 0 10px 25px rgba(0,0,0,0.1);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}

.metric-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 35px rgba(0,0,0,0.2);
}

.metric-card::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
    animation: ripple 15s infinite;
}

@keyframes ripple {
    0%, 100% { transform: scale(0.8) rotate(0deg); opacity: 0.3; }
    50% { transform: scale(1.2) rotate(180deg); opacity: 0.5; }
}

.metric-card:nth-child(1) { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.metric-card:nth-child(2) { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
.metric-card:nth-child(3) { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
.metric-card:nth-child(4) { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }

.metric-icon {
    font-size: 48px;
    opacity: 0.9;
    margin-bottom: 15px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
}

.metric-value {
    font-size: 36px;
    font-weight: bold;
    margin-bottom: 5px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
}

.metric-label {
    font-size: 14px;
    opacity: 0.9;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.service-status {
    float: right;
}

.badge-running {
    background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
    color: white;
    padding: 8px 16px;
    border-radius: 20px;
    font-weight: bold;
    box-shadow: 0 4px 15px rgba(17, 153, 142, 0.4);
}

.badge-stopped {
    background: linear-gradient(135deg, #ee0979 0%, #ff6a00 100%);
    color: white;
    padding: 8px 16px;
    border-radius: 20px;
    font-weight: bold;
    box-shadow: 0 4px 15px rgba(238, 9, 121, 0.4);
}

.badge-loading {
    background: linear-gradient(135deg, #868f96 0%, #596164 100%);
    color: white;
    padding: 8px 16px;
    border-radius: 20px;
    font-weight: bold;
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

.modal-body h6 {
    color: #1f2937;
    margin-bottom: 1rem;
    border-bottom: 1px solid #e5e7eb;
    padding-bottom: 0.5rem;
}

.modal-body p {
    margin-bottom: 0.5rem;
}

.modal-body code {
    background-color: #f3f4f6;
    padding: 0.2rem 0.4rem;
    border-radius: 3px;
    font-size: 0.9em;
}
</style>

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <div class="service-status">
                    <span id="serviceStatus" class="badge badge-loading">{{ lang._('Loading...') }}</span>
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
                        <tr>
                            <td colspan="6" class="text-center text-muted">
                                {{ lang._('No threats detected yet') }}
                            </td>
                        </tr>
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
                    <span class="info-label">{{ lang._('PID') }}:</span>
                    <span id="enginePid" class="info-value">{{ lang._('Unknown') }}</span>
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
// Cache globale per i threats
let threatsCache = [];

$(document).ready(function() {
    loadDashboardData();
    setInterval(loadDashboardData, 30000);

    $('#startService').click(function() { controlService('start'); });
    $('#restartService').click(function() { controlService('restart'); });
    $('#stopService').click(function() { controlService('stop'); });
});

function loadDashboardData() {
    ajaxCall("/api/deepinspector/settings/stats", {}, function(data) {
        if (data.status === 'ok' && data.data) {
            updateMetrics(data.data);
            updateRecentThreats(data.data.recent_threats || []);
            updateSystemInfo(data.data.system_info || {});
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

function updateSystemInfo(systemInfo) {
    $('#signaturesVersion').text(systemInfo.signatures_version || 'Unknown');
    $('#engineStatus').text(systemInfo.engine_status || 'Unknown');
    $('#enginePid').text(systemInfo.pid || 'Unknown');
    $('#memoryUsage').text(systemInfo.memory_usage || 'Unknown');
    $('#cpuUsage').text(systemInfo.cpu_usage || 'Unknown');
    $('#uptime').text(systemInfo.uptime || 'Unknown');

    updateServiceBadge(systemInfo.engine_status);
}

function updateServiceBadge(status) {
    const badge = $('#serviceStatus');
    badge.removeClass('badge-loading badge-running badge-stopped');
    
    if (status === 'Active') {
        badge.addClass('badge-running').text('{{ lang._("Running") }}');
    } else if (status === 'Inactive') {
        badge.addClass('badge-stopped').text('{{ lang._("Stopped") }}');
    } else {
        badge.addClass('badge-loading').text('{{ lang._("Unknown") }}');
    }
}

function updateRecentThreats(threats) {
    const tbody = $('#threatTableBody');
    tbody.empty();
    
    // Salva i threats nella cache globale
    threatsCache = threats || [];

    if (!threats || threats.length === 0) {
        tbody.append(`
            <tr>
                <td colspan="6" class="text-center text-muted">
                    {{ lang._('No threats detected yet') }}
                </td>
            </tr>
        `);
        return;
    }

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

function controlService(action) {
    const button = $(`#${action}Service`);
    const originalHtml = button.html();

    button.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Processing...") }}');

    ajaxCall(`/api/deepinspector/service/${action}`, {}, function(data) {
        button.prop('disabled', false).html(originalHtml);

        if (data.status === 'ok') {
            showNotification(`{{ lang._("Service") }} ${action} {{ lang._("completed successfully") }}`, 'success');
            setTimeout(function() {
                loadDashboardData();
            }, 2000);
        } else {
            showNotification(`{{ lang._("Service") }} ${action} {{ lang._("failed") }}`, 'error');
        }
    });
}

function viewThreatDetails(threatId) {
    // Cerca il threat nella cache locale invece di fare una chiamata API
    const threatData = threatsCache.find(t => t.id === threatId);
    
    if (!threatData) {
        showNotification('{{ lang._("Threat data not found") }}', 'error');
        return;
    }

    const modal = $(`
        <div class="modal fade" id="threatModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ lang._("Threat Details") }}</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>{{ lang._("Basic Information") }}</h6>
                                <p><strong>{{ lang._("Threat ID") }}:</strong> <code>${threatData.id}</code></p>
                                <p><strong>{{ lang._("Timestamp") }}:</strong> ${formatTimestamp(threatData.timestamp)}</p>
                                <p><strong>{{ lang._("Source IP") }}:</strong> <code>${threatData.source_ip}</code></p>
                                <p><strong>{{ lang._("Source Port") }}:</strong> ${threatData.source_port || 'N/A'}</p>
                                <p><strong>{{ lang._("Destination IP") }}:</strong> <code>${threatData.destination_ip || 'N/A'}</code></p>
                                <p><strong>{{ lang._("Destination Port") }}:</strong> ${threatData.destination_port || 'N/A'}</p>
                                <p><strong>{{ lang._("Protocol") }}:</strong> ${threatData.protocol}</p>
                                <p><strong>{{ lang._("Interface") }}:</strong> ${threatData.interface || 'N/A'}</p>
                            </div>
                            <div class="col-md-6">
                                <h6>{{ lang._("Analysis Results") }}</h6>
                                <p><strong>{{ lang._("Threat Type") }}:</strong> ${threatData.threat_type}</p>
                                <p><strong>{{ lang._("Severity") }}:</strong> <span class="badge ${getSeverityClass(threatData.severity)}">${threatData.severity}</span></p>
                                <p><strong>{{ lang._("Detection Method") }}:</strong> ${threatData.detection_method || 'pattern_match'}</p>
                                <p><strong>{{ lang._("Pattern") }}:</strong> <code>${threatData.pattern || 'N/A'}</code></p>
                                <p><strong>{{ lang._("Confidence") }}:</strong> ${threatData.confidence ? (threatData.confidence * 100).toFixed(0) + '%' : 'N/A'}</p>
                                <p><strong>{{ lang._("Industrial Context") }}:</strong> ${threatData.industrial_context ? 'Yes' : 'No'}</p>
                                ${threatData.subtype ? `<p><strong>{{ lang._("Subtype") }}:</strong> ${threatData.subtype}</p>` : ''}
                                ${threatData.action_taken !== undefined ? `<p><strong>{{ lang._("Action Taken") }}:</strong> ${threatData.action_taken ? 'Yes' : 'No'}</p>` : ''}
                                <hr>
                                <h6>{{ lang._("Description") }}</h6>
                                <p>${threatData.description}</p>
                                ${threatData.packet_size ? `<p><strong>{{ lang._("Packet Size") }}:</strong> ${threatData.packet_size} bytes</p>` : ''}
                                ${threatData.tcp_port ? `<p><strong>{{ lang._("TCP Port") }}:</strong> ${threatData.tcp_port}</p>` : ''}
                                ${threatData.udp_port ? `<p><strong>{{ lang._("UDP Port") }}:</strong> ${threatData.udp_port}</p>` : ''}
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" onclick="blockSource('${threatData.source_ip}')">
                            <i class="fa fa-ban"></i> {{ lang._("Block Source IP") }}
                        </button>
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">
                            {{ lang._("Close") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `);

    $('body').append(modal);
    $('#threatModal').modal('show');
    $('#threatModal').on('hidden.bs.modal', function() { 
        $(this).remove(); 
    });
}

function blockSource(sourceIP) {
    if (confirm(`{{ lang._("Are you sure you want to block IP") }} ${sourceIP}?`)) {
        ajaxCall("/api/deepinspector/service/blockIP", {ip: sourceIP}, function(data) {
            if (data.status === 'ok') {
                showNotification(`{{ lang._("IP") }} ${sourceIP} {{ lang._("blocked successfully") }}`, 'success');
                $('#threatModal').modal('hide');
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