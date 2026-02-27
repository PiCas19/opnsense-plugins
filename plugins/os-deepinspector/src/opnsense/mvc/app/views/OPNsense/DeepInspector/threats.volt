{# threats.volt - Deep Packet Inspector Threats & Alerts #}

<div class="content-box">
    <div class="alert-header">
        <div class="alert-controls">
            <button class="btn btn-secondary" id="refreshAlerts">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
            <button class="btn btn-primary" id="exportAlerts">
                <i class="fa fa-download"></i> {{ lang._('Export') }}
            </button>
            <button class="btn btn-warning" id="clearAlerts">
                <i class="fa fa-trash"></i> {{ lang._('Clear Old') }}
            </button>
        </div>
    </div>

    <div class="alert-filters">
        <div class="row">
            <div class="col-md-3">
                <label for="severityFilter">{{ lang._('Severity') }}</label>
                <select class="form-control" id="severityFilter">
                    <option value="all">{{ lang._('All Severities') }}</option>
                    <option value="critical">{{ lang._('Critical') }}</option>
                    <option value="high">{{ lang._('High') }}</option>
                    <option value="medium">{{ lang._('Medium') }}</option>
                    <option value="low">{{ lang._('Low') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="threatTypeFilter">{{ lang._('Threat Type') }}</label>
                <select class="form-control" id="threatTypeFilter">
                    <option value="all">{{ lang._('All Types') }}</option>
                    <option value="malware">{{ lang._('Malware') }}</option>
                    <option value="trojan">{{ lang._('Trojan') }}</option>
                    <option value="virus">{{ lang._('Virus') }}</option>
                    <option value="command_injection">{{ lang._('Command Injection') }}</option>
                    <option value="sql_injection">{{ lang._('SQL Injection') }}</option>
                    <option value="script_injection">{{ lang._('Script Injection') }}</option>
                    <option value="crypto_mining">{{ lang._('Crypto Mining') }}</option>
                    <option value="data_exfiltration">{{ lang._('Data Exfiltration') }}</option>
                    <option value="phishing">{{ lang._('Phishing') }}</option>
                    <option value="botnet">{{ lang._('Botnet') }}</option>
                    <option value="industrial_threat">{{ lang._('Industrial Threat') }}</option>
                    <option value="scada_attack">{{ lang._('SCADA Attack') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="timeFilter">{{ lang._('Time Range') }}</label>
                <select class="form-control" id="timeFilter">
                    <option value="1h">{{ lang._('Last Hour') }}</option>
                    <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                    <option value="7d">{{ lang._('Last Week') }}</option>
                    <option value="30d">{{ lang._('Last Month') }}</option>
                    <option value="all">{{ lang._('All Time') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="sourceFilter">{{ lang._('Source IP') }}</label>
                <input type="text" class="form-control" id="sourceFilter" placeholder="{{ lang._('Filter by IP...') }}">
            </div>
        </div>
    </div>

    <div class="alert-summary">
        <div class="row">
            <div class="col-md-2">
                <div class="summary-card critical">
                    <div class="summary-icon">
                        <i class="fa fa-exclamation-triangle"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="criticalCount">0</div>
                        <div class="summary-label">{{ lang._('Critical') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card high">
                    <div class="summary-icon">
                        <i class="fa fa-warning"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="highCount">0</div>
                        <div class="summary-label">{{ lang._('High') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card medium">
                    <div class="summary-icon">
                        <i class="fa fa-info-circle"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="mediumCount">0</div>
                        <div class="summary-label">{{ lang._('Medium') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card low">
                    <div class="summary-icon">
                        <i class="fa fa-check-circle"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="lowCount">0</div>
                        <div class="summary-label">{{ lang._('Low') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card industrial">
                    <div class="summary-icon">
                        <i class="fa fa-industry"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="industrialCount">0</div>
                        <div class="summary-label">{{ lang._('Industrial') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card zero-trust">
                    <div class="summary-icon">
                        <i class="fa fa-shield-alt"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="zeroTrustBlocks">0</div>
                        <div class="summary-label">{{ lang._('Zero Trust Blocks') }}</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="alert-table-container">
        <table class="table table-striped table-hover" id="alertsTable">
            <thead>
                <tr>
                    <th>{{ lang._('Timestamp') }}</th>
                    <th>{{ lang._('Severity') }}</th>
                    <th>{{ lang._('Threat Type') }}</th>
                    <th>{{ lang._('Source IP') }}</th>
                    <th>{{ lang._('Destination IP') }}</th>
                    <th>{{ lang._('Protocol') }}</th>
                    <th>{{ lang._('Description') }}</th>
                    <th>{{ lang._('Actions') }}</th>
                </tr>
            </thead>
            <tbody id="alertsTableBody">
                <tr>
                    <td colspan="8" class="text-center">
                        <div class="loading-spinner">
                            <i class="fa fa-spinner fa-spin"></i>
                            {{ lang._('Loading alerts...') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <div class="alert-pagination">
        <nav>
            <ul class="pagination justify-content-center" id="alertsPagination">
                <!-- Pagination will be dynamically generated -->
            </ul>
        </nav>
    </div>
</div>

<!-- Alert Details Modal -->
<div class="modal fade" id="alertDetailsModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ lang._('Alert Details') }}</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <div class="modal-body" id="alertDetailsBody">
                <!-- Alert details will be loaded here -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">
                    {{ lang._('Close') }}
                </button>
                <button type="button" class="btn btn-danger" id="blockSourceIP">
                    <i class="fa fa-ban"></i> {{ lang._('Block Source IP') }}
                </button>
                <button type="button" class="btn btn-success" id="whitelistSourceIP">
                    <i class="fa fa-check"></i> {{ lang._('Whitelist Source IP') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Industrial Threat Details Modal -->
<div class="modal fade" id="industrialThreatModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-xl" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ lang._('Industrial Threat Analysis') }}</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <div class="modal-body" id="industrialThreatBody">
                <!-- Industrial threat details will be loaded here -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">
                    {{ lang._('Close') }}
                </button>
                <button type="button" class="btn btn-warning" id="isolateIndustrialDevice">
                    <i class="fa fa-shield-alt"></i> {{ lang._('Isolate Device') }}
                </button>
                <button type="button" class="btn btn-danger" id="emergencyShutdown">
                    <i class="fa fa-power-off"></i> {{ lang._('Emergency Shutdown') }}
                </button>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    // Initialize threats page
    loadAlerts();
    
    // Set up event handlers
    $('#refreshAlerts').click(function() {
        loadAlerts();
    });
    
    $('#exportAlerts').click(function() {
        exportAlerts();
    });
    
    $('#clearAlerts').click(function() {
        clearOldAlerts();
    });
    
    // Filter change handlers
    $('#severityFilter, #threatTypeFilter, #timeFilter').change(function() {
        loadAlerts();
    });
    
    $('#sourceFilter').on('input', debounce(function() {
        loadAlerts();
    }, 500));
    
    // Auto-refresh every 30 seconds
    setInterval(loadAlerts, 30000);
});

function loadAlerts() {
    const filters = {
        severity: $('#severityFilter').val(),
        type: $('#threatTypeFilter').val(),
        time: $('#timeFilter').val(),
        source: $('#sourceFilter').val()
    };
    
    $('#alertsTableBody').html(`
        <tr>
            <td colspan="8" class="text-center">
                <div class="loading-spinner">
                    <i class="fa fa-spinner fa-spin"></i>
                    {{ lang._('Loading alerts...') }}
                </div>
            </td>
        </tr>
    `);
    
    ajaxCall("/api/deepinspector/alerts/list", filters, function(data) {
        if (data.status === 'ok') {
            populateAlertsTable(data.data);
            updateSummaryCards(data.data);
        } else {
            $('#alertsTableBody').html(`
                <tr>
                    <td colspan="8" class="text-center text-danger">
                        {{ lang._('Error loading alerts') }}: ${data.message || 'Unknown error'}
                    </td>
                </tr>
            `);
        }
    });
}

function populateAlertsTable(alerts) {
    const tbody = $('#alertsTableBody');
    tbody.empty();
    
    if (alerts.length === 0) {
        tbody.html(`
            <tr>
                <td colspan="8" class="text-center text-muted">
                    {{ lang._('No alerts found for the selected criteria') }}
                </td>
            </tr>
        `);
        return;
    }
    
    alerts.forEach(function(alert) {
        const severityClass = getSeverityClass(alert.severity);
        const threatTypeIcon = getThreatTypeIcon(alert.threat_type);
        const isIndustrialThreat = isIndustrialThreatType(alert.threat_type);
        
        const row = $(`
            <tr data-alert-id="${alert.id}" class="${isIndustrialThreat ? 'industrial-threat' : ''}">
                <td>${formatTimestamp(alert.timestamp)}</td>
                <td>
                    <span class="badge ${severityClass}">
                        ${alert.severity.toUpperCase()}
                    </span>
                    ${isIndustrialThreat ? '<i class="fa fa-industry text-warning ms-2" title="Industrial Threat"></i>' : ''}
                </td>
                <td>
                    <i class="fa ${threatTypeIcon}"></i>
                    ${alert.threat_type}
                    ${alert.zero_trust_triggered ? '<i class="fa fa-shield-alt text-primary ms-2" title="Zero Trust Triggered"></i>' : ''}
                </td>
                <td>
                    <div class="ip-container">
                        <code>${alert.source_ip}</code>
                        <span class="ip-status-indicator" id="status-${alert.source_ip.replace(/\./g, '-')}">
                            <i class="fa fa-spinner fa-spin text-muted" title="Checking status..."></i>
                        </span>
                    </div>
                    <small class="text-muted">${alert.source_port || '-'}</small>
                </td>
                <td>
                    <code>${alert.destination_ip}</code>
                    <br>
                    <small class="text-muted">${alert.destination_port || '-'}</small>
                </td>
                <td>
                    <span class="badge badge-info">${alert.protocol}</span>
                    ${alert.industrial_protocol ? `<br><span class="badge badge-warning">${alert.industrial_protocol}</span>` : ''}
                </td>
                <td>
                    <span class="alert-description" title="${alert.description}">
                        ${truncateText(alert.description, 50)}
                    </span>
                </td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="showAlertDetails('${alert.id}')">
                            <i class="fa fa-eye"></i>
                        </button>
                        ${isIndustrialThreat ? 
                            `<button class="btn btn-outline-warning" onclick="showIndustrialThreatDetails('${alert.id}')">
                                <i class="fa fa-industry"></i>
                            </button>` : ''
                        }
                        <button class="btn btn-outline-danger" onclick="blockSourceIP('${alert.source_ip}')" 
                                id="block-btn-${alert.source_ip.replace(/\./g, '-')}">
                            <i class="fa fa-ban"></i>
                        </button>
                        <button class="btn btn-outline-success" onclick="whitelistSourceIP('${alert.source_ip}')"
                                id="whitelist-btn-${alert.source_ip.replace(/\./g, '-')}">
                            <i class="fa fa-check"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `);
        
        tbody.append(row);
        
        // Check IP status asynchronously
        checkIPStatus(alert.source_ip, function(status, message) {
            updateIPStatusIndicator(alert.source_ip, status, message);
        });
    });
}

function updateSummaryCards(alerts) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        industrial: 0,
        zero_trust: 0
    };
    
    alerts.forEach(function(alert) {
        if (counts.hasOwnProperty(alert.severity)) {
            counts[alert.severity]++;
        }
        
        if (isIndustrialThreatType(alert.threat_type)) {
            counts.industrial++;
        }
        
        if (alert.zero_trust_triggered) {
            counts.zero_trust++;
        }
    });
    
    $('#criticalCount').text(counts.critical);
    $('#highCount').text(counts.high);
    $('#mediumCount').text(counts.medium);
    $('#lowCount').text(counts.low);
    $('#industrialCount').text(counts.industrial);
    $('#zeroTrustBlocks').text(counts.zero_trust);
}

// Function to check IP status and update UI accordingly
function checkIPStatus(sourceIP, callback) {
    ajaxCall("/api/deepinspector/service/checkIPStatus", {ip: sourceIP}, function(data) {
        if (data.status === 'ok') {
            callback(data.ip_status, data.message);
        } else {
            callback('unknown', data.message || 'Error checking IP status');
        }
    });
}

// Function to update IP status indicator
function updateIPStatusIndicator(ip, status, message) {
    const safeIP = ip.replace(/\./g, '-');
    const indicator = $(`#status-${safeIP}`);
    const blockBtn = $(`#block-btn-${safeIP}`);
    const whitelistBtn = $(`#whitelist-btn-${safeIP}`);
    
    // Clear spinner
    indicator.html('');
    
    // Update indicator and buttons based on status
    switch(status) {
        case 'blocked':
            indicator.html('<i class="fa fa-ban text-danger ms-1" title="IP is blocked"></i>');
            blockBtn.prop('disabled', true).removeClass('btn-outline-danger').addClass('btn-danger');
            blockBtn.attr('title', 'IP is already blocked');
            whitelistBtn.prop('disabled', false);
            break;
            
        case 'whitelisted':
            indicator.html('<i class="fa fa-check text-success ms-1" title="IP is whitelisted"></i>');
            whitelistBtn.prop('disabled', true).removeClass('btn-outline-success').addClass('btn-success');
            whitelistBtn.attr('title', 'IP is already whitelisted');
            blockBtn.prop('disabled', false);
            break;
            
        case 'unknown':
        default:
            indicator.html('<i class="fa fa-question-circle text-muted ms-1" title="IP status unknown"></i>');
            blockBtn.prop('disabled', false);
            whitelistBtn.prop('disabled', false);
            break;
    }
}

function showAlertDetails(alertId) {
    $('#alertDetailsBody').html(`
        <div class="text-center">
            <i class="fa fa-spinner fa-spin"></i>
            {{ lang._('Loading alert details...') }}
        </div>
    `);
    
    $('#alertDetailsModal').modal('show');
    
    ajaxCall(`/api/deepinspector/alerts/threatDetails/${alertId}`, {}, function(data) {
        if (data.status === 'ok') {
            const alert = data.data;
            
            $('#alertDetailsBody').html(`
                <div class="alert-details">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>{{ lang._('Alert Information') }}</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>{{ lang._('Alert ID') }}:</strong></td>
                                    <td>${alert.id}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Timestamp') }}:</strong></td>
                                    <td>${formatTimestamp(alert.timestamp)}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Severity') }}:</strong></td>
                                    <td>
                                        <span class="badge ${getSeverityClass(alert.severity)}">
                                            ${alert.severity.toUpperCase()}
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Threat Type') }}:</strong></td>
                                    <td>${alert.threat_type}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Status') }}:</strong></td>
                                    <td>${alert.status || 'Active'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Zero Trust') }}:</strong></td>
                                    <td>${alert.zero_trust_triggered ? 'Triggered' : 'Not Triggered'}</td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h6>{{ lang._('Network Information') }}</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>{{ lang._('Source IP') }}:</strong></td>
                                    <td><code>${alert.source_ip}</code></td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Source Port') }}:</strong></td>
                                    <td>${alert.source_port || '-'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Destination IP') }}:</strong></td>
                                    <td><code>${alert.destination_ip}</code></td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Destination Port') }}:</strong></td>
                                    <td>${alert.destination_port || '-'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Protocol') }}:</strong></td>
                                    <td>${alert.protocol}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Interface') }}:</strong></td>
                                    <td>${alert.interface || '-'}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('Description') }}</h6>
                            <div class="alert alert-info">
                                ${alert.description}
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <h6>{{ lang._('Detection Method') }}</h6>
                            <p><strong>{{ lang._('Method') }}:</strong> ${alert.detection_method || 'Unknown'}</p>
                            <p><strong>{{ lang._('Pattern') }}:</strong> <code>${alert.pattern || 'N/A'}</code></p>
                            <p><strong>{{ lang._('Confidence') }}:</strong> ${alert.confidence || 'Unknown'}</p>
                        </div>
                        <div class="col-md-6">
                            <h6>{{ lang._('Impact Assessment') }}</h6>
                            <p><strong>{{ lang._('Risk Level') }}:</strong> ${alert.risk_level || 'Unknown'}</p>
                            <p><strong>{{ lang._('Potential Impact') }}:</strong> ${alert.potential_impact || 'Unknown'}</p>
                            <p><strong>{{ lang._('Recommended Action') }}:</strong> ${alert.recommended_action || 'Review manually'}</p>
                        </div>
                    </div>
                    
                    ${alert.packet_data ? `
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('Packet Data') }}</h6>
                            <pre class="packet-data"><code>${alert.packet_data}</code></pre>
                        </div>
                    </div>
                    ` : ''}
                    
                    ${alert.industrial_context ? `
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('Industrial Context') }}</h6>
                            <div class="alert alert-warning">
                                <i class="fa fa-industry"></i>
                                ${alert.industrial_context}
                            </div>
                        </div>
                    </div>
                    ` : ''}
                </div>
            `);
            
            // Set up modal action buttons
            $('#blockSourceIP').off('click').on('click', function() {
                blockSourceIP(alert.source_ip);
                $('#alertDetailsModal').modal('hide');
            });
            
            $('#whitelistSourceIP').off('click').on('click', function() {
                whitelistSourceIP(alert.source_ip);
                $('#alertDetailsModal').modal('hide');
            });
        } else {
            $('#alertDetailsBody').html(`
                <div class="alert alert-danger">
                    {{ lang._('Error loading alert details') }}: ${data.message || 'Unknown error'}
                </div>
            `);
        }
    });
}

function showIndustrialThreatDetails(alertId) {
    $('#industrialThreatBody').html(`
        <div class="text-center">
            <i class="fa fa-spinner fa-spin"></i>
            {{ lang._('Loading industrial threat analysis...') }}
        </div>
    `);
    
    $('#industrialThreatModal').modal('show');
    
    ajaxCall(`/api/deepinspector/alerts/threatDetails/${alertId}`, {}, function(data) {
        if (data.status === 'ok') {
            const threat = data.data;
            
            $('#industrialThreatBody').html(`
                <div class="industrial-threat-analysis">
                    <div class="alert alert-warning">
                        <i class="fa fa-industry"></i>
                        <strong>{{ lang._('Industrial Environment Threat Detected') }}</strong>
                        {{ lang._('This threat affects industrial control systems and may impact operational technology.') }}
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <h6>{{ lang._('Threat Classification') }}</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>{{ lang._('Industrial Protocol') }}:</strong></td>
                                    <td>${threat.industrial_protocol || 'Unknown'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Target System') }}:</strong></td>
                                    <td>${threat.target_system || 'Unknown'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Attack Vector') }}:</strong></td>
                                    <td>${threat.attack_vector || 'Unknown'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Operational Impact') }}:</strong></td>
                                    <td>${threat.operational_impact || 'Unknown'}</td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h6>{{ lang._('Safety Assessment') }}</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>{{ lang._('Safety Risk') }}:</strong></td>
                                    <td><span class="badge ${getSafetyRiskClass(threat.safety_risk)}">${threat.safety_risk || 'Unknown'}</span></td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Production Impact') }}:</strong></td>
                                    <td>${threat.production_impact || 'Unknown'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Recovery Time') }}:</strong></td>
                                    <td>${threat.recovery_time || 'Unknown'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Isolation Required') }}:</strong></td>
                                    <td>${threat.isolation_required ? 'Yes' : 'No'}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('Mitigation Recommendations') }}</h6>
                            <ul class="list-group">
                                ${threat.mitigation_steps ? threat.mitigation_steps.map(step => `<li class="list-group-item">${step}</li>`).join('') : '<li class="list-group-item">No specific recommendations available</li>'}
                            </ul>
                        </div>
                    </div>
                    
                    ${threat.scada_context ? `
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('SCADA/PLC Context') }}</h6>
                            <div class="alert alert-info">
                                ${threat.scada_context}
                            </div>
                        </div>
                    </div>
                    ` : ''}
                </div>
            `);
            
            // Set up industrial threat action buttons
            $('#isolateIndustrialDevice').off('click').on('click', function() {
                isolateIndustrialDevice(threat);
                $('#industrialThreatModal').modal('hide');
            });
            
            $('#emergencyShutdown').off('click').on('click', function() {
                emergencyShutdown(threat);
                $('#industrialThreatModal').modal('hide');
            });
        } else {
            $('#industrialThreatBody').html(`
                <div class="alert alert-danger">
                    {{ lang._('Error loading industrial threat details') }}: ${data.message || 'Unknown error'}
                </div>
            `);
        }
    });
}

function blockSourceIP(sourceIP) {
    if (confirm(`{{ lang._('Are you sure you want to block IP') }} ${sourceIP}?`)) {
        ajaxCall("/api/deepinspector/service/blockIP", {ip: sourceIP}, function(data) {
            if (data.status === 'ok') {
                showNotification(`IP ${sourceIP} {{ lang._('blocked successfully') }}`, 'success');
                loadAlerts();
            } else {
                showNotification(`{{ lang._('Failed to block IP') }}: ${data.message || 'Unknown error'}`, 'error');
            }
        });
    }
}

function whitelistSourceIP(sourceIP) {
    if (confirm(`{{ lang._('Are you sure you want to whitelist IP') }} ${sourceIP}?`)) {
        ajaxCall("/api/deepinspector/service/whitelistIP", {ip: sourceIP}, function(data) {
            if (data.status === 'ok') {
                showNotification(`IP ${sourceIP} {{ lang._('whitelisted successfully') }}`, 'success');
                loadAlerts();
            } else {
                showNotification(`{{ lang._('Failed to whitelist IP') }}: ${data.message || 'Unknown error'}`, 'error');
            }
        });
    }
}

function isolateIndustrialDevice(threat) {
    showNotification('{{ lang._("Isolate Device: feature not yet implemented") }}', 'warning');
}

function emergencyShutdown(threat) {
    showNotification('{{ lang._("Emergency Shutdown: feature not yet implemented") }}', 'warning');
}

function exportAlerts() {
    const filters = {
        severity: $('#severityFilter').val(),
        type: $('#threatTypeFilter').val(),
        time: $('#timeFilter').val(),
        source: $('#sourceFilter').val(),
        format: 'csv'
    };
    
    ajaxCall("/api/deepinspector/alerts/export", filters, function(data) {
        if (data.status === 'ok') {
            const blob = new Blob([data.data], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `dpi_alerts_${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showNotification('{{ lang._("Alerts exported successfully") }}', 'success');
        } else {
            showNotification('{{ lang._("Failed to export alerts") }}', 'error');
        }
    });
}

function clearOldAlerts() {
    if (confirm('{{ lang._("This will clear alerts older than 30 days. Are you sure?") }}')) {
        ajaxCall("/api/deepinspector/alerts/clearOld", {}, function(data) {
            if (data.status === 'ok') {
                showNotification('{{ lang._("Old alerts cleared successfully") }}', 'success');
                loadAlerts();
            } else {
                showNotification('{{ lang._("Failed to clear old alerts") }}', 'error');
            }
        });
    }
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

function getSafetyRiskClass(risk) {
    switch(risk?.toLowerCase()) {
        case 'critical': return 'badge-danger';
        case 'high': return 'badge-warning';
        case 'medium': return 'badge-info';
        case 'low': return 'badge-success';
        default: return 'badge-secondary';
    }
}

function getThreatTypeIcon(threatType) {
    switch(threatType.toLowerCase()) {
        case 'malware': return 'fa-bug';
        case 'virus': return 'fa-virus';
        case 'trojan': return 'fa-user-secret';
        case 'command_injection': return 'fa-terminal';
        case 'sql_injection': return 'fa-database';
        case 'script_injection': return 'fa-code';
        case 'crypto_mining': return 'fa-bitcoin';
        case 'data_exfiltration': return 'fa-upload';
        case 'phishing': return 'fa-fish';
        case 'botnet': return 'fa-sitemap';
        case 'industrial_threat': return 'fa-industry';
        case 'scada_attack': return 'fa-cogs';
        default: return 'fa-exclamation-triangle';
    }
}

function isIndustrialThreatType(threatType) {
    return ['industrial_threat', 'scada_attack'].includes(threatType.toLowerCase());
}

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
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