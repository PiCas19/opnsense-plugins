{# alerts.volt - Deep Packet Inspector Alerts #}
<div class="content-box">
    <div class="alert-header">
        <h2>{{ lang._('Deep Packet Inspector Alerts') }}</h2>
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
            <div class="col-md-3">
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
            <div class="col-md-3">
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
            <div class="col-md-3">
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
            <div class="col-md-3">
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
                <!-- Alerts will be loaded dynamically -->
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

<script>
$(document).ready(function() {
    // Initialize alerts page
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

    $('#alertsTableBody').html('');

    ajaxCall("/api/deepinspector/alerts/list", filters, function(data) {
        if (data.status === 'ok') {
            populateAlertsTable(data.data);
            updateSummaryCards(data.data);
        } else {
            // Show empty table on error (no fallback message)
            $('#alertsTableBody').html('');
        }
    });
}

function populateAlertsTable(alerts) {
    const tbody = $('#alertsTableBody');
    tbody.empty();

    // Show nothing if no alerts (Zero Trust - no fallback message)
    if (alerts.length === 0) {
        return;
    }
    
    alerts.forEach(function(alert) {
        const severityClass = getSeverityClass(alert.severity);
        const threatTypeIcon = getThreatTypeIcon(alert.threat_type);
        
        const row = $(`
            <tr data-alert-id="${alert.id}">
                <td>${formatTimestamp(alert.timestamp)}</td>
                <td>
                    <span class="badge ${severityClass}">
                        ${alert.severity.toUpperCase()}
                    </span>
                </td>
                <td>
                    <i class="fa ${threatTypeIcon}"></i>
                    ${alert.threat_type}
                </td>
                <td>
                    <code>${alert.source_ip}</code>
                    <br>
                    <small class="text-muted">${alert.source_port || '-'}</small>
                </td>
                <td>
                    <code>${alert.destination_ip}</code>
                    <br>
                    <small class="text-muted">${alert.destination_port || '-'}</small>
                </td>
                <td>
                    <span class="badge badge-info">${alert.protocol}</span>
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
                        <button class="btn btn-outline-danger" onclick="blockSourceIP('${alert.source_ip}')">
                            <i class="fa fa-ban"></i>
                        </button>
                        <button class="btn btn-outline-success" onclick="whitelistSourceIP('${alert.source_ip}')">
                            <i class="fa fa-check"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `);
        
        tbody.append(row);
    });
}

function updateSummaryCards(alerts) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };
    
    alerts.forEach(function(alert) {
        if (counts.hasOwnProperty(alert.severity)) {
            counts[alert.severity]++;
        }
    });
    
    $('#criticalCount').text(counts.critical);
    $('#highCount').text(counts.high);
    $('#mediumCount').text(counts.medium);
    $('#lowCount').text(counts.low);
}

function showAlertDetails(alertId) {
    $('#alertDetailsBody').html('');

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
                        <div class="col-md-12">
                            <h6>{{ lang._('Detection Method') }}</h6>
                            <p><strong>{{ lang._('Method') }}:</strong> ${alert.method || 'Unknown'}</p>
                            <p><strong>{{ lang._('Pattern') }}:</strong> <code>${alert.pattern || 'N/A'}</code></p>
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
            // Show empty on error (no fallback message)
            $('#alertDetailsBody').html('');
            $('#alertDetailsModal').modal('hide');
        }
    });
}

function blockSourceIP(sourceIP) {
    if (confirm(`{{ lang._('Are you sure you want to block IP') }} ${sourceIP}?`)) {
        ajaxCall("/api/deepinspector/service/blockIP", {ip: sourceIP}, function(data) {
            if (data.status === 'ok') {
                showNotification(`{{ lang._('IP') }} ${sourceIP} {{ lang._('has been blocked') }}`, 'success');
            } else {
                showNotification(`{{ lang._('Failed to block IP') }} ${sourceIP}`, 'error');
            }
        });
    }
}

function whitelistSourceIP(sourceIP) {
    if (confirm(`{{ lang._('Are you sure you want to whitelist IP') }} ${sourceIP}?`)) {
        ajaxCall("/api/deepinspector/service/whitelistIP", {ip: sourceIP}, function(data) {
            if (data.status === 'ok') {
                showNotification(`{{ lang._('IP') }} ${sourceIP} {{ lang._('has been whitelisted') }}`, 'success');
            } else {
                showNotification(`{{ lang._('Failed to whitelist IP') }} ${sourceIP}`, 'error');
            }
        });
    }
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
        default: return 'fa-exclamation-triangle';
    }
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