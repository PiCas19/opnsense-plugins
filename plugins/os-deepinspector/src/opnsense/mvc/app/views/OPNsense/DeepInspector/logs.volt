{# logs.volt - Deep Packet Inspector Logs #}

<div class="content-box">
    <div class="logs-header">
        <h2>{{ lang._('Deep Packet Inspector - Logs') }}</h2>
        <div class="logs-controls">
            <button class="btn btn-secondary" id="refreshLogs">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
            <button class="btn btn-primary" id="downloadLogs">
                <i class="fa fa-download"></i> {{ lang._('Download') }}
            </button>
            <button class="btn btn-warning" id="clearLogs">
                <i class="fa fa-trash"></i> {{ lang._('Clear') }}
            </button>
        </div>
    </div>

    <!-- Log Filters -->
    <div class="logs-filters">
        <div class="row">
            <div class="col-md-2">
                <label for="logLevel">{{ lang._('Log Level') }}</label>
                <select class="form-control" id="logLevel">
                    <option value="all">{{ lang._('All Levels') }}</option>
                    <option value="trace">{{ lang._('Trace') }}</option>
                    <option value="debug">{{ lang._('Debug') }}</option>
                    <option value="info" selected>{{ lang._('Info') }}</option>
                    <option value="warning">{{ lang._('Warning') }}</option>
                    <option value="error">{{ lang._('Error') }}</option>
                    <option value="critical">{{ lang._('Critical') }}</option>
                </select>
            </div>
            <div class="col-md-2">
                <label for="logSource">{{ lang._('Source') }}</label>
                <select class="form-control" id="logSource">
                    <option value="all">{{ lang._('All Sources') }}</option>
                    <option value="engine">{{ lang._('DPI Engine') }}</option>
                    <option value="detection">{{ lang._('Detection') }}</option>
                    <option value="analysis">{{ lang._('Analysis') }}</option>
                    <option value="alerts">{{ lang._('Alerts') }}</option>
                    <option value="industrial">{{ lang._('Industrial') }}</option>
                    <option value="zerotrust">{{ lang._('Zero Trust') }}</option>
                </select>
            </div>
            <div class="col-md-2">
                <label for="logTimeRange">{{ lang._('Time Range') }}</label>
                <select class="form-control" id="logTimeRange">
                    <option value="1h">{{ lang._('Last Hour') }}</option>
                    <option value="6h">{{ lang._('Last 6 Hours') }}</option>
                    <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                    <option value="7d">{{ lang._('Last Week') }}</option>
                    <option value="30d">{{ lang._('Last Month') }}</option>
                </select>
            </div>
            <div class="col-md-3">
                <label for="logSearch">{{ lang._('Search') }}</label>
                <input type="text" class="form-control" id="logSearch" placeholder="{{ lang._('Search logs...') }}">
            </div>
            <div class="col-md-1">
                <label>&nbsp;</label>
                <button class="btn btn-info btn-block" id="searchLogs">
                    <i class="fa fa-search"></i>
                </button>
            </div>
            <div class="col-md-2">
                <label for="autoRefresh">{{ lang._('Auto Refresh') }}</label>
                <select class="form-control" id="autoRefresh">
                    <option value="0">{{ lang._('Off') }}</option>
                    <option value="5">{{ lang._('5 seconds') }}</option>
                    <option value="10">{{ lang._('10 seconds') }}</option>
                    <option value="30" selected>{{ lang._('30 seconds') }}</option>
                    <option value="60">{{ lang._('1 minute') }}</option>
                </select>
            </div>
        </div>
    </div>

    <!-- Log Statistics -->
    <div class="log-statistics">
        <div class="row">
            <div class="col-md-2">
                <div class="stat-card trace">
                    <div class="stat-icon">
                        <i class="fa fa-microscope"></i>
                    </div>
                    <div class="stat-content">
                        <div class="stat-value" id="traceCount">0</div>
                        <div class="stat-label">{{ lang._('Trace') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card debug">
                    <div class="stat-icon">
                        <i class="fa fa-bug"></i>
                    </div>
                    <div class="stat-content">
                        <div class="stat-value" id="debugCount">0</div>
                        <div class="stat-label">{{ lang._('Debug') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card info">
                    <div class="stat-icon">
                        <i class="fa fa-info-circle"></i>
                    </div>
                    <div class="stat-content">
                        <div class="stat-value" id="infoCount">0</div>
                        <div class="stat-label">{{ lang._('Info') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card warning">
                    <div class="stat-icon">
                        <i class="fa fa-exclamation-triangle"></i>
                    </div>
                    <div class="stat-content">
                        <div class="stat-value" id="warningCount">0</div>
                        <div class="stat-label">{{ lang._('Warning') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card error">
                    <div class="stat-icon">
                        <i class="fa fa-times-circle"></i>
                    </div>
                    <div class="stat-content">
                        <div class="stat-value" id="errorCount">0</div>
                        <div class="stat-label">{{ lang._('Error') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card critical">
                    <div class="stat-icon">
                        <i class="fa fa-skull"></i>
                    </div>
                    <div class="stat-content">
                        <div class="stat-value" id="criticalCount">0</div>
                        <div class="stat-label">{{ lang._('Critical') }}</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Log Display -->
    <div class="logs-display">
        <div class="log-container">
            <div class="log-header">
                <div class="log-info">
                    <span id="logCount">0</span> {{ lang._('entries') }} |
                    <span id="logSize">0 KB</span> |
                    {{ lang._('Last updated') }}: <span id="lastUpdated">--</span>
                </div>
                <div class="log-controls-inline">
                    <button class="btn btn-sm btn-secondary" id="pauseScroll">
                        <i class="fa fa-pause"></i> {{ lang._('Pause') }}
                    </button>
                    <button class="btn btn-sm btn-info" id="scrollToTop">
                        <i class="fa fa-arrow-up"></i> {{ lang._('Top') }}
                    </button>
                    <button class="btn btn-sm btn-info" id="scrollToBottom">
                        <i class="fa fa-arrow-down"></i> {{ lang._('Bottom') }}
                    </button>
                </div>
            </div>
            
            <div class="log-content" id="logContent">
                <div class="log-loading">
                    <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading logs...') }}
                </div>
            </div>
        </div>
    </div>

    <!-- Log Entry Details Modal -->
    <div class="modal fade" id="logDetailsModal" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">{{ lang._('Log Entry Details') }}</h5>
                    <button type="button" class="close" data-dismiss="modal">
                        <span>&times;</span>
                    </button>
                </div>
                <div class="modal-body" id="logDetailsBody">
                    <!-- Log details will be loaded here -->
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">
                        {{ lang._('Close') }}
                    </button>
                    <button type="button" class="btn btn-primary" id="copyLogEntry">
                        <i class="fa fa-copy"></i> {{ lang._('Copy') }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    // Initialize logs page
    loadLogs();
    
    // Set up event handlers
    $('#refreshLogs').click(function() {
        loadLogs();
    });
    
    $('#downloadLogs').click(function() {
        downloadLogs();
    });
    
    $('#clearLogs').click(function() {
        clearLogs();
    });
    
    $('#searchLogs').click(function() {
        loadLogs();
    });
    
    // Filter change handlers
    $('#logLevel, #logSource, #logTimeRange').change(function() {
        loadLogs();
    });
    
    // Search on Enter key
    $('#logSearch').keypress(function(e) {
        if (e.which == 13) {
            loadLogs();
        }
    });
    
    // Auto-refresh handler
    $('#autoRefresh').change(function() {
        setupAutoRefresh();
    });
    
    // Scroll controls
    $('#pauseScroll').click(function() {
        toggleScrollPause();
    });
    
    $('#scrollToTop').click(function() {
        $('#logContent').scrollTop(0);
    });
    
    $('#scrollToBottom').click(function() {
        const logContent = $('#logContent')[0];
        logContent.scrollTop = logContent.scrollHeight;
    });
    
    // Setup initial auto-refresh
    setupAutoRefresh();
});

let autoRefreshInterval;
let scrollPaused = false;

function loadLogs() {
    const filters = {
        level: $('#logLevel').val(),
        source: $('#logSource').val(),
        timeRange: $('#logTimeRange').val(),
        search: $('#logSearch').val()
    };
    
    $('#logContent').html(`
        <div class="log-loading">
            <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading logs...') }}
        </div>
    `);
    
    ajaxCall("/api/deepinspector/logs/list", filters, function(data) {
        if (data.status === 'ok') {
            displayLogs(data.data);
            updateLogStatistics(data.statistics);
            updateLogInfo(data.info);
        } else {
            $('#logContent').html(`
                <div class="log-error">
                    <i class="fa fa-exclamation-triangle"></i>
                    {{ lang._('Error loading logs') }}: ${data.message}
                </div>
            `);
        }
    });
}

function displayLogs(logs) {
    const logContent = $('#logContent');
    logContent.empty();
    
    if (logs.length === 0) {
        logContent.html(`
            <div class="log-empty">
                <i class="fa fa-info-circle"></i>
                {{ lang._('No logs found for the selected criteria') }}
            </div>
        `);
        return;
    }
    
    logs.forEach(function(log) {
        const logEntry = createLogEntry(log);
        logContent.append(logEntry);
    });
    
    // Auto-scroll to bottom unless paused
    if (!scrollPaused) {
        const logContentElement = logContent[0];
        logContentElement.scrollTop = logContentElement.scrollHeight;
    }
}

function createLogEntry(log) {
    const levelClass = getLogLevelClass(log.level);
    const sourceIcon = getSourceIcon(log.source);
    
    return $(`
        <div class="log-entry ${levelClass}" data-log-id="${log.id}">
            <div class="log-timestamp">${formatTimestamp(log.timestamp)}</div>
            <div class="log-level">
                <span class="badge badge-${levelClass}">${log.level.toUpperCase()}</span>
            </div>
            <div class="log-source">
                <i class="fa ${sourceIcon}"></i>
                ${log.source}
            </div>
            <div class="log-message" onclick="showLogDetails('${log.id}')">
                ${highlightLogMessage(log.message)}
                ${log.details ? '<i class="fa fa-info-circle text-info ms-2" title="Has details"></i>' : ''}
            </div>
            ${log.context ? `
            <div class="log-context">
                <small class="text-muted">${log.context}</small>
            </div>
            ` : ''}
        </div>
    `);
}

function updateLogStatistics(stats) {
    $('#traceCount').text(stats.trace || 0);
    $('#debugCount').text(stats.debug || 0);
    $('#infoCount').text(stats.info || 0);
    $('#warningCount').text(stats.warning || 0);
    $('#errorCount').text(stats.error || 0);
    $('#criticalCount').text(stats.critical || 0);
}

function updateLogInfo(info) {
    $('#logCount').text(info.count || 0);
    $('#logSize').text(formatBytes(info.size || 0));
    $('#lastUpdated').text(formatTimestamp(info.lastUpdated));
}

function showLogDetails(logId) {
    $('#logDetailsBody').html(`
        <div class="text-center">
            <i class="fa fa-spinner fa-spin"></i>
            {{ lang._('Loading log details...') }}
        </div>
    `);
    
    $('#logDetailsModal').modal('show');
    
    ajaxCall(`/api/deepinspector/logs/details/${logId}`, {}, function(data) {
        if (data.status === 'ok') {
            const log = data.data;
            
            $('#logDetailsBody').html(`
                <div class="log-details">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>{{ lang._('Basic Information') }}</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>{{ lang._('ID') }}:</strong></td>
                                    <td>${log.id}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Timestamp') }}:</strong></td>
                                    <td>${formatTimestamp(log.timestamp)}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Level') }}:</strong></td>
                                    <td><span class="badge badge-${getLogLevelClass(log.level)}">${log.level.toUpperCase()}</span></td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Source') }}:</strong></td>
                                    <td><i class="fa ${getSourceIcon(log.source)}"></i> ${log.source}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Thread') }}:</strong></td>
                                    <td>${log.thread || 'N/A'}</td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h6>{{ lang._('Context Information') }}</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>{{ lang._('Process') }}:</strong></td>
                                    <td>${log.process || 'N/A'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Module') }}:</strong></td>
                                    <td>${log.module || 'N/A'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Function') }}:</strong></td>
                                    <td>${log.function || 'N/A'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('Line') }}:</strong></td>
                                    <td>${log.line || 'N/A'}</td>
                                </tr>
                                <tr>
                                    <td><strong>{{ lang._('File') }}:</strong></td>
                                    <td>${log.file || 'N/A'}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('Message') }}</h6>
                            <div class="log-message-detail">
                                ${log.message}
                            </div>
                        </div>
                    </div>
                    
                    ${log.details ? `
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('Details') }}</h6>
                            <pre class="log-details-text">${log.details}</pre>
                        </div>
                    </div>
                    ` : ''}
                    
                    ${log.stack_trace ? `
                    <div class="row">
                        <div class="col-md-12">
                            <h6>{{ lang._('Stack Trace') }}</h6>
                            <pre class="log-stack-trace">${log.stack_trace}</pre>
                        </div>
                    </div>
                    ` : ''}
                </div>
            `);
            
            // Set up copy button
            $('#copyLogEntry').off('click').on('click', function() {
                const logText = `[${log.timestamp}] ${log.level.toUpperCase()} [${log.source}] ${log.message}`;
                navigator.clipboard.writeText(logText).then(function() {
                    showNotification('{{ lang._("Log entry copied to clipboard") }}', 'success');
                });
            });
        } else {
            $('#logDetailsBody').html(`
                <div class="alert alert-danger">
                    {{ lang._('Error loading log details') }}: ${data.message}
                </div>
            `);
        }
    });
}

function downloadLogs() {
    const filters = {
        level: $('#logLevel').val(),
        source: $('#logSource').val(),
        timeRange: $('#logTimeRange').val(),
        search: $('#logSearch').val(),
        format: 'txt'
    };
    
    ajaxCall("/api/deepinspector/logs/export", filters, function(data) {
        if (data.status === 'ok') {
            const blob = new Blob([data.data], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `dpi_logs_${new Date().toISOString().split('T')[0]}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showNotification('{{ lang._("Logs downloaded successfully") }}', 'success');
        } else {
            showNotification('{{ lang._("Failed to download logs") }}', 'error');
        }
    });
}

function clearLogs() {
    if (confirm('{{ lang._("Are you sure you want to clear all logs? This action cannot be undone.") }}')) {
        ajaxCall("/api/deepinspector/logs/clear", {}, function(data) {
            if (data.status === 'ok') {
                showNotification('{{ lang._("Logs cleared successfully") }}', 'success');
                loadLogs();
            } else {
                showNotification('{{ lang._("Failed to clear logs") }}', 'error');
            }
        });
    }
}

function setupAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    
    const interval = parseInt($('#autoRefresh').val()) * 1000;
    if (interval > 0) {
        autoRefreshInterval = setInterval(loadLogs, interval);
    }
}

function toggleScrollPause() {
    scrollPaused = !scrollPaused;
    const $btn = $('#pauseScroll');
    
    if (scrollPaused) {
        $btn.html('<i class="fa fa-play"></i> {{ lang._("Resume") }}');
        $btn.removeClass('btn-secondary').addClass('btn-warning');
    } else {
        $btn.html('<i class="fa fa-pause"></i> {{ lang._("Pause") }}');
        $btn.removeClass('btn-warning').addClass('btn-secondary');
    }
}

function highlightLogMessage(message) {
    const search = $('#logSearch').val();
    if (search && search.length > 0) {
        const regex = new RegExp(`(${search})`, 'gi');
        return message.replace(regex, '<mark>$1</mark>');
    }
    return message;
}

function getLogLevelClass(level) {
    switch(level.toLowerCase()) {
        case 'critical': return 'critical';
        case 'error': return 'error';
        case 'warning': return 'warning';
        case 'info': return 'info';
        case 'debug': return 'debug';
        case 'trace': return 'trace';
        default: return 'info';
    }
}

function getSourceIcon(source) {
    switch(source.toLowerCase()) {
        case 'engine': return 'fa-cogs';
        case 'detection': return 'fa-shield-alt';
        case 'analysis': return 'fa-chart-line';
        case 'alerts': return 'fa-bell';
        case 'industrial': return 'fa-industry';
        case 'zerotrust': return 'fa-lock';
        default: return 'fa-info-circle';
    }
}

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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
.logs-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}

.logs-filters {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 0.5rem;
    margin-bottom: 1rem;
}

.log-statistics {
    margin-bottom: 1rem;
}

.stat-card {
    background: white;
    border-radius: 0.5rem;
    padding: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
    margin-bottom: 0.5rem;
}

.stat-card.trace {
    border-left: 4px solid #6c757d;
}

.stat-card.debug {
    border-left: 4px solid #17a2b8;
}

.stat-card.info {
    border-left: 4px solid #007bff;
}

.stat-card.warning {
    border-left: 4px solid #ffc107;
}

.stat-card.error {
    border-left: 4px solid #dc3545;
}

.stat-card.critical {
    border-left: 4px solid #6f42c1;
}

.stat-icon {
    font-size: 1.5rem;
    margin-right: 1rem;
    color: #6c757d;
}

.stat-content {
    flex: 1;
}

.stat-value {
    font-size: 1.5rem;
    font-weight: bold;
    color: #212529;
}

.stat-label {
    font-size: 0.75rem;
    color: #6c757d;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.logs-display {
    background: white;
    border-radius: 0.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.log-container {
    height: 600px;
    display: flex;
    flex-direction: column;
}

.log-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    border-bottom: 1px solid #dee2e6;
    background: #f8f9fa;
    border-radius: 0.5rem 0.5rem 0 0;
}

.log-info {
    font-size: 0.875rem;
    color: #6c757d;
}

.log-content {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem;
    font-family: 'Courier New', monospace;
    font-size: 0.875rem;
}

.log-entry {
    display: flex;
    padding: 0.5rem;
    border-bottom: 1px solid #f0f0f0;
    transition: background-color 0.2s;
}

.log-entry:hover {
    background-color: #f8f9fa;
}

.log-entry.critical {
    background-color: #f8d7da;
}

.log-entry.error {
    background-color: #f5c6cb;
}

.log-entry.warning {
    background-color: #fff3cd;
}

.log-timestamp {
    min-width: 150px;
    color: #6c757d;
    font-size: 0.75rem;
}

.log-level {
    min-width: 80px;
    margin-right: 0.5rem;
}

.log-source {
    min-width: 100px;
    margin-right: 0.5rem;
    color: #495057;
}

.log-message {
    flex: 1;
    cursor: pointer;
    color: #212529;
}

.log-message:hover {
    text-decoration: underline;
}

.log-context {
    margin-top: 0.25rem;
    font-size: 0.75rem;
}

.log-loading,
.log-error,
.log-empty {
    text-align: center;
    padding: 3rem;
    color: #6c757d;
}

.log-error {
    color: #dc3545;
}

.log-message-detail {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 0.375rem;
    padding: 1rem;
    font-family: 'Courier New', monospace;
    font-size: 0.875rem;
    white-space: pre-wrap;
}

.log-details-text,
.log-stack-trace {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 0.375rem;
    padding: 1rem;
    font-family: 'Courier New', monospace;
    font-size: 0.75rem;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
}

.log-stack-trace {
    background: #fff5f5;
    border-color: #fed7d7;
    color: #c53030;
}

.badge-trace {
    background-color: #6c757d;
}

.badge-debug {
    background-color: #17a2b8;
}

.badge-info {
    background-color: #007bff;
}

.badge-warning {
    background-color: #ffc107;
    color: #212529;
}

.badge-error {
    background-color: #dc3545;
}

.badge-critical {
    background-color: #6f42c1;
}

mark {
    background-color: #fff3cd;
    padding: 0.1em 0.2em;
    border-radius: 0.2em;
}

@media (max-width: 768px) {
    .logs-header {
        flex-direction: column;
        align-items: stretch;
    }
    
    .logs-controls {
        margin-top: 1rem;
    }
    
    .log-entry {
        flex-direction: column;
        padding: 0.75rem;
    }
    
    .log-timestamp,
    .log-level,
    .log-source {
        min-width: auto;
        margin-bottom: 0.25rem;
    }
    
    .log-container {
        height: 400px;
    }
    
    .log-header {
        flex-direction: column;
        align-items: stretch;
    }
    
    .log-controls-inline {
        margin-top: 0.5rem;
    }
}

/* Scrollbar styling */
.log-content::-webkit-scrollbar {
    width: 8px;
}

.log-content::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 4px;
}

.log-content::-webkit-scrollbar-thumb {
    background: #c1c1c1;
    border-radius: 4px;
}

.log-content::-webkit-scrollbar-thumb:hover {
    background: #a8a8a8;
}

/* Animation for new log entries */
@keyframes logEntryFadeIn {
    from {
        opacity: 0;
        transform: translateY(-10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.log-entry {
    animation: logEntryFadeIn 0.3s ease-out;
}
</style>