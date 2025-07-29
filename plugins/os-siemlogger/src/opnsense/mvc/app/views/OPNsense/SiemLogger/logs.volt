{#
 # Copyright (C) 2025 OPNsense SIEM Logger Plugin
 # All rights reserved.
 #}

<script>
$(document).ready(function() {
    // Initialize global variables - FIX per "limit is not defined"
    window.currentPage = 1;
    window.logsLimit = 50;
    window.isLoading = false;
    
    // Load logs on page load
    loadLogs(window.currentPage);
    
    // Refresh every 30 seconds
    setInterval(function() {
        if (!window.isLoading) {
            loadLogs(window.currentPage);
        }
    }, 30000);
});

function loadLogs(page) {
    // Prevent multiple concurrent requests
    if (window.isLoading) {
        return;
    }
    
    window.isLoading = true;
    page = page || 1;
    
    $("#logsContent").html('<div class="text-center" style="padding: 40px;"><i class="fa fa-spinner fa-pulse fa-2x text-primary"></i><br><br>Loading logs...</div>');
    
    // Add loading state to refresh button
    var refreshBtn = $('button[onclick="refreshLogs()"]');
    var originalRefreshText = refreshBtn.html();
    refreshBtn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Loading...');
    
    ajaxCall('/api/siemlogger/service/getLogs', {
        'page': page,
        'limit': window.logsLimit
    }, function(data, status) {
        window.isLoading = false;
        refreshBtn.prop('disabled', false).html(originalRefreshText);
        
        if (status === "success" && data && data.status === 'ok') {
            if (data.data && data.data.logs) {
                displayLogs(data.data.logs, data.data.total || data.data.logs.length, page);
            } else {
                $("#logsContent").html('<div class="alert alert-info"><i class="fa fa-info-circle"></i> No logs found</div>');
            }
        } else {
            var errorMsg = 'Error loading logs';
            if (data && data.message) {
                errorMsg += ': ' + data.message;
            }
            $("#logsContent").html('<div class="alert alert-danger"><i class="fa fa-exclamation-triangle"></i> ' + errorMsg + '</div>');
        }
    }, function(xhr, status, error) {
        // Error callback
        window.isLoading = false;
        refreshBtn.prop('disabled', false).html(originalRefreshText);
        
        console.error('AJAX Error:', error, xhr.responseText);
        $("#logsContent").html('<div class="alert alert-danger"><i class="fa fa-times-circle"></i> Network error: ' + error + '</div>');
    });
}

function displayLogs(logs, total, page) {
    var html = '<div class="table-responsive">';
    html += '<table class="table table-striped table-hover">';
    html += '<thead>';
    html += '<tr class="active">';
    html += '<th><i class="fa fa-clock-o"></i> Timestamp</th>';
    html += '<th><i class="fa fa-globe"></i> Source IP</th>';
    html += '<th><i class="fa fa-tag"></i> Event Type</th>';
    html += '<th><i class="fa fa-exclamation-circle"></i> Severity</th>';
    html += '<th><i class="fa fa-comment"></i> Message</th>';
    html += '<th><i class="fa fa-user"></i> User</th>';
    html += '</tr>';
    html += '</thead>';
    html += '<tbody>';
    
    if (!logs || logs.length === 0) {
        html += '<tr><td colspan="6" class="text-center text-muted" style="padding: 40px;">';
        html += '<i class="fa fa-inbox fa-2x"></i><br><br>No logs available';
        html += '</td></tr>';
    } else {
        $.each(logs, function(i, log) {
            var severityClass = getSeverityClass(log.severity);
            var timestamp = formatTimestamp(log.timestamp_iso || log.timestamp);
            var message = truncateMessage(log.message || log.description || 'No message', 100);
            
            html += '<tr>';
            html += '<td><small>' + timestamp + '</small></td>';
            html += '<td><code>' + (log.source_ip || 'Unknown') + '</code></td>';
            html += '<td><span class="badge badge-default">' + (log.event_type || 'Unknown') + '</span></td>';
            html += '<td><span class="label label-' + severityClass + '">' + (log.severity || 'info').toUpperCase() + '</span></td>';
            html += '<td><span title="' + (log.message || log.description || 'No message') + '">' + message + '</span></td>';
            html += '<td><small>' + (log.user || 'System') + '</small></td>';
            html += '</tr>';
        });
    }
    
    html += '</tbody></table></div>';
    
    // Add pagination if needed
    if (total > window.logsLimit) {
        html += createPagination(total, page, window.logsLimit);
    }
    
    // Add summary info
    var startRecord = ((page - 1) * window.logsLimit) + 1;
    var endRecord = Math.min(page * window.logsLimit, total);
    html += '<div class="text-muted small" style="margin-top: 10px;">';
    html += 'Showing ' + startRecord + ' to ' + endRecord + ' of ' + total + ' entries';
    html += '</div>';
    
    $("#logsContent").html(html);
    window.currentPage = page;
}

function createPagination(total, currentPage, limit) {
    var totalPages = Math.ceil(total / limit);
    var html = '<nav style="text-align: center; margin-top: 20px;">';
    html += '<ul class="pagination pagination-sm">';
    
    // Previous button
    if (currentPage > 1) {
        html += '<li><a href="#" onclick="loadLogs(' + (currentPage - 1) + ')" title="Previous page">&laquo;</a></li>';
    } else {
        html += '<li class="disabled"><span>&laquo;</span></li>';
    }
    
    // Page numbers (smart pagination)
    var startPage = Math.max(1, currentPage - 3);
    var endPage = Math.min(totalPages, currentPage + 3);
    
    // Show first page if not in range
    if (startPage > 1) {
        html += '<li><a href="#" onclick="loadLogs(1)">1</a></li>';
        if (startPage > 2) {
            html += '<li class="disabled"><span>...</span></li>';
        }
    }
    
    // Show page range
    for (var i = startPage; i <= endPage; i++) {
        var activeClass = (i === currentPage) ? ' class="active"' : '';
        html += '<li' + activeClass + '><a href="#" onclick="loadLogs(' + i + ')">' + i + '</a></li>';
    }
    
    // Show last page if not in range
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            html += '<li class="disabled"><span>...</span></li>';
        }
        html += '<li><a href="#" onclick="loadLogs(' + totalPages + ')">' + totalPages + '</a></li>';
    }
    
    // Next button
    if (currentPage < totalPages) {
        html += '<li><a href="#" onclick="loadLogs(' + (currentPage + 1) + ')" title="Next page">&raquo;</a></li>';
    } else {
        html += '<li class="disabled"><span>&raquo;</span></li>';
    }
    
    html += '</ul></nav>';
    return html;
}

function getSeverityClass(severity) {
    if (!severity) return 'default';
    
    switch(severity.toLowerCase()) {
        case 'critical':
            return 'danger';
        case 'error':
            return 'danger';
        case 'warning':
            return 'warning';
        case 'info':
            return 'info';
        case 'debug':
            return 'default';
        default:
            return 'default';
    }
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    
    try {
        var date = new Date(timestamp);
        if (isNaN(date.getTime())) {
            // Try parsing as unix timestamp
            date = new Date(parseInt(timestamp) * 1000);
        }
        
        if (!isNaN(date.getTime())) {
            return date.toLocaleString('en-GB', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
    } catch (e) {
        console.warn('Invalid timestamp:', timestamp);
    }
    
    return timestamp;
}

function truncateMessage(message, maxLength) {
    if (!message || message.length <= maxLength) {
        return message || 'No message';
    }
    return message.substring(0, maxLength - 3) + '...';
}

function clearLogs() {
    if (!confirm('{{ lang._("Are you sure you want to clear all logs? This action cannot be undone.") }}')) {
        return;
    }
    
    var clearBtn = $('button[onclick="clearLogs()"]');
    var originalText = clearBtn.html();
    clearBtn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Clearing...');
    
    ajaxCall('/api/siemlogger/service/clearLogs', {}, function(data, status) {
        clearBtn.prop('disabled', false).html(originalText);
        
        if (status === "success" && data && data.status === 'ok') {
            showNotification('{{ lang._("Logs cleared successfully") }}', 'success');
            loadLogs(1);
        } else {
            showNotification('{{ lang._("Failed to clear logs") }}: ' + (data.message || 'Unknown error'), 'error');
        }
    }, function(xhr, status, error) {
        clearBtn.prop('disabled', false).html(originalText);
        showNotification('{{ lang._("Network error occurred") }}: ' + error, 'error');
    });
}

function refreshLogs() {
    loadLogs(window.currentPage);
}

function exportLogs() {
    var exportBtn = $('button[onclick="exportLogs()"]');
    var originalText = exportBtn.html();
    exportBtn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Exporting...');
    
    // Use AJAX instead of direct window.location to handle the response properly
    ajaxCall('/api/siemlogger/service/exportLogs', {'format': 'json'}, function(data, status) {
        exportBtn.prop('disabled', false).html(originalText);
        
        if (status === "success" && data && data.status === 'ok') {
            if (data.export_file) {
                // If server returns a file path, try to download it
                var downloadUrl = '/api/siemlogger/service/downloadExport?file=' + encodeURIComponent(data.export_file);
                window.open(downloadUrl, '_blank');
                showNotification('Export completed successfully', 'success');
            } else if (data.data) {
                // If server returns data directly, create a download
                downloadJson(data.data, 'siemlogger_export_' + new Date().toISOString().slice(0,10) + '.json');
                showNotification('Export completed successfully', 'success');
            } else {
                showNotification('Export completed but no download link provided', 'warning');
            }
        } else {
            showNotification('Export failed: ' + (data.message || 'Unknown error'), 'error');
        }
    }, function(xhr, status, error) {
        exportBtn.prop('disabled', false).html(originalText);
        
        // Try to parse response as JSON for direct download
        try {
            var response = JSON.parse(xhr.responseText);
            if (response && (response.logs || response.data)) {
                downloadJson(response, 'siemlogger_export_' + new Date().toISOString().slice(0,10) + '.json');
                showNotification('Export completed successfully', 'success');
                return;
            }
        } catch (e) {
            // Not JSON, handle as error
        }
        
        showNotification('Export failed: ' + error, 'error');
    });
}

function downloadJson(data, filename) {
    var jsonStr = JSON.stringify(data, null, 2);
    var blob = new Blob([jsonStr], {type: 'application/json'});
    var url = window.URL.createObjectURL(blob);
    
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

function showNotification(message, type) {
    var alertClass = type === 'success' ? 'alert-success' : (type === 'warning' ? 'alert-warning' : 'alert-danger');
    var iconClass = type === 'success' ? 'fa-check-circle' : (type === 'warning' ? 'fa-exclamation-triangle' : 'fa-times-circle');
    
    var notification = $('<div class="alert ' + alertClass + ' alert-dismissible fade in" role="alert" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;">' +
        '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
        '<i class="fa ' + iconClass + '"></i> ' + message +
        '</div>');
    
    $('body').append(notification);
    
    setTimeout(function() {
        notification.alert('close');
    }, 5000);
}

// Enhanced AJAX helper
function ajaxCall(url, data, successCallback, errorCallback) {
    var isPost = data && Object.keys(data).length > 0;
    
    $.ajax({
        url: url,
        method: isPost ? 'POST' : 'GET',
        data: data || {},
        dataType: 'json',
        timeout: 30000, // 30 second timeout
        success: function(response) {
            if (successCallback) {
                successCallback(response, "success");
            }
        },
        error: function(xhr, status, error) {
            console.error('AJAX Error for ' + url + ':', {
                status: xhr.status,
                statusText: xhr.statusText,
                error: error,
                responseText: xhr.responseText
            });
            
            if (errorCallback) {
                errorCallback(xhr, status, error);
            }
        }
    });
}
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    {% if error is defined %}
    <div class="alert alert-danger alert-dismissible" role="alert">
        <button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span></button>
        <strong>Error:</strong> {{ error }}
    </div>
    {% endif %}

    <!-- Header with controls -->
    <div class="row" style="margin-bottom: 20px;">
        <div class="col-md-8">
            <h3 style="margin-top: 0;">
                <i class="fa fa-list-alt"></i> {{ lang._('SIEM Logger - Event Logs') }}
            </h3>
            <p class="text-muted">{{ lang._('View and manage security event logs from your SIEM Logger') }}</p>
        </div>
        <div class="col-md-4">
            <div class="pull-right">
                <div class="btn-group" role="group">
                    <button class="btn btn-default" onclick="refreshLogs()" title="{{ lang._('Refresh logs') }}">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
                    <button class="btn btn-info" onclick="exportLogs()" title="{{ lang._('Export logs to JSON') }}">
                        <i class="fa fa-download"></i> {{ lang._('Export') }}
                    </button>
                    <button class="btn btn-warning" onclick="clearLogs()" title="{{ lang._('Clear all logs') }}">
                        <i class="fa fa-trash"></i> {{ lang._('Clear All') }}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Filters row (for future enhancement) -->
    <div class="row" style="margin-bottom: 15px;">
        <div class="col-md-12">
            <div class="well well-sm">
                <div class="row">
                    <div class="col-md-3">
                        <label class="control-label">{{ lang._('Severity Filter') }}</label>
                        <select class="form-control input-sm" id="severityFilter" onchange="filterLogs()">
                            <option value="">{{ lang._('All Severities') }}</option>
                            <option value="critical">{{ lang._('Critical') }}</option>
                            <option value="error">{{ lang._('Error') }}</option>
                            <option value="warning">{{ lang._('Warning') }}</option>
                            <option value="info">{{ lang._('Info') }}</option>
                            <option value="debug">{{ lang._('Debug') }}</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="control-label">{{ lang._('Event Type') }}</label>
                        <select class="form-control input-sm" id="eventTypeFilter" onchange="filterLogs()">
                            <option value="">{{ lang._('All Event Types') }}</option>
                            <option value="authentication">{{ lang._('Authentication') }}</option>
                            <option value="configuration">{{ lang._('Configuration') }}</option>
                            <option value="network">{{ lang._('Network') }}</option>
                            <option value="firewall">{{ lang._('Firewall') }}</option>
                            <option value="system">{{ lang._('System') }}</option>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label class="control-label">{{ lang._('Search') }}</label>
                        <input type="text" class="form-control input-sm" id="searchFilter" placeholder="{{ lang._('Search in messages...') }}" onkeyup="if(event.keyCode==13) filterLogs()">
                    </div>
                    <div class="col-md-2">
                        <label class="control-label">&nbsp;</label>
                        <div>
                            <button class="btn btn-primary btn-sm btn-block" onclick="filterLogs()">
                                <i class="fa fa-search"></i> {{ lang._('Filter') }}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Main content area -->
    <div class="row">
        <div class="col-md-12">
            <div id="logsContent">
                <div class="text-center" style="padding: 40px;">
                    <i class="fa fa-spinner fa-pulse fa-2x text-primary"></i><br><br>
                    Loading logs...
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// Additional filter functionality
function filterLogs() {
    var severity = $('#severityFilter').val();
    var eventType = $('#eventTypeFilter').val();
    var search = $('#searchFilter').val();
    
    window.currentPage = 1; // Reset to first page when filtering
    
    ajaxCall('/api/siemlogger/service/getLogs', {
        'page': 1,
        'limit': window.logsLimit,
        'severity': severity,
        'event_type': eventType,
        'search': search
    }, function(data, status) {
        if (status === "success" && data && data.status === 'ok') {
            if (data.data && data.data.logs) {
                displayLogs(data.data.logs, data.data.total || data.data.logs.length, 1);
            } else {
                $("#logsContent").html('<div class="alert alert-info"><i class="fa fa-filter"></i> No logs match the current filters</div>');
            }
        } else {
            $("#logsContent").html('<div class="alert alert-danger"><i class="fa fa-exclamation-triangle"></i> Error applying filters</div>');
        }
    });
}
</script>