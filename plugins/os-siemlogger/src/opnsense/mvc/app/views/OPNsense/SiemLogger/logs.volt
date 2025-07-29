{#
 # Copyright (C) 2025 OPNsense SIEM Logger Plugin
 # All rights reserved.
 #}

<script>
$(document).ready(function() {
    var currentPage = 1;
    var limit = 50;
    
    // Load logs on page load
    loadLogs(currentPage);
    
    // Refresh every 30 seconds
    setInterval(function() {
        loadLogs(currentPage);
    }, 30000);
});

function loadLogs(page) {
    $("#logsContent").html('<div class="text-center"><i class="fa fa-spinner fa-pulse fa-2x"></i><br>Loading logs...</div>');
    
    ajaxCall('/api/siemlogger/service/getLogs', {
        'page': page || 1,
        'limit': limit
    }, function(data, status) {
        if (status === "success" && data && data.status === 'ok') {
            if (data.data && data.data.logs) {
                displayLogs(data.data.logs, data.data.total, page);
            } else {
                $("#logsContent").html('<div class="alert alert-info">No logs found</div>');
            }
        } else {
            $("#logsContent").html('<div class="alert alert-danger">Error loading logs: ' + 
                (data.message || 'Unknown error') + '</div>');
        }
    });
}

function displayLogs(logs, total, page) {
    var html = '<div class="table-responsive">';
    html += '<table class="table table-striped table-condensed">';
    html += '<thead><tr>';
    html += '<th>Timestamp</th>';
    html += '<th>Source IP</th>';
    html += '<th>Event Type</th>';
    html += '<th>Severity</th>';
    html += '<th>Message</th>';
    html += '</tr></thead>';
    html += '<tbody>';
    
    if (logs.length === 0) {
        html += '<tr><td colspan="5" class="text-center">No logs available</td></tr>';
    } else {
        $.each(logs, function(i, log) {
            var severityClass = getSeverityClass(log.severity);
            html += '<tr>';
            html += '<td>' + (log.timestamp_iso || log.timestamp || 'N/A') + '</td>';
            html += '<td>' + (log.source_ip || 'Unknown') + '</td>';
            html += '<td>' + (log.event_type || 'Unknown') + '</td>';
            html += '<td><span class="label label-' + severityClass + '">' + (log.severity || 'info') + '</span></td>';
            html += '<td>' + (log.message || 'No message') + '</td>';
            html += '</tr>';
        });
    }
    
    html += '</tbody></table></div>';
    
    // Add pagination
    if (total > limit) {
        var totalPages = Math.ceil(total / limit);
        html += '<nav><ul class="pagination">';
        
        // Previous button
        if (page > 1) {
            html += '<li><a href="#" onclick="loadLogs(' + (page - 1) + ')">&laquo; Previous</a></li>';
        }
        
        // Page numbers (show max 10 pages)
        var startPage = Math.max(1, page - 5);
        var endPage = Math.min(totalPages, startPage + 9);
        
        for (var i = startPage; i <= endPage; i++) {
            var activeClass = (i === page) ? ' class="active"' : '';
            html += '<li' + activeClass + '><a href="#" onclick="loadLogs(' + i + ')">' + i + '</a></li>';
        }
        
        // Next button
        if (page < totalPages) {
            html += '<li><a href="#" onclick="loadLogs(' + (page + 1) + ')">Next &raquo;</a></li>';
        }
        
        html += '</ul></nav>';
    }
    
    $("#logsContent").html(html);
    currentPage = page;
}

function getSeverityClass(severity) {
    switch(severity) {
        case 'critical':
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

function clearLogs() {
    if (!confirm('{{ lang._("Are you sure you want to clear all logs?") }}')) {
        return;
    }
    
    ajaxCall('/api/siemlogger/service/clearLogs', {}, function(data, status) {
        if (status === "success" && data && data.status === 'ok') {
            alert('{{ lang._("Logs cleared successfully") }}');
            loadLogs(1);
        } else {
            alert('{{ lang._("Failed to clear logs") }}: ' + (data.message || 'Unknown error'));
        }
    });
}

function refreshLogs() {
    loadLogs(currentPage);
}

function exportLogs() {
    window.location.href = '/api/siemlogger/service/exportLogs?format=json';
}
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    {% if error is defined %}
    <div class="alert alert-danger alert-dismissible" role="alert">
        <button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span></button>
        <strong>Error:</strong> {{ error }}
    </div>
    {% endif %}

    <div class="row">
        <div class="col-md-12">
            <div class="pull-right" style="margin-bottom: 10px;">
                <button class="btn btn-default" onclick="refreshLogs()" title="{{ lang._('Refresh logs') }}">
                    <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                </button>
                <button class="btn btn-info" onclick="exportLogs()" title="{{ lang._('Export logs') }}">
                    <i class="fa fa-download"></i> {{ lang._('Export') }}
                </button>
                <button class="btn btn-warning" onclick="clearLogs()" title="{{ lang._('Clear all logs') }}">
                    <i class="fa fa-trash"></i> {{ lang._('Clear Logs') }}
                </button>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-12">
            <div id="logsContent">
                <div class="text-center">
                    <i class="fa fa-spinner fa-pulse fa-2x"></i><br>
                    Loading logs...
                </div>
            </div>
        </div>
    </div>
</div>