{#
# Copyright (C) 2025 OPNsense SIEM Logger Plugin
# All rights reserved.
#}

<script>
$(document).ready(function() {
    // Initialize dashboard
    initDashboard();
    
    // Set refresh interval (every 30 seconds)
    setInterval(refreshDashboard, 30000);
});

function initDashboard() {
    refreshServiceStatus();
    loadRecentEvents();
    loadSystemStats();
}

function refreshDashboard() {
    refreshServiceStatus();
    loadRecentEvents();
    loadSystemStats();
}

function refreshServiceStatus() {
    ajaxCall('/api/siemlogger/service/status', {}, function(data, status) {
        if (status === "success" && data) {
            var statusHtml = '';
            var statusClass = data.running ? 'label-success' : 'label-danger';
            var statusText = data.running ? '{{ lang._("Running") }}' : '{{ lang._("Stopped") }}';
            
            $('#service_status').html('<span class="label ' + statusClass + '">' + statusText + '</span>');
            
            // Update last updated
            $('#last_updated').text(new Date().toLocaleString());
        }
    });
}

function loadRecentEvents() {
    ajaxCall('/api/siemlogger/service/getLogs', {'page': 1, 'limit': 10}, function(data, status) {
        if (status === "success" && data && data.status === 'ok' && data.data && data.data.logs) {
            updateRecentEventsTable(data.data.logs);
        } else {
            $('#recent_events_body').html('<tr><td colspan="5" class="text-center">No recent events</td></tr>');
        }
    });
}

function updateRecentEventsTable(logs) {
    var tbody = $('#recent_events_body');
    tbody.empty();
    
    if (logs.length === 0) {
        tbody.append('<tr><td colspan="5" class="text-center">No recent events</td></tr>');
        return;
    }
    
    $.each(logs, function(i, log) {
        var row = '<tr>' +
            '<td>' + (log.timestamp_iso || log.timestamp || 'N/A') + '</td>' +
            '<td>' + (log.source_ip || 'Unknown') + '</td>' +
            '<td>' + (log.event_type || 'Unknown') + '</td>' +
            '<td><span class="label label-' + getSeverityClass(log.severity) + '">' + 
                (log.severity || 'info') + '</span></td>' +
            '<td>' + truncateMessage(log.message || 'No message', 50) + '</td>' +
            '</tr>';
        tbody.append(row);
    });
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

function truncateMessage(message, maxLength) {
    if (message.length <= maxLength) {
        return message;
    }
    return message.substring(0, maxLength) + '...';
}

function loadSystemStats() {
    ajaxCall('/api/siemlogger/settings/stats', {}, function(data, status) {
        if (status === "success" && data && data.status === 'ok' && data.data) {
            updateSystemStats(data.data);
        }
    });
}

function updateSystemStats(stats) {
    if (stats.total_events !== undefined) {
        $('#total_events').text(stats.total_events);
    }
    if (stats.events_today !== undefined) {
        $('#events_today').text(stats.events_today);
    }
    if (stats.export_errors !== undefined) {
        $('#export_errors').text(stats.export_errors);
    }
    if (stats.disk_usage !== undefined) {
        $('#disk_usage').text(stats.disk_usage + '%');
        
        var progressClass = 'progress-bar-info';
        if (stats.disk_usage > 80) {
            progressClass = 'progress-bar-danger';
        } else if (stats.disk_usage > 60) {
            progressClass = 'progress-bar-warning';
        }
        
        $('#disk_usage_bar').removeClass('progress-bar-info progress-bar-warning progress-bar-danger')
            .addClass(progressClass)
            .css('width', stats.disk_usage + '%');
    }
}

function toggleService() {
    ajaxCall('/api/siemlogger/service/status', {}, function(data, status) {
        if (status === "success" && data) {
            var action = data.running ? 'stop' : 'start';
            ajaxCall('/api/siemlogger/service/' + action, {}, function(result, status) {
                if (status === "success") {
                    setTimeout(refreshServiceStatus, 1000);
                }
            });
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

    <div class="row">
        <!-- Service Status Panel -->
        <div class="col-md-4">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">{{ lang._('Service Status') }}</h3>
                </div>
                <div class="panel-body">
                    <table class="table table-condensed">
                        <tr>
                            <td><strong>{{ lang._('Status') }}</strong></td>
                            <td id="service_status">
                                <span class="label label-default">{{ lang._('Unknown') }}</span>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Enabled') }}</strong></td>
                            <td>
                                {% if isEnabled %}
                                    <span class="label label-success">{{ lang._('Yes') }}</span>
                                {% else %}
                                    <span class="label label-danger">{{ lang._('No') }}</span>
                                {% endif %}
                            </td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Log Level') }}</strong></td>
                            <td><span class="label label-info">{{ logLevel }}</span></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('SIEM Export') }}</strong></td>
                            <td>
                                {% if exportEnabled %}
                                    <span class="label label-success">{{ lang._('Enabled') }}</span>
                                {% else %}
                                    <span class="label label-default">{{ lang._('Disabled') }}</span>
                                {% endif %}
                            </td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Audit Logging') }}</strong></td>
                            <td>
                                {% if auditEnabled %}
                                    <span class="label label-success">{{ lang._('Enabled') }}</span>
                                {% else %}
                                    <span class="label label-default">{{ lang._('Disabled') }}</span>
                                {% endif %}
                            </td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Last Updated') }}</strong></td>
                            <td><small id="last_updated">{{ 'now'|date('Y-m-d H:i:s') }}</small></td>
                        </tr>
                    </table>
                    <div class="text-center">
                        <button class="btn btn-primary btn-sm" onclick="toggleService()">
                            <i class="fa fa-power-off"></i> {{ lang._('Toggle Service') }}
                        </button>
                        <button class="btn btn-default btn-sm" onclick="refreshDashboard()">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- System Statistics Panel -->
        <div class="col-md-4">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">{{ lang._('System Statistics') }}</h3>
                </div>
                <div class="panel-body">
                    <table class="table table-condensed">
                        <tr>
                            <td><strong>{{ lang._('Total Events') }}</strong></td>
                            <td><span id="total_events" class="badge">0</span></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Events Today') }}</strong></td>
                            <td><span id="events_today" class="badge">0</span></td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Export Errors') }}</strong></td>
                            <td><span id="export_errors" class="badge">0</span></td>
                        </tr>
                        <tr>
                            <td colspan="2">
                                <strong>{{ lang._('Disk Usage') }}</strong>
                                <div class="progress" style="margin-top: 5px; margin-bottom: 0;">
                                    <div id="disk_usage_bar" class="progress-bar progress-bar-info" 
                                         role="progressbar" style="width: 0%">
                                        <span id="disk_usage">0%</span>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Quick Actions Panel -->
        <div class="col-md-4">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">{{ lang._('Quick Actions') }}</h3>
                </div>
                <div class="panel-body">
                    <div class="btn-group-vertical btn-block" role="group">
                        <a href="/ui/siemlogger/index" class="btn btn-default">
                            <i class="fa fa-cog"></i> {{ lang._('Settings') }}
                        </a>
                        <a href="/ui/siemlogger/logging" class="btn btn-default">
                            <i class="fa fa-list"></i> {{ lang._('View Logs') }}
                        </a>
                        <button class="btn btn-warning" onclick="clearAllLogs()">
                            <i class="fa fa-trash"></i> {{ lang._('Clear All Logs') }}
                        </button>
                        <button class="btn btn-info" onclick="exportLogs()">
                            <i class="fa fa-download"></i> {{ lang._('Export Logs') }}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Events Panel -->
    <div class="row">
        <div class="col-md-12">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">{{ lang._('Recent Events') }}</h3>
                </div>
                <div class="panel-body">
                    <div class="table-responsive">
                        <table class="table table-condensed table-hover table-striped">
                            <thead>
                                <tr>
                                    <th>{{ lang._('Timestamp') }}</th>
                                    <th>{{ lang._('Source IP') }}</th>
                                    <th>{{ lang._('Event Type') }}</th>
                                    <th>{{ lang._('Severity') }}</th>
                                    <th>{{ lang._('Message') }}</th>
                                </tr>
                            </thead>
                            <tbody id="recent_events_body">
                                <tr>
                                    <td colspan="5" class="text-center">
                                        <i class="fa fa-spinner fa-pulse"></i> Loading...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="text-right">
                        <a href="/ui/siemlogger/logging" class="btn btn-sm btn-primary">
                            {{ lang._('View All Logs') }} <i class="fa fa-arrow-right"></i>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function clearAllLogs() {
    if (confirm('{{ lang._("Are you sure you want to clear all logs? This action cannot be undone.") }}')) {
        ajaxCall('/api/siemlogger/service/clearLogs', {}, function(data, status) {
            if (status === "success" && data && data.status === 'ok') {
                alert('{{ lang._("All logs have been cleared successfully.") }}');
                loadRecentEvents();
                loadSystemStats();
            } else {
                alert('{{ lang._("Failed to clear logs.") }}');
            }
        });
    }
}

function exportLogs() {
    // Download logs as JSON
    window.location.href = '/api/siemlogger/service/exportLogs?format=json';
}
</script>