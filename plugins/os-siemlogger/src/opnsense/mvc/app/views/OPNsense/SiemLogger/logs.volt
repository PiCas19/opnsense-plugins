{#
# Copyright (C) 2025 OPNsense SIEM Logger Plugin
# All rights reserved.
#}

<script>
$(document).ready(function() {
    // Initialize the page
    initLogsPage();
});

var currentPage = 1;
var limit = 100;

function initLogsPage() {
    loadLogs(currentPage);
}

function loadLogs(page) {
    $("#responseMsg").removeClass("hidden");
    $("#responseMsg").html('<div class="alert alert-info">' + 
        '<i class="fa fa-spinner fa-pulse"></i> Loading logs...' + 
        '</div>');
    
    ajaxCall('/api/siemlogger/service/getLogs', {
        'page': page || 1,
        'limit': limit
    }, function(data, status) {
        $("#responseMsg").addClass("hidden");
        
        if (status === "success" && data && data.status === 'ok') {
            if (data.data && data.data.logs) {
                updateLogsTable(data.data.logs);
                updatePagination(data.data.total, page);
            } else {
                $('#logsTableBody').html('<tr><td colspan="5">No logs found</td></tr>');
            }
        } else {
            $("#responseMsg").removeClass("hidden");
            $("#responseMsg").html('<div class="alert alert-danger">' + 
                'Error loading logs: ' + (data.message || 'Unknown error') + 
                '</div>');
        }
    });
}

function updateLogsTable(logs) {
    var tbody = $('#logsTableBody');
    tbody.empty();
    
    if (logs.length === 0) {
        tbody.append('<tr><td colspan="5" class="text-center">No logs available</td></tr>');
        return;
    }
    
    $.each(logs, function(i, log) {
        var row = '<tr>' +
            '<td>' + (log.timestamp_iso || log.timestamp || 'N/A') + '</td>' +
            '<td>' + (log.source_ip || 'Unknown') + '</td>' +
            '<td>' + (log.event_type || 'Unknown') + '</td>' +
            '<td><span class="label label-' + getSeverityClass(log.severity) + '">' + 
                (log.severity || 'info') + '</span></td>' +
            '<td>' + (log.message || 'No message') + '</td>' +
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

function updatePagination(total, currentPage) {
    var totalPages = Math.ceil(total / limit);
    var pagination = $('#pagination');
    pagination.empty();
    
    if (totalPages <= 1) {
        return;
    }
    
    // Previous button
    if (currentPage > 1) {
        pagination.append('<li><a href="#" onclick="loadLogs(' + (currentPage - 1) + 
            ')">&laquo; Previous</a></li>');
    }
    
    // Page numbers
    for (var i = 1; i <= totalPages; i++) {
        var activeClass = (i === currentPage) ? ' class="active"' : '';
        pagination.append('<li' + activeClass + '><a href="#" onclick="loadLogs(' + i + 
            ')">' + i + '</a></li>');
    }
    
    // Next button
    if (currentPage < totalPages) {
        pagination.append('<li><a href="#" onclick="loadLogs(' + (currentPage + 1) + 
            ')">Next &raquo;</a></li>');
    }
}

function clearLogs() {
    if (!confirm('{{ lang._("Are you sure you want to clear all logs?") }}')) {
        return;
    }
    
    $("#responseMsg").removeClass("hidden");
    $("#responseMsg").html('<div class="alert alert-info">' + 
        '<i class="fa fa-spinner fa-pulse"></i> Clearing logs...' + 
        '</div>');
    
    ajaxCall('/api/siemlogger/service/clearLogs', {}, function(data, status) {
        if (status === "success" && data && data.status === 'ok') {
            $("#responseMsg").html('<div class="alert alert-success">' + 
                'Logs cleared successfully' + 
                '</div>');
            setTimeout(function() {
                $("#responseMsg").addClass("hidden");
                loadLogs(1);
            }, 2000);
        } else {
            $("#responseMsg").html('<div class="alert alert-danger">' + 
                'Failed to clear logs: ' + (data.message || 'Unknown error') + 
                '</div>');
        }
    });
}

function refreshLogs() {
    loadLogs(currentPage);
}
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    {% if error is defined %}
    <div class="alert alert-danger alert-dismissible" role="alert">
        <button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span></button>
        <strong>Error:</strong> {{ error }}
    </div>
    {% endif %}

    <div id="responseMsg" class="alert alert-info hidden" role="alert"></div>

    <div class="tab-content content-box col-xs-12 col-lg-6">
        <div class="table-responsive">
            <div class="col-xs-12">
                <div class="pull-right">
                    <button class="btn btn-default" onclick="refreshLogs()" title="{{ lang._('Refresh logs') }}">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
                    <button class="btn btn-warning" onclick="clearLogs()" title="{{ lang._('Clear all logs') }}">
                        <i class="fa fa-trash"></i> {{ lang._('Clear Logs') }}
                    </button>
                </div>
            </div>
            <div class="col-xs-12">
                <hr/>
            </div>
            <table class="table table-condensed table-hover table-striped table-responsive">
                <thead>
                    <tr>
                        <th>{{ lang._('Timestamp') }}</th>
                        <th>{{ lang._('Source IP') }}</th>
                        <th>{{ lang._('Event Type') }}</th>
                        <th>{{ lang._('Severity') }}</th>
                        <th>{{ lang._('Message') }}</th>
                    </tr>
                </thead>
                <tbody id="logsTableBody">
                    <tr>
                        <td colspan="5" class="text-center">
                            <i class="fa fa-spinner fa-pulse"></i> Loading...
                        </td>
                    </tr>
                </tbody>
            </table>
            <nav>
                <ul class="pagination" id="pagination"></ul>
            </nav>
        </div>
    </div>
</div>