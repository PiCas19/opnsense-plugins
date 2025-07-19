{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="content-box-main">
        <div class="table-responsive">
            <div class="col-sm-12">
                <div class="pull-right">
                    <small>{{ lang._('full help') }}&nbsp;</small>
                    <a href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
                </div>
            </div>

            <!-- Threat Overview Cards -->
            <div class="row">
                <div class="col-md-3">
                    <div class="info-box">
                        <span class="info-box-icon bg-red"><i class="fa fa-exclamation-triangle"></i></span>
                        <div class="info-box-content">
                            <span class="info-box-text">{{ lang._('Total Threats') }}</span>
                            <span class="info-box-number" id="total-threats">--</span>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="info-box">
                        <span class="info-box-icon bg-yellow"><i class="fa fa-clock"></i></span>
                        <div class="info-box-content">
                            <span class="info-box-text">{{ lang._('Last 24 Hours') }}</span>
                            <span class="info-box-number" id="threats-24h">--</span>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="info-box">
                        <span class="info-box-icon bg-blue"><i class="fa fa-shield"></i></span>
                        <div class="info-box-content">
                            <span class="info-box-text">{{ lang._('Blocked Today') }}</span>
                            <span class="info-box-number" id="blocked-today">--</span>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="info-box">
                        <span class="info-box-icon bg-green"><i class="fa fa-check-circle"></i></span>
                        <div class="info-box-content">
                            <span class="info-box-text">{{ lang._('Detection Rate') }}</span>
                            <span class="info-box-number" id="detection-rate">--</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Filters and Controls -->
            <div class="row">
                <div class="col-md-12">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-filter"></i> {{ lang._('Threat Filters') }}
                                <div class="pull-right">
                                    <button class="btn btn-xs btn-primary" id="refreshThreats">
                                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                    </button>
                                    <button class="btn btn-xs btn-success" id="exportThreats">
                                        <i class="fa fa-download"></i> {{ lang._('Export') }}
                                    </button>
                                    <button class="btn btn-xs btn-warning" id="clearOldThreats">
                                        <i class="fa fa-trash"></i> {{ lang._('Clear Old') }}
                                    </button>
                                </div>
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="row">
                                <div class="col-md-2">
                                    <select class="form-control" id="severityFilter">
                                        <option value="">{{ lang._('All Severities') }}</option>
                                        <option value="critical">{{ lang._('Critical') }}</option>
                                        <option value="high">{{ lang._('High') }}</option>
                                        <option value="medium">{{ lang._('Medium') }}</option>
                                        <option value="low">{{ lang._('Low') }}</option>
                                    </select>
                                </div>
                                <div class="col-md-2">
                                    <select class="form-control" id="typeFilter">
                                        <option value="">{{ lang._('All Types') }}</option>
                                        <option value="sql_injection">{{ lang._('SQL Injection') }}</option>
                                        <option value="xss">{{ lang._('XSS') }}</option>
                                        <option value="csrf">{{ lang._('CSRF') }}</option>
                                        <option value="file_upload">{{ lang._('File Upload') }}</option>
                                        <option value="behavioral">{{ lang._('Behavioral') }}</option>
                                        <option value="covert_channel">{{ lang._('Covert Channel') }}</option>
                                    </select>
                                </div>
                                <div class="col-md-2">
                                    <input type="text" class="form-control" id="sourceIpFilter" placeholder="{{ lang._('Source IP') }}">
                                </div>
                                <div class="col-md-2">
                                    <input type="date" class="form-control" id="startDateFilter">
                                </div>
                                <div class="col-md-2">
                                    <input type="date" class="form-control" id="endDateFilter">
                                </div>
                                <div class="col-md-2">
                                    <button class="btn btn-primary btn-block" id="applyFilters">
                                        <i class="fa fa-search"></i> {{ lang._('Apply') }}
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Threats Table -->
            <div class="row">
                <div class="col-md-12">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-list"></i> {{ lang._('Threat Log') }}
                                <span class="badge" id="threatCount">0</span>
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover" id="threatsTable">
                                    <thead>
                                        <tr>
                                            <th>{{ lang._('Time') }}</th>
                                            <th>{{ lang._('Source IP') }}</th>
                                            <th>{{ lang._('Type') }}</th>
                                            <th>{{ lang._('Severity') }}</th>
                                            <th>{{ lang._('Target') }}</th>
                                            <th>{{ lang._('Method') }}</th>
                                            <th>{{ lang._('Status') }}</th>
                                            <th>{{ lang._('Actions') }}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Populated by JavaScript -->
                                    </tbody>
                                </table>
                            </div>
                            
                            <!-- Pagination -->
                            <div class="row">
                                <div class="col-md-6">
                                    <div id="threatsPagination"></div>
                                </div>
                                <div class="col-md-6">
                                    <div class="pull-right">
                                        <select class="form-control" id="pageSize" style="width: auto; display: inline-block;">
                                            <option value="25">25 {{ lang._('per page') }}</option>
                                            <option value="50" selected>50 {{ lang._('per page') }}</option>
                                            <option value="100">100 {{ lang._('per page') }}</option>
                                            <option value="200">200 {{ lang._('per page') }}</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Threat Detail Modal -->
<div class="modal fade" id="threatDetailModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Threat Details') }}</h4>
            </div>
            <div class="modal-body" id="threatDetailContent">
                <!-- Populated by JavaScript -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
                <button type="button" class="btn btn-warning" id="markFalsePositive">
                    <i class="fa fa-times"></i> {{ lang._('Mark False Positive') }}
                </button>
                <button type="button" class="btn btn-success" id="whitelistIp">
                    <i class="fa fa-check"></i> {{ lang._('Whitelist IP') }}
                </button>
                <button type="button" class="btn btn-danger" id="blockIp">
                    <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Export Modal -->
<div class="modal fade" id="exportModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Export Threats') }}</h4>
            </div>
            <div class="modal-body">
                <form id="exportForm">
                    <div class="form-group">
                        <label for="exportFormat">{{ lang._('Format') }}</label>
                        <select class="form-control" id="exportFormat">
                            <option value="json">JSON</option>
                            <option value="csv">CSV</option>
                            <option value="xml">XML</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="exportStartDate">{{ lang._('Start Date') }}</label>
                        <input type="date" class="form-control" id="exportStartDate">
                    </div>
                    <div class="form-group">
                        <label for="exportEndDate">{{ lang._('End Date') }}</label>
                        <input type="date" class="form-control" id="exportEndDate">
                    </div>
                    <div class="form-group">
                        <label for="exportSeverity">{{ lang._('Severity') }}</label>
                        <select class="form-control" id="exportSeverity">
                            <option value="">{{ lang._('All') }}</option>
                            <option value="critical">{{ lang._('Critical') }}</option>
                            <option value="high">{{ lang._('High') }}</option>
                            <option value="medium">{{ lang._('Medium') }}</option>
                            <option value="low">{{ lang._('Low') }}</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="exportType">{{ lang._('Type') }}</label>
                        <select class="form-control" id="exportType">
                            <option value="">{{ lang._('All') }}</option>
                            <option value="sql_injection">{{ lang._('SQL Injection') }}</option>
                            <option value="xss">{{ lang._('XSS') }}</option>
                            <option value="csrf">{{ lang._('CSRF') }}</option>
                            <option value="file_upload">{{ lang._('File Upload') }}</option>
                            <option value="behavioral">{{ lang._('Behavioral') }}</option>
                            <option value="covert_channel">{{ lang._('Covert Channel') }}</option>
                        </select>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-primary" id="downloadExport">
                    <i class="fa fa-download"></i> {{ lang._('Export') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Clear Old Threats Modal -->
<div class="modal fade" id="clearOldModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Clear Old Threats') }}</h4>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="daysOld">{{ lang._('Delete threats older than (days)') }}</label>
                    <input type="number" class="form-control" id="daysOld" value="30" min="1" max="365">
                </div>
                <div class="checkbox">
                    <label>
                        <input type="checkbox" id="keepCritical" checked>
                        {{ lang._('Keep critical threats regardless of age') }}
                    </label>
                </div>
                <div class="alert alert-warning">
                    <i class="fa fa-warning"></i>
                    {{ lang._('This action cannot be undone. Please make sure you have exported any important data first.') }}
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-danger" id="confirmClearOld">
                    <i class="fa fa-trash"></i> {{ lang._('Clear Old Threats') }}
                </button>
            </div>
        </div>
    </div>
</div>

<style>
.info-box {
    display: block;
    min-height: 90px;
    background: #fff;
    width: 100%;
    box-shadow: 0 1px 1px rgba(0,0,0,0.1);
    border-radius: 2px;
    margin-bottom: 15px;
}

.info-box-icon {
    border-top-left-radius: 2px;
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
    border-bottom-left-radius: 2px;
    display: block;
    float: left;
    height: 90px;
    width: 90px;
    text-align: center;
    font-size: 45px;
    line-height: 90px;
    background: rgba(0,0,0,0.2);
}

.info-box-content {
    padding: 5px 10px;
    margin-left: 90px;
}

.info-box-text {
    text-transform: uppercase;
    font-weight: bold;
    font-size: 13px;
}

.info-box-number {
    display: block;
    font-weight: bold;
    font-size: 18px;
}

.bg-blue { background-color: #3c8dbc !important; }
.bg-green { background-color: #00a65a !important; }
.bg-yellow { background-color: #f39c12 !important; }
.bg-red { background-color: #dd4b39 !important; }

.severity-critical { color: #d9534f; font-weight: bold; }
.severity-high { color: #f0ad4e; font-weight: bold; }
.severity-medium { color: #5bc0de; }
.severity-low { color: #5cb85c; }

.status-blocked { color: #d9534f; }
.status-allowed { color: #5cb85c; }
.status-logged { color: #5bc0de; }

.threat-detail-section {
    margin-bottom: 20px;
}

.threat-detail-section h5 {
    border-bottom: 1px solid #ddd;
    padding-bottom: 5px;
    margin-bottom: 10px;
}

.table > tbody > tr > td {
    vertical-align: middle;
}
</style>

<script>
$(document).ready(function() {
    let currentPage = 1;
    let pageSize = 50;
    let currentThreatId = null;
    
    // Initialize
    loadThreatStats();
    loadThreats();
    
    // Auto-refresh every 30 seconds
    setInterval(function() {
        loadThreatStats();
        loadThreats();
    }, 30000);
    
    // Filter controls
    $('#applyFilters').click(function() {
        currentPage = 1;
        loadThreats();
    });
    
    $('#pageSize').change(function() {
        pageSize = $(this).val();
        currentPage = 1;
        loadThreats();
    });
    
    // Action buttons
    $('#refreshThreats').click(function() {
        loadThreatStats();
        loadThreats();
    });
    
    $('#exportThreats').click(function() {
        $('#exportModal').modal('show');
    });
    
    $('#clearOldThreats').click(function() {
        $('#clearOldModal').modal('show');
    });
    
    // Export functionality
    $('#downloadExport').click(function() {
        let params = {
            format: $('#exportFormat').val(),
            start_date: $('#exportStartDate').val(),
            end_date: $('#exportEndDate').val(),
            severity: $('#exportSeverity').val(),
            type: $('#exportType').val()
        };
        
        $('#downloadExport').prop('disabled', true).text('{{ lang._("Exporting...") }}');
        
        ajaxGet('/api/webguard/threats/export', params, function(data) {
            if (data.result === 'ok') {
                let blob = new Blob([data.data], {type: 'application/octet-stream'});
                let url = window.URL.createObjectURL(blob);
                let a = document.createElement('a');
                a.href = url;
                a.download = data.filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                $('#exportModal').modal('hide');
            } else {
                BootstrapDialog.alert('{{ lang._("Export failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
            }
            
            $('#downloadExport').prop('disabled', false).text('{{ lang._("Export") }}');
        });
    });
    
    // Clear old threats
    $('#confirmClearOld').click(function() {
        let daysOld = $('#daysOld').val();
        let keepCritical = $('#keepCritical').is(':checked');
        
        if (!daysOld || daysOld < 1) {
            BootstrapDialog.alert('{{ lang._("Please specify a valid number of days.") }}');
            return;
        }
        
        $('#confirmClearOld').prop('disabled', true).text('{{ lang._("Clearing...") }}');
        
        ajaxCall('/api/webguard/threats/clearOld', {
            days_old: daysOld,
            keep_critical: keepCritical
        }, function(data) {
            if (data.result === 'ok') {
                $('#clearOldModal').modal('hide');
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("Threats Cleared") }}',
                    message: data.message || '{{ lang._("Old threats cleared successfully.") }}',
                    buttons: [{
                        label: '{{ lang._("Close") }}',
                        action: function(dialogRef) {
                            dialogRef.close();
                            loadThreatStats();
                            loadThreats();
                        }
                    }]
                });
            } else {
                BootstrapDialog.alert('{{ lang._("Clear failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
            }
            
            $('#confirmClearOld').prop('disabled', false).text('{{ lang._("Clear Old Threats") }}');
        });
    });
    
    // Threat detail modal actions
    $('#markFalsePositive').click(function() {
        if (!currentThreatId) return;
        
        BootstrapDialog.show({
            title: '{{ lang._("Mark False Positive") }}',
            message: '<textarea id="fpComment" placeholder="{{ lang._("Optional comment...") }}" class="form-control" rows="3"></textarea>',
            buttons: [{
                label: '{{ lang._("Cancel") }}',
                action: function(dialogRef) {
                    dialogRef.close();
                }
            }, {
                label: '{{ lang._("Mark False Positive") }}',
                cssClass: 'btn-warning',
                action: function(dialogRef) {
                    let comment = $('#fpComment').val();
                    
                    ajaxCall('/api/webguard/threats/markFalsePositive/' + currentThreatId, {
                        comment: comment
                    }, function(data) {
                        if (data.result === 'ok') {
                            dialogRef.close();
                            $('#threatDetailModal').modal('hide');
                            loadThreats();
                            BootstrapDialog.alert({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                message: data.message || '{{ lang._("Threat marked as false positive.") }}'
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                    });
                }
            }]
        });
    });
    
    $('#whitelistIp').click(function() {
        if (!currentThreatId) return;
        
        BootstrapDialog.show({
            title: '{{ lang._("Whitelist IP") }}',
            message: '<div class="form-group"><label><input type="checkbox" id="permanentWhitelist" checked> {{ lang._("Permanent whitelist entry") }}</label></div><textarea id="whitelistComment" placeholder="{{ lang._("Optional comment...") }}" class="form-control" rows="3"></textarea>',
            buttons: [{
                label: '{{ lang._("Cancel") }}',
                action: function(dialogRef) {
                    dialogRef.close();
                }
            }, {
                label: '{{ lang._("Add to Whitelist") }}',
                cssClass: 'btn-success',
                action: function(dialogRef) {
                    let permanent = $('#permanentWhitelist').is(':checked');
                    let comment = $('#whitelistComment').val();
                    
                    ajaxCall('/api/webguard/threats/whitelistIp/' + currentThreatId, {
                        permanent: permanent,
                        comment: comment
                    }, function(data) {
                        if (data.result === 'ok') {
                            dialogRef.close();
                            $('#threatDetailModal').modal('hide');
                            BootstrapDialog.alert({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                message: data.message || '{{ lang._("IP added to whitelist.") }}'
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                    });
                }
            }]
        });
    });
    
    $('#blockIp').click(function() {
        if (!currentThreatId) return;
        
        BootstrapDialog.show({
            title: '{{ lang._("Block IP") }}',
            message: '<div class="form-group"><label>{{ lang._("Block duration") }}</label><select id="blockDuration" class="form-control"><option value="3600">1 {{ lang._("hour") }}</option><option value="21600">6 {{ lang._("hours") }}</option><option value="86400">24 {{ lang._("hours") }}</option><option value="604800">7 {{ lang._("days") }}</option><option value="0">{{ lang._("Permanent") }}</option></select></div><textarea id="blockComment" placeholder="{{ lang._("Optional comment...") }}" class="form-control" rows="3"></textarea>',
            buttons: [{
                label: '{{ lang._("Cancel") }}',
                action: function(dialogRef) {
                    dialogRef.close();
                }
            }, {
                label: '{{ lang._("Block IP") }}',
                cssClass: 'btn-danger',
                action: function(dialogRef) {
                    let duration = $('#blockDuration').val();
                    let comment = $('#blockComment').val();
                    
                    ajaxCall('/api/webguard/threats/blockIp/' + currentThreatId, {
                        duration: duration,
                        comment: comment
                    }, function(data) {
                        if (data.result === 'ok') {
                            dialogRef.close();
                            $('#threatDetailModal').modal('hide');
                            BootstrapDialog.alert({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                message: data.message || '{{ lang._("IP blocked successfully.") }}'
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                    });
                }
            }]
        });
    });
    
    function loadThreatStats() {
        ajaxGet('/api/webguard/threats/getStats', {period: '24h'}, function(data) {
            $('#total-threats').text(formatNumber(data.total_threats || 0));
            $('#threats-24h').text(formatNumber(data.threats_24h || 0));
            $('#blocked-today').text(formatNumber(data.blocked_today || 0));
            
            if (data.total_threats > 0) {
                let rate = Math.round((data.blocked_today / data.total_threats) * 100);
                $('#detection-rate').text(rate + '%');
            } else {
                $('#detection-rate').text('--');
            }
        });
    }
    
    function loadThreats() {
        let params = {
            page: currentPage,
            limit: pageSize,
            severity: $('#severityFilter').val(),
            type: $('#typeFilter').val(),
            source_ip: $('#sourceIpFilter').val(),
            start_date: $('#startDateFilter').val(),
            end_date: $('#endDateFilter').val()
        };
        
        ajaxGet('/api/webguard/threats/get', params, function(data) {
            let tbody = $('#threatsTable tbody');
            tbody.empty();
            
            if (data.threats && data.threats.length > 0) {
                data.threats.forEach(function(threat) {
                    let row = $('<tr>');
                    row.append('<td>' + formatTimestamp(threat.timestamp) + '</td>');
                    row.append('<td><a href="/ui/webguard/blocking/history/' + threat.source_ip + '">' + threat.source_ip + '</a></td>');
                    row.append('<td>' + threat.type + '</td>');
                    row.append('<td><span class="severity-' + threat.severity + '">' + threat.severity.toUpperCase() + '</span></td>');
                    row.append('<td>' + threat.target + '</td>');
                    row.append('<td>' + threat.method + '</td>');
                    row.append('<td><span class="status-' + threat.status + '">' + threat.status.toUpperCase() + '</span></td>');
                    
                    let actions = '<div class="btn-group btn-group-xs">';
                    actions += '<button class="btn btn-default btn-view-threat" data-id="' + threat.id + '"><i class="fa fa-eye"></i></button>';
                    actions += '<a href="/ui/webguard/threats/detail/' + threat.id + '" class="btn btn-primary"><i class="fa fa-info"></i></a>';
                    actions += '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                
                // Update threat count
                $('#threatCount').text(data.total || 0);
                
                // Generate pagination
                generatePagination(data.total || 0);
            } else {
                tbody.append('<tr><td colspan="8" class="text-center">{{ lang._("No threats found") }}</td></tr>');
                $('#threatCount').text('0');
            }
        });
    }
    
    // View threat details
    $(document).on('click', '.btn-view-threat', function() {
        let threatId = $(this).data('id');
        currentThreatId = threatId;
        
        ajaxGet('/api/webguard/threats/getDetail/' + threatId, {}, function(data) {
            if (data.result === 'ok') {
                let threat = data.threat;
                let html = '<div class="threat-detail-section">';
                html += '<h5>{{ lang._("Basic Information") }}</h5>';
                html += '<div class="row">';
                html += '<div class="col-md-6"><strong>{{ lang._("Timestamp") }}:</strong> ' + formatTimestamp(threat.timestamp) + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Source IP") }}:</strong> ' + threat.source_ip + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Type") }}:</strong> ' + threat.type + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Severity") }}:</strong> <span class="severity-' + threat.severity + '">' + threat.severity.toUpperCase() + '</span></div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Target") }}:</strong> ' + threat.target + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Method") }}:</strong> ' + threat.method + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Status") }}:</strong> <span class="status-' + threat.status + '">' + threat.status.toUpperCase() + '</span></div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Score") }}:</strong> ' + (threat.score || 0) + '</div>';
                html += '</div></div>';
                
                if (threat.request_headers) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Request Headers") }}</h5>';
                    html += '<pre>' + JSON.stringify(threat.request_headers, null, 2) + '</pre>';
                    html += '</div>';
                }
                
                if (threat.payload) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Payload") }}</h5>';
                    html += '<pre>' + threat.payload + '</pre>';
                    html += '</div>';
                }
                
                if (threat.rule_matched) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Rule Matched") }}</h5>';
                    html += '<p>' + threat.rule_matched + '</p>';
                    html += '</div>';
                }
                
                if (threat.description) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Description") }}</h5>';
                    html += '<p>' + threat.description + '</p>';
                    html += '</div>';
                }
                
                $('#threatDetailContent').html(html);
                $('#threatDetailModal').modal('show');
            } else {
                BootstrapDialog.alert('{{ lang._("Failed to load threat details") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
            }
        });
    });
    
    function generatePagination(total) {
        let totalPages = Math.ceil(total / pageSize);
        let pagination = $('#threatsPagination');
        pagination.empty();
        
        if (totalPages <= 1) return;
        
        let nav = $('<nav><ul class="pagination pagination-sm"></ul></nav>');
        let ul = nav.find('ul');
        
        // Previous
        if (currentPage > 1) {
            ul.append('<li><a href="#" data-page="' + (currentPage - 1) + '">&laquo;</a></li>');
        }
        
        // Pages
        let start = Math.max(1, currentPage - 2);
        let end = Math.min(totalPages, currentPage + 2);
        
        for (let i = start; i <= end; i++) {
            let li = $('<li><a href="#" data-page="' + i + '">' + i + '</a></li>');
            if (i === currentPage) {
                li.addClass('active');
            }
            ul.append(li);
        }
        
        // Next
        if (currentPage < totalPages) {
            ul.append('<li><a href="#" data-page="' + (currentPage + 1) + '">&raquo;</a></li>');
        }
        
        pagination.append(nav);
    }
    
    // Pagination click handler
    $(document).on('click', '.pagination a', function(e) {
        e.preventDefault();
        let page = $(this).data('page');
        if (page && page !== currentPage) {
            currentPage = page;
            loadThreats();
        }
    });
    
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    
    function formatTimestamp(timestamp) {
        let date = new Date(timestamp * 1000);
        return date.toLocaleString();
    }
});
</script>