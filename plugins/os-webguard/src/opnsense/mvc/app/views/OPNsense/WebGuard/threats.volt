{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box">
    <!-- Header moderno -->
    <div class="row">
        <div class="col-md-12">
            <div class="modern-header">
                <h1><i class="fa fa-exclamation-triangle"></i> {{ lang._('WebGuard Threat Analysis') }}</h1>
                <p class="header-subtitle">{{ lang._('Real-time security threat monitoring and analysis') }}</p>
            </div>
        </div>
    </div>

    <!-- Stats Cards moderne -->
    <div class="row stats-row">
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-threats">
                <div class="stat-content">
                    <div class="stat-number" id="total-threats">0</div>
                    <div class="stat-label">{{ lang._('Total Threats') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-exclamation-triangle"></i>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-recent">
                <div class="stat-content">
                    <div class="stat-number" id="threats-24h">0</div>
                    <div class="stat-label">{{ lang._('Last 24 Hours') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-clock-o"></i>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-blocked">
                <div class="stat-content">
                    <div class="stat-number" id="blocked-today">0</div>
                    <div class="stat-label">{{ lang._('Blocked Today') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-shield"></i>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-rate">
                <div class="stat-content">
                    <div class="stat-number" id="detection-rate">--</div>
                    <div class="stat-label">{{ lang._('Detection Rate') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-check-circle"></i>
                </div>
            </div>
        </div>
    </div>

    <!-- Filters Panel -->
    <div class="row">
        <div class="col-md-12">
            <div class="modern-panel">
                <div class="panel-header">
                    <h3 class="panel-title">{{ lang._('Threat Filters') }}</h3>
                    <div class="panel-actions">
                        <button class="btn btn-primary btn-modern" id="refreshThreats">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <button class="btn btn-success btn-modern" id="exportThreats">
                            <i class="fa fa-download"></i> {{ lang._('Export') }}
                        </button>
                        <button class="btn btn-warning btn-modern" id="clearOldThreats">
                            <i class="fa fa-trash"></i> {{ lang._('Clear Old') }}
                        </button>
                    </div>
                </div>
                <div class="panel-body">
                    <div class="row filter-row">
                        <div class="col-md-2">
                            <label class="control-label">{{ lang._('Severity') }}</label>
                            <select class="form-control" id="severityFilter">
                                <option value="">{{ lang._('All Severities') }}</option>
                                <option value="critical">{{ lang._('Critical') }}</option>
                                <option value="high">{{ lang._('High') }}</option>
                                <option value="medium">{{ lang._('Medium') }}</option>
                                <option value="low">{{ lang._('Low') }}</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label class="control-label">{{ lang._('Type') }}</label>
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
                            <label class="control-label">{{ lang._('Source IP') }}</label>
                            <input type="text" class="form-control" id="sourceIpFilter" placeholder="{{ lang._('IP Address') }}">
                        </div>
                        <div class="col-md-2">
                            <label class="control-label">{{ lang._('Start Date') }}</label>
                            <input type="date" class="form-control" id="startDateFilter">
                        </div>
                        <div class="col-md-2">
                            <label class="control-label">{{ lang._('End Date') }}</label>
                            <input type="date" class="form-control" id="endDateFilter">
                        </div>
                        <div class="col-md-2">
                            <label class="control-label">&nbsp;</label>
                            <button class="btn btn-primary btn-block btn-modern" id="applyFilters">
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
            <div class="modern-panel">
                <div class="panel-header">
                    <h3 class="panel-title">
                        {{ lang._('Threat Log') }}
                        <span class="badge badge-modern" id="threatCount">0</span>
                    </h3>
                    <div class="panel-actions">
                        <select class="form-control" id="pageSize" style="width: auto; display: inline-block;">
                            <option value="25">25 {{ lang._('per page') }}</option>
                            <option value="50" selected>50 {{ lang._('per page') }}</option>
                            <option value="100">100 {{ lang._('per page') }}</option>
                            <option value="200">200 {{ lang._('per page') }}</option>
                        </select>
                    </div>
                </div>
                <div class="panel-body">
                    <div class="modern-table-container">
                        <table class="table table-modern" id="threatsTable">
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
                    <div class="row pagination-row">
                        <div class="col-md-6">
                            <div id="threatsPagination"></div>
                        </div>
                        <div class="col-md-6">
                            <div class="pull-right">
                                <span class="pagination-info" id="paginationInfo"></span>
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
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Threat Details') }}</h4>
            </div>
            <div class="modal-body" id="threatDetailContent">
                <!-- Populated by JavaScript -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
                <button type="button" class="btn btn-warning btn-modern" id="markFalsePositive">
                    <i class="fa fa-times"></i> {{ lang._('Mark False Positive') }}
                </button>
                <button type="button" class="btn btn-success btn-modern" id="whitelistIp">
                    <i class="fa fa-check"></i> {{ lang._('Whitelist IP') }}
                </button>
                <button type="button" class="btn btn-danger btn-modern" id="blockIp">
                    <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Export Modal -->
<div class="modal fade" id="exportModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
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
                            <option value="txt">Plain Text</option>
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
                <button type="button" class="btn btn-primary btn-modern" id="downloadExport">
                    <i class="fa fa-download"></i> {{ lang._('Export') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Clear Old Threats Modal -->
<div class="modal fade" id="clearOldModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
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
                <button type="button" class="btn btn-danger btn-modern" id="confirmClearOld">
                    <i class="fa fa-trash"></i> {{ lang._('Clear Old Threats') }}
                </button>
            </div>
        </div>
    </div>
</div>

<style>
/* Modern WebGuard Threats Styles */
.modern-header {
    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
    color: white;
    padding: 30px;
    border-radius: 10px;
    margin-bottom: 30px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

.modern-header h1 {
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 10px;
}

.header-subtitle {
    font-size: 1.1rem;
    opacity: 0.9;
    margin: 0;
}

.stats-row {
    margin-bottom: 30px;
}

.stat-card {
    background: white;
    border-radius: 12px;
    padding: 25px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    border: none;
    margin-bottom: 20px;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 4px;
}

.stat-threats::before { background: linear-gradient(135deg, #ff6b6b, #ee5a52); }
.stat-recent::before { background: linear-gradient(135deg, #ffd43b, #fab005); }
.stat-blocked::before { background: linear-gradient(135deg, #339af0, #228be6); }
.stat-rate::before { background: linear-gradient(135deg, #51cf66, #40c057); }

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 8px 30px rgba(0,0,0,0.15);
}

.stat-content {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
}

.stat-number {
    font-size: 2.5rem;
    font-weight: 800;
    color: #2d3748;
    margin-bottom: 5px;
}

.stat-label {
    color: #718096;
    font-weight: 600;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.stat-icon {
    position: absolute;
    right: 25px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 2.5rem;
    opacity: 0.1;
}

.modern-panel {
    background: white;
    border: none;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    margin-bottom: 20px;
    overflow: hidden;
}

.panel-header {
    padding: 20px 25px;
    border-bottom: 1px solid #e2e8f0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    background: #f8fafc;
}

.panel-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: #2d3748;
    margin: 0;
}

.panel-actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.panel-body {
    padding: 25px;
}

.filter-row {
    align-items: end;
}

.filter-row .form-group {
    margin-bottom: 0;
}

.btn-modern {
    border-radius: 8px;
    font-weight: 600;
    padding: 10px 20px;
    transition: all 0.3s ease;
    border: none;
}

.btn-modern:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

.modern-table-container {
    background: white;
    border-radius: 8px;
    overflow: hidden;
}

.table-modern {
    margin: 0;
    border: none;
}

.table-modern thead th {
    background: #f8fafc;
    border: none;
    color: #4a5568;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.85rem;
    letter-spacing: 0.5px;
    padding: 15px 20px;
}

.table-modern tbody td {
    border: none;
    border-bottom: 1px solid #f1f5f9;
    padding: 15px 20px;
    vertical-align: middle;
}

.table-modern tbody tr:hover {
    background: #f8fafc;
}

.table-modern tbody tr:last-child td {
    border-bottom: none;
}

.severity-critical { 
    color: #e53e3e; 
    font-weight: bold;
    background: rgba(229, 62, 62, 0.1);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.85rem;
}

.severity-high { 
    color: #dd6b20; 
    font-weight: bold;
    background: rgba(221, 107, 32, 0.1);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.85rem;
}

.severity-medium { 
    color: #3182ce;
    background: rgba(49, 130, 206, 0.1);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.85rem;
}

.severity-low { 
    color: #38a169;
    background: rgba(56, 161, 105, 0.1);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.85rem;
}

.status-blocked { 
    color: #e53e3e;
    background: rgba(229, 62, 62, 0.1);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.85rem;
    font-weight: 600;
}

.status-allowed { 
    color: #38a169;
    background: rgba(56, 161, 105, 0.1);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.85rem;
    font-weight: 600;
}

.status-logged { 
    color: #3182ce;
    background: rgba(49, 130, 206, 0.1);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.85rem;
    font-weight: 600;
}

.badge-modern {
    background: #667eea;
    color: white;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.85rem;
    font-weight: 600;
}

.modern-modal .modal-content {
    border-radius: 12px;
    border: none;
    box-shadow: 0 10px 40px rgba(0,0,0,0.15);
}

.modern-modal .modal-header {
    background: #f8fafc;
    border-bottom: 1px solid #e2e8f0;
    border-radius: 12px 12px 0 0;
    padding: 20px 25px;
}

.modern-modal .modal-title {
    font-weight: 600;
    color: #2d3748;
}

.modern-modal .modal-body {
    padding: 25px;
}

.modern-modal .modal-footer {
    background: #f8fafc;
    border-top: 1px solid #e2e8f0;
    border-radius: 0 0 12px 12px;
    padding: 20px 25px;
}

.pagination-row {
    margin-top: 20px;
    padding-top: 20px;
    border-top: 1px solid #e2e8f0;
}

.pagination-info {
    color: #718096;
    font-size: 0.9rem;
}

.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #a0aec0;
}

.empty-state i {
    font-size: 3rem;
    margin-bottom: 15px;
    opacity: 0.5;
}

.empty-state h4 {
    color: #718096;
    margin-bottom: 10px;
}

.threat-detail-section {
    margin-bottom: 20px;
}

.threat-detail-section h5 {
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 8px;
    margin-bottom: 15px;
    font-weight: 600;
    color: #2d3748;
}

.threat-detail-section pre {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 15px;
    font-size: 0.9rem;
    max-height: 300px;
    overflow-y: auto;
}

/* Loading animation */
.btn-loading {
    position: relative;
    color: transparent !important;
}

.btn-loading::after {
    content: '';
    position: absolute;
    width: 16px;
    height: 16px;
    top: 50%;
    left: 50%;
    margin-left: -8px;
    margin-top: -8px;
    border: 2px solid transparent;
    border-top: 2px solid currentColor;
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Responsive */
@media (max-width: 768px) {
    .panel-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 15px;
    }
    
    .panel-actions {
        width: 100%;
        justify-content: flex-start;
    }
    
    .filter-row .col-md-2 {
        margin-bottom: 15px;
    }
    
    .stat-card {
        margin-bottom: 15px;
    }
    
    .stat-number {
        font-size: 2rem;
    }
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
    
    // Add clear filters button
    addClearFiltersButton();
    
    // Filter controls
    $('#applyFilters').click(function() {
        console.log('Applying filters...');
        console.log('Filter values:', {
            severity: $('#severityFilter').val(),
            type: $('#typeFilter').val(),
            source_ip: $('#sourceIpFilter').val(),
            start_date: $('#startDateFilter').val(),
            end_date: $('#endDateFilter').val()
        });
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
        const btn = $(this);
        const format = $('#exportFormat').val();
        const params = {
            format: format,
            start_date: $('#exportStartDate').val(),
            end_date: $('#exportEndDate').val(),
            severity: $('#exportSeverity').val(),
            type: $('#exportType').val()
        };
        
        setButtonLoading(btn, true);
        
        ajaxGet('/api/webguard/threats/export', params, function(data) {
            setButtonLoading(btn, false);
            
            if (data.result === 'ok') {
                downloadFile(data.data, data.filename, 'application/octet-stream');
                $('#exportModal').modal('hide');
                showNotification('{{ lang._("Export completed successfully") }}', 'success');
            } else {
                showNotification('{{ lang._("Export failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    // Clear old threats
    $('#confirmClearOld').click(function() {
        const btn = $(this);
        const daysOld = $('#daysOld').val();
        const keepCritical = $('#keepCritical').is(':checked');
        
        if (!daysOld || daysOld < 1) {
            showNotification('{{ lang._("Please specify a valid number of days.") }}', 'error');
            return;
        }
        
        setButtonLoading(btn, true);
        
        ajaxPost('/api/webguard/threats/clearOld', {
            days_old: daysOld,
            keep_critical: keepCritical
        }, function(data) {
            setButtonLoading(btn, false);
            
            if (data.result === 'ok') {
                $('#clearOldModal').modal('hide');
                showNotification(data.message || '{{ lang._("Old threats cleared successfully.") }}', 'success');
                loadThreatStats();
                loadThreats();
            } else {
                showNotification('{{ lang._("Clear failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    // Modal actions
    $('#markFalsePositive').click(function() {
        if (!currentThreatId) {
            showNotification('{{ lang._("No threat selected.") }}', 'error');
            return;
        }
        const btn = $(this);
        setButtonLoading(btn, true);
        const comment = 'Marked as false positive from threat';
        ajaxPost('/api/webguard/threats/markFalsePositive/' + currentThreatId, { comment: comment }, function(data) {
            setButtonLoading(btn, false);
            if (data.result === 'ok') {
                $('#threatDetailModal').modal('hide');
                showNotification(data.message || '{{ lang._("Threat marked as false positive.") }}', 'success');
                loadThreats();
            } else {
                showNotification('{{ lang._("Failed to mark as false positive") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });

    $('#whitelistIp').click(function() {
        if (!currentThreatId) {
            showNotification('{{ lang._("No threat selected.") }}', 'error');
            return;
        }
        const btn = $(this);
        setButtonLoading(btn, true);
        const description = 'Manual whitelist entry';
        const comment = 'Whitelisted from threat';
        ajaxPost('/api/webguard/threats/whitelistIp/' + currentThreatId, { description: description, comment: comment }, function(data) {
            setButtonLoading(btn, false);
            if (data.result === 'ok') {
                $('#threatDetailModal').modal('hide');
                showNotification(data.message || '{{ lang._("IP added to whitelist.") }}', 'success');
                loadThreats();
            } else {
                showNotification('{{ lang._("Failed to add IP to whitelist") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    $('#blockIp').click(function() {
        if (!currentThreatId) {
            showNotification('{{ lang._("No threat selected.") }}', 'error');
            return;
        }
        const btn = $(this);
        setButtonLoading(btn, true);
        const duration = 3600; // 1 ora di default
        const comment = 'Blocked from threat';
        ajaxPost('/api/webguard/threats/blockIp/' + currentThreatId, { duration: duration, comment: comment }, function(data) {
            setButtonLoading(btn, false);
            if (data.result === 'ok') {
                $('#threatDetailModal').modal('hide');
                showNotification(data.message || '{{ lang._("IP blocked successfully.") }}', 'success');
                loadThreats();
            } else {
                showNotification('{{ lang._("Failed to block IP") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    // View threat details
    $(document).on('click', '.btn-view-threat', function() {
        const threatId = $(this).data('id');
        currentThreatId = threatId;
        
        ajaxGet('/api/webguard/threats/getDetail/' + threatId, {}, function(data) {
            if (data.result === 'ok') {
                const threat = data.threat;
                let html = '<div class="threat-detail-section">';
                html += '<h5>{{ lang._("Basic Information") }}</h5>';
                html += '<div class="row">';
                html += '<div class="col-md-6"><strong>{{ lang._("Timestamp") }}:</strong> ' + formatTimestamp(threat.timestamp) + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Source IP") }}:</strong> ' + (threat.source_ip || threat.ip_address) + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Type") }}:</strong> ' + (threat.type || threat.threat_type) + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Severity") }}:</strong> <span class="severity-' + threat.severity + '">' + (threat.severity || 'low').toUpperCase() + '</span></div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Target") }}:</strong> ' + (threat.target || threat.url || '-') + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Method") }}:</strong> ' + (threat.method || 'GET') + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Status") }}:</strong> <span class="status-' + (threat.status || 'logged') + '">' + (threat.status || 'LOGGED').toUpperCase() + '</span></div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Score") }}:</strong> ' + (threat.score || 0) + '</div>';
                html += '</div></div>';
                
                if (threat.request_headers || threat.headers) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Request Headers") }}</h5>';
                    html += '<pre>' + JSON.stringify(threat.request_headers || threat.headers, null, 2) + '</pre>';
                    html += '</div>';
                }
                
                if (threat.payload || threat.request_body) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Payload") }}</h5>';
                    html += '<pre>' + (threat.payload || threat.request_body) + '</pre>';
                    html += '</div>';
                }
                
                if (threat.rule_matched || threat.rule) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Rule Matched") }}</h5>';
                    html += '<p>' + (threat.rule_matched || threat.rule) + '</p>';
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
                showNotification('{{ lang._("Failed to load threat details") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });

    // Pagination click handler
    $(document).on('click', '.pagination a', function(e) {
        e.preventDefault();
        const page = $(this).data('page');
        if (page && page !== currentPage) {
            currentPage = page;
            loadThreats();
        }
    });

    // MIGLIORAMENTO: Filtri in tempo reale per IP
    $('#sourceIpFilter').on('input', function() {
        clearTimeout(window.ipFilterTimeout);
        window.ipFilterTimeout = setTimeout(function() {
            if ($('#sourceIpFilter').val().length === 0 || $('#sourceIpFilter').val().length >= 3) {
                currentPage = 1;
                loadThreats();
            }
        }, 500);
    });

    // MIGLIORAMENTO: Auto-apply quando si cambiano date
    $('#startDateFilter, #endDateFilter').change(function() {
        console.log('Date filter changed, auto-applying...');
        currentPage = 1;
        loadThreats();
    });
    
    // Functions
    function loadThreatStats() {
        console.log('Loading threat stats...');
        ajaxGet('/api/webguard/threats/getStats', {period: '24h'}, function(data) {
            console.log('Threat stats response:', data);
            
            const totalThreats = data.total_threats || 0;
            const threats24h = data.threats_24h || 0;
            const blockedToday = data.blocked_today || 0;
            
            $('#total-threats').text(formatNumber(totalThreats));
            $('#threats-24h').text(formatNumber(threats24h));
            $('#blocked-today').text(formatNumber(blockedToday));
            
            if (totalThreats > 0 && blockedToday >= 0) {
                const rate = Math.round((blockedToday / totalThreats) * 100);
                $('#detection-rate').text(rate + '%');
            } else {
                $('#detection-rate').text('0%');
            }
        });
    }

    function addClearFiltersButton() {
        if ($('#clearFilters').length === 0) {
            const clearBtn = $('<button class="btn btn-default btn-modern" id="clearFilters">' +
                '<i class="fa fa-times"></i> {{ lang._("Clear") }}</button>');
            
            $('#applyFilters').after(clearBtn);
            
            $('#clearFilters').click(function() {
                console.log('Clearing filters...');
                $('#severityFilter').val('');
                $('#typeFilter').val('');
                $('#sourceIpFilter').val('');
                $('#startDateFilter').val('');
                $('#endDateFilter').val('');
                currentPage = 1;
                loadThreats();
            });
        }
    }
    
    function loadThreats() {
        console.log('Loading threats...');
        
        const params = {
            page: currentPage,
            limit: pageSize,
            severity: $('#severityFilter').val() || '',
            type: $('#typeFilter').val() || '',
            source_ip: $('#sourceIpFilter').val() || '',
            start_date: $('#startDateFilter').val() || '',
            end_date: $('#endDateFilter').val() || ''
        };
        
        // Rimuovi parametri vuoti
        Object.keys(params).forEach(key => {
            if (params[key] === '' || params[key] === null || params[key] === undefined) {
                delete params[key];
            }
        });
        
        console.log('Request params:', params);
        
        ajaxGet('/api/webguard/threats/getAllThreats', params, function(data) {
            console.log('Threats response:', data);
            const tbody = $('#threatsTable tbody');
            tbody.empty();
            
            const threats = data.threats || [];
            const total = data.total || threats.length;
            
            if (threats && threats.length > 0) {
                console.log('Found', threats.length, 'threats');
                threats.forEach(function(threat) {
                    const row = $('<tr>');
                    
                    const timestamp = threat.first_seen || threat.timestamp || threat.last_seen;
                    const sourceIp = threat.ip_address || threat.source_ip;
                    const threatType = threat.threat_type || threat.type;
                    const severity = threat.severity || 'low';
                    const target = threat.url || threat.target || threat.description || '-';
                    const method = threat.method || 'GET';
                    const status = threat.status || 'logged';
                    const threatId = threat.id || threat.threat_id;
                    
                    row.append('<td>' + formatTimestamp(timestamp) + '</td>');
                    row.append('<td><strong>' + sourceIp + '</strong></td>');
                    row.append('<td>' + threatType + '</td>');
                    row.append('<td><span class="severity-' + severity + '">' + severity.toUpperCase() + '</span></td>');
                    row.append('<td>' + target + '</td>');
                    row.append('<td>' + method + '</td>');
                    row.append('<td><span class="status-' + status + '">' + status.toUpperCase() + '</span></td>');
                    
                    const actions = '<div class="btn-group btn-group-xs">' +
                        '<button class="btn btn-default btn-view-threat" data-id="' + threatId + '">' +
                        '<i class="fa fa-eye"></i></button>' +
                        '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                
                $('#threatCount').text(total);
                
                const start = ((currentPage - 1) * pageSize) + 1;
                const end = Math.min(currentPage * pageSize, total);
                $('#paginationInfo').text(`Showing ${start}-${end} of ${total} threats`);
                
                generatePagination(total);
            } else {
                console.log('No threats found or empty response');
                tbody.append(createEmptyState('{{ lang._("No threats found") }}', 'exclamation-triangle'));
                $('#threatCount').text('0');
                $('#paginationInfo').text('No threats found');
            }
        });
    }
    
    function generatePagination(total) {
        const totalPages = Math.ceil(total / pageSize);
        const pagination = $('#threatsPagination');
        pagination.empty();
        
        if (totalPages <= 1) return;
        
        const nav = $('<nav><ul class="pagination pagination-sm"></ul></nav>');
        const ul = nav.find('ul');
        
        if (currentPage > 1) {
            ul.append('<li><a href="#" data-page="' + (currentPage - 1) + '">&laquo;</a></li>');
        }
        
        const start = Math.max(1, currentPage - 2);
        const end = Math.min(totalPages, currentPage + 2);
        
        for (let i = start; i <= end; i++) {
            const li = $('<li><a href="#" data-page="' + i + '">' + i + '</a></li>');
            if (i === currentPage) {
                li.addClass('active');
            }
            ul.append(li);
        }
        
        if (currentPage < totalPages) {
            ul.append('<li><a href="#" data-page="' + (currentPage + 1) + '">&raquo;</a></li>');
        }
        
        pagination.append(nav);
    }
    
    function createEmptyState(message, icon) {
        return '<tr><td colspan="8" class="empty-state">' +
            '<i class="fa fa-' + icon + '"></i>' +
            '<h4>' + message + '</h4>' +
            '<p>{{ lang._("No data to display at this time") }}</p>' +
            '</td></tr>';
    }
    
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        
        let date;
        if (typeof timestamp === 'string') {
            date = new Date(timestamp);
        } else {
            date = new Date(timestamp * 1000);
        }
        
        return date.toLocaleString();
    }
    
    function setButtonLoading(btn, loading) {
        if (loading) {
            btn.addClass('btn-loading').prop('disabled', true);
        } else {
            btn.removeClass('btn-loading').prop('disabled', false);
        }
    }
    
    function showNotification(message, type) {
        const notification = $('<div class="alert alert-' + (type === 'error' ? 'danger' : type) + ' alert-dismissible" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;">' +
            '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
            '<i class="fa fa-' + getNotificationIcon(type) + '"></i> ' + message + '</div>');

        $('body').append(notification);
        setTimeout(function() {
            notification.fadeOut(300, function() {
                $(this).remove();
            });
        }, 5000);
    }
    
    function getNotificationIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }
    
    function downloadFile(data, filename, contentType) {
        try {
            const blob = new Blob([data], { type: contentType });
            const link = document.createElement('a');
            link.href = window.URL.createObjectURL(blob);
            link.download = filename;
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            window.URL.revokeObjectURL(link.href);
        } catch (error) {
            console.error('Download error:', error);
            showNotification('{{ lang._("Download failed") }}', 'error');
        }
    }

    function ajaxPost(url, data, callback) {
        $.ajax({
            url: url,
            type: 'POST',
            data: data,
            dataType: 'json',
            success: callback,
            error: function(xhr, status, error) {
                console.error('AJAX Error:', error);
                console.error('Response:', xhr.responseText);
                
                let msg = error || '{{ lang._("Connection error") }}';
                
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response && response.message) {
                        msg = response.message;
                    }
                } catch (e) {
                    if (xhr.responseText && xhr.responseText.length < 200) {
                        msg = xhr.responseText;
                    }
                }
                
                showNotification('{{ lang._("Error") }}: ' + msg, 'error');
            }
        });
    }

    function ajaxGet(url, data, callback) {
        console.log('AJAX GET:', url, data);
        $.ajax({
            url: url,
            type: 'GET',
            data: data,
            dataType: 'json',
            success: function(response) {
                console.log('AJAX Success:', response);
                callback(response);
            },
            error: function(xhr, status, error) {
                console.error('AJAX Error:', {
                    url: url,
                    status: xhr.status,
                    statusText: xhr.statusText,
                    error: error,
                    response: xhr.responseText
                });
                
                let msg = error || '{{ lang._("Connection error") }}';
                
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response && response.message) {
                        msg = response.message;
                    }
                } catch (e) {
                    if (xhr.responseText && xhr.responseText.length < 200) {
                        msg = xhr.responseText;
                    }
                }
                
                // Fallback per gli endpoint threats
                if (url.includes('/api/webguard/threats/')) {
                    console.log('API endpoint failed, using fallback data');
                    if (url.includes('/getStats')) {
                        callback({
                            total_threats: 0,
                            threats_24h: 0,
                            blocked_today: 0
                        });
                    } else if (url.includes('/get')) {
                        callback({
                            threats: [],
                            total: 0
                        });
                    }
                } else {
                    showNotification('{{ lang._("Error loading data") }}: ' + msg, 'error');
                }
            }
        });
    }
});
</script>