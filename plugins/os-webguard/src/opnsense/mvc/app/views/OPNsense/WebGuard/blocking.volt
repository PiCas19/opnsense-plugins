{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box">
    <!-- Header moderno -->
    <div class="row">
        <div class="col-md-12">
            <div class="modern-header">
                <h1><i class="fa fa-shield"></i> {{ lang._('WebGuard IP Management') }}</h1>
                <p class="header-subtitle">{{ lang._('Advanced IP blocking and security management system') }}</p>
            </div>
        </div>
    </div>

    <!-- Stats Cards moderne -->
    <div class="row stats-row">
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-blocked">
                <div class="stat-content">
                    <div class="stat-number" id="active-blocks">0</div>
                    <div class="stat-label">{{ lang._('Active Blocks') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-ban"></i>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-whitelist">
                <div class="stat-content">
                    <div class="stat-number" id="whitelist-count">0</div>
                    <div class="stat-label">{{ lang._('Whitelist Entries') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-check-circle"></i>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-temp">
                <div class="stat-content">
                    <div class="stat-number" id="temp-blocks">0</div>
                    <div class="stat-label">{{ lang._('Temporary Blocks') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-clock-o"></i>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-status">
                <div class="stat-content">
                    <div class="stat-number" id="service-status">{{ lang._('Loading') }}</div>
                    <div class="stat-label">{{ lang._('Service Status') }}</div>
                </div>
                <div class="stat-icon">
                    <i class="fa fa-heartbeat"></i>
                </div>
            </div>
        </div>
    </div>

    <!-- Tabs moderne -->
    <div class="row">
        <div class="col-md-12">
            <div class="modern-tabs">
                <ul class="nav nav-tabs modern-nav-tabs" role="tablist">
                    <li class="active">
                        <a href="#blocked-tab" data-toggle="tab" role="tab">
                            <i class="fa fa-ban"></i>
                            <span>{{ lang._('Blocked IPs') }}</span>
                        </a>
                    </li>
                    <li>
                        <a href="#whitelist-tab" data-toggle="tab" role="tab">
                            <i class="fa fa-check-circle"></i>
                            <span>{{ lang._('Whitelist') }}</span>
                        </a>
                    </li>
                    <li>
                        <a href="#threats-tab" data-toggle="tab" role="tab">
                            <i class="fa fa-exclamation-triangle"></i>
                            <span>{{ lang._('Threats') }}</span>
                        </a>
                    </li>
                    <li>
                        <a href="#tools-tab" data-toggle="tab" role="tab">
                            <i class="fa fa-cogs"></i>
                            <span>{{ lang._('Tools') }}</span>
                        </a>
                    </li>
                    <li>
                        <a href="#false-positive-tab" data-toggle="tab" role="tab">
                            <i class="fa fa-times-circle"></i>
                            <span>{{ lang._('Mark False Positives') }}</span>
                        </a>
                    </li>
                </ul>

                <div class="tab-content modern-tab-content">
                    <!-- Blocked IPs Tab -->
                    <div class="tab-pane active" id="blocked-tab">
                        <div class="modern-panel">
                            <div class="panel-header">
                                <h3 class="panel-title">{{ lang._('Blocked IP Addresses') }}</h3>
                                <div class="panel-actions">
                                    <button type="button" class="btn btn-primary btn-modern" id="add-block-btn">
                                        <i class="fa fa-plus"></i> {{ lang._('Block IP') }}
                                    </button>
                                    <button type="button" class="btn btn-warning btn-modern" id="bulk-block-btn">
                                        <i class="fa fa-list"></i> {{ lang._('Bulk Block') }}
                                    </button>
                                    <button type="button" class="btn btn-info btn-modern" id="clear-expired-btn">
                                        <i class="fa fa-clock-o"></i> {{ lang._('Clear Expired') }}
                                    </button>
                                    <button type="button" class="btn btn-default btn-modern" id="refresh-blocked-btn">
                                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                    </button>
                                </div>
                            </div>
                            <div class="panel-body">
                                <div class="modern-table-container">
                                    <table class="table table-modern" id="blocked-table">
                                        <thead>
                                            <tr>
                                                <th>{{ lang._('IP Address') }}</th>
                                                <th>{{ lang._('Block Type') }}</th>
                                                <th>{{ lang._('Blocked Since') }}</th>
                                                <th>{{ lang._('Expires') }}</th>
                                                <th>{{ lang._('Reason') }}</th>
                                                <th>{{ lang._('Actions') }}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <!-- Loaded via AJAX -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Whitelist Tab -->
                    <div class="tab-pane" id="whitelist-tab">
                        <div class="modern-panel">
                            <div class="panel-header">
                                <h3 class="panel-title">{{ lang._('Whitelisted Addresses') }}</h3>
                                <div class="panel-actions">
                                    <button type="button" class="btn btn-success btn-modern" id="add-whitelist-btn">
                                        <i class="fa fa-plus"></i> {{ lang._('Add to Whitelist') }}
                                    </button>
                                    <button type="button" class="btn btn-default btn-modern" id="refresh-whitelist-btn">
                                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                    </button>
                                </div>
                            </div>
                            <div class="panel-body">
                                <div class="modern-table-container">
                                    <table class="table table-modern" id="whitelist-table">
                                        <thead>
                                            <tr>
                                                <th>{{ lang._('IP Address') }}</th>
                                                <th>{{ lang._('Description') }}</th>
                                                <th>{{ lang._('Added') }}</th>
                                                <th>{{ lang._('Type') }}</th>
                                                <th>{{ lang._('Actions') }}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <!-- Loaded via AJAX -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Threats Tab -->
                    <div class="tab-pane" id="threats-tab">
                        <div class="modern-panel">
                            <div class="panel-header">
                                <h3 class="panel-title">{{ lang._('Security Threats') }}</h3>
                                <div class="panel-actions">
                                    <button type="button" class="btn btn-default btn-modern" id="refresh-threats-btn">
                                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                    </button>
                                </div>
                            </div>
                            <div class="panel-body">
                                <div class="modern-table-container">
                                    <table class="table table-modern" id="threats-table">
                                        <thead>
                                            <tr>
                                                <th>{{ lang._('IP Address') }}</th>
                                                <th>{{ lang._('Threat Type') }}</th>
                                                <th>{{ lang._('Severity') }}</th>
                                                <th>{{ lang._('First Seen') }}</th>
                                                <th>{{ lang._('Last Seen') }}</th>
                                                <th>{{ lang._('Actions') }}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <!-- Loaded via AJAX -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Tools Tab -->
                    <div class="tab-pane" id="tools-tab">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="modern-panel">
                                    <div class="panel-header">
                                        <h3 class="panel-title">{{ lang._('Export Data') }}</h3>
                                    </div>
                                    <div class="panel-body">
                                        <div class="form-group">
                                            <label class="control-label">{{ lang._('Export Format') }}</label>
                                            <select class="form-control" id="export-format">
                                                <option value="json">JSON</option>
                                                <option value="csv">CSV</option>
                                                <option value="txt">Plain Text</option>
                                            </select>
                                        </div>
                                        <div class="btn-group-vertical btn-group-modern">
                                            <button type="button" class="btn btn-primary btn-modern" id="export-blocked-btn">
                                                <i class="fa fa-download"></i> {{ lang._('Export Blocked IPs') }}
                                            </button>
                                            <button type="button" class="btn btn-success btn-modern" id="export-whitelist-btn">
                                                <i class="fa fa-download"></i> {{ lang._('Export Whitelist') }}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="modern-panel">
                                    <div class="panel-header">
                                        <h3 class="panel-title">{{ lang._('Maintenance') }}</h3>
                                    </div>
                                    <div class="panel-body">
                                        <div class="btn-group-vertical btn-group-modern">
                                            <button type="button" class="btn btn-warning btn-modern" id="add-sample-threats-btn">
                                                <i class="fa fa-plus"></i> {{ lang._('Add Sample Threats') }}
                                            </button>
                                            <button type="button" class="btn btn-info btn-modern" id="clear-logs-btn">
                                                <i class="fa fa-trash"></i> {{ lang._('Clear Logs') }}
                                            </button>
                                            <button type="button" class="btn btn-default btn-modern" id="restart-service-btn">
                                                <i class="fa fa-refresh"></i> {{ lang._('Restart Service') }}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Mark False Positives Tab -->
                    <div class="tab-pane" id="false-positive-tab">
                        <div class="modern-panel">
                            <div class="panel-header">
                                <h3 class="panel-title">{{ lang._('Mark False Positives') }}</h3>
                                <div class="panel-actions">
                                    <button type="button" class="btn btn-default btn-modern" id="refresh-false-positives-btn">
                                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                    </button>
                                </div>
                            </div>
                            <div class="panel-body">
                                <div class="modern-table-container">
                                    <table class="table table-modern" id="false-positives-table">
                                        <thead>
                                            <tr>
                                                <th>{{ lang._('IP Address') }}</th>
                                                <th>{{ lang._('Threat Type') }}</th>
                                                <th>{{ lang._('Severity') }}</th>
                                                <th>{{ lang._('First Seen') }}</th>
                                                <th>{{ lang._('Reason') }}</th>
                                                <th>{{ lang._('Actions') }}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <!-- Loaded via AJAX -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modals -->
<!-- Block IP Modal -->
<div class="modal fade" id="block-ip-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>×</span>
                </button>
                <h4 class="modal-title">{{ lang._('Block IP Address') }}</h4>
            </div>
            <div class="modal-body">
                <form id="block-ip-form">
                    <div class="form-group">
                        <label class="control-label">{{ lang._('IP Address') }}</label>
                        <input type="text" class="form-control" id="block-ip" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label class="control-label">{{ lang._('Duration') }}</label>
                        <select class="form-control" id="block-duration">
                            <option value="300">5 {{ lang._('minutes') }}</option>
                            <option value="900">15 {{ lang._('minutes') }}</option>
                            <option value="1800">30 {{ lang._('minutes') }}</option>
                            <option value="3600" selected>1 {{ lang._('hour') }}</option>
                            <option value="21600">6 {{ lang._('hours') }}</option>
                            <option value="86400">24 {{ lang._('hours') }}</option>
                            <option value="604800">7 {{ lang._('days') }}</option>
                            <option value="0">{{ lang._('Permanent') }}</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="control-label">{{ lang._('Reason') }}</label>
                        <input type="text" class="form-control" id="block-reason" placeholder="Manual block" value="Manual block">
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-danger" id="confirm-block-btn">
                    <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Bulk Block Modal -->
<div class="modal fade" id="bulk-block-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>×</span>
                </button>
                <h4 class="modal-title">{{ lang._('Bulk Block IP Addresses') }}</h4>
            </div>
            <div class="modal-body">
                <form id="bulk-block-form">
                    <div class="form-group">
                        <label class="control-label">{{ lang._('IP Addresses (one per line)') }}</label>
                        <textarea class="form-control" id="bulk-block-ips" rows="6" placeholder="192.168.1.100
10.0.0.50
172.16.0.25"></textarea>
                    </div>
                    <div class="form-group">
                        <label class="control-label">{{ lang._('Duration') }}</label>
                        <select class="form-control" id="bulk-block-duration">
                            <option value="300">5 {{ lang._('minutes') }}</option>
                            <option value="900">15 {{ lang._('minutes') }}</option>
                            <option value="1800">30 {{ lang._('minutes') }}</option>
                            <option value="3600" selected>1 {{ lang._('hour') }}</option>
                            <option value="21600">6 {{ lang._('hours') }}</option>
                            <option value="86400">24 {{ lang._('hours') }}</option>
                            <option value="604800">7 {{ lang._('days') }}</option>
                            <option value="0">{{ lang._('Permanent') }}</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="control-label">{{ lang._('Reason') }}</label>
                        <input type="text" class="form-control" id="bulk-block-reason" placeholder="Bulk block" value="Bulk block">
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-danger" id="confirm-bulk-block-btn">
                    <i class="fa fa-ban"></i> {{ lang._('Block IPs') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Add Whitelist Modal -->
<div class="modal fade" id="add-whitelist-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>×</span>
                </button>
                <h4 class="modal-title">{{ lang._('Add to Whitelist') }}</h4>
            </div>
            <div class="modal-body">
                <form id="add-whitelist-form">
                    <div class="form-group">
                        <label class="control-label">{{ lang._('IP Address') }}</label>
                        <input type="text" class="form-control" id="whitelist-ip" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label class="control-label">{{ lang._('Description') }}</label>
                        <input type="text" class="form-control" id="whitelist-description" placeholder="Manual whitelist entry" value="Manual whitelist entry">
                    </div>
                    <div class="checkbox">
                        <label>
                            <input type="checkbox" id="whitelist-permanent" checked> {{ lang._('Permanent entry') }}
                        </label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-success" id="confirm-whitelist-btn">
                    <i class="fa fa-check"></i> {{ lang._('Add to Whitelist') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- False Positive Detail Modal -->
<div class="modal fade" id="false-positive-detail-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>×</span>
                </button>
                <h4 class="modal-title">{{ lang._('False Positive Details') }}</h4>
            </div>
            <div class="modal-body" id="false-positive-detail-content">
                <!-- Populated by JavaScript -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
                <button type="button" class="btn btn-info btn-modern" id="unmark-false-positive-btn">
                    <i class="fa fa-undo"></i> {{ lang._('Unmark False Positive') }}
                </button>
            </div>
        </div>
    </div>
</div>

<style>
/* Modern WebGuard Styles - OPNsense Compatible */
.modern-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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

.stat-blocked::before { background: linear-gradient(135deg, #ff6b6b, #ee5a52); }
.stat-whitelist::before { background: linear-gradient(135deg, #51cf66, #40c057); }
.stat-temp::before { background: linear-gradient(135deg, #ffd43b, #fab005); }
.stat-status::before { background: linear-gradient(135deg, #339af0, #228be6); }

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

.modern-tabs {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    overflow: hidden;
}

.modern-nav-tabs {
    background: #f8fafc;
    border-bottom: none;
    padding: 10px;
    margin: 0;
}

.modern-nav-tabs > li {
    margin-bottom: 0;
}

.modern-nav-tabs > li > a {
    border: none;
    border-radius: 8px;
    margin-right: 5px;
    padding: 15px 20px;
    color: #718096;
    font-weight: 600;
    transition: all 0.3s ease;
}

.modern-nav-tabs > li > a:hover,
.modern-nav-tabs > li > a:focus {
    background: rgba(255,255,255,0.7);
    color: #4a5568;
    border: none;
}

.modern-nav-tabs > li.active > a,
.modern-nav-tabs > li.active > a:hover,
.modern-nav-tabs > li.active > a:focus {
    background: white;
    color: #667eea;
    border: none;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.modern-nav-tabs > li > a i {
    margin-right: 8px;
}

.modern-tab-content {
    padding: 30px;
}

.modern-panel {
    background: white;
    border: none;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    margin-bottom: 20px;
}

.panel-header {
    padding: 20px 25px;
    border-bottom: 1px solid #e2e8f0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
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

.btn-group-modern {
    width: 100%;
}

.btn-group-modern .btn-modern {
    margin-bottom: 10px;
    width: 100%;
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

.label-modern {
    border-radius: 12px;
    padding: 4px 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
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

.notification-modern {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 15px 20px;
    border-radius: 8px;
    color: white;
    font-weight: 600;
    z-index: 9999;
    min-width: 300px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
}

.notification-success { background: linear-gradient(135deg, #51cf66, #40c057); }
.notification-error { background: linear-gradient(135deg, #ff6b6b, #ee5a52); }
.notification-info { background: linear-gradient(135deg, #339af0, #228be6); }
.notification-warning { background: linear-gradient(135deg, #ffd43b, #fab005); }

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
    
    .modern-nav-tabs {
        padding: 5px;
    }
    
    .modern-nav-tabs > li > a {
        padding: 10px 15px;
        font-size: 0.9rem;
    }
    
    .modern-nav-tabs > li > a span {
        display: none;
    }
    
    .stat-card {
        margin-bottom: 15px;
    }
    
    .stat-number {
        font-size: 2rem;
    }
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
</style>

<script>
$(function() {
    // Initialize app
    loadStats();
    loadBlockedIps();

    // Auto-refresh every 30 seconds
    setInterval(function() {
        loadStats();
        if ($('#blocked-tab').hasClass('active')) {
            loadBlockedIps();
        } else if ($('#whitelist-tab').hasClass('active')) {
            loadWhitelist();
        } else if ($('#threats-tab').hasClass('active')) {
            loadThreats();
        } else if ($('#false-positive-tab').hasClass('active')) {
            loadFalsePositives();
        }
    }, 30000);

    // Tab change events
    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        var target = $(e.target).attr("href");
        switch(target) {
            case '#blocked-tab':
                loadBlockedIps();
                break;
            case '#whitelist-tab':
                loadWhitelist();
                break;
            case '#threats-tab':
                loadThreats();
                break;
            case '#false-positive-tab':
                loadFalsePositives();
                break;
        }
    });

    // Button events
    $('#add-block-btn').click(() => $('#block-ip-modal').modal('show'));
    $('#bulk-block-btn').click(() => $('#bulk-block-modal').modal('show'));
    $('#add-whitelist-btn').click(() => $('#add-whitelist-modal').modal('show'));
    $('#refresh-blocked-btn').click(() => { loadStats(); loadBlockedIps(); });
    $('#refresh-whitelist-btn').click(() => loadWhitelist());
    $('#refresh-threats-btn').click(() => loadThreats());
    $('#refresh-false-positives-btn').click(() => loadFalsePositives());

    // Action buttons
    $('#clear-expired-btn').click(function() {
        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/clearExpired', {}, function(data) {
            setButtonLoading($('#clear-expired-btn'), false);
            if (data.status === 'ok') {
                showNotification('{{ lang._("Expired blocks cleared") }}', 'success');
                loadStats();
                loadBlockedIps();
            } else {
                showNotification('{{ lang._("Failed to clear expired blocks") }}', 'error');
            }
        });
    });

    // EXPORT BUTTONS - FIXED VERSION
    $('#export-blocked-btn').click(function() {
        const btn = $(this);
        const format = $('#export-format').val();
        
        setButtonLoading(btn, true);
        
        ajaxGet('/api/webguard/service/exportBlocked', { format: format }, function(data) {
            setButtonLoading(btn, false);
            
            if (data.status === 'ok') {
                downloadFile(data.data, data.filename, data.content_type);
                showNotification('{{ lang._("Blocked IPs exported successfully") }}', 'success');
            } else {
                showNotification('{{ lang._("Failed to export blocked IPs") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $('#export-whitelist-btn').click(function() {
        const btn = $(this);
        const format = $('#export-format').val();
        
        setButtonLoading(btn, true);
        
        ajaxGet('/api/webguard/service/exportWhitelist', { format: format }, function(data) {
            setButtonLoading(btn, false);
            
            if (data.status === 'ok') {
                downloadFile(data.data, data.filename, data.content_type);
                showNotification('{{ lang._("Whitelist exported successfully") }}', 'success');
            } else {
                showNotification('{{ lang._("Failed to export whitelist") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $('#add-sample-threats-btn').click(function() {
        const btn = $(this);
        setButtonLoading(btn, true);
        ajaxPost('/api/webguard/service/addSampleThreats', {}, function(data) {
            setButtonLoading(btn, false);
            if (data.status === 'ok') {
                showNotification('{{ lang._("Sample threats added") }}', 'success');
                loadThreats();
            } else {
                showNotification('{{ lang._("Failed to add sample threats") }}', 'error');
            }
        });
    });

    $('#clear-logs-btn').click(function() {
        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/clearLogs', {}, function(data) {
            setButtonLoading($('#clear-logs-btn'), false);
            if (data.status === 'ok') {
                showNotification('{{ lang._("Logs cleared") }}', 'success');
            } else {
                showNotification('{{ lang._("Failed to clear logs") }}', 'error');
            }
        });
    });

    $('#restart-service-btn').click(function() {
        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/restart', {}, function(data) {
            setButtonLoading($('#restart-service-btn'), false);
            if (data.status === 'ok') {
                showNotification('{{ lang._("Service restarted") }}', 'success');
                setTimeout(loadStats, 2000);
            } else {
                showNotification('{{ lang._("Failed to restart service") }}', 'error');
            }
        });
    });

    // Modal confirm buttons
    $('#confirm-block-btn').click(function() {
        let ip = $('#block-ip').val().trim();
        let duration = $('#block-duration').val();
        let reason = $('#block-reason').val().trim();

        if (!ip) {
            showNotification('{{ lang._("Please enter an IP address") }}', 'error');
            return;
        }

        if (!isValidIP(ip)) {
            showNotification('{{ lang._("Please enter a valid IP address") }}', 'error');
            return;
        }

        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/blockIP', {
            ip: ip,
            duration: duration,
            reason: reason,
            block_type: 'manual'
        }, function(data) {
            setButtonLoading($('#confirm-block-btn'), false);
            if (data.status === 'ok') {
                $('#block-ip-modal').modal('hide');
                showNotification('{{ lang._("IP blocked successfully") }}', 'success');
                loadStats(); 
                loadBlockedIps(); 
                clearForm('block-ip-form');
            } else {
                showNotification('{{ lang._("Failed to block IP") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $('#confirm-bulk-block-btn').click(function() {
        let ips = $('#bulk-block-ips').val().trim();
        let duration = $('#bulk-block-duration').val();
        let reason = $('#bulk-block-reason').val().trim();

        if (!ips) {
            showNotification('{{ lang._("Please enter IP addresses") }}', 'error');
            return;
        }

        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/bulkBlock', {
            ip_list: ips,
            duration: duration,
            reason: reason,
            block_type: 'manual'
        }, function(data) {
            setButtonLoading($('#confirm-bulk-block-btn'), false);
            if (data.status === 'ok') {
                $('#bulk-block-modal').modal('hide');
                showNotification('{{ lang._("IPs blocked successfully") }}', 'success');
                loadStats(); 
                loadBlockedIps(); 
                clearForm('bulk-block-form');
            } else {
                showNotification('{{ lang._("Failed to bulk block IPs") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $('#confirm-whitelist-btn').click(function() {
        let ip = $('#whitelist-ip').val().trim();
        let description = $('#whitelist-description').val().trim();
        let permanent = $('#whitelist-permanent').is(':checked') ? '1' : '0';

        if (!ip) {
            showNotification('{{ lang._("Please enter an IP address") }}', 'error');
            return;
        }

        if (!isValidIP(ip)) {
            showNotification('{{ lang._("Please enter a valid IP address") }}', 'error');
            return;
        }

        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/addWhitelist', {
            ip: ip,
            description: description,
            permanent: permanent
        }, function(data) {
            setButtonLoading($('#confirm-whitelist-btn'), false);
            if (data.status === 'ok') {
                $('#add-whitelist-modal').modal('hide');
                showNotification('{{ lang._("IP whitelisted successfully") }}', 'success');
                loadStats(); 
                loadWhitelist(); 
                clearForm('add-whitelist-form');
            } else {
                showNotification('{{ lang._("Failed to whitelist IP") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    // Dynamic table button events
    $(document).on('click', '.unblock-btn', function() {
        const ip = $(this).data('ip');
        ajaxPost('/api/webguard/service/unblockIP', { ip }, function(data) {
            if (data.status === 'ok') {
                showNotification('{{ lang._("IP unblocked successfully") }}', 'success');
                loadStats();
                loadBlockedIps();
            } else {
                showNotification('{{ lang._("Failed to unblock IP") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $(document).on('click', '.remove-whitelist-btn', function() {
        const ip = $(this).data('ip');
        ajaxPost('/api/webguard/service/removeWhitelist', { ip }, function(data) {
            if (data.status === 'ok') {
                showNotification('{{ lang._("IP removed from whitelist") }}', 'success');
                loadStats();
                loadWhitelist();
            } else {
                showNotification('{{ lang._("Failed to remove IP from whitelist") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $(document).on('click', '.block-threat-btn', function() {
        const ip = $(this).data('ip');
        ajaxPost('/api/webguard/service/blockIP', {
            ip: ip,
            duration: 3600,
            reason: 'Blocked from threats',
            block_type: 'threat'
        }, function(data) {
            if (data.status === 'ok') {
                showNotification('{{ lang._("IP blocked from threats") }}', 'success');
                loadStats();
                loadBlockedIps();
            } else {
                showNotification('{{ lang._("Failed to block IP") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $(document).on('click', '.whitelist-threat-btn', function() {
        const ip = $(this).data('ip');
        ajaxPost('/api/webguard/service/addWhitelist', {
            ip: ip,
            description: 'Whitelisted from threats',
            permanent: '1'
        }, function(data) {
            if (data.status === 'ok') {
                showNotification('{{ lang._("IP added to whitelist") }}', 'success');
                loadStats();
                loadWhitelist();
            } else {
                showNotification('{{ lang._("Failed to whitelist IP") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $(document).on('click', '.mark-false-positive-btn', function() {
        const threatId = $(this).data('threat-id');
        const btn = $(this);
        setButtonLoading(btn, true);
        const comment = prompt('{{ lang._("Enter reason for marking as false positive (optional):") }}') || '';
        ajaxPost('/api/webguard/threats/markFalsePositive/' + threatId, { comment: comment }, function(data) {
            setButtonLoading(btn, false);
            if (data.status === 'ok') {
                showNotification(data.message || '{{ lang._("Threat marked as false positive") }}', 'success');
                loadFalsePositives();
            } else {
                showNotification('{{ lang._("Failed to mark as false positive") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $(document).on('click', '.view-false-positive-btn', function() {
        const threatId = $(this).data('threat-id');
        ajaxGet('/api/webguard/threats/getDetail/' + threatId, {}, function(data) {
            if (data.status === 'ok') {
                const threat = data.data;
                let html = '<div class="threat-detail-section">';
                html += '<h5>{{ lang._("Basic Information") }}</h5>';
                html += '<div class="row">';
                html += '<div class="col-md-6"><strong>{{ lang._("IP Address") }}:</strong> ' + (threat.ip_address || '-') + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Threat Type") }}:</strong> ' + (threat.threat_type || '-') + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Severity") }}:</strong> <span class="label label-' + (threat.severity === 'high' ? 'danger' : threat.severity === 'medium' ? 'warning' : 'info') + '">' + (threat.severity || 'LOW').toUpperCase() + '</span></div>';
                html += '<div class="col-md-6"><strong>{{ lang._("First Seen") }}:</strong> ' + formatDate(threat.first_seen_iso) + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Last Seen") }}:</strong> ' + formatDate(threat.last_seen_iso) + '</div>';
                html += '<div class="col-md-6"><strong>{{ lang._("Reason") }}:</strong> ' + (threat.description.match(/\[FALSE POSITIVE: (.*?)\]/) ? threat.description.match(/\[FALSE POSITIVE: (.*?)\]/)[1] : 'No reason') + '</div>';
                html += '</div></div>';
                if (threat.payload) {
                    html += '<div class="threat-detail-section">';
                    html += '<h5>{{ lang._("Payload") }}</h5>';
                    html += '<pre>' + threat.payload + '</pre>';
                    html += '</div>';
                }
                $('#false-positive-detail-content').html(html);
                $('#false-positive-detail-modal').modal('show');
            } else {
                showNotification('{{ lang._("Failed to load false positive details") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $(document).on('click', '.unmark-false-positive-btn', function() {
        const threatId = $(this).data('threat-id');
        const btn = $(this);
        setButtonLoading(btn, true);
        const comment = prompt('{{ lang._("Enter reason for unmarking (optional):") }}') || '';
        ajaxPost('/api/webguard/threats/unmarkFalsePositive/' + threatId, { comment: comment }, function(data) {
            setButtonLoading(btn, false);
            if (data.status === 'ok') {
                $('#false-positive-detail-modal').modal('hide');
                showNotification(data.message || '{{ lang._("Threat unmarked as false positive") }}', 'success');
                loadFalsePositives();
            } else {
                showNotification('{{ lang._("Failed to unmark as false positive") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    // Functions
    function loadStats() {
        ajaxGet('/api/webguard/service/status', {}, function(data) {
            if (data && data.status === 'ok') {
                $('#service-status').text(
                data.running ? '{{ lang._("Running") }}' : '{{ lang._("Stopped") }}'
                );
            }
        });

        ajaxGet('/api/webguard/service/getStats', {}, function(data) {
            if (data && data.status === 'ok' && data.data) {
                let s = data.data;
                $('#active-blocks').text(s.ips_blocked != null 
                    ? s.ips_blocked 
                    : (s.blocked_count || 0)
                );
                $('#temp-blocks').text(s.threats_blocked != null 
                    ? s.threats_blocked 
                    : (s.temp_blocks || 0)
                );
                $('#whitelist-count').text(s.whitelist_count != null 
                    ? s.whitelist_count 
                    : 0
                );
            }
        });
    }

    function loadBlockedIps() {
        ajaxGet('/api/webguard/service/listBlocked', {}, function(data) {
            let tbody = $('#blocked-table tbody').empty();

            if (data && data.status === 'ok' && data.data && data.data.blocked_ips) {
                const arr = data.data.blocked_ips;
                if (arr.length) {
                    arr.forEach(function(item) {
                        let badgeClass = item.block_type === 'permanent' ? 'danger' : 'warning';
                        let row = $('<tr>');
                        row.append('<td><strong>' + item.ip_address + '</strong></td>');
                        row.append('<td><span class="label label-' + badgeClass + '">' + 
                            (item.block_type || 'manual').toUpperCase() + '</span></td>');
                        row.append('<td>' + formatDate(item.blocked_since_iso) + '</td>');
                        row.append('<td>' + (item.expires_at_iso ? formatDate(item.expires_at_iso) : '{{ lang._("Never") }}') + '</td>');
                        row.append('<td>' + (item.reason || 'Manual block') + '</td>');
                        row.append('<td><button class="btn btn-xs btn-warning unblock-btn" data-ip="' + 
                            item.ip_address + '"><i class="fa fa-unlock"></i> {{ lang._("Unblock") }}</button></td>');
                        tbody.append(row);
                    });
                } else {
                    tbody.append(createEmptyState('{{ lang._("No blocked IPs found") }}', 'ban'));
                }
            } else {
                tbody.append(createErrorState('{{ lang._("Error loading blocked IPs") }}'));
            }
        });
    }

    function loadWhitelist() {
        ajaxGet('/api/webguard/service/listWhitelist', {}, function(data) {
            let tbody = $('#whitelist-table tbody').empty();

            if (data && data.status === 'ok' && data.data && data.data.whitelist) {
                const arr = data.data.whitelist;
                if (arr.length) {
                    arr.forEach(function(item) {
                        let badgeClass = item.permanent ? 'success' : 'warning';
                        let type = item.permanent ? '{{ lang._("Permanent") }}' : '{{ lang._("Temporary") }}';
                        let row = $('<tr>');
                        row.append('<td><strong>' + item.ip_address + '</strong></td>');
                        row.append('<td>' + (item.description || 'Manual entry') + '</td>');
                        row.append('<td>' + formatDate(item.added_at_iso) + '</td>');
                        row.append('<td><span class="label label-' + badgeClass + '">' + type + '</span></td>');
                        row.append('<td><button class="btn btn-xs btn-danger remove-whitelist-btn" data-ip="' + 
                            item.ip_address + '"><i class="fa fa-times"></i> {{ lang._("Remove") }}</button></td>');
                        tbody.append(row);
                    });
                } else {
                    tbody.append(createEmptyState('{{ lang._("No whitelist entries found") }}', 'check-circle'));
                }
            } else {
                tbody.append(createErrorState('{{ lang._("Error loading whitelist") }}'));
            }
        });
    }

    function loadThreats() {
        ajaxGet('/api/webguard/service/getThreats', {}, function(data) {
            let tbody = $('#threats-table tbody').empty();

            if (data && data.status === 'ok' && data.data && data.data.threats) {
                const arr = data.data.threats;
                if (arr.length) {
                    arr.forEach(function(item) {
                        let severityClass = {
                            'high': 'danger',
                            'medium': 'warning', 
                            'low': 'info'
                        }[item.severity] || 'info';
                        
                        let row = $('<tr>');
                        row.append('<td><strong>' + item.ip_address + '</strong></td>');
                        row.append('<td>' + (item.threat_type || 'Unknown') + '</td>');
                        row.append('<td><span class="label label-' + severityClass + '">' + 
                            (item.severity || 'LOW').toUpperCase() + '</span></td>');
                        row.append('<td>' + formatDate(item.first_seen_iso) + '</td>');
                        row.append('<td>' + formatDate(item.last_seen_iso) + '</td>');
                        row.append('<td>' +
                            '<button class="btn btn-xs btn-danger block-threat-btn" data-ip="' + item.ip_address + '">' +
                            '<i class="fa fa-ban"></i> {{ lang._("Block") }}</button> ' +
                            '<button class="btn btn-xs btn-success whitelist-threat-btn" data-ip="' + item.ip_address + '">' +
                            '<i class="fa fa-check"></i> {{ lang._("Whitelist") }}</button>' +
                            '</td>');
                        tbody.append(row);
                    });
                } else {
                    tbody.append(createEmptyState('{{ lang._("No threats detected") }}', 'shield'));
                }
            } else {
                tbody.append(createEmptyState('{{ lang._("No threat data available") }}', 'exclamation-triangle'));
            }
        });
    }

    function loadFalsePositives() {
        ajaxGet('/api/webguard/threats/getFalsePositives', {}, function(data) {
            let tbody = $('#false-positives-table tbody').empty();

            if (data && data.status === 'ok' && data.data && data.data.threats) {
                const arr = data.data.threats;
                if (arr.length) {
                    arr.forEach(function(item) {
                        let severityClass = {
                            'high': 'danger',
                            'medium': 'warning',
                            'low': 'info'
                        }[item.severity] || 'info';
                        let reason = item.description.match(/\[FALSE POSITIVE: (.*?)\]/) ? item.description.match(/\[FALSE POSITIVE: (.*?)\]/)[1] : 'No reason';
                        let row = $('<tr>');
                        row.append('<td><strong>' + (item.ip_address || '-') + '</strong></td>');
                        row.append('<td>' + (item.threat_type || 'Unknown') + '</td>');
                        row.append('<td><span class="label label-' + severityClass + '">' + (item.severity || 'LOW').toUpperCase() + '</span></td>');
                        row.append('<td>' + formatDate(item.first_seen_iso) + '</td>');
                        row.append('<td>' + reason + '</td>');
                        row.append('<td>' +
                            '<button class="btn btn-xs btn-warning mark-false-positive-btn" data-threat-id="' + item.id + '">' +
                            '<i class="fa fa-times"></i> {{ lang._("Mark") }}</button> ' +
                            '<button class="btn btn-xs btn-info view-false-positive-btn" data-threat-id="' + item.id + '">' +
                            '<i class="fa fa-eye"></i> {{ lang._("View") }}</button>' +
                            '</td>');
                        tbody.append(row);
                    });
                } else {
                    tbody.append(createEmptyState('{{ lang._("No false positives found") }}', 'times-circle'));
                }
            } else {
                tbody.append(createErrorState('{{ lang._("Error loading false positives") }}'));
            }
        });
    }

    function createEmptyState(message, icon) {
        return '<tr><td colspan="6" class="empty-state">' +
            '<i class="fa fa-' + icon + '"></i>' +
            '<h4>' + message + '</h4>' +
            '<p>{{ lang._("No data to display at this time") }}</p>' +
            '</td></tr>';
    }

    function createErrorState(message) {
        return '<tr><td colspan="6" class="empty-state">' +
            '<i class="fa fa-exclamation-triangle" style="color: #ff6b6b;"></i>' +
            '<h4 style="color: #ff6b6b;">' + message + '</h4>' +
            '<p>{{ lang._("Please try refreshing the page") }}</p>' +
            '</td></tr>';
    }

    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        try { 
            return new Date(dateString).toLocaleString(); 
        } catch (e) { 
            return dateString; 
        }
    }

    function isValidIP(ip) {
        var ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        var ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    function clearForm(formId) {
        $('#' + formId + ' input[type="text"], #' + formId + ' textarea').val('');
        $('#' + formId + ' input[type="checkbox"]').prop('checked', false);
        $('#' + formId + ' select').prop('selectedIndex', 0);
    }

    function setButtonLoading(btn, loading) {
        if (loading) {
            btn.addClass('btn-loading').prop('disabled', true);
        } else {
            btn.removeClass('btn-loading').prop('disabled', false);
        }
    }

    function showNotification(message, type) {
        var notification = $('<div class="notification-modern notification-' + type + '">' +
            '<i class="fa fa-' + getNotificationIcon(type) + '"></i> ' + message + '</div>');

        $('body').append(notification);
        setTimeout(function() {
            notification.fadeOut(300, function() {
                $(this).remove();
            });
        }, 5000);
    }

    function getNotificationIcon(type) {
        var icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    // DOWNLOAD FILE FUNCTION - NEW
    function downloadFile(data, filename, contentType) {
        try {
            // Crea un blob con i dati
            const blob = new Blob([data], { type: contentType });
            
            // Crea un link temporaneo per il download
            const link = document.createElement('a');
            link.href = window.URL.createObjectURL(blob);
            link.download = filename;
            
            // Aggiungi il link al DOM, clicca e rimuovi
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            // Pulisci l'URL del blob
            window.URL.revokeObjectURL(link.href);
        } catch (error) {
            console.error('Download error:', error);
            showNotification('{{ lang._("Download failed") }}', 'error');
        }
    }

    // AJAX FUNCTIONS - IMPROVED
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
        $.ajax({
            url: url,
            type: 'GET',
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
                
                showNotification('{{ lang._("Error loading data") }}: ' + msg, 'error');
            }
        });
    }
});
</script>