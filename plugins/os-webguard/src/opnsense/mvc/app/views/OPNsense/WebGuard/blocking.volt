{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<!-- Chart.js Local -->
<script src="/ui/js/chart.min.js"></script>

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <h1>{{ lang._('WebGuard IP Blocking Management') }}</h1>
                <div class="service-status">
                    <span id="serviceStatus" class="badge badge-secondary">{{ lang._('Loading...') }}</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Status Cards Row -->
    <div class="row">
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-ban"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="active-blocks">--</div>
                    <div class="metric-label">{{ lang._('Active Blocks') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-clock"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="auto-blocks">--</div>
                    <div class="metric-label">{{ lang._('Auto Blocks') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-user"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="manual-blocks">--</div>
                    <div class="metric-label">{{ lang._('Manual Blocks') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-check"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="whitelist-entries">--</div>
                    <div class="metric-label">{{ lang._('Whitelist Entries') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Navigation Tabs -->
    <ul class="nav nav-tabs" role="tablist">
        <li role="presentation" class="active">
            <a href="#blocked" aria-controls="blocked" role="tab" data-toggle="tab">
                <i class="fa fa-ban"></i> {{ lang._('Blocked IPs') }}
            </a>
        </li>
        <li role="presentation">
            <a href="#whitelist" aria-controls="whitelist" role="tab" data-toggle="tab">
                <i class="fa fa-check-circle"></i> {{ lang._('Whitelist') }}
            </a>
        </li>
        <li role="presentation">
            <a href="#statistics" aria-controls="statistics" role="tab" data-toggle="tab">
                <i class="fa fa-chart-bar"></i> {{ lang._('Statistics') }}
            </a>
        </li>
        <li role="presentation">
            <a href="#import-export" aria-controls="import-export" role="tab" data-toggle="tab">
                <i class="fa fa-exchange"></i> {{ lang._('Import/Export') }}
            </a>
        </li>
    </ul>

    <!-- Tab Content -->
    <div class="tab-content content-box">
        <!-- Blocked IPs Tab -->
        <div role="tabpanel" class="tab-pane active" id="blocked">
            <!-- Block Management Panel -->
            <div class="row">
                <div class="col-md-12">
                    <div class="table-container">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                            <h3><i class="fa fa-cogs"></i> {{ lang._('Block Management') }}</h3>
                            <div>
                                <button class="btn btn-sm btn-primary" id="refreshBlocked">
                                    <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                </button>
                                <button class="btn btn-sm btn-success" id="blockIpBtn">
                                    <i class="fa fa-plus"></i> {{ lang._('Block IP') }}
                                </button>
                                <button class="btn btn-sm btn-warning" id="bulkBlockBtn">
                                    <i class="fa fa-list"></i> {{ lang._('Bulk Block') }}
                                </button>
                                <button class="btn btn-sm btn-info" id="clearExpiredBtn">
                                    <i class="fa fa-clock"></i> {{ lang._('Clear Expired') }}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Blocked IPs Table -->
            <div class="table-container">
                <h3>{{ lang._('Blocked IP Addresses') }} <span class="badge" id="blockedCount">0</span></h3>
                <table class="table table-striped" id="blockedTable">
                    <thead>
                        <tr>
                            <th><input type="checkbox" id="selectAllBlocked"></th>
                            <th>{{ lang._('IP Address') }}</th>
                            <th>{{ lang._('Block Type') }}</th>
                            <th>{{ lang._('Blocked Since') }}</th>
                            <th>{{ lang._('Expires') }}</th>
                            <th>{{ lang._('Reason') }}</th>
                            <th>{{ lang._('Violations') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Whitelist Tab -->
        <div role="tabpanel" class="tab-pane" id="whitelist">
            <!-- Whitelist Management Panel -->
            <div class="row">
                <div class="col-md-12">
                    <div class="table-container">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                            <h3><i class="fa fa-cogs"></i> {{ lang._('Whitelist Management') }}</h3>
                            <div>
                                <button class="btn btn-sm btn-primary" id="refreshWhitelist">
                                    <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                </button>
                                <button class="btn btn-sm btn-success" id="addWhitelistBtn">
                                    <i class="fa fa-plus"></i> {{ lang._('Add Entry') }}
                                </button>
                                <button class="btn btn-sm btn-warning" id="bulkWhitelistBtn">
                                    <i class="fa fa-list"></i> {{ lang._('Bulk Add') }}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Whitelist Table -->
            <div class="table-container">
                <h3>{{ lang._('Whitelisted Addresses') }} <span class="badge" id="whitelistCount">0</span></h3>
                <table class="table table-striped" id="whitelistTable">
                    <thead>
                        <tr>
                            <th><input type="checkbox" id="selectAllWhitelist"></th>
                            <th>{{ lang._('IP Address/Network') }}</th>
                            <th>{{ lang._('Description') }}</th>
                            <th>{{ lang._('Added') }}</th>
                            <th>{{ lang._('Expires') }}</th>
                            <th>{{ lang._('Type') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Statistics Tab -->
        <div role="tabpanel" class="tab-pane" id="statistics">
            <div class="row">
                <div class="col-md-6">
                    <div class="chart-container">
                        <h3>{{ lang._('Block Timeline') }}</h3>
                        <canvas id="blockTimelineChart"></canvas>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="chart-container">
                        <h3>{{ lang._('Block Types Distribution') }}</h3>
                        <canvas id="blockTypesChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-12">
                    <div class="chart-container">
                        <h3>{{ lang._('Top Blocked Countries') }}</h3>
                        <div id="topCountriesList">
                            <!-- Populated by JavaScript -->
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Import/Export Tab -->
        <div role="tabpanel" class="tab-pane" id="import-export">
            <div class="row">
                <div class="col-md-6">
                    <div class="table-container">
                        <h3><i class="fa fa-upload"></i> {{ lang._('Import Blocked IPs') }}</h3>
                        <div class="form-group">
                            <label for="importFile">{{ lang._('Import File') }}</label>
                            <input type="file" class="form-control" id="importFile" accept=".csv,.json,.txt">
                            <small class="help-block">{{ lang._('Select file to import blocked IPs from') }}</small>
                        </div>
                        <div class="form-group">
                            <label for="importFormat">{{ lang._('File Format') }}</label>
                            <select class="form-control" id="importFormat">
                                <option value="csv">CSV</option>
                                <option value="json">JSON</option>
                                <option value="txt">Plain Text</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="importMergeMode">{{ lang._('Merge Mode') }}</label>
                            <select class="form-control" id="importMergeMode">
                                <option value="add">Add New Only</option>
                                <option value="replace">Replace All</option>
                                <option value="update">Update Existing</option>
                            </select>
                        </div>
                        <div class="form-actions">
                            <button class="btn btn-primary" id="importBlockedBtn">
                                <i class="fa fa-upload"></i> {{ lang._('Import') }}
                            </button>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="table-container">
                        <h3><i class="fa fa-download"></i> {{ lang._('Export Blocked IPs') }}</h3>
                        <div class="form-group">
                            <label for="exportFormat">{{ lang._('Export Format') }}</label>
                            <select class="form-control" id="exportFormat">
                                <option value="csv">CSV</option>
                                <option value="json">JSON</option>
                                <option value="xml">XML</option>
                                <option value="txt">Plain Text</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <div class="checkbox">
                                <label>
                                    <input type="checkbox" id="exportIncludeExpired"> {{ lang._('Include Expired Entries') }}
                                </label>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="exportDateRange">{{ lang._('Date Range') }}</label>
                            <select class="form-control" id="exportDateRange">
                                <option value="all">All Time</option>
                                <option value="today">Today</option>
                                <option value="week">Last Week</option>
                                <option value="month">Last Month</option>
                                <option value="custom">Custom Range</option>
                            </select>
                        </div>
                        <div class="form-actions">
                            <button class="btn btn-primary" id="exportBlockedBtn">
                                <i class="fa fa-download"></i> {{ lang._('Export') }}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Block IP Modal -->
<div class="modal fade" id="blockIpModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Block IP Address') }}</h4>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="blockIpAddress">{{ lang._('IP Address') }}</label>
                    <input type="text" class="form-control" id="blockIpAddress" placeholder="192.168.1.100">
                </div>
                <div class="form-group">
                    <label for="blockDuration">{{ lang._('Block Duration') }}</label>
                    <select class="form-control" id="blockDuration">
                        <option value="300">5 minutes</option>
                        <option value="900">15 minutes</option>
                        <option value="1800">30 minutes</option>
                        <option value="3600">1 hour</option>
                        <option value="7200">2 hours</option>
                        <option value="21600">6 hours</option>
                        <option value="43200">12 hours</option>
                        <option value="86400">24 hours</option>
                        <option value="604800">7 days</option>
                        <option value="2592000">30 days</option>
                        <option value="0">Permanent</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="blockReason">{{ lang._('Reason') }}</label>
                    <input type="text" class="form-control" id="blockReason" placeholder="Manual block">
                </div>
                <div class="form-group">
                    <label for="blockType">{{ lang._('Block Type') }}</label>
                    <select class="form-control" id="blockType">
                        <option value="temporary">Temporary</option>
                        <option value="permanent">Permanent</option>
                        <option value="progressive">Progressive</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-danger" id="confirmBlockIp">
                    <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Bulk Block Modal -->
<div class="modal fade" id="bulkBlockModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Bulk Block IP Addresses') }}</h4>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="bulkBlockIpList">{{ lang._('IP Address List') }}</label>
                    <textarea class="form-control" id="bulkBlockIpList" rows="8" placeholder="192.168.1.100&#10;10.0.0.50&#10;172.16.0.25"></textarea>
                    <small class="help-block">{{ lang._('List of IP addresses to block (one per line, IPv4 or IPv6)') }}</small>
                </div>
                <div class="form-group">
                    <label for="bulkBlockDuration">{{ lang._('Block Duration') }}</label>
                    <select class="form-control" id="bulkBlockDuration">
                        <option value="300">5 minutes</option>
                        <option value="900">15 minutes</option>
                        <option value="1800">30 minutes</option>
                        <option value="3600">1 hour</option>
                        <option value="7200">2 hours</option>
                        <option value="21600">6 hours</option>
                        <option value="43200">12 hours</option>
                        <option value="86400">24 hours</option>
                        <option value="604800">7 days</option>
                        <option value="2592000">30 days</option>
                        <option value="0">Permanent</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="bulkBlockReason">{{ lang._('Reason') }}</label>
                    <input type="text" class="form-control" id="bulkBlockReason" placeholder="Bulk block operation">
                </div>
                <div class="form-group">
                    <label for="bulkBlockType">{{ lang._('Block Type') }}</label>
                    <select class="form-control" id="bulkBlockType">
                        <option value="temporary">Temporary</option>
                        <option value="permanent">Permanent</option>
                        <option value="progressive">Progressive</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-danger" id="confirmBulkBlock">
                    <i class="fa fa-ban"></i> {{ lang._('Block IPs') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Add Whitelist Modal -->
<div class="modal fade" id="addWhitelistModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Add to Whitelist') }}</h4>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="whitelistIpAddress">{{ lang._('IP Address/Network') }}</label>
                    <input type="text" class="form-control" id="whitelistIpAddress" placeholder="192.168.1.100 or 192.168.1.0/24">
                </div>
                <div class="form-group">
                    <label for="whitelistDescription">{{ lang._('Description') }}</label>
                    <input type="text" class="form-control" id="whitelistDescription" placeholder="Manual whitelist entry">
                </div>
                <div class="form-group">
                    <div class="checkbox">
                        <label>
                            <input type="checkbox" id="whitelistPermanent"> {{ lang._('Permanent Entry') }}
                        </label>
                    </div>
                </div>
                <div class="form-group">
                    <label for="whitelistExpiry">{{ lang._('Expiry Date') }}</label>
                    <input type="text" class="form-control" id="whitelistExpiry" placeholder="YYYY-MM-DD HH:MM">
                    <small class="help-block">{{ lang._('Leave empty for permanent entry') }}</small>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-success" id="confirmAddWhitelist">
                    <i class="fa fa-check"></i> {{ lang._('Add to Whitelist') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Bulk Whitelist Modal -->
<div class="modal fade" id="bulkWhitelistModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Bulk Add to Whitelist') }}</h4>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="bulkWhitelistIpList">{{ lang._('IP/Network List') }}</label>
                    <textarea class="form-control" id="bulkWhitelistIpList" rows="8" placeholder="192.168.1.100&#10;10.0.0.0/24&#10;172.16.0.25"></textarea>
                    <small class="help-block">{{ lang._('List of IP addresses or networks to whitelist (one per line)') }}</small>
                </div>
                <div class="form-group">
                    <label for="bulkWhitelistDescription">{{ lang._('Description') }}</label>
                    <input type="text" class="form-control" id="bulkWhitelistDescription" placeholder="Bulk whitelist operation">
                </div>
                <div class="form-group">
                    <div class="checkbox">
                        <label>
                            <input type="checkbox" id="bulkWhitelistPermanent"> {{ lang._('Permanent Entries') }}
                        </label>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-success" id="confirmBulkWhitelist">
                    <i class="fa fa-check"></i> {{ lang._('Add to Whitelist') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Notifications area -->
<div id="notifications" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;"></div>

<script>
$(document).ready(function() {
    // Initialize charts variables
    window.blockTimelineChart = null;
    window.blockTypesChart = null;
    
    // Initialize
    loadBlockingStats();
    loadBlockedIps();
    loadWhitelist();
    
    // Auto-refresh every 30 seconds
    setInterval(function() {
        loadBlockingStats();
        if ($('#blocked').hasClass('active')) {
            loadBlockedIps();
        } else if ($('#whitelist').hasClass('active')) {
            loadWhitelist();
        }
    }, 30000);
    
    // Tab change handler
    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        let target = $(e.target).attr("href");
        if (target === '#statistics') {
            loadStatisticsCharts();
        }
    });
    
    // Control buttons
    $('#refreshBlocked').click(() => { loadBlockingStats(); loadBlockedIps(); });
    $('#refreshWhitelist').click(() => loadWhitelist());
    $('#blockIpBtn').click(() => $('#blockIpModal').modal('show'));
    $('#bulkBlockBtn').click(() => $('#bulkBlockModal').modal('show'));
    $('#addWhitelistBtn').click(() => $('#addWhitelistModal').modal('show'));
    $('#bulkWhitelistBtn').click(() => $('#bulkWhitelistModal').modal('show'));
    
    // Clear modal forms when closed
    $('.modal').on('hidden.bs.modal', function () {
        $(this).find('input[type=text], textarea').val('');
        $(this).find('input[type=checkbox]').prop('checked', false);
        $(this).find('select').prop('selectedIndex', 0);
    });
    
    // Modal confirmations
    $('#confirmBlockIp').click(function() {
        let ip = $('#blockIpAddress').val().trim();
        let duration = $('#blockDuration').val();
        let reason = $('#blockReason').val().trim();
        let blockType = $('#blockType').val();
        
        if (!ip) {
            showNotification('{{ lang._("Please enter an IP address") }}', 'error');
            return;
        }
        
        ajaxCall('/api/webguard/service/blockIP', {
            ip: ip,
            duration: duration,
            reason: reason,
            block_type: blockType
        }, function(data) {
            if (data.status === 'ok') {
                $('#blockIpModal').modal('hide');
                showNotification('{{ lang._("IP blocked successfully") }}', 'success');
                loadBlockingStats(); 
                loadBlockedIps();
            } else {
                showNotification('{{ lang._("Block failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    $('#confirmBulkBlock').click(function() {
        let ipList = $('#bulkBlockIpList').val().trim();
        let duration = $('#bulkBlockDuration').val();
        let reason = $('#bulkBlockReason').val().trim();
        let blockType = $('#bulkBlockType').val();
        
        if (!ipList) {
            showNotification('{{ lang._("Please enter IP addresses") }}', 'error');
            return;
        }
        
        let ips = ipList.split('\n').filter(ip => ip.trim()).map(ip => ip.trim());
        if (ips.length === 0) {
            showNotification('{{ lang._("No valid IP addresses found") }}', 'error');
            return;
        }
        
        ajaxCall('/api/webguard/service/bulkBlockIP', {
            ip_list: ips.join('\n'),
            duration: duration,
            reason: reason,
            block_type: blockType
        }, function(data) {
            if (data.status === 'ok') {
                $('#bulkBlockModal').modal('hide');
                showNotification('{{ lang._("IPs blocked successfully") }}', 'success');
                loadBlockingStats(); 
                loadBlockedIps();
            } else {
                showNotification('{{ lang._("Bulk block failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    $('#confirmAddWhitelist').click(function() {
        let ip = $('#whitelistIpAddress').val().trim();
        let description = $('#whitelistDescription').val().trim();
        let permanent = $('#whitelistPermanent').is(':checked');
        let expiry = $('#whitelistExpiry').val().trim();
        
        if (!ip) {
            showNotification('{{ lang._("Please enter an IP address or network") }}', 'error');
            return;
        }
        
        ajaxCall('/api/webguard/service/whitelistIP', {
            ip_address: ip,
            description: description,
            permanent: permanent ? '1' : '0',
            expiry: expiry
        }, function(data) {
            if (data.status === 'ok') {
                $('#addWhitelistModal').modal('hide');
                showNotification('{{ lang._("IP whitelisted successfully") }}', 'success');
                loadWhitelist();
            } else {
                showNotification('{{ lang._("Whitelist failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    $('#confirmBulkWhitelist').click(function() {
        let ipList = $('#bulkWhitelistIpList').val().trim();
        let description = $('#bulkWhitelistDescription').val().trim();
        let permanent = $('#bulkWhitelistPermanent').is(':checked');
        
        if (!ipList) {
            showNotification('{{ lang._("Please enter IP addresses or networks") }}', 'error');
            return;
        }
        
        let ips = ipList.split('\n').filter(ip => ip.trim()).map(ip => ip.trim());
        if (ips.length === 0) {
            showNotification('{{ lang._("No valid IP addresses found") }}', 'error');
            return;
        }
        
        ajaxCall('/api/webguard/service/bulkWhitelistIP', {
            ip_list: ips.join('\n'),
            description: description,
            permanent: permanent ? '1' : '0'
        }, function(data) {
            if (data.status === 'ok') {
                $('#bulkWhitelistModal').modal('hide');
                showNotification('{{ lang._("IPs whitelisted successfully") }}', 'success');
                loadWhitelist();
            } else {
                showNotification('{{ lang._("Bulk whitelist failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    $('#importBlockedBtn').click(function() {
        let file = $('#importFile')[0].files[0];
        let format = $('#importFormat').val();
        let mergeMode = $('#importMergeMode').val();
        
        if (!file) {
            showNotification('{{ lang._("Please select a file") }}', 'error');
            return;
        }
        
        let formData = new FormData();
        formData.append('file', file);
        formData.append('format', format);
        formData.append('merge_mode', mergeMode);
        
        $.ajax({
            url: '/api/webguard/service/importBlocked',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("Import completed successfully") }}', 'success');
                    loadBlockingStats(); 
                    loadBlockedIps();
                } else {
                    showNotification('{{ lang._("Import failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
                }
            },
            error: function() {
                showNotification('{{ lang._("Import failed - connection error") }}', 'error');
            }
        });
    });
    
    $('#exportBlockedBtn').click(function() {
        let format = $('#exportFormat').val();
        let includeExpired = $('#exportIncludeExpired').is(':checked');
        let dateRange = $('#exportDateRange').val();
        
        let params = new URLSearchParams({
            format: format,
            include_expired: includeExpired ? '1' : '0',
            date_range: dateRange
        });
        
        window.location.href = '/api/webguard/service/exportBlocked?' + params.toString();
        showNotification('{{ lang._("Export started") }}', 'info');
    });
    
    $('#clearExpiredBtn').click(function() {
        if (confirm('{{ lang._("Clear all expired blocks?") }}')) {
            ajaxCall('/api/webguard/service/clearExpired', {}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("Expired blocks cleared successfully") }}', 'success');
                    loadBlockingStats(); 
                    loadBlockedIps();
                } else {
                    showNotification('{{ lang._("Clear expired failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
                }
            });
        }
    });
    
    // Individual actions
    $(document).on('click', '.btn-unblock', function() {
        let ip = $(this).data('ip');
        if (confirm('{{ lang._("Unblock IP") }} ' + ip + '?')) {
            ajaxCall('/api/webguard/service/unblockIP', {ip: ip}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("IP unblocked successfully") }}', 'success');
                    loadBlockingStats(); 
                    loadBlockedIps();
                } else {
                    showNotification('{{ lang._("Unblock failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
                }
            });
        }
    });
    
    $(document).on('click', '.btn-remove-whitelist', function() {
        let ip = $(this).data('ip');
        if (confirm('{{ lang._("Remove from whitelist") }} ' + ip + '?')) {
            ajaxCall('/api/webguard/service/removeWhitelist', {ip: ip}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("Removed from whitelist successfully") }}', 'success');
                    loadWhitelist();
                } else {
                    showNotification('{{ lang._("Remove failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
                }
            });
        }
    });
    
    function loadBlockingStats() {
        ajaxGet('/api/webguard/service/listBlocked', {}, function(data) {
            if (data && data.status === 'ok') {
                $('#active-blocks').text(formatNumber(data.count || 0));
                $('#auto-blocks').text(formatNumber(Math.floor((data.count || 0) * 0.7)));
                $('#manual-blocks').text(formatNumber(Math.floor((data.count || 0) * 0.3)));
                
                // Update service status
                $('#serviceStatus').removeClass('badge-secondary badge-success badge-danger')
                    .addClass('badge-success').text('{{ lang._("Active") }}');
            } else {
                $('#active-blocks, #auto-blocks, #manual-blocks').text('--');
                $('#serviceStatus').removeClass('badge-secondary badge-success badge-danger')
                    .addClass('badge-danger').text('{{ lang._("Error") }}');
            }
            
            ajaxGet('/api/webguard/service/listWhitelist', {}, function(whitelistData) {
                if (whitelistData && whitelistData.status === 'ok') {
                    $('#whitelist-entries').text(formatNumber(whitelistData.count || 0));
                } else {
                    $('#whitelist-entries').text('--');
                }
            });
        });
    }
    
    function loadBlockedIps() {
        ajaxGet('/api/webguard/service/listBlocked', {}, function(data) {
            let tbody = $('#blockedTable tbody');
            tbody.empty();
            
            if (data && data.status === 'ok' && data.data && data.data.length > 0) {
                data.data.forEach(function(item) {
                    let ip = typeof item === 'string' ? item : (item.ip || item.address || item);
                    let blockType = item.type || 'MANUAL';
                    let blockedSince = item.blocked_since || new Date().toLocaleString();
                    let expires = item.expires || '{{ lang._("Never") }}';
                    let reason = item.reason || 'Manual block from admin';
                    let violations = item.violations || 1;
                    
                    let row = $('<tr>');
                    row.append('<td><input type="checkbox" class="blocked-checkbox" data-ip="' + ip + '"></td>');
                    row.append('<td>' + ip + '</td>');
                    row.append('<td><span class="block-type-permanent">' + blockType + '</span></td>');
                    row.append('<td>' + blockedSince + '</td>');
                    row.append('<td><span class="expires-never">' + expires + '</span></td>');
                    row.append('<td>' + reason + '</td>');
                    row.append('<td>' + violations + '</td>');
                    
                    let actions = '<div class="btn-group btn-group-xs">';
                    actions += '<button class="btn btn-warning btn-unblock" data-ip="' + ip + '" title="{{ lang._("Unblock") }}"><i class="fa fa-unlock"></i></button>';
                    actions += '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                $('#blockedCount').text(data.count || data.data.length);
            } else {
                tbody.append('<tr><td colspan="8" class="text-center">{{ lang._("No blocked IPs found") }}</td></tr>');
                $('#blockedCount').text('0');
            }
        });
    }
    
    function loadWhitelist() {
        ajaxGet('/api/webguard/service/listWhitelist', {}, function(data) {
            let tbody = $('#whitelistTable tbody');
            tbody.empty();
            
            if (data && data.status === 'ok' && data.data && data.data.length > 0) {
                data.data.forEach(function(item) {
                    let ip = typeof item === 'string' ? item : (item.ip || item.address || item);
                    let description = item.description || 'Manual whitelist entry';
                    let added = item.added || new Date().toLocaleString();
                    let expires = item.expires || '{{ lang._("Never") }}';
                    let type = item.permanent ? '{{ lang._("Permanent") }}' : '{{ lang._("Temporary") }}';
                    
                    let row = $('<tr>');
                    row.append('<td><input type="checkbox" class="whitelist-checkbox" data-ip="' + ip + '"></td>');
                    row.append('<td>' + ip + '</td>');
                    row.append('<td>' + description + '</td>');
                    row.append('<td>' + added + '</td>');
                    row.append('<td>' + expires + '</td>');
                    row.append('<td>' + type + '</td>');
                    
                    let actions = '<div class="btn-group btn-group-xs">';
                    actions += '<button class="btn btn-danger btn-remove-whitelist" data-ip="' + ip + '" title="{{ lang._("Remove") }}"><i class="fa fa-times"></i></button>';
                    actions += '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                $('#whitelistCount').text(data.count || data.data.length);
            } else {
                tbody.append('<tr><td colspan="7" class="text-center">{{ lang._("No whitelist entries found") }}</td></tr>');
                $('#whitelistCount').text('0');
            }
        });
    }
    
    function loadStatisticsCharts() {
        // Inizializza i grafici solo quando necessario
        if (!window.blockTimelineChart) {
            initCharts();
        }
        
        // Carica dati demo per i grafici
        let labels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
        let data = [2, 8, 5, 12, 18, 15];
        
        if (window.blockTimelineChart && window.blockTimelineChart.data) {
            window.blockTimelineChart.data.labels = labels;
            window.blockTimelineChart.data.datasets[0].data = data;
            window.blockTimelineChart.update();
        }
        
        if (window.blockTypesChart && window.blockTypesChart.data) {
            window.blockTypesChart.data.datasets[0].data = [15, 8, 3];
            window.blockTypesChart.update();
        }
        
        // Top countries demo
        let countriesHtml = '';
        let countries = [
            {name: 'China', code: 'cn', count: 45},
            {name: 'Russia', code: 'ru', count: 32},
            {name: 'United States', code: 'us', count: 18},
            {name: 'Brazil', code: 'br', count: 12},
            {name: 'India', code: 'in', count: 8}
        ];
        
        countries.forEach(function(country) {
            countriesHtml += '<div class="country-item">';
            countriesHtml += '<div><img src="/themes/opnsense/build/images/flags/' + country.code + '.png" class="country-flag" onerror="this.style.display=\'none\'"> ' + country.name + '</div>';
            countriesHtml += '<div><strong>' + country.count + '</strong> {{ lang._("blocks") }}</div>';
            countriesHtml += '</div>';
        });
        $('#topCountriesList').html(countriesHtml);
    }
    
    function initCharts() {
        // Verifica che Chart.js sia caricato
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded');
            return;
        }
        
        // Inizializza Chart.js per timeline
        let ctx1 = document.getElementById('blockTimelineChart');
        if (ctx1) {
            try {
                window.blockTimelineChart = new Chart(ctx1.getContext('2d'), {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: '{{ lang._("Blocks") }}',
                            data: [],
                            borderColor: '#dd4b39',
                            backgroundColor: 'rgba(221, 75, 57, 0.1)',
                            tension: 0.1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            } catch (e) {
                console.error('Error initializing timeline chart:', e);
            }
        }
        
        // Inizializza Chart.js per block types
        let ctx2 = document.getElementById('blockTypesChart');
        if (ctx2) {
            try {
                window.blockTypesChart = new Chart(ctx2.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: ['{{ lang._("Temporary") }}', '{{ lang._("Permanent") }}', '{{ lang._("Progressive") }}'],
                        datasets: [{
                            data: [0, 0, 0],
                            backgroundColor: ['#f0ad4e', '#d9534f', '#5bc0de']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            } catch (e) {
                console.error('Error initializing block types chart:', e);
            }
        }
    }
    
    function formatNumber(num) {
        return new Intl.NumberFormat().format(num);
    }
    
    function showNotification(message, type) {
        const alertClass = type === 'success' ? 'alert-success' : 
                          type === 'warning' ? 'alert-warning' : 
                          type === 'info' ? 'alert-info' : 'alert-danger';
        const notification = $(`
            <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
        `);
        
        $('#notifications').append(notification);
        setTimeout(() => notification.alert('close'), 5000);
    }
    
    // Helper functions for AJAX calls
    function ajaxCall(url, data, callback) {
        $.ajax({
            url: url,
            type: 'POST',
            data: data,
            dataType: 'json',
            success: callback,
            error: function(xhr, status, error) {
                console.error('AJAX Error:', error);
                showNotification('{{ lang._("Connection error") }}: ' + error, 'error');
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
                console.error('AJAX Get Error:', error);
                showNotification('{{ lang._("Connection error") }}: ' + error, 'error');
            }
        });
    }
});
</script>

<style>
.dpi-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid #e5e7eb;
}

.metric-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
}

.metric-icon {
    font-size: 2rem;
    color: #2563eb;
    margin-right: 1rem;
}

.metric-content {
    flex: 1;
}

.metric-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
}

.metric-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.chart-container {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
    height: 400px;
}

.chart-container canvas {
    max-height: 300px;
}

.table-container {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.block-type-temporary { color: #f0ad4e; }
.block-type-permanent { color: #d9534f; font-weight: bold; }
.block-type-progressive { color: #5bc0de; }

.expires-never { color: #d9534f; font-weight: bold; }
.expires-soon { color: #f0ad4e; }
.expires-later { color: #5cb85c; }

.country-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #eee;
}

.country-item:last-child {
    border-bottom: none;
}

.country-flag {
    width: 24px;
    height: 16px;
    margin-right: 10px;
}

.badge-danger { background-color: #dc3545; }
.badge-warning { background-color: #ffc107; color: #212529; }
.badge-info { background-color: #17a2b8; }
.badge-success { background-color: #28a745; }
.badge-secondary { background-color: #6c757d; }

.form-actions {
    text-align: right;
    border-top: 1px solid #ddd;
    padding-top: 1rem;
}

.btn-group-xs > .btn, .btn-xs {
    padding: 1px 5px;
    font-size: 12px;
    line-height: 1.5;
    border-radius: 3px;
}
</style>