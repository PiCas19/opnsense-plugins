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
            </ul>

            <!-- Tab Content -->
            <div class="tab-content">
                <!-- Blocked IPs Tab -->
                <div role="tabpanel" class="tab-pane active" id="blocked">
                    <!-- Status Cards -->
                    <div class="row">
                        <div class="col-md-3">
                            <div class="info-box">
                                <span class="info-box-icon bg-red"><i class="fa fa-ban"></i></span>
                                <div class="info-box-content">
                                    <span class="info-box-text">{{ lang._('Active Blocks') }}</span>
                                    <span class="info-box-number" id="active-blocks">--</span>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="info-box">
                                <span class="info-box-icon bg-yellow"><i class="fa fa-clock"></i></span>
                                <div class="info-box-content">
                                    <span class="info-box-text">{{ lang._('Auto Blocks') }}</span>
                                    <span class="info-box-number" id="auto-blocks">--</span>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="info-box">
                                <span class="info-box-icon bg-blue"><i class="fa fa-user"></i></span>
                                <div class="info-box-content">
                                    <span class="info-box-text">{{ lang._('Manual Blocks') }}</span>
                                    <span class="info-box-number" id="manual-blocks">--</span>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="info-box">
                                <span class="info-box-icon bg-green"><i class="fa fa-check"></i></span>
                                <div class="info-box-content">
                                    <span class="info-box-text">{{ lang._('Whitelist Entries') }}</span>
                                    <span class="info-box-number" id="whitelist-entries">--</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Controls -->
                    <div class="row">
                        <div class="col-md-12">
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                    <h3 class="panel-title">
                                        <i class="fa fa-cogs"></i> {{ lang._('Block Management') }}
                                        <div class="pull-right">
                                            <button class="btn btn-xs btn-primary" id="refreshBlocked">
                                                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                            </button>
                                            <button class="btn btn-xs btn-success" id="blockIpBtn">
                                                <i class="fa fa-plus"></i> {{ lang._('Block IP') }}
                                            </button>
                                            <button class="btn btn-xs btn-warning" id="bulkBlockBtn">
                                                <i class="fa fa-list"></i> {{ lang._('Bulk Block') }}
                                            </button>
                                            <button class="btn btn-xs btn-info" id="clearExpiredBtn">
                                                <i class="fa fa-clock"></i> {{ lang._('Clear Expired') }}
                                            </button>
                                            <button class="btn btn-xs btn-default" id="exportBlockedBtn">
                                                <i class="fa fa-download"></i> {{ lang._('Export') }}
                                            </button>
                                        </div>
                                    </h3>
                                </div>
                                <div class="panel-body">
                                    <div class="row">
                                        <div class="col-md-2">
                                            <select class="form-control" id="blockTypeFilter">
                                                <option value="">{{ lang._('All Block Types') }}</option>
                                                <option value="temporary">{{ lang._('Temporary') }}</option>
                                                <option value="permanent">{{ lang._('Permanent') }}</option>
                                                <option value="progressive">{{ lang._('Progressive') }}</option>
                                            </select>
                                        </div>
                                        <div class="col-md-2">
                                            <input type="text" class="form-control" id="blockedIpFilter" placeholder="{{ lang._('IP Address') }}">
                                        </div>
                                        <div class="col-md-2">
                                            <input type="date" class="form-control" id="blockedStartDate">
                                        </div>
                                        <div class="col-md-2">
                                            <input type="date" class="form-control" id="blockedEndDate">
                                        </div>
                                        <div class="col-md-2">
                                            <button class="btn btn-primary btn-block" id="applyBlockedFilters">
                                                <i class="fa fa-search"></i> {{ lang._('Apply') }}
                                            </button>
                                        </div>
                                        <div class="col-md-2">
                                            <button class="btn btn-warning btn-block" id="bulkUnblockBtn">
                                                <i class="fa fa-unlock"></i> {{ lang._('Bulk Unblock') }}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Blocked IPs Table -->
                    <div class="row">
                        <div class="col-md-12">
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                    <h3 class="panel-title">
                                        <i class="fa fa-list"></i> {{ lang._('Blocked IP Addresses') }}
                                        <span class="badge" id="blockedCount">0</span>
                                    </h3>
                                </div>
                                <div class="panel-body">
                                    <div class="table-responsive">
                                        <table class="table table-striped table-hover" id="blockedTable">
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
                                    
                                    <!-- Pagination -->
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div id="blockedPagination"></div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="pull-right">
                                                <select class="form-control" id="blockedPageSize" style="width: auto; display: inline-block;">
                                                    <option value="25">25 {{ lang._('per page') }}</option>
                                                    <option value="50" selected>50 {{ lang._('per page') }}</option>
                                                    <option value="100">100 {{ lang._('per page') }}</option>
                                                </select>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Whitelist Tab -->
                <div role="tabpanel" class="tab-pane" id="whitelist">
                    <!-- Controls -->
                    <div class="row">
                        <div class="col-md-12">
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                    <h3 class="panel-title">
                                        <i class="fa fa-cogs"></i> {{ lang._('Whitelist Management') }}
                                        <div class="pull-right">
                                            <button class="btn btn-xs btn-primary" id="refreshWhitelist">
                                                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                            </button>
                                            <button class="btn btn-xs btn-success" id="addWhitelistBtn">
                                                <i class="fa fa-plus"></i> {{ lang._('Add Entry') }}
                                            </button>
                                            <button class="btn btn-xs btn-warning" id="bulkWhitelistBtn">
                                                <i class="fa fa-list"></i> {{ lang._('Bulk Add') }}
                                            </button>
                                        </div>
                                    </h3>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Whitelist Table -->
                    <div class="row">
                        <div class="col-md-12">
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                    <h3 class="panel-title">
                                        <i class="fa fa-list"></i> {{ lang._('Whitelisted Addresses') }}
                                        <span class="badge" id="whitelistCount">0</span>
                                    </h3>
                                </div>
                                <div class="panel-body">
                                    <div class="table-responsive">
                                        <table class="table table-striped table-hover" id="whitelistTable">
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
                                    
                                    <!-- Pagination -->
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div id="whitelistPagination"></div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="pull-right">
                                                <select class="form-control" id="whitelistPageSize" style="width: auto; display: inline-block;">
                                                    <option value="25">25 {{ lang._('per page') }}</option>
                                                    <option value="50" selected>50 {{ lang._('per page') }}</option>
                                                    <option value="100">100 {{ lang._('per page') }}</option>
                                                </select>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Statistics Tab -->
                <div role="tabpanel" class="tab-pane" id="statistics">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                    <h3 class="panel-title"><i class="fa fa-chart-line"></i> {{ lang._('Block Timeline') }}</h3>
                                </div>
                                <div class="panel-body">
                                    <canvas id="blockTimelineChart" width="400" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                    <h3 class="panel-title"><i class="fa fa-chart-pie"></i> {{ lang._('Block Types') }}</h3>
                                </div>
                                <div class="panel-body">
                                    <canvas id="blockTypesChart" width="400" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-12">
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                    <h3 class="panel-title"><i class="fa fa-list"></i> {{ lang._('Top Blocked Countries') }}</h3>
                                </div>
                                <div class="panel-body">
                                    <div id="topCountriesList">
                                        <!-- Populated by JavaScript -->
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
                {{ partial("layout_partials/base_form",['fields':blockIpForm,'id':'frm_block_ip']) }}
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
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Bulk Block IP Addresses') }}</h4>
            </div>
            <div class="modal-body">
                {{ partial("layout_partials/base_form",['fields':bulkBlockForm,'id':'frm_bulk_block']) }}
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
                {{ partial("layout_partials/base_form",['fields':addWhitelistForm,'id':'frm_add_whitelist']) }}
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

.table > tbody > tr > td {
    vertical-align: middle;
}
</style>

<script>
$(document).ready(function() {
    let blockedPage = 1;
    let blockedPageSize = 50;
    let whitelistPage = 1;
    let whitelistPageSize = 50;
    
    // Initialize
    loadBlockingStats();
    loadBlockedIps();
    loadWhitelist();
    initCharts();
    
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
    $('#refreshBlocked').click(function() {
        loadBlockingStats();
        loadBlockedIps();
    });
    
    $('#refreshWhitelist').click(function() {
        loadWhitelist();
    });
    
    $('#blockIpBtn').click(function() {
        $('#blockIpModal').modal('show');
    });
    
    $('#bulkBlockBtn').click(function() {
        $('#bulkBlockModal').modal('show');
    });
    
    $('#addWhitelistBtn').click(function() {
        $('#addWhitelistModal').modal('show');
    });
    
    // Clear expired blocks
    $('#clearExpiredBtn').click(function() {
        BootstrapDialog.confirm({
            title: '{{ lang._("Clear Expired Blocks") }}',
            message: '{{ lang._("This will remove all expired IP blocks. Continue?") }}',
            type: BootstrapDialog.TYPE_WARNING,
            btnCancelLabel: '{{ lang._("Cancel") }}',
            btnOKLabel: '{{ lang._("Clear") }}',
            callback: function(result) {
                if (result) {
                    ajaxCall('/api/webguard/blocking/clearExpired', {}, function(data) {
                        if (data.result === 'ok') {
                            BootstrapDialog.show({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                title: '{{ lang._("Expired Blocks Cleared") }}',
                                message: data.cleared_count + ' {{ lang._("expired blocks have been cleared.") }}',
                                buttons: [{
                                    label: '{{ lang._("Close") }}',
                                    action: function(dialogRef) {
                                        dialogRef.close();
                                        loadBlockingStats();
                                        loadBlockedIps();
                                    }
                                }]
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Clear failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                    });
                }
            }
        });
    });
    
    // Block IP confirmation
    $('#confirmBlockIp').click(function() {
        saveFormToEndpoint('/api/webguard/blocking/blockIp', 'frm_block_ip', function(data) {
            if (data.result === 'ok') {
                $('#blockIpModal').modal('hide');
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("IP Blocked") }}',
                    message: data.message || '{{ lang._("IP address blocked successfully.") }}',
                    buttons: [{
                        label: '{{ lang._("Close") }}',
                        action: function(dialogRef) {
                            dialogRef.close();
                            loadBlockingStats();
                            loadBlockedIps();
                        }
                    }]
                });
            }
        });
    });
    
    // Bulk block confirmation
    $('#confirmBulkBlock').click(function() {
        saveFormToEndpoint('/api/webguard/blocking/bulkBlock', 'frm_bulk_block', function(data) {
            if (data.result === 'ok') {
                $('#bulkBlockModal').modal('hide');
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("IPs Blocked") }}',
                    message: data.blocked_count + ' {{ lang._("IP addresses blocked successfully.") }}',
                    buttons: [{
                        label: '{{ lang._("Close") }}',
                        action: function(dialogRef) {
                            dialogRef.close();
                            loadBlockingStats();
                            loadBlockedIps();
                        }
                    }]
                });
            }
        });
    });
    
    // Add whitelist confirmation
    $('#confirmAddWhitelist').click(function() {
        saveFormToEndpoint('/api/webguard/blocking/addToWhitelist', 'frm_add_whitelist', function(data) {
            if (data.result === 'ok') {
                $('#addWhitelistModal').modal('hide');
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("Added to Whitelist") }}',
                    message: data.message || '{{ lang._("IP address added to whitelist successfully.") }}',
                    buttons: [{
                        label: '{{ lang._("Close") }}',
                        action: function(dialogRef) {
                            dialogRef.close();
                            loadWhitelist();
                        }
                    }]
                });
            }
        });
    });
    
    // Filters
    $('#applyBlockedFilters').click(function() {
        blockedPage = 1;
        loadBlockedIps();
    });
    
    $('#blockedPageSize').change(function() {
        blockedPageSize = $(this).val();
        blockedPage = 1;
        loadBlockedIps();
    });
    
    $('#whitelistPageSize').change(function() {
        whitelistPageSize = $(this).val();
        whitelistPage = 1;
        loadWhitelist();
    });
    
    // Select all checkboxes
    $('#selectAllBlocked').change(function() {
        $('.blocked-checkbox').prop('checked', $(this).is(':checked'));
    });
    
    $('#selectAllWhitelist').change(function() {
        $('.whitelist-checkbox').prop('checked', $(this).is(':checked'));
    });
    
    // Bulk unblock
    $('#bulkUnblockBtn').click(function() {
        let selectedIps = [];
        $('.blocked-checkbox:checked').each(function() {
            selectedIps.push($(this).data('ip'));
        });
        
        if (selectedIps.length === 0) {
            BootstrapDialog.alert('{{ lang._("Please select at least one IP address to unblock.") }}');
            return;
        }
        
        BootstrapDialog.confirm({
            title: '{{ lang._("Bulk Unblock") }}',
            message: '{{ lang._("Are you sure you want to unblock") }} ' + selectedIps.length + ' {{ lang._("IP addresses?") }}',
            type: BootstrapDialog.TYPE_WARNING,
            btnCancelLabel: '{{ lang._("Cancel") }}',
            btnOKLabel: '{{ lang._("Unblock") }}',
            callback: function(result) {
                if (result) {
                    ajaxCall('/api/webguard/blocking/bulkUnblock', {
                        ip_list: selectedIps.join('\n'),
                        reason: 'Bulk unblock from admin interface'
                    }, function(data) {
                        if (data.result === 'ok') {
                            BootstrapDialog.show({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                title: '{{ lang._("IPs Unblocked") }}',
                                message: data.unblocked_count + ' {{ lang._("IP addresses unblocked successfully.") }}',
                                buttons: [{
                                    label: '{{ lang._("Close") }}',
                                    action: function(dialogRef) {
                                        dialogRef.close();
                                        loadBlockingStats();
                                        loadBlockedIps();
                                    }
                                }]
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Bulk unblock failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                    });
                }
            }
        });
    });
    
    // Individual unblock action
    $(document).on('click', '.btn-unblock', function() {
        let ip = $(this).data('ip');
        
        BootstrapDialog.confirm({
            title: '{{ lang._("Unblock IP") }}',
            message: '{{ lang._("Are you sure you want to unblock") }} ' + ip + '?',
            type: BootstrapDialog.TYPE_WARNING,
            btnCancelLabel: '{{ lang._("Cancel") }}',
            btnOKLabel: '{{ lang._("Unblock") }}',
            callback: function(result) {
                if (result) {
                    ajaxCall('/api/webguard/blocking/unblockIp', {
                        ip_address: ip,
                        reason: 'Manual unblock from admin interface'
                    }, function(data) {
                        if (data.result === 'ok') {
                            loadBlockingStats();
                            loadBlockedIps();
                            BootstrapDialog.alert({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                message: data.message || '{{ lang._("IP address unblocked successfully.") }}'
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Unblock failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                    });
                }
            }
        });
    });
    
    // Individual whitelist remove action
    $(document).on('click', '.btn-remove-whitelist', function() {
        let ip = $(this).data('ip');
        
        BootstrapDialog.confirm({
            title: '{{ lang._("Remove from Whitelist") }}',
            message: '{{ lang._("Are you sure you want to remove") }} ' + ip + ' {{ lang._("from whitelist?") }}',
            type: BootstrapDialog.TYPE_WARNING,
            btnCancelLabel: '{{ lang._("Cancel") }}',
            btnOKLabel: '{{ lang._("Remove") }}',
            callback: function(result) {
                if (result) {
                    ajaxCall('/api/webguard/blocking/removeFromWhitelist', {
                        ip_address: ip,
                        reason: 'Manual removal from admin interface'
                    }, function(data) {
                        if (data.result === 'ok') {
                            loadWhitelist();
                            BootstrapDialog.alert({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                message: data.message || '{{ lang._("IP address removed from whitelist successfully.") }}'
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Remove failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                    });
                }
            }
        });
    });
    
    function loadBlockingStats() {
        ajaxGet('/api/webguard/blocking/getStats', {period: '24h'}, function(data) {
            $('#active-blocks').text(formatNumber(data.active_blocks || 0));
            $('#auto-blocks').text(formatNumber(data.auto_blocks || 0));
            $('#manual-blocks').text(formatNumber(data.manual_blocks || 0));
            $('#whitelist-entries').text(formatNumber(data.whitelist_entries || 0));
        });
    }
    
    function loadBlockedIps() {
        let params = {
            page: blockedPage,
            limit: blockedPageSize,
            block_type: $('#blockTypeFilter').val(),
            source_ip: $('#blockedIpFilter').val(),
            start_date: $('#blockedStartDate').val(),
            end_date: $('#blockedEndDate').val()
        };
        
        ajaxGet('/api/webguard/blocking/getBlockedIps', params, function(data) {
            let tbody = $('#blockedTable tbody');
            tbody.empty();
            
            if (data.blocked_ips && data.blocked_ips.length > 0) {
                data.blocked_ips.forEach(function(block) {
                    let row = $('<tr>');
                    row.append('<td><input type="checkbox" class="blocked-checkbox" data-ip="' + block.ip_address + '"></td>');
                    row.append('<td><a href="/ui/webguard/blocking/history/' + block.ip_address + '">' + block.ip_address + '</a></td>');
                    row.append('<td><span class="block-type-' + block.block_type + '">' + block.block_type.toUpperCase() + '</span></td>');
                    row.append('<td>' + formatTimestamp(block.blocked_since) + '</td>');
                    
                    let expires = block.expires_at ? formatTimestamp(block.expires_at) : '{{ lang._("Never") }}';
                    let expiresClass = block.expires_at ? (block.expires_at < (Date.now() / 1000 + 3600) ? 'expires-soon' : 'expires-later') : 'expires-never';
                    row.append('<td><span class="' + expiresClass + '">' + expires + '</span></td>');
                    
                    row.append('<td>' + (block.reason || '{{ lang._("N/A") }}') + '</td>');
                    row.append('<td>' + (block.violations || 0) + '</td>');
                    
                    let actions = '<div class="btn-group btn-group-xs">';
                    actions += '<button class="btn btn-warning btn-unblock" data-ip="' + block.ip_address + '"><i class="fa fa-unlock"></i></button>';
                    actions += '<a href="/ui/webguard/blocking/history/' + block.ip_address + '" class="btn btn-info"><i class="fa fa-history"></i></a>';
                    actions += '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                
                $('#blockedCount').text(data.total || 0);
                generatePagination('blocked', data.total || 0);
            } else {
                tbody.append('<tr><td colspan="8" class="text-center">{{ lang._("No blocked IPs found") }}</td></tr>');
                $('#blockedCount').text('0');
            }
        });
    }
    
    function loadWhitelist() {
        let params = {
            page: whitelistPage,
            limit: whitelistPageSize
        };
        
        ajaxGet('/api/webguard/blocking/getWhitelist', params, function(data) {
            let tbody = $('#whitelistTable tbody');
            tbody.empty();
            
            if (data.whitelist && data.whitelist.length > 0) {
                data.whitelist.forEach(function(entry) {
                    let row = $('<tr>');
                    row.append('<td><input type="checkbox" class="whitelist-checkbox" data-ip="' + entry.ip_address + '"></td>');
                    row.append('<td>' + entry.ip_address + '</td>');
                    row.append('<td>' + (entry.description || '{{ lang._("N/A") }}') + '</td>');
                    row.append('<td>' + formatTimestamp(entry.added_at) + '</td>');
                    
                    let expires = entry.expires_at ? formatTimestamp(entry.expires_at) : '{{ lang._("Never") }}';
                    row.append('<td>' + expires + '</td>');
                    
                    let type = entry.permanent ? '{{ lang._("Permanent") }}' : '{{ lang._("Temporary") }}';
                    row.append('<td>' + type + '</td>');
                    
                    let actions = '<div class="btn-group btn-group-xs">';
                    actions += '<button class="btn btn-danger btn-remove-whitelist" data-ip="' + entry.ip_address + '"><i class="fa fa-times"></i></button>';
                    actions += '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                
                $('#whitelistCount').text(data.total || 0);
                generatePagination('whitelist', data.total || 0);
            } else {
                tbody.append('<tr><td colspan="7" class="text-center">{{ lang._("No whitelist entries found") }}</td></tr>');
                $('#whitelistCount').text('0');
            }
        });
    }
    
    function initCharts() {
        // Initialize Chart.js charts
        let ctx1 = document.getElementById('blockTimelineChart').getContext('2d');
        window.blockTimelineChart = new Chart(ctx1, {
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
        
        let ctx2 = document.getElementById('blockTypesChart').getContext('2d');
        window.blockTypesChart = new Chart(ctx2, {
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
                legend: {
                    position: 'bottom'
                }
            }
        });
    }
    
    function loadStatisticsCharts() {
        ajaxGet('/api/webguard/blocking/getStats', {period: '7d'}, function(data) {
            if (data.block_timeline) {
                window.blockTimelineChart.data.labels = data.block_timeline.labels || [];
                window.blockTimelineChart.data.datasets[0].data = data.block_timeline.data || [];
                window.blockTimelineChart.update();
            }
            
            if (data.block_types) {
                window.blockTypesChart.data.datasets[0].data = [
                    data.block_types.temporary || 0,
                    data.block_types.permanent || 0,
                    data.block_types.progressive || 0
                ];
                window.blockTypesChart.update();
            }
            
            if (data.top_countries) {
                let html = '';
                data.top_countries.forEach(function(country) {
                    html += '<div class="country-item">';
                    html += '<div><img src="/themes/opnsense/build/images/flags/' + country.code.toLowerCase() + '.png" class="country-flag" onerror="this.style.display=\'none\'"> ' + country.name + '</div>';
                    html += '<div><strong>' + country.count + '</strong> {{ lang._("blocks") }}</div>';
                    html += '</div>';
                });
                $('#topCountriesList').html(html);
            }
        });
    }
    
    function generatePagination(type, total) {
        let currentPage = type === 'blocked' ? blockedPage : whitelistPage;
        let pageSize = type === 'blocked' ? blockedPageSize : whitelistPageSize;
        let totalPages = Math.ceil(total / pageSize);
        let pagination = $('#' + type + 'Pagination');
        pagination.empty();
        
        if (totalPages <= 1) return;
        
        let nav = $('<nav><ul class="pagination pagination-sm"></ul></nav>');
        let ul = nav.find('ul');
        
        // Previous
        if (currentPage > 1) {
            ul.append('<li><a href="#" data-type="' + type + '" data-page="' + (currentPage - 1) + '">&laquo;</a></li>');
        }
        
        // Pages
        let start = Math.max(1, currentPage - 2);
        let end = Math.min(totalPages, currentPage + 2);
        
        for (let i = start; i <= end; i++) {
            let li = $('<li><a href="#" data-type="' + type + '" data-page="' + i + '">' + i + '</a></li>');
            if (i === currentPage) {
                li.addClass('active');
            }
            ul.append(li);
        }
        
        // Next
        if (currentPage < totalPages) {
            ul.append('<li><a href="#" data-type="' + type + '" data-page="' + (currentPage + 1) + '">&raquo;</a></li>');
        }
        
        pagination.append(nav);
    }
    
    // Pagination click handler
    $(document).on('click', '.pagination a', function(e) {
        e.preventDefault();
        let page = $(this).data('page');
        let type = $(this).data('type');
        
        if (page) {
            if (type === 'blocked' && page !== blockedPage) {
                blockedPage = page;
                loadBlockedIps();
            } else if (type === 'whitelist' && page !== whitelistPage) {
                whitelistPage = page;
                loadWhitelist();
            }
        }
    });
    
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    
    function formatTimestamp(timestamp) {
        if (!timestamp) return '{{ lang._("N/A") }}';
        let date = new Date(timestamp * 1000);
        return date.toLocaleString();
    }
});
</script>