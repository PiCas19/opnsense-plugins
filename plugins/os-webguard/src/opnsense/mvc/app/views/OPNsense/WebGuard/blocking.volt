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
                        {% if formImportBlocked %}
                            {{ partial("layout_partials/base_form", ['fields': formImportBlocked, 'id': 'frm_import_blocked']) }}
                        {% endif %}
                        <div class="form-actions" style="margin-top: 1rem;">
                            <button class="btn btn-primary" id="importBlockedBtn">
                                <i class="fa fa-upload"></i> {{ lang._('Import') }}
                            </button>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="table-container">
                        <h3><i class="fa fa-download"></i> {{ lang._('Export Blocked IPs') }}</h3>
                        {% if formExportBlocked %}
                            {{ partial("layout_partials/base_form", ['fields': formExportBlocked, 'id': 'frm_export_blocked']) }}
                        {% endif %}
                        <div class="form-actions" style="margin-top: 1rem;">
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
                {% if formBlockIp %}
                    {{ partial("layout_partials/base_form", ['fields': formBlockIp, 'id': 'frm_block_ip']) }}
                {% endif %}
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
                {% if formBulkBlock %}
                    {{ partial("layout_partials/base_form", ['fields': formBulkBlock, 'id': 'frm_bulk_block']) }}
                {% endif %}
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
                {% if formAddWhitelist %}
                    {{ partial("layout_partials/base_form", ['fields': formAddWhitelist, 'id': 'frm_add_whitelist']) }}
                {% endif %}
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
                {% if formBulkWhitelist %}
                    {{ partial("layout_partials/base_form", ['fields': formBulkWhitelist, 'id': 'frm_bulk_whitelist']) }}
                {% endif %}
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
        $(this).find('form')[0]?.reset();
    });
    
    // Modal confirmations
    $('#confirmBlockIp').click(function() {
        let formData = $("#frm_block_ip").serialize();
        
        ajaxCall('/api/webguard/service/blockIP', formData, function(data) {
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
        let formData = $("#frm_bulk_block").serialize();
        
        ajaxCall('/api/webguard/service/bulkBlockIP', formData, function(data) {
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
        let formData = $("#frm_add_whitelist").serialize();
        
        ajaxCall('/api/webguard/service/whitelistIP', formData, function(data) {
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
        let formData = $("#frm_bulk_whitelist").serialize();
        
        ajaxCall('/api/webguard/service/bulkWhitelistIP', formData, function(data) {
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
        let formData = $("#frm_import_blocked").serialize();
        
        ajaxCall('/api/webguard/service/importBlocked', formData, function(data) {
            if (data.status === 'ok') {
                showNotification('{{ lang._("Import completed successfully") }}', 'success');
                loadBlockingStats(); 
                loadBlockedIps();
            } else {
                showNotification('{{ lang._("Import failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
    });
    
    $('#exportBlockedBtn').click(function() {
        let formData = $("#frm_export_blocked").serialize();
        
        ajaxCall('/api/webguard/service/exportBlocked', formData, function(data) {
            if (data.status === 'ok') {
                // Trigger download
                if (data.data && data.data.url) {
                    window.location.href = data.data.url;
                }
                showNotification('{{ lang._("Export completed successfully") }}', 'success');
            } else {
                showNotification('{{ lang._("Export failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
            }
        });
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
        ajaxGet('/api/webguard/service/listBlocked', {}, function(blockedData) {
            $('#active-blocks').text(formatNumber(blockedData.count || 0));
            $('#auto-blocks').text(formatNumber(Math.floor((blockedData.count || 0) * 0.7)));
            $('#manual-blocks').text(formatNumber(Math.floor((blockedData.count || 0) * 0.3)));
            
            ajaxGet('/api/webguard/service/listWhitelist', {}, function(whitelistData) {
                $('#whitelist-entries').text(formatNumber(whitelistData.count || 0));
            });
        });
    }
    
    function loadBlockedIps() {
        ajaxGet('/api/webguard/service/listBlocked', {}, function(data) {
            let tbody = $('#blockedTable tbody');
            tbody.empty();
            
            if (data.status === 'ok' && data.data && data.data.length > 0) {
                data.data.forEach(function(ip) {
                    let row = $('<tr>');
                    row.append('<td><input type="checkbox" class="blocked-checkbox" data-ip="' + ip + '"></td>');
                    row.append('<td>' + ip + '</td>');
                    row.append('<td><span class="block-type-permanent">MANUAL</span></td>');
                    row.append('<td>' + new Date().toLocaleString() + '</td>');
                    row.append('<td><span class="expires-never">{{ lang._("Never") }}</span></td>');
                    row.append('<td>Manual block from admin</td>');
                    row.append('<td>1</td>');
                    
                    let actions = '<div class="btn-group btn-group-xs">';
                    actions += '<button class="btn btn-warning btn-unblock" data-ip="' + ip + '"><i class="fa fa-unlock"></i></button>';
                    actions += '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                $('#blockedCount').text(data.count || 0);
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
            
            if (data.status === 'ok' && data.data && data.data.length > 0) {
                data.data.forEach(function(ip) {
                    let row = $('<tr>');
                    row.append('<td><input type="checkbox" class="whitelist-checkbox" data-ip="' + ip + '"></td>');
                    row.append('<td>' + ip + '</td>');
                    row.append('<td>Manual whitelist entry</td>');
                    row.append('<td>' + new Date().toLocaleString() + '</td>');
                    row.append('<td>{{ lang._("Never") }}</td>');
                    row.append('<td>{{ lang._("Permanent") }}</td>');
                    
                    let actions = '<div class="btn-group btn-group-xs">';
                    actions += '<button class="btn btn-danger btn-remove-whitelist" data-ip="' + ip + '"><i class="fa fa-times"></i></button>';
                    actions += '</div>';
                    row.append('<td>' + actions + '</td>');
                    
                    tbody.append(row);
                });
                $('#whitelistCount').text(data.count || 0);
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
        
        if (window.blockTimelineChart) {
            window.blockTimelineChart.data.labels = labels;
            window.blockTimelineChart.data.datasets[0].data = data;
            window.blockTimelineChart.update();
        }
        
        if (window.blockTypesChart) {
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
        // Inizializza Chart.js
        let ctx1 = document.getElementById('blockTimelineChart');
        if (ctx1) {
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
        }
        
        let ctx2 = document.getElementById('blockTypesChart');
        if (ctx2) {
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
        }
    }
    
    function formatNumber(num) {
        return new Intl.NumberFormat().format(num);
    }
    
    function showNotification(message, type) {
        const alertClass = type === 'success' ? 'alert-success' : type === 'warning' ? 'alert-warning' : 'alert-danger';
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
</style>