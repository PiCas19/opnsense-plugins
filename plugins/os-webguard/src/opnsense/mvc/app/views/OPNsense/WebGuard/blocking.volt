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
                <div class="stat-icon"><i class="fa fa-ban"></i></div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-whitelist">
                <div class="stat-content">
                    <div class="stat-number" id="whitelist-count">0</div>
                    <div class="stat-label">{{ lang._('Whitelist Entries') }}</div>
                </div>
                <div class="stat-icon"><i class="fa fa-check-circle"></i></div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-temp">
                <div class="stat-content">
                    <div class="stat-number" id="temp-blocks">0</div>
                    <div class="stat-label">{{ lang._('Temporary Blocks') }}</div>
                </div>
                <div class="stat-icon"><i class="fa fa-clock-o"></i></div>
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="stat-card stat-status">
                <div class="stat-content">
                    <div class="stat-number" id="service-status">{{ lang._('Loading') }}</div>
                    <div class="stat-label">{{ lang._('Service Status') }}</div>
                </div>
                <div class="stat-icon"><i class="fa fa-heartbeat"></i></div>
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
                                        <tbody><!-- caricato via AJAX --></tbody>
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
                                        <tbody><!-- caricato via AJAX --></tbody>
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
                                        <tbody><!-- caricato via AJAX --></tbody>
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
                                            <label>{{ lang._('Export Format') }}</label>
                                            <select id="export-format" class="form-control">
                                                <option value="json">JSON</option>
                                                <option value="csv">CSV</option>
                                                <option value="txt">Plain Text</option>
                                            </select>
                                        </div>
                                        <div class="btn-group-vertical btn-group-modern">
                                            <button id="export-blocked-btn" class="btn btn-primary btn-modern">
                                                <i class="fa fa-download"></i> {{ lang._('Export Blocked IPs') }}
                                            </button>
                                            <button id="export-whitelist-btn" class="btn btn-success btn-modern">
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
                                            <button id="add-sample-threats-btn" class="btn btn-warning btn-modern">
                                                <i class="fa fa-plus"></i> {{ lang._('Add Sample Threats') }}
                                            </button>
                                            <button id="clear-logs-btn" class="btn btn-info btn-modern">
                                                <i class="fa fa-trash"></i> {{ lang._('Clear Logs') }}
                                            </button>
                                            <button id="restart-service-btn" class="btn btn-default btn-modern">
                                                <i class="fa fa-refresh"></i> {{ lang._('Restart Service') }}
                                            </button>
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
</div>

<!-- Modals -->
<!-- Block IP Modal -->
<div class="modal fade" id="block-ip-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title">{{ lang._('Block IP Address') }}</h4>
            </div>
            <div class="modal-body">
                <form id="block-ip-form">
                    <div class="form-group">
                        <label>{{ lang._('IP Address') }}</label>
                        <input type="text" class="form-control" id="block-ip" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label>{{ lang._('Duration') }}</label>
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
                        <label>{{ lang._('Reason') }}</label>
                        <input type="text" class="form-control" id="block-reason" value="Manual block">
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button data-dismiss="modal" class="btn btn-default">{{ lang._('Cancel') }}</button>
                <button id="confirm-block-btn" class="btn btn-danger"><i class="fa fa-ban"></i> {{ lang._('Block IP') }}</button>
            </div>
        </div>
    </div>
</div>

<!-- Bulk Block Modal -->
<div class="modal fade" id="bulk-block-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button data-dismiss="modal" class="close"><span>&times;</span></button>
                <h4 class="modal-title">{{ lang._('Bulk Block IP Addresses') }}</h4>
            </div>
            <div class="modal-body">
                <form id="bulk-block-form">
                    <div class="form-group">
                        <label>{{ lang._('IP Addresses (one per line)') }}</label>
                        <textarea class="form-control" id="bulk-block-ips" rows="6"></textarea>
                    </div>
                    <div class="form-group">
                        <label>{{ lang._('Duration') }}</label>
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
                        <label>{{ lang._('Reason') }}</label>
                        <input type="text" class="form-control" id="bulk-block-reason" value="Bulk block">
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button data-dismiss="modal" class="btn btn-default">{{ lang._('Cancel') }}</button>
                <button id="confirm-bulk-block-btn" class="btn btn-danger"><i class="fa fa-ban"></i> {{ lang._('Block IPs') }}</button>
            </div>
        </div>
    </div>
</div>

<!-- Add Whitelist Modal -->
<div class="modal fade" id="add-whitelist-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content modern-modal">
            <div class="modal-header">
                <button data-dismiss="modal" class="close"><span>&times;</span></button>
                <h4 class="modal-title">{{ lang._('Add to Whitelist') }}</h4>
            </div>
            <div class="modal-body">
                <form id="add-whitelist-form">
                    <div class="form-group">
                        <label>{{ lang._('IP Address') }}</label>
                        <input type="text" class="form-control" id="whitelist-ip" required>
                    </div>
                    <div class="form-group">
                        <label>{{ lang._('Description') }}</label>
                        <input type="text" class="form-control" id="whitelist-description" value="Manual whitelist entry">
                    </div>
                    <div class="checkbox">
                        <label>
                            <input type="checkbox" id="whitelist-permanent" checked> {{ lang._('Permanent entry') }}
                        </label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button data-dismiss="modal" class="btn btn-default">{{ lang._('Cancel') }}</button>
                <button id="confirm-whitelist-btn" class="btn btn-success"><i class="fa fa-check"></i> {{ lang._('Add to Whitelist') }}</button>
            </div>
        </div>
    </div>
</div>

<style>
/* Inserisci qui il tuo CSS esistente (il lungo blocco di styling che avevi) */
</style>

<script>
$(function() {
    // Inizializzazione
    loadStats(); loadBlockedIps();
    setInterval(() => {
        loadStats();
        if ($('#blocked-tab').hasClass('active')) loadBlockedIps();
        if ($('#whitelist-tab').hasClass('active')) loadWhitelist();
        if ($('#threats-tab').hasClass('active')) loadThreats();
    }, 30000);
    $('a[data-toggle="tab"]').on('shown.bs.tab', function(e) {
        const target = $(e.target).attr('href');
        if (target === '#blocked-tab') loadBlockedIps();
        if (target === '#whitelist-tab') loadWhitelist();
        if (target === '#threats-tab') loadThreats();
    });

    // Pulsanti modals
    $('#add-block-btn').click(() => $('#block-ip-modal').modal('show'));
    $('#bulk-block-btn').click(() => $('#bulk-block-modal').modal('show'));
    $('#add-whitelist-btn').click(() => $('#add-whitelist-modal').modal('show'));
    $('#refresh-blocked-btn').click(() => { loadStats(); loadBlockedIps(); });
    $('#refresh-whitelist-btn').click(loadWhitelist);
    $('#refresh-threats-btn').click(loadThreats);

    // Confirm + AJAX dinamici
    $(document).on('click', '.unblock-btn', function(e) {
        e.preventDefault();
        const ip = $(this).data('ip');
        const msg = '{{ lang._("Unblock IP")|e("js") }} ' + ip + '?';
        if (!confirm(msg)) return;
        ajaxPost('/api/webguard/service/unblockIP', { ip }, commonCallback);
    });

    $(document).on('click', '.remove-whitelist-btn', function(e) {
        e.preventDefault();
        const ip = $(this).data('ip');
        const msg = '{{ lang._("Remove")|e("js") }} ' + ip + ' {{ lang._("from whitelist")|e("js") }}?';
        if (!confirm(msg)) return;
        ajaxPost('/api/webguard/service/removeWhitelist', { ip }, commonCallback);
    });

    $(document).on('click', '.block-threat-btn', function(e) {
        e.preventDefault();
        const ip = $(this).data('ip');
        const msg = '{{ lang._("Block IP")|e("js") }} ' + ip + ' {{ lang._("from threats")|e("js") }}?';
        if (!confirm(msg)) return;
        ajaxPost('/api/webguard/service/blockIP', {
            ip, duration: 3600, reason: 'Blocked from threats', block_type: 'threat'
        }, commonCallback);
    });

    $(document).on('click', '.whitelist-threat-btn', function(e) {
        e.preventDefault();
        const ip = $(this).data('ip');
        const msg = '{{ lang._("Add IP")|e("js") }} ' + ip + ' {{ lang._("to whitelist")|e("js") }}?';
        if (!confirm(msg)) return;
        ajaxPost('/api/webguard/service/addWhitelist', {
            ip, description: 'Whitelisted from threats', permanent: '1'
        }, commonCallback);
    });

    // Clear expired
    $('#clear-expired-btn').click(function() {
        const msg = '{{ lang._("Clear all expired blocks?")|e("js") }}';
        if (!confirm(msg)) return;
        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/clearExpired', {}, data => {
            setButtonLoading($('#clear-expired-btn'), false);
            commonCallback(data);
        });
    });

    // Export
    $('#export-blocked-btn').click(function() {
        window.location.href = '/api/webguard/service/exportBlocked?format=' + $('#export-format').val();
        showNotification('{{ lang._("Export started") }}', 'info');
    });
    $('#export-whitelist-btn').click(function() {
        window.location.href = '/api/webguard/service/exportWhitelist?format=' + $('#export-format').val();
        showNotification('{{ lang._("Export started") }}', 'info');
    });

    // Add sample threats
    $('#add-sample-threats-btn').click(function() {
        const btn = $(this);
        const msg = '{{ lang._("Add sample threat data for testing?")|e("js") }}';
        if (!confirm(msg)) return;
        setButtonLoading(btn, true);
        ajaxPost('/api/webguard/service/addSampleThreats', {}, data => {
            setButtonLoading(btn, false);
            commonCallback(data);
        });
    });

    // Clear logs
    $('#clear-logs-btn').click(function() {
        const msg = '{{ lang._("Clear all WebGuard logs? This cannot be undone.")|e("js") }}';
        if (!confirm(msg)) return;
        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/clearLogs', {}, data => {
            setButtonLoading($('#clear-logs-btn'), false);
            commonCallback(data);
        });
    });

    // Restart service
    $('#restart-service-btn').click(function() {
        const msg = '{{ lang._("Restart WebGuard service?")|e("js") }}';
        if (!confirm(msg)) return;
        setButtonLoading($(this), true);
        ajaxPost('/api/webguard/service/restart', {}, data => {
            setButtonLoading($('#restart-service-btn'), false);
            commonCallback(data);
            if (data.status==='ok') setTimeout(loadStats,2000);
        });
    });

    // Modal confirms: block / bulk block / whitelist add
    $('#confirm-block-btn').click(function() {
        const ip = $('#block-ip').val().trim();
        const dur = $('#block-duration').val();
        const reason = $('#block-reason').val().trim();
        if (!ip) { showNotification('{{ lang._("Please enter an IP address") }}','error'); return; }
        if (!isValidIP(ip)) { showNotification('{{ lang._("Please enter a valid IP address") }}','error'); return; }
        setButtonLoading($(this),true);
        ajaxPost('/api/webguard/service/blockIP', { ip, duration: dur, reason, block_type:'manual' }, data=>{
            setButtonLoading($('#confirm-block-btn'),false);
            commonCallback(data);
            if (data.status==='ok') { $('#block-ip-modal').modal('hide'); clearForm('block-ip-form'); }
        });
    });

    $('#confirm-bulk-block-btn').click(function() {
        const ips = $('#bulk-block-ips').val().trim();
        const dur = $('#bulk-block-duration').val();
        const reason = $('#bulk-block-reason').val().trim();
        if (!ips) { showNotification('{{ lang._("Please enter IP addresses") }}','error'); return; }
        setButtonLoading($(this),true);
        ajaxPost('/api/webguard/service/bulkBlock', { ip_list:ips, duration:dur, reason, block_type:'manual' }, data=>{
            setButtonLoading($('#confirm-bulk-block-btn'),false);
            commonCallback(data);
            if (data.status==='ok') { $('#bulk-block-modal').modal('hide'); clearForm('bulk-block-form'); }
        });
    });

    $('#confirm-whitelist-btn').click(function() {
        const ip = $('#whitelist-ip').val().trim();
        const desc = $('#whitelist-description').val().trim();
        const perm = $('#whitelist-permanent').is(':checked')?'1':'0';
        if (!ip) { showNotification('{{ lang._("Please enter an IP address") }}','error'); return; }
        if (!isValidIP(ip)) { showNotification('{{ lang._("Please enter a valid IP address") }}','error'); return; }
        setButtonLoading($(this),true);
        ajaxPost('/api/webguard/service/addWhitelist',{ ip, description:desc, permanent:perm }, data=>{
            setButtonLoading($('#confirm-whitelist-btn'),false);
            commonCallback(data);
            if (data.status==='ok') { $('#add-whitelist-modal').modal('hide'); clearForm('add-whitelist-form'); }
        });
    });

    // --- Funzioni comuni ---
    function commonCallback(data) {
        if (data.status==='ok') {
            showNotification(data.message||'{{ lang._("Operation successful") }}','success');
        } else {
            showNotification(data.message||'{{ lang._("Operation failed") }}','error');
        }
        loadStats(); loadBlockedIps(); loadWhitelist(); loadThreats();
    }

    function loadStats(){
        ajaxGet('/api/webguard/service/status',{},d=>{
            if(d.status==='ok') $('#service-status').text(d.running? '{{ lang._("Running") }}':'{{ lang._("Stopped") }}');
        });
        ajaxGet('/api/webguard/service/getStats',{},d=>{
            if(d.status==='ok'&&d.data){
                $('#active-blocks').text(d.data.blocked_count||0);
                $('#whitelist-count').text(d.data.whitelist_count||0);
                $('#temp-blocks').text(d.data.temp_blocks||0);
            }
        });
    }

    function loadBlockedIps(){
        ajaxGet('/api/webguard/service/listBlocked',{},d=>{
            const tbody=$('#blocked-table tbody').empty();
            if(d.status==='ok'&&d.data&&d.data.blocked_ips){
                if(d.data.blocked_ips.length){
                    d.data.blocked_ips.forEach(item=>{
                        const css=item.block_type==='permanent'?'danger':'warning';
                        const expires=item.expires_at_iso?formatDate(item.expires_at_iso):'{{ lang._("Never") }}';
                        tbody.append(`<tr>
                          <td><strong>${item.ip_address}</strong></td>
                          <td><span class="label label-${css}">${item.block_type.toUpperCase()}</span></td>
                          <td>${formatDate(item.blocked_since_iso)}</td>
                          <td>${expires}</td>
                          <td>${item.reason||'Manual block'}</td>
                          <td><button class="btn btn-xs btn-warning unblock-btn" data-ip="${item.ip_address}">
                            <i class="fa fa-unlock"></i> {{ lang._("Unblock") }}
                          </button></td>
                        </tr>`);
                    });
                } else {
                    tbody.append(createEmptyState('{{ lang._("No blocked IPs found") }}','ban'));
                }
            } else {
                tbody.append(createErrorState('{{ lang._("Error loading blocked IPs") }}'));
            }
        });
    }

    function loadWhitelist(){
        ajaxGet('/api/webguard/service/listWhitelist',{},d=>{
            const tbody=$('#whitelist-table tbody').empty();
            if(d.status==='ok'&&d.data&&d.data.whitelist){
                if(d.data.whitelist.length){
                    d.data.whitelist.forEach(item=>{
                        const css=item.permanent?'success':'warning';
                        const type=item.permanent?'{{ lang._("Permanent") }}':'{{ lang._("Temporary") }}';
                        tbody.append(`<tr>
                          <td><strong>${item.ip_address}</strong></td>
                          <td>${item.description||'Manual entry'}</td>
                          <td>${formatDate(item.added_at_iso)}</td>
                          <td><span class="label label-${css}">${type}</span></td>
                          <td><button class="btn btn-xs btn-danger remove-whitelist-btn" data-ip="${item.ip_address}">
                            <i class="fa fa-times"></i> {{ lang._("Remove") }}
                          </button></td>
                        </tr>`);
                    });
                } else {
                    tbody.append(createEmptyState('{{ lang._("No whitelist entries found") }}','check-circle'));
                }
            } else {
                tbody.append(createErrorState('{{ lang._("Error loading whitelist") }}'));
            }
        });
    }

    function loadThreats(){
        ajaxGet('/api/webguard/service/getThreats',{},d=>{
            const tbody=$('#threats-table tbody').empty();
            if(d.status==='ok'&&d.data&&d.data.threats){
                if(d.data.threats.length){
                    d.data.threats.forEach(item=>{
                        const sev = { high:'danger', medium:'warning', low:'info' }[item.severity]||'info';
                        tbody.append(`<tr>
                          <td><strong>${item.ip_address}</strong></td>
                          <td>${item.threat_type||'Unknown'}</td>
                          <td><span class="label label-${sev}">${item.severity.toUpperCase()}</span></td>
                          <td>${formatDate(item.first_seen_iso)}</td>
                          <td>${formatDate(item.last_seen_iso)}</td>
                          <td>
                            <button class="btn btn-xs btn-danger block-threat-btn" data-ip="${item.ip_address}">
                              <i class="fa fa-ban"></i> {{ lang._("Block") }}
                            </button>
                            <button class="btn btn-xs btn-success whitelist-threat-btn" data-ip="${item.ip_address}">
                              <i class="fa fa-check"></i> {{ lang._("Whitelist") }}
                            </button>
                          </td>
                        </tr>`);
                    });
                } else {
                    tbody.append(createEmptyState('{{ lang._("No threats detected") }}','shield'));
                }
            } else {
                tbody.append(createEmptyState('{{ lang._("No threat data available") }}','exclamation-triangle'));
            }
        });
    }

    function createEmptyState(message, icon){
        return `<tr><td colspan="6" class="empty-state">
          <i class="fa fa-${icon}"></i><h4>${message}</h4>
          <p>{{ lang._("No data to display at this time") }}</p>
        </td></tr>`;
    }
    function createErrorState(message){
        return `<tr><td colspan="6" class="empty-state">
          <i class="fa fa-exclamation-triangle" style="color:#ff6b6b;"></i>
          <h4 style="color:#ff6b6b;">${message}</h4>
          <p>{{ lang._("Please try refreshing the page") }}</p>
        </td></tr>`;
    }

    function formatDate(dt){ try{ return new Date(dt).toLocaleString(); }catch(e){return dt;} }
    function isValidIP(ip){
        const v4=/^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
        const v6=/^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return v4.test(ip)||v6.test(ip);
    }

    function clearForm(id){
        $(`#${id} input[type="text"], #${id} textarea`).val('');
        $(`#${id} input[type="checkbox"]`).prop('checked',false);
        $(`#${id} select`).prop('selectedIndex',0);
    }
    function setButtonLoading(btn,loading){
        if(loading) btn.addClass('btn-loading').prop('disabled',true);
        else btn.removeClass('btn-loading').prop('disabled',false);
    }
    function showNotification(msg,type){
        const n=$(`<div class="notification-modern notification-${type}"><i class="fa fa-${{'success':'check-circle','error':'exclamation-circle','warning':'exclamation-triangle','info':'info-circle'}[type]||'info-circle'}"></i> ${msg}</div>`);
        $('body').append(n);
        setTimeout(()=>n.fadeOut(300,()=>n.remove()),5000);
    }
    function ajaxPost(url,data,cb){ $.ajax({url,type:'POST',data,dataType:'json',success:cb,error:function(xhr,_,err){const m=(xhr.responseJSON&&xhr.responseJSON.message)||err||'{{ lang._("Connection error") }}';showNotification(`{{ lang._("Error") }}: ${m}`,'error');}}); }
    function ajaxGet(url,data,cb){ $.ajax({url,type:'GET',data,dataType:'json',success:cb,error:function(xhr,_,err){const m=(xhr.responseJSON&&xhr.responseJSON.message)||err||'{{ lang._("Connection error") }}';showNotification(`{{ lang._("Error loading data") }}: ${m}`,'error');}}); }
});
</script>
