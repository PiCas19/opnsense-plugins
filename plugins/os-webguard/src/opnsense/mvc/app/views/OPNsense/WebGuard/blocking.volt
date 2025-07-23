{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box">
    <!-- Header -->
    <div class="row">
        <div class="col-md-12">
            <h1>{{ lang._('WebGuard IP Blocking Management') }}</h1>
            <p class="text-muted">{{ lang._('Manage blocked IPs and whitelist entries') }}</p>
        </div>
    </div>

    <!-- Status Row -->
    <div class="row">
        <div class="col-md-3">
            <div class="info-box">
                <span class="info-box-icon bg-red"><i class="fa fa-ban"></i></span>
                <div class="info-box-content">
                    <span class="info-box-text">{{ lang._('Active Blocks') }}</span>
                    <span class="info-box-number" id="active-blocks">0</span>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="info-box">
                <span class="info-box-icon bg-green"><i class="fa fa-check"></i></span>
                <div class="info-box-content">
                    <span class="info-box-text">{{ lang._('Whitelist Entries') }}</span>
                    <span class="info-box-number" id="whitelist-count">0</span>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="info-box">
                <span class="info-box-icon bg-yellow"><i class="fa fa-clock-o"></i></span>
                <div class="info-box-content">
                    <span class="info-box-text">{{ lang._('Temporary Blocks') }}</span>
                    <span class="info-box-number" id="temp-blocks">0</span>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="info-box">
                <span class="info-box-icon bg-blue"><i class="fa fa-shield"></i></span>
                <div class="info-box-content">
                    <span class="info-box-text">{{ lang._('Service Status') }}</span>
                    <span class="info-box-number" id="service-status">{{ lang._('Loading') }}</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="row">
        <div class="col-md-12">
            <div class="nav-tabs-custom">
                <ul class="nav nav-tabs">
                    <li class="active">
                        <a href="#blocked-tab" data-toggle="tab">
                            <i class="fa fa-ban"></i> {{ lang._('Blocked IPs') }}
                        </a>
                    </li>
                    <li>
                        <a href="#whitelist-tab" data-toggle="tab">
                            <i class="fa fa-check-circle"></i> {{ lang._('Whitelist') }}
                        </a>
                    </li>
                    <li>
                        <a href="#tools-tab" data-toggle="tab">
                            <i class="fa fa-wrench"></i> {{ lang._('Tools') }}
                        </a>
                    </li>
                </ul>
                
                <div class="tab-content">
                    <!-- Blocked IPs Tab -->
                    <div class="tab-pane active" id="blocked-tab">
                        <div class="row">
                            <div class="col-md-12">
                                <div class="box">
                                    <div class="box-header with-border">
                                        <h3 class="box-title">{{ lang._('Blocked IP Addresses') }}</h3>
                                        <div class="box-tools pull-right">
                                            <button type="button" class="btn btn-primary btn-sm" id="add-block-btn">
                                                <i class="fa fa-plus"></i> {{ lang._('Block IP') }}
                                            </button>
                                            <button type="button" class="btn btn-warning btn-sm" id="bulk-block-btn">
                                                <i class="fa fa-list"></i> {{ lang._('Bulk Block') }}
                                            </button>
                                            <button type="button" class="btn btn-info btn-sm" id="clear-expired-btn">
                                                <i class="fa fa-clock-o"></i> {{ lang._('Clear Expired') }}
                                            </button>
                                            <button type="button" class="btn btn-default btn-sm" id="refresh-blocked-btn">
                                                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                            </button>
                                        </div>
                                    </div>
                                    <div class="box-body">
                                        <div class="table-responsive">
                                            <table class="table table-hover" id="blocked-table">
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
                                                    <!-- Data loaded via AJAX -->
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Whitelist Tab -->
                    <div class="tab-pane" id="whitelist-tab">
                        <div class="row">
                            <div class="col-md-12">
                                <div class="box">
                                    <div class="box-header with-border">
                                        <h3 class="box-title">{{ lang._('Whitelisted Addresses') }}</h3>
                                        <div class="box-tools pull-right">
                                            <button type="button" class="btn btn-success btn-sm" id="add-whitelist-btn">
                                                <i class="fa fa-plus"></i> {{ lang._('Add to Whitelist') }}
                                            </button>
                                            <button type="button" class="btn btn-default btn-sm" id="refresh-whitelist-btn">
                                                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                                            </button>
                                        </div>
                                    </div>
                                    <div class="box-body">
                                        <div class="table-responsive">
                                            <table class="table table-hover" id="whitelist-table">
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
                                                    <!-- Data loaded via AJAX -->
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Tools Tab -->
                    <div class="tab-pane" id="tools-tab">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="box">
                                    <div class="box-header with-border">
                                        <h3 class="box-title">{{ lang._('Export Data') }}</h3>
                                    </div>
                                    <div class="box-body">
                                        <div class="form-group">
                                            <label>{{ lang._('Export Format') }}</label>
                                            <select class="form-control" id="export-format">
                                                <option value="json">JSON</option>
                                                <option value="csv">CSV</option>
                                                <option value="txt">Plain Text</option>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <button type="button" class="btn btn-primary" id="export-blocked-btn">
                                                <i class="fa fa-download"></i> {{ lang._('Export Blocked IPs') }}
                                            </button>
                                            <button type="button" class="btn btn-success" id="export-whitelist-btn">
                                                <i class="fa fa-download"></i> {{ lang._('Export Whitelist') }}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="box">
                                    <div class="box-header with-border">
                                        <h3 class="box-title">{{ lang._('Maintenance') }}</h3>
                                    </div>
                                    <div class="box-body">
                                        <div class="form-group">
                                            <button type="button" class="btn btn-warning" id="add-sample-threats-btn">
                                                <i class="fa fa-plus"></i> {{ lang._('Add Sample Threats') }}
                                            </button>
                                        </div>
                                        <div class="form-group">
                                            <button type="button" class="btn btn-info" id="clear-logs-btn">
                                                <i class="fa fa-trash"></i> {{ lang._('Clear Logs') }}
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

<!-- Block IP Modal -->
<div class="modal fade" id="block-ip-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Block IP Address') }}</h4>
            </div>
            <div class="modal-body">
                <form id="block-ip-form">
                    <div class="form-group">
                        <label for="block-ip">{{ lang._('IP Address') }}</label>
                        <input type="text" class="form-control" id="block-ip" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label for="block-duration">{{ lang._('Duration') }}</label>
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
                        <label for="block-reason">{{ lang._('Reason') }}</label>
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
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Bulk Block IP Addresses') }}</h4>
            </div>
            <div class="modal-body">
                <form id="bulk-block-form">
                    <div class="form-group">
                        <label for="bulk-block-ips">{{ lang._('IP Addresses (one per line)') }}</label>
                        <textarea class="form-control" id="bulk-block-ips" rows="6" placeholder="192.168.1.100&#10;10.0.0.50&#10;172.16.0.25"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="bulk-block-duration">{{ lang._('Duration') }}</label>
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
                        <label for="bulk-block-reason">{{ lang._('Reason') }}</label>
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
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Add to Whitelist') }}</h4>
            </div>
            <div class="modal-body">
                <form id="add-whitelist-form">
                    <div class="form-group">
                        <label for="whitelist-ip">{{ lang._('IP Address') }}</label>
                        <input type="text" class="form-control" id="whitelist-ip" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label for="whitelist-description">{{ lang._('Description') }}</label>
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

<script>
$(function() {

    loadStats();
    loadBlockedIps();
    loadWhitelist();

    setInterval(function() {
        loadStats();
        if ($('#blocked-tab').hasClass('active')) {
            loadBlockedIps();
        } else if ($('#whitelist-tab').hasClass('active')) {
            loadWhitelist();
        }
    }, 30000);

    /* Buttons */
    $('#add-block-btn').click(() => $('#block-ip-modal').modal('show'));
    $('#bulk-block-btn').click(() => $('#bulk-block-modal').modal('show'));
    $('#add-whitelist-btn').click(() => $('#add-whitelist-modal').modal('show'));
    $('#refresh-blocked-btn').click(() => { loadStats(); loadBlockedIps(); });
    $('#refresh-whitelist-btn').click(() => loadWhitelist());

    $('#clear-expired-btn').click(function() {
        if (confirm('{{ lang._("Clear all expired blocks?") }}')) {
            ajaxPost('/api/webguard/service/clearExpired', {}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("Expired blocks cleared") }}', 'success');
                    loadStats();
                    loadBlockedIps();
                } else {
                    showNotification('{{ lang._("Failed to clear expired blocks") }}', 'error');
                }
            });
        }
    });

    $('#export-blocked-btn').click(function() {
        let format = $('#export-format').val();
        window.location.href = '/api/webguard/service/exportBlocked?format=' + format;
        showNotification('{{ lang._("Export started") }}', 'info');
    });

    $('#export-whitelist-btn').click(function() {
        let format = $('#export-format').val();
        window.location.href = '/api/webguard/service/exportWhitelist?format=' + format;
        showNotification('{{ lang._("Export started") }}', 'info');
    });

    $('#add-sample-threats-btn').click(function() {
        if (confirm('{{ lang._("Add sample threat data for testing?") }}')) {
            ajaxPost('/api/webguard/service/addSampleThreats', {}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("Sample threats added") }}', 'success');
                } else {
                    showNotification('{{ lang._("Failed to add sample threats") }}', 'error');
                }
            });
        }
    });

    $('#clear-logs-btn').click(function() {
        if (confirm('{{ lang._("Clear all WebGuard logs?") }}')) {
            ajaxPost('/api/webguard/service/clearLogs', {}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("Logs cleared") }}', 'success');
                } else {
                    showNotification('{{ lang._("Failed to clear logs") }}', 'error');
                }
            });
        }
    });

    /* Modals confirm */
    $('#confirm-block-btn').click(function() {
        let ip       = $('#block-ip').val().trim();
        let duration = $('#block-duration').val();
        let reason   = $('#block-reason').val().trim();

        if (!ip) { showNotification('{{ lang._("Please enter an IP address") }}', 'error'); return; }

        ajaxPost('/api/webguard/service/blockIP', {
            ip: ip,
            duration: duration,
            reason: reason,
            block_type: 'manual'
        }, function(data) {
            if (data.status === 'ok') {
                $('#block-ip-modal').modal('hide');
                showNotification('{{ lang._("IP blocked successfully") }}', 'success');
                loadStats(); loadBlockedIps(); clearForm('block-ip-form');
            } else {
                showNotification('{{ lang._("Failed to block IP") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $('#confirm-bulk-block-btn').click(function() {
        let ips      = $('#bulk-block-ips').val().trim();
        let duration = $('#bulk-block-duration').val();
        let reason   = $('#bulk-block-reason').val().trim();

        if (!ips) { showNotification('{{ lang._("Please enter IP addresses") }}', 'error'); return; }

        ajaxPost('/api/webguard/service/bulkBlock', {
            ip_list: ips,
            duration: duration,
            reason: reason,
            block_type: 'manual'
        }, function(data) {
            if (data.status === 'ok') {
                $('#bulk-block-modal').modal('hide');
                showNotification('{{ lang._("IPs blocked successfully") }}', 'success');
                loadStats(); loadBlockedIps(); clearForm('bulk-block-form');
            } else {
                showNotification('{{ lang._("Failed to bulk block IPs") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    $('#confirm-whitelist-btn').click(function() {
        let ip         = $('#whitelist-ip').val().trim();
        let description= $('#whitelist-description').val().trim();
        let permanent  = $('#whitelist-permanent').is(':checked') ? '1' : '0';

        if (!ip) { showNotification('{{ lang._("Please enter an IP address") }}', 'error'); return; }

        ajaxPost('/api/webguard/service/addWhitelist', {
            ip: ip,
            description: description,
            permanent: permanent
        }, function(data) {
            if (data.status === 'ok') {
                $('#add-whitelist-modal').modal('hide');
                showNotification('{{ lang._("IP whitelisted successfully") }}', 'success');
                loadStats(); loadWhitelist(); clearForm('add-whitelist-form');
            } else {
                showNotification('{{ lang._("Failed to whitelist IP") }}: ' + (data.message || ''), 'error');
            }
        });
    });

    /* Dynamic buttons */
    $(document).on('click', '.unblock-btn', function() {
        let ip = $(this).data('ip');
        if (confirm('{{ lang._("Unblock IP") }} ' + ip + '?')) {
            ajaxPost('/api/webguard/service/unblockIP', {ip: ip}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("IP unblocked successfully") }}', 'success');
                    loadStats(); loadBlockedIps();
                } else {
                    showNotification('{{ lang._("Failed to unblock IP") }}: ' + (data.message || ''), 'error');
                }
            });
        }
    });

    $(document).on('click', '.remove-whitelist-btn', function() {
        let ip = $(this).data('ip');
        if (confirm('{{ lang._("Remove") }} ' + ip + ' {{ lang._("from whitelist") }}?')) {
            ajaxPost('/api/webguard/service/removeWhitelist', {ip: ip}, function(data) {
                if (data.status === 'ok') {
                    showNotification('{{ lang._("IP removed from whitelist") }}', 'success');
                    loadStats(); loadWhitelist();
                } else {
                    showNotification('{{ lang._("Failed to remove IP from whitelist") }}: ' + (data.message || ''), 'error');
                }
            });
        }
    });

    /* Helpers */

    function loadStats() {
        ajaxGet('/api/webguard/service/status', {}, function(data) {
            if (data && data.status === 'ok') {
                $('#service-status').text(data.running ? '{{ lang._("Running") }}' : '{{ lang._("Stopped") }}');
            }
        });

        ajaxGet('/api/webguard/service/getStats', {}, function(data) {
            if (data && data.status === 'ok' && data.data) {
                $('#active-blocks').text(data.data.blocked_count   || 0);
                $('#whitelist-count').text(data.data.whitelist_count || 0);
                $('#temp-blocks').text(data.data.active_blocks    || 0);
            }
        });
    }

    function loadBlockedIps() {
        ajaxGet('/api/webguard/service/listBlocked', {}, function(data) {
            let tbody = $('#blocked-table tbody').empty();

            if (data && data.status === 'ok' && data.data) {
                const arr = data.data.blocked_ips || [];
                if (arr.length) {
                    arr.forEach(function(item) {
                        let row = $('<tr>');
                        row.append('<td>' + item.ip_address + '</td>');
                        row.append('<td><span class="label label-' +
                            (item.block_type === 'permanent' ? 'danger' : 'warning') + '">' +
                            (item.block_type || '').toUpperCase() + '</span></td>');
                        row.append('<td>' + formatDate(item.blocked_since_iso) + '</td>');
                        row.append('<td>' + (item.expires_at_iso ? formatDate(item.expires_at_iso) : '{{ lang._("Never") }}') + '</td>');
                        row.append('<td>' + (item.reason || 'Manual block') + '</td>');
                        row.append('<td><button class="btn btn-xs btn-warning unblock-btn" data-ip="' + item.ip_address + '"><i class="fa fa-unlock"></i> {{ lang._("Unblock") }}</button></td>');
                        tbody.append(row);
                    });
                } else {
                    tbody.append('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No blocked IPs found") }}</td></tr>');
                }
            } else {
                tbody.append('<tr><td colspan="6" class="text-center text-danger">{{ lang._("Error loading data") }}</td></tr>');
            }
        });
    }

    function loadWhitelist() {
        ajaxGet('/api/webguard/service/listWhitelist', {}, function(data) {
            let tbody = $('#whitelist-table tbody').empty();

            if (data && data.status === 'ok' && data.data) {
                const arr = data.data.whitelist || [];
                if (arr.length) {
                    arr.forEach(function(item) {
                        let row = $('<tr>');
                        row.append('<td>' + item.ip_address + '</td>');
                        row.append('<td>' + (item.description || 'Manual entry') + '</td>');
                        row.append('<td>' + formatDate(item.added_at_iso) + '</td>');
                        row.append('<td><span class="label label-' + (item.permanent ? 'success' : 'warning') + '">' +
                            (item.permanent ? '{{ lang._("Permanent") }}' : '{{ lang._("Temporary") }}') + '</span></td>');
                        row.append('<td><button class="btn btn-xs btn-danger remove-whitelist-btn" data-ip="' + item.ip_address + '"><i class="fa fa-times"></i> {{ lang._("Remove") }}</button></td>');
                        tbody.append(row);
                    });
                } else {
                    tbody.append('<tr><td colspan="5" class="text-center text-muted">{{ lang._("No whitelist entries found") }}</td></tr>');
                }
            } else {
                tbody.append('<tr><td colspan="5" class="text-center text-danger">{{ lang._("Error loading data") }}</td></tr>');
            }
        });
    }

    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        try { return new Date(dateString).toLocaleString(); }
        catch (e) { return dateString; }
    }

    function clearForm(formId) {
        $('#' + formId + ' input[type="text"], #' + formId + ' textarea').val('');
        $('#' + formId + ' input[type="checkbox"]').prop('checked', false);
        $('#' + formId + ' select').prop('selectedIndex', 0);
    }

    function showNotification(message, type) {
        const cls = type === 'success' ? 'alert-success' :
                    type === 'warning' ? 'alert-warning' :
                    type === 'info'    ? 'alert-info'    : 'alert-danger';

        const notification = $('<div class="alert ' + cls + ' alert-dismissible" role="alert">' +
            '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
            message + '</div>');

        $('body').append(notification);
        setTimeout(() => notification.alert('close'), 5000);
    }

    function xhrError(xhr, status, error) {
        console.error('AJAX Error:', error);
        let msg = error || (xhr.responseText || '').toString();
        showNotification('{{ lang._("Connection error") }}: ' + msg, 'error');
    }

    function ajaxPost(url, data, cb) {
        $.ajax({
            url: url,
            type: 'POST',
            data: data,
            dataType: 'json',
            success: cb,
            error: xhrError
        });
    }

    function ajaxGet(url, data, cb) {
        $.ajax({
            url: url,
            type: 'GET',
            data: data,
            dataType: 'json',
            success: cb,
            error: xhrError
        });
    }
});
</script>


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

.info-box-icon > .fa {
    color: #fff;
}

.info-box-content {
    padding: 5px 10px;
    margin-left: 90px;
}

.info-box-number {
    display: block;
    font-weight: bold;
    font-size: 18px;
}

.info-box-text {
    display: block;
    font-size: 14px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.bg-red { background-color: #dd4b39 !important; }
.bg-green { background-color: #00a65a !important; }
.bg-yellow { background-color: #f39c12 !important; }
.bg-blue { background-color: #3c8dbc !important; }

.nav-tabs-custom {
    margin-bottom: 20px;
    background: #fff;
    box-shadow: 0 1px 1px rgba(0,0,0,0.1);
    border-radius: 3px;
}

.nav-tabs-custom > .nav-tabs {
    margin: 0;
    border-bottom-color: #f4f4f4;
    border-top-right-radius: 3px;
    border-top-left-radius: 3px;
}

.nav-tabs-custom > .tab-content {
    background: #fff;
    padding: 10px;
    border-bottom-right-radius: 3px;
    border-bottom-left-radius: 3px;
}

.box {
    position: relative;
    border-radius: 3px;
    background: #ffffff;
    border-top: 3px solid #d2d6de;
    margin-bottom: 20px;
    width: 100%;
    box-shadow: 0 1px 1px rgba(0,0,0,0.1);
}

.box-header {
    color: #444;
    display: block;
    padding: 10px;
    position: relative;
}

.box-header.with-border {
    border-bottom: 1px solid #f4f4f4;
}

.box-title {
    font-size: 18px;
    margin: 0;
    line-height: 1.8;
}

.box-tools {
    position: absolute;
    right: 10px;
    top: 5px;
}

.box-body {
    border-top-left-radius: 0;
    border-top-right-radius: 0;
    border-bottom-right-radius: 3px;
    border-bottom-left-radius: 3px;
    padding: 10px;
}

.label {
    display: inline;
    padding: .2em .6em .3em;
    font-size: 75%;
    font-weight: bold;
    line-height: 1;
    color: #fff;
    text-align: center;
    white-space: nowrap;
    vertical-align: baseline;
    border-radius: .25em;
}

.label-danger { background-color: #d9534f; }
.label-warning { background-color: #f0ad4e; }
.label-success { background-color: #5cb85c; }
.label-info { background-color: #5bc0de; }
</style>