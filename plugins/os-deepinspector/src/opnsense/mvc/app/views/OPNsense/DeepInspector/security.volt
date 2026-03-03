{# security.volt - Deep Packet Inspector Security Management #}

<div id="di-security-notifications" style="position:fixed;top:20px;right:20px;z-index:9999;min-width:300px;"></div>

<!-- Nav tabs -->
<ul class="nav nav-tabs" id="securityTabs" role="tablist" style="margin-bottom:1.5rem;">
    <li class="nav-item active">
        <a class="nav-link active" id="tab-blocklist" data-toggle="tab" href="#pane-blocklist" role="tab">
            <i class="fa fa-ban"></i> {{ lang._('Blocklist') }}
        </a>
    </li>
    <li class="nav-item">
        <a class="nav-link" id="tab-whitelist" data-toggle="tab" href="#pane-whitelist" role="tab">
            <i class="fa fa-check-circle"></i> {{ lang._('Whitelist') }}
        </a>
    </li>
    <li class="nav-item">
        <a class="nav-link" id="tab-fp" data-toggle="tab" href="#pane-fp" role="tab">
            <i class="fa fa-flag"></i> {{ lang._('False Positives') }}
        </a>
    </li>
</ul>

<div class="tab-content">

    <!-- ── Blocklist tab ───────────────────────────────────────────────────── -->
    <div class="tab-pane fade in active" id="pane-blocklist" role="tabpanel">
        <div class="content-box" style="padding:1.25rem;">
            <div class="row" style="margin-bottom:1rem;align-items:flex-end;">
                <div class="col-md-8">
                    <h4 style="margin-top:0;">{{ lang._('Blocked IPs') }}</h4>
                    <p class="text-muted" style="font-size:.875rem;margin:0;">
                        {{ lang._('IP addresses currently blocked by the Deep Packet Inspector engine.') }}
                    </p>
                </div>
                <div class="col-md-4 text-right">
                    <button class="btn btn-default btn-sm" id="refreshBlocklist">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
                </div>
            </div>

            <!-- Add IP form -->
            <div class="well well-sm" style="margin-bottom:1rem;">
                <strong>{{ lang._('Add IP to Blocklist') }}</strong>
                <div class="row" style="margin-top:.5rem;">
                    <div class="col-md-6">
                        <input type="text" class="form-control" id="blocklistAddIP"
                               placeholder="{{ lang._('e.g. 192.0.2.1') }}" maxlength="45">
                    </div>
                    <div class="col-md-3">
                        <button class="btn btn-danger btn-sm" id="blocklistAddBtn" style="margin-top:2px;">
                            <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                        </button>
                    </div>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-sm">
                    <thead>
                        <tr>
                            <th>{{ lang._('IP Address') }}</th>
                            <th style="width:120px;">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="blocklistBody">
                        <tr><td colspan="2" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ── Whitelist tab ───────────────────────────────────────────────────── -->
    <div class="tab-pane fade" id="pane-whitelist" role="tabpanel">
        <div class="content-box" style="padding:1.25rem;">
            <div class="row" style="margin-bottom:1rem;align-items:flex-end;">
                <div class="col-md-8">
                    <h4 style="margin-top:0;">{{ lang._('Whitelisted IPs') }}</h4>
                    <p class="text-muted" style="font-size:.875rem;margin:0;">
                        {{ lang._('IP addresses excluded from blocking by the Deep Packet Inspector engine.') }}
                    </p>
                </div>
                <div class="col-md-4 text-right">
                    <button class="btn btn-default btn-sm" id="refreshWhitelist">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
                </div>
            </div>

            <!-- Add IP form -->
            <div class="well well-sm" style="margin-bottom:1rem;">
                <strong>{{ lang._('Add IP to Whitelist') }}</strong>
                <div class="row" style="margin-top:.5rem;">
                    <div class="col-md-6">
                        <input type="text" class="form-control" id="whitelistAddIP"
                               placeholder="{{ lang._('e.g. 192.168.1.10') }}" maxlength="45">
                    </div>
                    <div class="col-md-3">
                        <button class="btn btn-success btn-sm" id="whitelistAddBtn" style="margin-top:2px;">
                            <i class="fa fa-check"></i> {{ lang._('Whitelist IP') }}
                        </button>
                    </div>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-sm">
                    <thead>
                        <tr>
                            <th>{{ lang._('IP Address') }}</th>
                            <th style="width:120px;">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="whitelistBody">
                        <tr><td colspan="2" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ── False Positives tab ─────────────────────────────────────────────── -->
    <div class="tab-pane fade" id="pane-fp" role="tabpanel">
        <div class="content-box" style="padding:1.25rem;">
            <div class="row" style="margin-bottom:1rem;align-items:flex-end;">
                <div class="col-md-8">
                    <h4 style="margin-top:0;">{{ lang._('False Positives') }}</h4>
                    <p class="text-muted" style="font-size:.875rem;margin:0;">
                        {{ lang._('Alerts manually marked as false positives. Use the Dashboard threat table to mark new false positives.') }}
                    </p>
                </div>
                <div class="col-md-4 text-right">
                    <button class="btn btn-default btn-sm" id="refreshFP">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-sm">
                    <thead>
                        <tr>
                            <th>{{ lang._('Alert ID') }}</th>
                            <th>{{ lang._('Marked At') }}</th>
                            <th>{{ lang._('Source IP') }}</th>
                            <th>{{ lang._('Threat Type') }}</th>
                            <th>{{ lang._('Reason') }}</th>
                            <th style="width:100px;">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="fpBody">
                        <tr><td colspan="6" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

</div>

<script>
$(document).ready(function () {
    loadBlocklist();
    loadWhitelist();
    loadFP();

    $('#refreshBlocklist').click(loadBlocklist);
    $('#refreshWhitelist').click(loadWhitelist);
    $('#refreshFP').click(loadFP);

    $('#blocklistAddBtn').click(function () {
        var ip = $('#blocklistAddIP').val().trim();
        if (!ip) return;
        ajaxCall('/api/deepinspector/service/blockIP', { ip: ip }, function (data) {
            if (data.status === 'ok') {
                showSecNotification('{{ lang._("IP blocked successfully") }}', 'success');
                $('#blocklistAddIP').val('');
                loadBlocklist();
            } else {
                showSecNotification(data.message || '{{ lang._("Failed to block IP") }}', 'error');
            }
        });
    });

    $('#whitelistAddBtn').click(function () {
        var ip = $('#whitelistAddIP').val().trim();
        if (!ip) return;
        ajaxCall('/api/deepinspector/service/whitelistIP', { ip: ip }, function (data) {
            if (data.status === 'ok') {
                showSecNotification('{{ lang._("IP whitelisted successfully") }}', 'success');
                $('#whitelistAddIP').val('');
                loadWhitelist();
            } else {
                showSecNotification(data.message || '{{ lang._("Failed to whitelist IP") }}', 'error');
            }
        });
    });

    // Allow Enter key in input fields
    $('#blocklistAddIP').keypress(function (e) { if (e.which === 13) $('#blocklistAddBtn').click(); });
    $('#whitelistAddIP').keypress(function (e) { if (e.which === 13) $('#whitelistAddBtn').click(); });
});

// ── Blocklist ─────────────────────────────────────────────────────────────────

function loadBlocklist() {
    ajaxCall('/api/deepinspector/service/listBlocked', {}, function (data) {
        var tbody = $('#blocklistBody');
        tbody.empty();
        var ips = (data.status === 'ok' && Array.isArray(data.data)) ? data.data : [];
        if (ips.length === 0) {
            tbody.html('<tr><td colspan="2" class="text-center text-muted">{{ lang._("No blocked IPs") }}</td></tr>');
            return;
        }
        ips.forEach(function (ip) {
            if (!ip) return;
            tbody.append(
                '<tr>' +
                '<td><code>' + escHtml(ip) + '</code></td>' +
                '<td>' +
                '<button class="btn btn-xs btn-danger" onclick="unblockIP(\'' + escHtml(ip) + '\')">' +
                '<i class="fa fa-times"></i> {{ lang._("Remove") }}</button>' +
                '</td>' +
                '</tr>'
            );
        });
    });
}

function unblockIP(ip) {
    if (!confirm('{{ lang._("Remove") }} ' + ip + ' {{ lang._("from blocklist?") }}')) return;
    ajaxCall('/api/deepinspector/service/unblockIP', { ip: ip }, function (data) {
        if (data.status === 'ok') {
            showSecNotification('{{ lang._("IP removed from blocklist") }}', 'success');
            loadBlocklist();
        } else {
            showSecNotification(data.message || '{{ lang._("Failed to remove IP") }}', 'error');
        }
    });
}

// ── Whitelist ─────────────────────────────────────────────────────────────────

function loadWhitelist() {
    ajaxCall('/api/deepinspector/service/listWhitelist', {}, function (data) {
        var tbody = $('#whitelistBody');
        tbody.empty();
        var ips = (data.status === 'ok' && Array.isArray(data.data)) ? data.data : [];
        if (ips.length === 0) {
            tbody.html('<tr><td colspan="2" class="text-center text-muted">{{ lang._("No whitelisted IPs") }}</td></tr>');
            return;
        }
        ips.forEach(function (ip) {
            if (!ip) return;
            tbody.append(
                '<tr>' +
                '<td><code>' + escHtml(ip) + '</code></td>' +
                '<td>' +
                '<button class="btn btn-xs btn-warning" onclick="removeWhitelistIP(\'' + escHtml(ip) + '\')">' +
                '<i class="fa fa-times"></i> {{ lang._("Remove") }}</button>' +
                '</td>' +
                '</tr>'
            );
        });
    });
}

function removeWhitelistIP(ip) {
    if (!confirm('{{ lang._("Remove") }} ' + ip + ' {{ lang._("from whitelist?") }}')) return;
    ajaxCall('/api/deepinspector/service/removeWhitelistIP', { ip: ip }, function (data) {
        if (data.status === 'ok') {
            showSecNotification('{{ lang._("IP removed from whitelist") }}', 'success');
            loadWhitelist();
        } else {
            showSecNotification(data.message || '{{ lang._("Failed to remove IP") }}', 'error');
        }
    });
}

// ── False Positives ───────────────────────────────────────────────────────────

function loadFP() {
    ajaxCall('/api/deepinspector/alerts/listFalsePositives', {}, function (data) {
        var tbody = $('#fpBody');
        tbody.empty();
        var fps = (data.status === 'ok' && Array.isArray(data.data)) ? data.data : [];
        if (fps.length === 0) {
            tbody.html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No false positives recorded") }}</td></tr>');
            return;
        }
        fps.forEach(function (fp) {
            tbody.append(
                '<tr>' +
                '<td><code style="font-size:.8em">' + escHtml(fp.alert_id || '') + '</code></td>' +
                '<td style="font-size:.85em">' + escHtml(fp.marked_at || '') + '</td>' +
                '<td><code>' + escHtml(fp.source_ip || '') + '</code></td>' +
                '<td>' + escHtml(fp.threat_type || '') + '</td>' +
                '<td>' + escHtml(fp.reason || '') + '</td>' +
                '<td>' +
                '<button class="btn btn-xs btn-danger" onclick="removeFP(\'' + escHtml(fp.alert_id) + '\')">' +
                '<i class="fa fa-trash"></i> {{ lang._("Remove") }}</button>' +
                '</td>' +
                '</tr>'
            );
        });
    });
}

function removeFP(alertId) {
    if (!confirm('{{ lang._("Remove false positive entry?") }}')) return;
    ajaxCall('/api/deepinspector/alerts/removeFalsePositive', { alert_id: alertId }, function (data) {
        if (data.status === 'ok') {
            showSecNotification('{{ lang._("False positive removed") }}', 'success');
            loadFP();
        } else {
            showSecNotification(data.message || '{{ lang._("Failed to remove") }}', 'error');
        }
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showSecNotification(message, type) {
    var cls = type === 'success' ? 'alert-success' : 'alert-danger';
    var n = $('<div class="alert ' + cls + ' alert-dismissible fade show" role="alert">' +
        message +
        '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
        '</div>');
    $('#di-security-notifications').append(n);
    setTimeout(function () { n.alert('close'); }, 5000);
}
</script>
