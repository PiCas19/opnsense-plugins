{# security.volt - Deep Packet Inspector Security Management #}

<div id="sec-notifications" style="position:fixed;top:20px;right:20px;z-index:9999;min-width:300px;"></div>

<!-- ── Nav tabs (Bootstrap 3) ───────────────────────────────────────────────── -->
<ul class="nav nav-tabs" role="tablist" style="margin-bottom:1.25rem;">
    <li role="presentation" class="active">
        <a href="#pane-blocklist" data-toggle="tab" role="tab">
            <i class="fa fa-ban"></i> {{ lang._('Blocklist') }}
        </a>
    </li>
    <li role="presentation">
        <a href="#pane-whitelist" data-toggle="tab" role="tab">
            <i class="fa fa-check-circle"></i> {{ lang._('Whitelist') }}
        </a>
    </li>
    <li role="presentation">
        <a href="#pane-fp" data-toggle="tab" role="tab">
            <i class="fa fa-flag"></i> {{ lang._('False Positives') }}
        </a>
    </li>
</ul>

<div class="tab-content">

    <!-- ── Blocklist ──────────────────────────────────────────────────────── -->
    <div role="tabpanel" class="tab-pane active" id="pane-blocklist">
        <div class="content-box" style="padding:1.25rem;">
            <div class="row" style="margin-bottom:1rem;">
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

            <div class="well well-sm" style="margin-bottom:1rem;">
                <strong>{{ lang._('Add IP to Blocklist') }}</strong>
                <div class="row" style="margin-top:.5rem;">
                    <div class="col-md-5">
                        <input type="text" class="form-control input-sm" id="blocklistAddIP"
                               placeholder="e.g. 192.0.2.1" maxlength="45">
                    </div>
                    <div class="col-md-4">
                        <button class="btn btn-danger btn-sm" id="blocklistAddBtn">
                            <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                        </button>
                    </div>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>{{ lang._('IP Address') }}</th>
                            <th style="width:100px;">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="blocklistBody">
                        <tr><td colspan="2" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
            <div id="blocklistPager"></div>
        </div>
    </div>

    <!-- ── Whitelist ──────────────────────────────────────────────────────── -->
    <div role="tabpanel" class="tab-pane" id="pane-whitelist">
        <div class="content-box" style="padding:1.25rem;">
            <div class="row" style="margin-bottom:1rem;">
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

            <div class="well well-sm" style="margin-bottom:1rem;">
                <strong>{{ lang._('Add IP to Whitelist') }}</strong>
                <div class="row" style="margin-top:.5rem;">
                    <div class="col-md-5">
                        <input type="text" class="form-control input-sm" id="whitelistAddIP"
                               placeholder="e.g. 192.168.1.10" maxlength="45">
                    </div>
                    <div class="col-md-4">
                        <button class="btn btn-success btn-sm" id="whitelistAddBtn">
                            <i class="fa fa-check"></i> {{ lang._('Whitelist IP') }}
                        </button>
                    </div>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>{{ lang._('IP Address') }}</th>
                            <th style="width:100px;">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="whitelistBody">
                        <tr><td colspan="2" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
            <div id="whitelistPager"></div>
        </div>
    </div>

    <!-- ── False Positives ────────────────────────────────────────────────── -->
    <div role="tabpanel" class="tab-pane" id="pane-fp">
        <div class="content-box" style="padding:1.25rem;">
            <div class="row" style="margin-bottom:1rem;">
                <div class="col-md-8">
                    <h4 style="margin-top:0;">{{ lang._('False Positives') }}</h4>
                    <p class="text-muted" style="font-size:.875rem;margin:0;">
                        {{ lang._('Alerts manually marked as false positives from the Dashboard threat table.') }}
                    </p>
                </div>
                <div class="col-md-4 text-right">
                    <button class="btn btn-default btn-sm" id="refreshFP">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>{{ lang._('Alert ID') }}</th>
                            <th>{{ lang._('Marked At') }}</th>
                            <th>{{ lang._('Source IP') }}</th>
                            <th>{{ lang._('Threat Type') }}</th>
                            <th>{{ lang._('Reason') }}</th>
                            <th style="width:90px;">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="fpBody">
                        <tr><td colspan="6" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
            <div id="fpPager"></div>
        </div>
    </div>

</div><!-- /tab-content -->

<script>
// ── State ─────────────────────────────────────────────────────────────────────
var blocklistData  = [], blocklistPage = 1, blocklistPerPage = 25;
var whitelistData  = [], whitelistPage = 1, whitelistPerPage = 25;
var fpData         = [], fpPage        = 1, fpPerPage        = 25;

// ── Init ──────────────────────────────────────────────────────────────────────
$(document).ready(function () {
    loadBlocklist();
    loadWhitelist();
    loadFP();

    $('#refreshBlocklist').click(function () { blocklistPage=1; loadBlocklist(); });
    $('#refreshWhitelist').click(function () { whitelistPage=1; loadWhitelist(); });
    $('#refreshFP').click(function ()         { fpPage=1;        loadFP(); });

    $('#blocklistAddBtn').click(addToBlocklist);
    $('#whitelistAddBtn').click(addToWhitelist);

    $('#blocklistAddIP').keypress(function(e){ if(e.which===13) addToBlocklist(); });
    $('#whitelistAddIP').keypress(function(e){ if(e.which===13) addToWhitelist(); });

    // Reload tab data when switched to
    $('a[data-toggle="tab"]').on('shown.bs.tab', function(e) {
        var target = $(e.target).attr('href');
        if (target === '#pane-blocklist') { blocklistPage=1; loadBlocklist(); }
        if (target === '#pane-whitelist') { whitelistPage=1; loadWhitelist(); }
        if (target === '#pane-fp')        { fpPage=1;        loadFP(); }
    });
});

// ── Blocklist ─────────────────────────────────────────────────────────────────
function loadBlocklist() {
    ajaxCall('/api/deepinspector/service/listBlocked', {}, function(data) {
        blocklistData = (data.status==='ok' && Array.isArray(data.data)) ? data.data.filter(Boolean) : [];
        blocklistPage = 1;
        renderBlocklist();
    });
}

function renderBlocklist() {
    var tbody = $('#blocklistBody').empty();
    if (blocklistData.length === 0) {
        tbody.html('<tr><td colspan="2" class="text-center text-muted">{{ lang._("No blocked IPs") }}</td></tr>');
        $('#blocklistPager').empty();
        return;
    }
    var start = (blocklistPage-1)*blocklistPerPage;
    var page  = blocklistData.slice(start, start+blocklistPerPage);
    page.forEach(function(ip) {
        tbody.append(
            '<tr>' +
            '<td><code>' + secEsc(ip) + '</code></td>' +
            '<td>' +
            '<button class="btn btn-xs btn-danger" onclick="unblockIP(\'' + secEsc(ip) + '\')">' +
            '<i class="fa fa-times"></i> {{ lang._("Remove") }}</button>' +
            '</td></tr>'
        );
    });
    secRenderPager('blocklistPager', blocklistData.length, blocklistPage, blocklistPerPage, function(p){
        blocklistPage=p; renderBlocklist();
    });
}

function addToBlocklist() {
    var ip = $('#blocklistAddIP').val().trim();
    if (!ip) return;
    ajaxCall('/api/deepinspector/service/blockIP', { ip: ip }, function(data) {
        if (data.status === 'ok') {
            secNotify('{{ lang._("IP blocked successfully") }}', 'success');
            $('#blocklistAddIP').val('');
            blocklistPage=1; loadBlocklist();
        } else {
            secNotify(secEsc(data.message)||'{{ lang._("Failed to block IP") }}', 'error');
        }
    });
}

function unblockIP(ip) {
    if (!confirm('{{ lang._("Remove") }} ' + ip + ' {{ lang._("from blocklist?") }}')) return;
    ajaxCall('/api/deepinspector/service/unblockIP', { ip: ip }, function(data) {
        if (data.status === 'ok') {
            secNotify('{{ lang._("IP removed from blocklist") }}', 'success');
            blocklistPage=1; loadBlocklist();
        } else {
            secNotify(secEsc(data.message)||'{{ lang._("Failed to remove IP") }}', 'error');
        }
    });
}

// ── Whitelist ─────────────────────────────────────────────────────────────────
function loadWhitelist() {
    ajaxCall('/api/deepinspector/service/listWhitelist', {}, function(data) {
        whitelistData = (data.status==='ok' && Array.isArray(data.data)) ? data.data.filter(Boolean) : [];
        whitelistPage = 1;
        renderWhitelist();
    });
}

function renderWhitelist() {
    var tbody = $('#whitelistBody').empty();
    if (whitelistData.length === 0) {
        tbody.html('<tr><td colspan="2" class="text-center text-muted">{{ lang._("No whitelisted IPs") }}</td></tr>');
        $('#whitelistPager').empty();
        return;
    }
    var start = (whitelistPage-1)*whitelistPerPage;
    var page  = whitelistData.slice(start, start+whitelistPerPage);
    page.forEach(function(ip) {
        tbody.append(
            '<tr>' +
            '<td><code>' + secEsc(ip) + '</code></td>' +
            '<td>' +
            '<button class="btn btn-xs btn-warning" onclick="removeWhitelistIP(\'' + secEsc(ip) + '\')">' +
            '<i class="fa fa-times"></i> {{ lang._("Remove") }}</button>' +
            '</td></tr>'
        );
    });
    secRenderPager('whitelistPager', whitelistData.length, whitelistPage, whitelistPerPage, function(p){
        whitelistPage=p; renderWhitelist();
    });
}

function addToWhitelist() {
    var ip = $('#whitelistAddIP').val().trim();
    if (!ip) return;
    ajaxCall('/api/deepinspector/service/whitelistIP', { ip: ip }, function(data) {
        if (data.status === 'ok') {
            secNotify('{{ lang._("IP whitelisted successfully") }}', 'success');
            $('#whitelistAddIP').val('');
            whitelistPage=1; loadWhitelist();
        } else {
            secNotify(secEsc(data.message)||'{{ lang._("Failed to whitelist IP") }}', 'error');
        }
    });
}

function removeWhitelistIP(ip) {
    if (!confirm('{{ lang._("Remove") }} ' + ip + ' {{ lang._("from whitelist?") }}')) return;
    ajaxCall('/api/deepinspector/service/removeWhitelistIP', { ip: ip }, function(data) {
        if (data.status === 'ok') {
            secNotify('{{ lang._("IP removed from whitelist") }}', 'success');
            whitelistPage=1; loadWhitelist();
        } else {
            secNotify(secEsc(data.message)||'{{ lang._("Failed to remove IP") }}', 'error');
        }
    });
}

// ── False Positives ───────────────────────────────────────────────────────────
function loadFP() {
    ajaxCall('/api/deepinspector/alerts/listFalsePositives', {}, function(data) {
        fpData = (data.status==='ok' && Array.isArray(data.data)) ? data.data : [];
        fpPage = 1;
        renderFP();
    });
}

function renderFP() {
    var tbody = $('#fpBody').empty();
    if (fpData.length === 0) {
        tbody.html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No false positives recorded") }}</td></tr>');
        $('#fpPager').empty();
        return;
    }
    var start = (fpPage-1)*fpPerPage;
    var page  = fpData.slice(start, start+fpPerPage);
    page.forEach(function(fp) {
        var reason = fp.reason && fp.reason.trim() ? secEsc(fp.reason) : '<span class="text-muted">—</span>';
        tbody.append(
            '<tr>' +
            '<td><code style="font-size:.78em;">' + secEsc(fp.alert_id||'') + '</code></td>' +
            '<td style="font-size:.82em;white-space:nowrap;">' + secEsc(fp.marked_at||'') + '</td>' +
            '<td><code>' + secEsc(fp.source_ip||'') + '</code></td>' +
            '<td style="font-size:.85em;">' + secEsc(fp.threat_type||'') + '</td>' +
            '<td style="font-size:.85em;">' + reason + '</td>' +
            '<td>' +
            '<button class="btn btn-xs btn-danger" onclick="removeFP(\'' + secEsc(fp.alert_id||'') + '\')">' +
            '<i class="fa fa-trash"></i> {{ lang._("Remove") }}</button>' +
            '</td></tr>'
        );
    });
    secRenderPager('fpPager', fpData.length, fpPage, fpPerPage, function(p){
        fpPage=p; renderFP();
    });
}

function removeFP(alertId) {
    if (!alertId) return;
    if (!confirm('{{ lang._("Remove this false positive entry?") }}')) return;
    ajaxCall('/api/deepinspector/alerts/removeFalsePositive', { alert_id: alertId }, function(data) {
        if (data.status === 'ok') {
            secNotify('{{ lang._("False positive removed") }}', 'success');
            fpPage=1; loadFP();
        } else {
            secNotify(secEsc(data.message)||'{{ lang._("Failed to remove") }}', 'error');
        }
    });
}

// ── Pagination helper ─────────────────────────────────────────────────────────
function secRenderPager(containerId, total, page, perPage, onPage) {
    var totalPages = Math.ceil(total / perPage);
    var $c = $('#' + containerId).empty();
    if (totalPages <= 1) return;
    var from = (page-1)*perPage+1, to = Math.min(page*perPage, total);
    var html = '<div style="margin-top:.5rem;overflow:hidden;">' +
               '<small class="text-muted" style="float:left;line-height:28px;">Showing ' + from + '–' + to + ' of ' + total + '</small>' +
               '<ul class="pagination pagination-sm" style="float:right;margin:0;">';
    html += '<li class="'+(page===1?'disabled':'')+'"><a href="#" data-p="'+(page-1)+'">&laquo;</a></li>';
    var s=Math.max(1,page-2), e=Math.min(totalPages,s+4); s=Math.max(1,e-4);
    for (var i=s; i<=e; i++) html += '<li class="'+(i===page?'active':'')+'"><a href="#" data-p="'+i+'">'+i+'</a></li>';
    html += '<li class="'+(page===totalPages?'disabled':'')+'"><a href="#" data-p="'+(page+1)+'">&raquo;</a></li>';
    html += '</ul></div>';
    $c.html(html);
    $c.find('a[data-p]').click(function(e) {
        e.preventDefault();
        var p = parseInt($(this).data('p'));
        if (p >= 1 && p <= totalPages && p !== page) onPage(p);
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function secEsc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
function secNotify(message, type) {
    var cls = type === 'success' ? 'alert-success' : 'alert-danger';
    var n = $('<div class="alert '+cls+' alert-dismissible" role="alert" style="margin-bottom:.5rem;">' +
              '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
              message+'</div>');
    $('#sec-notifications').append(n);
    setTimeout(function(){ n.alert('close'); }, 5000);
}
</script>
