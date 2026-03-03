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

            <div style="margin-bottom:.5rem;">
                <input type="text" class="form-control input-sm" id="blocklistSearch"
                       placeholder="{{ lang._('Search IPs...') }}" style="max-width:300px;">
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th class="sec-sortable" data-table="blocklist" style="cursor:pointer;white-space:nowrap;">
                                {{ lang._('IP Address') }} <i class="fa fa-sort-asc"></i>
                            </th>
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

            <div style="margin-bottom:.5rem;">
                <input type="text" class="form-control input-sm" id="whitelistSearch"
                       placeholder="{{ lang._('Search IPs...') }}" style="max-width:300px;">
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th class="sec-sortable" data-table="whitelist" style="cursor:pointer;white-space:nowrap;">
                                {{ lang._('IP Address') }} <i class="fa fa-sort-asc"></i>
                            </th>
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

            <div style="margin-bottom:.5rem;">
                <input type="text" class="form-control input-sm" id="fpSearch"
                       placeholder="{{ lang._('Search...') }}" style="max-width:300px;">
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th class="sec-sortable" data-table="fp" data-col="alert_id" style="cursor:pointer;white-space:nowrap;">{{ lang._('Alert ID') }} <i class="fa fa-sort text-muted"></i></th>
                            <th class="sec-sortable" data-table="fp" data-col="marked_at" style="cursor:pointer;white-space:nowrap;">{{ lang._('Marked At') }} <i class="fa fa-sort-desc"></i></th>
                            <th class="sec-sortable" data-table="fp" data-col="source_ip" style="cursor:pointer;white-space:nowrap;">{{ lang._('Source IP') }} <i class="fa fa-sort text-muted"></i></th>
                            <th class="sec-sortable" data-table="fp" data-col="threat_type" style="cursor:pointer;white-space:nowrap;">{{ lang._('Threat Type') }} <i class="fa fa-sort text-muted"></i></th>
                            <th>{{ lang._('Reason') }}</th>
                            <th style="width:195px;">{{ lang._('Actions') }}</th>
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

<!-- ── FP Review Modal ────────────────────────────────────────────────────────── -->
<div class="modal fade" id="fpReviewModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title">{{ lang._('Review False Positive') }}</h4>
            </div>
            <div class="modal-body">
                <p><strong>{{ lang._('Alert ID') }}:</strong> <code id="reviewFPAlertId"></code></p>
                <p><strong>{{ lang._('Source IP') }}:</strong> <code id="reviewFPSourceIP"></code></p>
                <p><strong>{{ lang._('Threat Type') }}:</strong> <span id="reviewFPThreatType"></span></p>
                <div class="form-group">
                    <label>{{ lang._('Reason') }}</label>
                    <input type="text" class="form-control input-sm" id="reviewFPReasonInput"
                           maxlength="200" placeholder="{{ lang._('Optional reason') }}">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary btn-sm" id="saveReviewFPBtn">
                    <i class="fa fa-save"></i> {{ lang._('Save') }}
                </button>
                <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">{{ lang._('Cancel') }}</button>
            </div>
        </div>
    </div>
</div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
var blocklistData    = [], blocklistPage = 1, blocklistPerPage = 25;
var blocklistSearch  = '', blocklistSortDir = 'asc';
var whitelistData    = [], whitelistPage = 1, whitelistPerPage = 25;
var whitelistSearch  = '', whitelistSortDir = 'asc';
var fpData           = [], fpPage = 1, fpPerPage = 25;
var fpSearch         = '', fpSortCol = 'marked_at', fpSortDir = 'desc';
var _reviewFPAlertId = null;

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

    // Live search
    $('#blocklistSearch').on('input', function() { blocklistSearch=$(this).val(); blocklistPage=1; renderBlocklist(); });
    $('#whitelistSearch').on('input', function() { whitelistSearch=$(this).val(); whitelistPage=1; renderWhitelist(); });
    $('#fpSearch').on('input', function()         { fpSearch=$(this).val();        fpPage=1;        renderFP(); });

    // Column sort
    $(document).on('click', '.sec-sortable', function() {
        var tbl = $(this).data('table');
        var col = $(this).data('col');
        if (tbl === 'blocklist') {
            blocklistSortDir = blocklistSortDir === 'asc' ? 'desc' : 'asc';
            blocklistPage = 1; renderBlocklist();
        } else if (tbl === 'whitelist') {
            whitelistSortDir = whitelistSortDir === 'asc' ? 'desc' : 'asc';
            whitelistPage = 1; renderWhitelist();
        } else if (tbl === 'fp') {
            if (fpSortCol === col) { fpSortDir = fpSortDir === 'asc' ? 'desc' : 'asc'; }
            else { fpSortCol = col; fpSortDir = 'asc'; }
            fpPage = 1; renderFP();
        }
    });

    // Review FP save
    $('#saveReviewFPBtn').click(function() {
        if (!_reviewFPAlertId) return;
        var reason = $('#reviewFPReasonInput').val().trim();
        ajaxCall('/api/deepinspector/alerts/updatefalsepositive', { alert_id: _reviewFPAlertId, reason: reason }, function(data) {
            if (data.status === 'ok') {
                secNotify('{{ lang._("Reason updated") }}', 'success');
                $('#fpReviewModal').modal('hide');
                fpPage = 1; loadFP();
            } else {
                secNotify(secEsc(data.message) || '{{ lang._("Failed to update") }}', 'error');
            }
        });
    });

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
    ajaxCall('/api/deepinspector/service/listblocked', {}, function(data) {
        blocklistData = (data.status==='ok' && Array.isArray(data.data)) ? data.data.filter(Boolean) : [];
        blocklistPage = 1;
        renderBlocklist();
    });
}

function getBlocklistFiltered() {
    var s = blocklistSearch.toLowerCase().trim();
    var d = s ? blocklistData.filter(function(ip){ return ip.toLowerCase().indexOf(s) >= 0; }) : blocklistData.slice();
    d.sort(function(a, b) { return blocklistSortDir === 'asc' ? a.localeCompare(b) : b.localeCompare(a); });
    return d;
}

function renderBlocklist() {
    var data  = getBlocklistFiltered();
    var tbody = $('#blocklistBody').empty();
    var $th   = $('[data-table="blocklist"]');
    $th.find('i').removeClass('fa-sort fa-sort-asc fa-sort-desc text-muted')
       .addClass(blocklistSortDir === 'asc' ? 'fa-sort-asc' : 'fa-sort-desc');
    if (data.length === 0) {
        tbody.html('<tr><td colspan="2" class="text-center text-muted">{{ lang._("No blocked IPs") }}</td></tr>');
        $('#blocklistPager').empty();
        return;
    }
    var start = (blocklistPage-1)*blocklistPerPage;
    var page  = data.slice(start, start+blocklistPerPage);
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
    secRenderPager('blocklistPager', data.length, blocklistPage, blocklistPerPage, function(p){
        blocklistPage=p; renderBlocklist();
    });
}

function addToBlocklist() {
    var ip = $('#blocklistAddIP').val().trim();
    if (!ip) return;
    ajaxCall('/api/deepinspector/service/blockip', { ip: ip }, function(data) {
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
    ajaxCall('/api/deepinspector/service/unblockip', { ip: ip }, function(data) {
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
    ajaxCall('/api/deepinspector/service/listwhitelist', {}, function(data) {
        whitelistData = (data.status==='ok' && Array.isArray(data.data)) ? data.data.filter(Boolean) : [];
        whitelistPage = 1;
        renderWhitelist();
    });
}

function getWhitelistFiltered() {
    var s = whitelistSearch.toLowerCase().trim();
    var d = s ? whitelistData.filter(function(ip){ return ip.toLowerCase().indexOf(s) >= 0; }) : whitelistData.slice();
    d.sort(function(a, b) { return whitelistSortDir === 'asc' ? a.localeCompare(b) : b.localeCompare(a); });
    return d;
}

function renderWhitelist() {
    var data  = getWhitelistFiltered();
    var tbody = $('#whitelistBody').empty();
    var $th   = $('[data-table="whitelist"]');
    $th.find('i').removeClass('fa-sort fa-sort-asc fa-sort-desc text-muted')
       .addClass(whitelistSortDir === 'asc' ? 'fa-sort-asc' : 'fa-sort-desc');
    if (data.length === 0) {
        tbody.html('<tr><td colspan="2" class="text-center text-muted">{{ lang._("No whitelisted IPs") }}</td></tr>');
        $('#whitelistPager').empty();
        return;
    }
    var start = (whitelistPage-1)*whitelistPerPage;
    var page  = data.slice(start, start+whitelistPerPage);
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
    secRenderPager('whitelistPager', data.length, whitelistPage, whitelistPerPage, function(p){
        whitelistPage=p; renderWhitelist();
    });
}

function addToWhitelist() {
    var ip = $('#whitelistAddIP').val().trim();
    if (!ip) return;
    ajaxCall('/api/deepinspector/service/whitelistip', { ip: ip }, function(data) {
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
    ajaxCall('/api/deepinspector/service/removewhitelistip', { ip: ip }, function(data) {
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
    ajaxCall('/api/deepinspector/alerts/listfalsepositives', {}, function(data) {
        fpData = (data.status==='ok' && Array.isArray(data.data)) ? data.data : [];
        fpPage = 1;
        renderFP();
    });
}

function getFPFiltered() {
    var s = fpSearch.toLowerCase().trim();
    var d = s ? fpData.filter(function(fp) {
        return [(fp.alert_id||''),(fp.source_ip||''),(fp.threat_type||''),(fp.reason||'')]
            .join(' ').toLowerCase().indexOf(s) >= 0;
    }) : fpData.slice();
    var col = fpSortCol, dir = fpSortDir;
    d.sort(function(a, b) {
        var va = (a[col]||'').toLowerCase(), vb = (b[col]||'').toLowerCase();
        return dir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    });
    return d;
}

function updateFPSortHeaders() {
    $('[data-table="fp"]').each(function() {
        var col = $(this).data('col');
        var $i  = $(this).find('i');
        $i.removeClass('fa-sort fa-sort-asc fa-sort-desc text-muted');
        if (col === fpSortCol) { $i.addClass(fpSortDir === 'asc' ? 'fa-sort-asc' : 'fa-sort-desc'); }
        else                   { $i.addClass('fa-sort text-muted'); }
    });
}

function renderFP() {
    updateFPSortHeaders();
    var data  = getFPFiltered();
    var tbody = $('#fpBody').empty();
    if (data.length === 0) {
        tbody.html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No false positives recorded") }}</td></tr>');
        $('#fpPager').empty();
        return;
    }
    var start = (fpPage-1)*fpPerPage;
    var page  = data.slice(start, start+fpPerPage);
    page.forEach(function(fp) {
        var reason = fp.reason && fp.reason.trim() ? secEsc(fp.reason) : '<span class="text-muted">—</span>';
        var aid = secEsc(fp.alert_id||'');
        var sip = secEsc(fp.source_ip||'');
        tbody.append(
            '<tr>' +
            '<td><code style="font-size:.78em;">' + aid + '</code></td>' +
            '<td style="font-size:.82em;white-space:nowrap;">' + secEsc(fp.marked_at||'') + '</td>' +
            '<td><code>' + sip + '</code></td>' +
            '<td style="font-size:.85em;">' + secEsc(fp.threat_type||'') + '</td>' +
            '<td style="font-size:.85em;">' + reason + '</td>' +
            '<td style="white-space:nowrap;">' +
            '<button class="btn btn-xs btn-danger" onclick="removeFP(\'' + aid + '\')" title="{{ lang._("Delete") }}" style="margin-right:2px;">' +
            '<i class="fa fa-trash"></i></button>' +
            '<button class="btn btn-xs btn-default" onclick="reviewFP(\'' + aid + '\')" title="{{ lang._("Review / Edit Reason") }}" style="margin-right:2px;">' +
            '<i class="fa fa-pencil"></i></button>' +
            '<button class="btn btn-xs btn-success" onclick="whitelistFromFP(\'' + sip + '\')" title="{{ lang._("Whitelist IP") }}">' +
            '<i class="fa fa-check-circle"></i></button>' +
            '</td></tr>'
        );
    });
    secRenderPager('fpPager', data.length, fpPage, fpPerPage, function(p){
        fpPage=p; renderFP();
    });
}

function removeFP(alertId) {
    if (!alertId) return;
    if (!confirm('{{ lang._("Remove this false positive entry?") }}')) return;
    ajaxCall('/api/deepinspector/alerts/removefalsepositive', { alert_id: alertId }, function(data) {
        if (data.status === 'ok') {
            secNotify('{{ lang._("False positive removed") }}', 'success');
            fpPage=1; loadFP();
        } else {
            secNotify(secEsc(data.message)||'{{ lang._("Failed to remove") }}', 'error');
        }
    });
}

function reviewFP(alertId) {
    if (!alertId) return;
    var fp = fpData.filter(function(f){ return f.alert_id === alertId; })[0];
    if (!fp) return;
    _reviewFPAlertId = alertId;
    $('#reviewFPAlertId').text(fp.alert_id || '');
    $('#reviewFPSourceIP').text(fp.source_ip || '');
    $('#reviewFPThreatType').text(fp.threat_type || '');
    $('#reviewFPReasonInput').val(fp.reason || '');
    $('#fpReviewModal').modal('show');
}

function whitelistFromFP(ip) {
    if (!ip) return;
    if (!confirm('{{ lang._("Add") }} ' + ip + ' {{ lang._("to whitelist?") }}')) return;
    ajaxCall('/api/deepinspector/service/whitelistip', { ip: ip }, function(data) {
        if (data.status === 'ok') {
            secNotify('{{ lang._("IP whitelisted successfully") }}', 'success');
        } else {
            secNotify(secEsc(data.message) || '{{ lang._("Failed to whitelist IP") }}', 'error');
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
