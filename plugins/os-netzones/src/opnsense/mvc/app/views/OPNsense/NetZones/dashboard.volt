{#
 # NetZones Dashboard
 #}
<div id="nz-notifications" style="position:fixed;bottom:24px;right:24px;z-index:9999;min-width:280px;max-width:380px;pointer-events:none;"></div>

<!-- ── Toolbar ─────────────────────────────────────────────────────────────── -->
<div class="content-box" style="padding:.65rem 1.25rem;margin-bottom:1rem;">
    <div class="row" style="align-items:center;">
        <div class="col-md-2">
            <span id="nzServiceBadge" class="label label-default" style="font-size:.9em;padding:.35em .7em;">{{ lang._('Loading...') }}</span>
        </div>
        <div class="col-md-10 text-right">
            <span class="text-muted" style="font-size:.8em;">
                {{ lang._('Updated') }}: <strong id="nzLastUpdated">--</strong>
            </span>
            <button class="btn btn-default btn-sm" id="nzRefresh" style="margin-left:.5rem;">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
        </div>
    </div>
</div>

<!-- ── Metric cards ─────────────────────────────────────────────────────────── -->
<div class="row">
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon"><i class="fa fa-server"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="nzMetricService">--</div>
                <div class="di-metric-label">{{ lang._('Service') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon" style="color:#2563eb;"><i class="fa fa-shield"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="nzMetricZones">--</div>
                <div class="di-metric-label">{{ lang._('Active Zones') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon" style="color:#059669;"><i class="fa fa-exchange"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="nzMetricPolicies">--</div>
                <div class="di-metric-label">{{ lang._('Active Policies') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon" style="color:#d97706;"><i class="fa fa-list-alt"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="nzMetricEvents">--</div>
                <div class="di-metric-label">{{ lang._('Total Events') }}</div>
            </div>
        </div>
    </div>
</div>

<!-- ── Charts row ──────────────────────────────────────────────────────────── -->
<div class="row">
    <div class="col-md-6">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Activity (last 6h)') }}</span>
            </div>
            <div id="nzActivityChart" style="height:120px;"></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Decisions') }}</span>
            </div>
            <div id="nzDecisionStats" style="padding-top:.25rem;"></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Top Protocols') }}</span>
            </div>
            <div id="nzProtocols" style="padding-top:.25rem;"></div>
        </div>
    </div>
</div>

<!-- ── Main content ─────────────────────────────────────────────────────────── -->
<div class="row">
    <div class="col-md-9">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Recent Policy Decisions') }}</span>
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-condensed" style="font-size:.85em;margin:0;">
                    <thead>
                        <tr>
                            <th style="white-space:nowrap;">{{ lang._('Time') }}</th>
                            <th>{{ lang._('Source Zone') }}</th>
                            <th>{{ lang._('Dest Zone') }}</th>
                            <th>{{ lang._('Proto') }}</th>
                            <th>{{ lang._('Port') }}</th>
                            <th>{{ lang._('Decision') }}</th>
                        </tr>
                    </thead>
                    <tbody id="nzDecisionsBody">
                        <tr><td colspan="6" class="text-center text-muted"><i class="fa fa-spinner fa-spin"></i></td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box" style="margin-bottom:1rem;">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Zone Relationships') }}</span>
            </div>
            <div id="nzRelationships" style="padding-top:.25rem;"></div>
        </div>
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Service Controls') }}</span>
            </div>
            <div class="btn-group-vertical" style="width:100%;margin-top:.5rem;">
                <button class="btn btn-success btn-sm" id="nzStartBtn" style="margin-bottom:.3rem;">
                    <i class="fa fa-play"></i> {{ lang._('Start') }}
                </button>
                <button class="btn btn-warning btn-sm" id="nzRestartBtn" style="margin-bottom:.3rem;">
                    <i class="fa fa-refresh"></i> {{ lang._('Restart') }}
                </button>
                <button class="btn btn-danger btn-sm" id="nzStopBtn">
                    <i class="fa fa-stop"></i> {{ lang._('Stop') }}
                </button>
            </div>
        </div>
    </div>
</div>

<style>
.di-metric-card {
    background:#fff; border-radius:6px; padding:1.1rem;
    box-shadow:0 1px 4px rgba(0,0,0,.1); margin-bottom:1rem;
    display:flex; align-items:center; gap:.85rem;
}
.di-metric-icon  { font-size:1.75rem; color:#2563eb; width:2rem; text-align:center; flex-shrink:0; }
.di-metric-value { font-size:1.65rem; font-weight:700; color:#1f2937; line-height:1.1; }
.di-metric-label { font-size:.75rem; color:#6b7280; text-transform:uppercase; letter-spacing:.04em; }
.di-chart-box {
    background:#fff; border-radius:6px; padding:.9rem;
    box-shadow:0 1px 4px rgba(0,0,0,.1); margin-bottom:1rem;
}
.di-chart-hdr {
    display:flex; justify-content:space-between; align-items:center;
    margin-bottom:.5rem; min-height:26px;
}
.di-chart-title { font-size:.88rem; font-weight:600; color:#374151; }
.nz-zone-link {
    padding:4px 8px; border-left:3px solid #2563eb;
    margin-bottom:4px; background:#f9fafb; font-size:.82em;
    border-radius:0 3px 3px 0;
}
.nz-bar-wrap { display:flex; align-items:center; gap:.4rem; margin-bottom:.35rem; font-size:.82em; }
.nz-bar-bg   { flex:1; height:8px; background:#e5e7eb; border-radius:4px; overflow:hidden; }
.nz-bar-fill { height:100%; border-radius:4px; }
</style>

<script>
function nzNotify(message, type) {
    var cls  = type === 'success' ? 'alert-success' : (type === 'warning' ? 'alert-warning' : 'alert-danger');
    var icon = type === 'success' ? 'fa-check' : (type === 'warning' ? 'fa-exclamation-triangle' : 'fa-exclamation-circle');
    var $n = $('<div role="alert" style="pointer-events:all;margin-top:.4rem;border-radius:3px;box-shadow:0 2px 10px rgba(0,0,0,.28);">' +
               '<div class="alert ' + cls + ' alert-dismissible" style="margin:0;padding:.6rem .9rem;">' +
               '<button type="button" class="close" data-dismiss="alert" style="top:0;right:4px;"><span>&times;</span></button>' +
               '<i class="fa ' + icon + '" style="margin-right:.45rem;"></i>' + message + '</div></div>');
    $('#nz-notifications').append($n);
    setTimeout(function() { $n.find('.alert').alert('close'); $n.remove(); }, 4000);
}

function nzEsc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function loadDashboard() {
    loadStats();
    loadLogs();
    loadRelationships();
    loadTrafficPatterns();
    loadServiceStatus();
    $('#nzLastUpdated').text(new Date().toLocaleTimeString());
}

function loadServiceStatus() {
    ajaxCall('/api/netzones/service/status', {}, function(data) {
        if (data && data.running) {
            $('#nzServiceBadge').removeClass('label-default label-danger').addClass('label-success').text('{{ lang._("RUNNING") }}');
            $('#nzMetricService').text('{{ lang._("Running") }}').css('color','#059669');
        } else {
            $('#nzServiceBadge').removeClass('label-default label-success').addClass('label-danger').text('{{ lang._("STOPPED") }}');
            $('#nzMetricService').text('{{ lang._("Stopped") }}').css('color','#dc2626');
        }
    }).fail(function() {
        $('#nzServiceBadge').removeClass('label-success label-danger').addClass('label-default').text('{{ lang._("Unknown") }}');
        $('#nzMetricService').text('?');
    });
}

function loadStats() {
    ajaxCall('/api/netzones/management/dashboard_stats', {}, function(data) {
        if (!data || data.status !== 'ok' || !data.data) { return; }
        var s = data.data;

        // Zones card
        var za = (s.zones && s.zones.active) ? s.zones.active : 0;
        var zt = (s.zones && s.zones.total)  ? s.zones.total  : 0;
        $('#nzMetricZones').text(za + ' / ' + zt);

        // Policies card
        var pa = (s.policies && s.policies.active) ? s.policies.active : 0;
        var pt = (s.policies && s.policies.total)  ? s.policies.total  : 0;
        $('#nzMetricPolicies').text(pa + ' / ' + pt);

        // Events card
        var tot = s.total_events || 0;
        var lh  = s.last_hour_count || 0;
        $('#nzMetricEvents').text(tot);
        $('#nzMetricEvents').closest('.di-metric-content')
            .find('.di-metric-label').text(tot + ' {{ lang._("total") }} · ' + lh + ' {{ lang._("last hour") }}');

        // Decision breakdown
        var allow = s.allow_events || 0;
        var block = s.block_events || 0;
        var total = tot || 1;
        var aRate = Math.round((allow / total) * 100);
        var bRate = Math.round((block / total) * 100);
        $('#nzDecisionStats').html(
            '<div class="nz-bar-wrap">' +
            '<span style="width:50px;color:#059669;font-weight:600;">{{ lang._("Pass") }}</span>' +
            '<div class="nz-bar-bg"><div class="nz-bar-fill" style="width:' + aRate + '%;background:#059669;"></div></div>' +
            '<span style="width:45px;text-align:right;">' + allow + '</span></div>' +
            '<div class="nz-bar-wrap">' +
            '<span style="width:50px;color:#dc2626;font-weight:600;">{{ lang._("Block") }}</span>' +
            '<div class="nz-bar-bg"><div class="nz-bar-fill" style="width:' + bRate + '%;background:#dc2626;"></div></div>' +
            '<span style="width:45px;text-align:right;">' + block + '</span></div>'
        );

        // Top protocols
        var protos = s.top_protocols || {};
        var protoHtml = '';
        var ptotal = tot || 1;
        var pcount = 0;
        $.each(protos, function(k, v) {
            if (pcount++ >= 5) { return false; }
            var pct = Math.min(Math.round((v / ptotal) * 100), 100);
            protoHtml += '<div class="nz-bar-wrap">' +
                '<span style="width:50px;overflow:hidden;white-space:nowrap;">' + nzEsc(k.toUpperCase()) + '</span>' +
                '<div class="nz-bar-bg"><div class="nz-bar-fill" style="width:' + pct + '%;background:#2563eb;"></div></div>' +
                '<span style="width:30px;text-align:right;">' + v + '</span></div>';
        });
        $('#nzProtocols').html(protoHtml || '<span class="text-muted">{{ lang._("No data") }}</span>');

    }).fail(function() {});
}

function loadLogs() {
    ajaxCall('/api/netzones/management/dashboard_logs', {}, function(data) {
        if (!data || data.status !== 'ok' || !data.data || data.data.length === 0) {
            $('#nzDecisionsBody').html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No recent activity") }}</td></tr>');
            return;
        }
        var html = '';
        data.data.slice(0, 15).forEach(function(e) {
            var dec = (e.decision || '').toLowerCase();
            var cls = (dec === 'pass' || dec === 'allow') ? 'success' : (dec === 'block' ? 'danger' : 'warning');
            html += '<tr>' +
                '<td style="white-space:nowrap;"><small>' + nzEsc(e.timestamp || '--') + '</small></td>' +
                '<td><span class="label label-info">' + nzEsc(e.src || '--') + '</span></td>' +
                '<td><span class="label label-info">' + nzEsc(e.dst || '--') + '</span></td>' +
                '<td>' + nzEsc(e.protocol || '--') + '</td>' +
                '<td>' + nzEsc(e.port || '--') + '</td>' +
                '<td><span class="label label-' + cls + '">' + nzEsc(e.decision || '--') + '</span></td>' +
                '</tr>';
        });
        $('#nzDecisionsBody').html(html);
    }).fail(function() {
        $('#nzDecisionsBody').html('<tr><td colspan="6" class="text-center text-warning">{{ lang._("Unavailable") }}</td></tr>');
    });
}

function loadRelationships() {
    ajaxCall('/api/netzones/management/dashboard_zone_relationships', {}, function(data) {
        if (!data || data.status !== 'ok' || !data.relationships || data.relationships.length === 0) {
            $('#nzRelationships').html('<div class="text-muted text-center" style="font-size:.82em;padding:.5rem 0;">{{ lang._("No policies configured") }}</div>');
            return;
        }
        var html = '';
        data.relationships.forEach(function(r) {
            var act = (r.action || '').toLowerCase();
            var cls = (act === 'pass' || act === 'allow') ? '#059669' : (act === 'block' ? '#dc2626' : '#d97706');
            html += '<div class="nz-zone-link">' +
                '<span style="font-weight:600;">' + nzEsc(r.source_zone) + '</span>' +
                ' <i class="fa fa-arrow-right text-muted" style="font-size:.75em;"></i> ' +
                '<span style="font-weight:600;">' + nzEsc(r.destination_zone) + '</span>' +
                '<span class="pull-right" style="color:' + cls + ';font-weight:600;font-size:.8em;">' + nzEsc(r.action.toUpperCase()) + '</span>' +
                '</div>';
        });
        $('#nzRelationships').html(html);
    }).fail(function() {
        $('#nzRelationships').html('<div class="text-muted text-center" style="font-size:.82em;">{{ lang._("Unavailable") }}</div>');
    });
}

function loadTrafficPatterns() {
    ajaxCall('/api/netzones/management/dashboard_traffic_patterns', { hours: 6 }, function(data) {
        if (!data || data.status !== 'ok' || !data.data || !data.data.hourly) {
            $('#nzActivityChart').html('<div class="text-muted text-center" style="padding:1rem;font-size:.82em;">{{ lang._("No data") }}</div>');
            return;
        }
        var values = Object.values(data.data.hourly);
        if (values.length === 0) {
            $('#nzActivityChart').html('<div class="text-muted text-center" style="padding:1rem;font-size:.82em;">{{ lang._("No data") }}</div>');
            return;
        }
        var maxVal = Math.max.apply(null, values.concat([1]));
        var bars = values.slice(-12);
        var html = '<div style="display:flex;align-items:flex-end;justify-content:space-between;padding:8px 4px;height:110px;gap:2px;">';
        bars.forEach(function(val, i) {
            var h   = (new Date(Date.now() - (bars.length - 1 - i) * 3600000)).getHours();
            var pct = Math.max(Math.round((val / maxVal) * 90), val > 0 ? 3 : 1);
            html += '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;">' +
                    '<div style="width:100%;height:90px;display:flex;align-items:flex-end;justify-content:center;">' +
                    '<div style="width:80%;height:' + pct + '%;background:#2563eb;border-radius:2px 2px 0 0;min-height:2px;" title="' + val + ' events"></div></div>' +
                    '<div style="font-size:9px;color:#9ca3af;">' + h + 'h</div></div>';
        });
        html += '</div>';
        $('#nzActivityChart').html(html);
    }).fail(function() {
        $('#nzActivityChart').html('<div class="text-muted text-center" style="padding:1rem;font-size:.82em;">{{ lang._("Unavailable") }}</div>');
    });
}

function controlService(action) {
    ajaxCall('/api/netzones/service/' + action, {}, function(data) {
        var ok = data && (data.status === 'ok' || data.running === true);
        nzNotify(ok ? '{{ lang._("Service") }} ' + action + ' {{ lang._("OK") }}' : '{{ lang._("Service action failed") }}', ok ? 'success' : 'error');
        setTimeout(loadServiceStatus, 1500);
    }).fail(function() {
        nzNotify('{{ lang._("Service action failed") }}', 'error');
    });
}

$(function() {
    loadDashboard();
    setInterval(loadDashboard, 30000);
    $('#nzRefresh').click(loadDashboard);
    $('#nzStartBtn').click(function()   { controlService('start'); });
    $('#nzRestartBtn').click(function() { controlService('restart'); });
    $('#nzStopBtn').click(function()    { controlService('stop'); });
});
</script>
