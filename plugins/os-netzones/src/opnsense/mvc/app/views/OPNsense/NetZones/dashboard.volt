{#
 # NetZones Dashboard
 #}
<script src="/ui/js/chart.min.js"></script>
<div id="nz-notifications" style="position:fixed;bottom:24px;right:24px;z-index:9999;min-width:280px;max-width:380px;pointer-events:none;"></div>

<!-- ── Toolbar ─────────────────────────────────────────────────────────────── -->
<div class="content-box" style="padding:.65rem 1.25rem;margin-bottom:1rem;">
    <div class="row" style="align-items:center;">
        <div class="col-md-1">
            <span id="nzServiceBadge" class="label label-default" style="font-size:.9em;padding:.35em .7em;">{{ lang._('Loading...') }}</span>
        </div>
        <div class="col-md-2">
            <select id="nzTimeRange" class="form-control input-sm">
                <option value="last1h">{{ lang._('Last 1 hour') }}</option>
                <option value="last6h" selected>{{ lang._('Last 6 hours') }}</option>
                <option value="last24h">{{ lang._('Last 24 hours') }}</option>
                <option value="last7d">{{ lang._('Last 7 days') }}</option>
                <option value="last30d">{{ lang._('Last 30 days') }}</option>
                <option value="all">{{ lang._('All') }}</option>
            </select>
        </div>
        <div class="col-md-9 text-right">
            <span class="text-muted" style="font-size:.8em;">
                {{ lang._('Updated') }}: <strong id="nzLastUpdated">--</strong>
            </span>
            <button class="btn btn-default btn-sm" id="nzRefresh" style="margin-left:.5rem;">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
            <button class="btn btn-success btn-sm" id="nzStartBtn" style="margin-left:.5rem;">
                <i class="fa fa-play"></i> {{ lang._('Start') }}
            </button>
            <button class="btn btn-warning btn-sm" id="nzRestartBtn" style="margin-left:.3rem;">
                <i class="fa fa-refresh"></i> {{ lang._('Restart') }}
            </button>
            <button class="btn btn-danger btn-sm" id="nzStopBtn" style="margin-left:.3rem;">
                <i class="fa fa-stop"></i> {{ lang._('Stop') }}
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
                <div class="di-metric-label" id="nzMetricEventsLabel">{{ lang._('Total Events') }}</div>
            </div>
        </div>
    </div>
</div>

<!-- ── Charts row 1: Timeline | Decisions | Zone Relations ──────────────────── -->
<div class="row">
    <div class="col-md-6">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Activity Timeline') }}</span>
                <div style="display:flex;gap:.3rem;align-items:center;">
                    <select class="form-control di-inline-sel" id="nzTimelineGranularity">
                        <option value="auto" selected>Auto</option>
                        <option value="minute">{{ lang._('Per min') }}</option>
                        <option value="hour">{{ lang._('Per hour') }}</option>
                        <option value="day">{{ lang._('Per day') }}</option>
                    </select>
                </div>
            </div>
            <div style="position:relative;height:210px;"><canvas id="nzTimelineChart"></canvas></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Decisions') }}</span>
            </div>
            <div style="position:relative;height:210px;"><canvas id="nzDecisionsChart"></canvas></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Zone Relationships') }}</span>
            </div>
            <div id="nzRelationships" style="padding-top:.25rem;max-height:200px;overflow-y:auto;"></div>
        </div>
    </div>
</div>

<!-- ── Charts row 2: Protocols | Zone Pairs ─────────────────────────────────── -->
<div class="row">
    <div class="col-md-6">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Top Protocols') }}</span>
                <select class="form-control di-inline-sel" id="nzProtoTopN">
                    <option value="5" selected>Top 5</option>
                    <option value="10">Top 10</option>
                    <option value="0">{{ lang._('All') }}</option>
                </select>
            </div>
            <div style="position:relative;height:180px;"><canvas id="nzProtocolsChart"></canvas></div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Zone Pairs') }}</span>
                <select class="form-control di-inline-sel" id="nzZonePairsTopN">
                    <option value="5" selected>Top 5</option>
                    <option value="10">Top 10</option>
                    <option value="0">{{ lang._('All') }}</option>
                </select>
            </div>
            <div style="position:relative;height:180px;"><canvas id="nzZonePairsChart"></canvas></div>
        </div>
    </div>
</div>

<!-- ── Table filters ─────────────────────────────────────────────────────────── -->
<div class="content-box" style="padding:.65rem 1.25rem;margin-bottom:.4rem;">
    <div class="row" style="align-items:center;">
        <div class="col-md-3">
            <input type="text" id="nzSearch" class="form-control input-sm" placeholder="{{ lang._('Search IP, zone, reason...') }}">
        </div>
        <div class="col-md-2">
            <select id="nzFilterDecision" class="form-control input-sm">
                <option value="">{{ lang._('All Decisions') }}</option>
                <option value="pass">{{ lang._('Pass') }}</option>
                <option value="block">{{ lang._('Block') }}</option>
                <option value="reject">{{ lang._('Reject') }}</option>
            </select>
        </div>
        <div class="col-md-2">
            <select id="nzFilterProtocol" class="form-control input-sm">
                <option value="">{{ lang._('All Protocols') }}</option>
            </select>
        </div>
        <div class="col-md-2">
            <select id="nzFilterZone" class="form-control input-sm">
                <option value="">{{ lang._('All Zones') }}</option>
            </select>
        </div>
        <div class="col-md-1">
            <select id="nzPageSize" class="form-control input-sm">
                <option value="25" selected>25</option>
                <option value="50">50</option>
                <option value="100">100</option>
            </select>
        </div>
        <div class="col-md-2 text-right">
            <small class="text-muted" id="nzTableInfo"></small>
        </div>
    </div>
</div>

<!-- ── Decisions table ───────────────────────────────────────────────────────── -->
<div class="di-chart-box" style="padding:0;margin-bottom:.4rem;">
    <div class="table-responsive">
        <table class="table table-striped table-condensed" style="font-size:.82em;margin:0;">
            <thead>
                <tr>
                    <th class="nz-sort-hdr" data-col="ts" style="cursor:pointer;white-space:nowrap;">
                        {{ lang._('Time') }} <i class="fa fa-sort-desc nz-sort-icon" id="nzSortIcon-ts"></i>
                    </th>
                    <th class="nz-sort-hdr" data-col="source_ip" style="cursor:pointer;">
                        {{ lang._('Src IP') }} <i class="fa fa-sort nz-sort-icon" id="nzSortIcon-source_ip"></i>
                    </th>
                    <th class="nz-sort-hdr" data-col="source_zone" style="cursor:pointer;">
                        {{ lang._('Src Zone') }} <i class="fa fa-sort nz-sort-icon" id="nzSortIcon-source_zone"></i>
                    </th>
                    <th class="nz-sort-hdr" data-col="destination_ip" style="cursor:pointer;">
                        {{ lang._('Dst IP') }} <i class="fa fa-sort nz-sort-icon" id="nzSortIcon-destination_ip"></i>
                    </th>
                    <th class="nz-sort-hdr" data-col="destination_zone" style="cursor:pointer;">
                        {{ lang._('Dst Zone') }} <i class="fa fa-sort nz-sort-icon" id="nzSortIcon-destination_zone"></i>
                    </th>
                    <th class="nz-sort-hdr" data-col="protocol" style="cursor:pointer;">
                        {{ lang._('Proto') }} <i class="fa fa-sort nz-sort-icon" id="nzSortIcon-protocol"></i>
                    </th>
                    <th class="nz-sort-hdr" data-col="port" style="cursor:pointer;">
                        {{ lang._('Port') }} <i class="fa fa-sort nz-sort-icon" id="nzSortIcon-port"></i>
                    </th>
                    <th class="nz-sort-hdr" data-col="decision" style="cursor:pointer;">
                        {{ lang._('Decision') }} <i class="fa fa-sort nz-sort-icon" id="nzSortIcon-decision"></i>
                    </th>
                    <th>{{ lang._('Reason') }}</th>
                </tr>
            </thead>
            <tbody id="nzDecisionsBody">
                <tr><td colspan="9" class="text-center text-muted" style="padding:2rem;"><i class="fa fa-spinner fa-spin"></i></td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- ── Pagination ────────────────────────────────────────────────────────────── -->
<div class="row" style="margin-bottom:1rem;">
    <div class="col-md-12 text-center">
        <nav id="nzPagination"></nav>
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
.di-inline-sel {
    display:inline-block !important; width:auto !important; height:24px !important;
    padding:1px 6px !important; font-size:.78rem !important; border-radius:3px !important;
}
.nz-zone-link {
    padding:4px 8px; border-left:3px solid #2563eb;
    margin-bottom:4px; background:#f9fafb; font-size:.82em;
    border-radius:0 3px 3px 0;
}
.nz-sort-hdr { cursor:pointer; user-select:none; }
.nz-sort-hdr:hover { background:#f3f4f6; }
.nz-sort-hdr.nz-active { background:#eff6ff; }
.nz-sort-icon { color:#9ca3af; font-size:.8em; margin-left:2px; }
.nz-sort-hdr.nz-active .nz-sort-icon { color:#2563eb; }
#nzDecisionsBody code { background:none; padding:0; color:#374151; font-family:monospace; }
</style>

<script>
// ── State ───────────────────────────────────────────────────────────────────
var nzAllLogs   = [];
var nzTableData = [];
var nzPage      = 1;
var nzPageSize  = 25;
var nzSortCol   = 'ts';
var nzSortDir   = 'desc';
var nzChart1    = null;
var nzChart2    = null;
var nzChart3    = null;
var nzChart4    = null;

// ── Helpers ─────────────────────────────────────────────────────────────────
function nzNotify(msg, type) {
    var cls  = type === 'success' ? 'alert-success' : (type === 'warning' ? 'alert-warning' : 'alert-danger');
    var icon = type === 'success' ? 'fa-check' : (type === 'warning' ? 'fa-exclamation-triangle' : 'fa-exclamation-circle');
    var $n = $('<div role="alert" style="pointer-events:all;margin-top:.4rem;border-radius:3px;box-shadow:0 2px 10px rgba(0,0,0,.28);">' +
               '<div class="alert ' + cls + ' alert-dismissible" style="margin:0;padding:.6rem .9rem;">' +
               '<button type="button" class="close" data-dismiss="alert" style="top:0;right:4px;"><span>&times;</span></button>' +
               '<i class="fa ' + icon + '" style="margin-right:.45rem;"></i>' + msg + '</div></div>');
    $('#nz-notifications').append($n);
    setTimeout(function() { $n.find('.alert').alert('close'); $n.remove(); }, 4000);
}

function nzEsc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function nzPad(n) { return n < 10 ? '0' + n : '' + n; }

function getTimeCutoff(range) {
    var now = Math.floor(Date.now() / 1000);
    switch (range) {
        case 'last1h':  return now - 3600;
        case 'last6h':  return now - 21600;
        case 'last24h': return now - 86400;
        case 'last7d':  return now - 604800;
        case 'last30d': return now - 2592000;
        default:        return 0;
    }
}

function getFilteredLogs() {
    var cutoff = getTimeCutoff($('#nzTimeRange').val());
    if (!cutoff) return nzAllLogs;
    return nzAllLogs.filter(function(e) { return (e.ts || 0) >= cutoff; });
}

function destroyChart(c) {
    if (c) { try { c.destroy(); } catch(ex) {} }
    return null;
}

// ── Activity Timeline ────────────────────────────────────────────────────────
function renderTimelineChart(logs) {
    var gran  = $('#nzTimelineGranularity').val();
    var range = $('#nzTimeRange').val();

    if (gran === 'auto') {
        if (range === 'last1h')  gran = 'minute';
        else if (range === 'last6h' || range === 'last24h') gran = 'hour';
        else gran = 'day';
    }

    var stepSec = gran === 'minute' ? 60 : (gran === 'hour' ? 3600 : 86400);
    var cutoff  = getTimeCutoff(range);
    var now     = Math.floor(Date.now() / 1000);
    if (!cutoff) cutoff = now - (gran === 'minute' ? 3600 : gran === 'hour' ? 86400 : 2592000);

    var maxSteps = gran === 'minute' ? 60 : 48;
    var steps    = Math.min(Math.ceil((now - cutoff) / stepSec), maxSteps);

    // Build bucket keys
    function bucketKey(ts) {
        var d = new Date(ts * 1000);
        if (gran === 'minute') {
            return d.getFullYear() + '-' + nzPad(d.getMonth()+1) + '-' + nzPad(d.getDate()) +
                   ' ' + nzPad(d.getHours()) + ':' + nzPad(d.getMinutes());
        } else if (gran === 'hour') {
            return d.getFullYear() + '-' + nzPad(d.getMonth()+1) + '-' + nzPad(d.getDate()) +
                   ' ' + nzPad(d.getHours()) + ':00';
        } else {
            return d.getFullYear() + '-' + nzPad(d.getMonth()+1) + '-' + nzPad(d.getDate());
        }
    }

    var buckets = {};
    logs.forEach(function(e) {
        if (!e.ts) return;
        var k = bucketKey(e.ts);
        buckets[k] = (buckets[k] || 0) + 1;
    });

    var labels = [], values = [];
    for (var i = steps - 1; i >= 0; i--) {
        var t  = now - i * stepSec;
        var k2 = bucketKey(t);
        var d2 = new Date(t * 1000);
        var lbl;
        if (gran === 'minute') {
            lbl = nzPad(d2.getHours()) + ':' + nzPad(d2.getMinutes());
        } else if (gran === 'hour') {
            lbl = nzPad(d2.getMonth()+1) + '/' + nzPad(d2.getDate()) + ' ' + nzPad(d2.getHours()) + 'h';
        } else {
            lbl = nzPad(d2.getMonth()+1) + '/' + nzPad(d2.getDate());
        }
        labels.push(lbl);
        values.push(buckets[k2] || 0);
    }

    nzChart1 = destroyChart(nzChart1);
    var ctx = document.getElementById('nzTimelineChart');
    if (!ctx) return;
    nzChart1 = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ label: 'Events', data: values, backgroundColor: '#2563eb', borderRadius: 2, borderSkipped: false }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { font: { size: 10 }, maxRotation: 45, autoSkip: true, maxTicksLimit: 12 } },
                y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.05)' }, ticks: { font: { size: 10 }, precision: 0 } }
            }
        }
    });
}

// ── Decisions Doughnut ───────────────────────────────────────────────────────
function renderDecisionsChart(logs) {
    var counts = { pass: 0, block: 0, reject: 0 };
    logs.forEach(function(e) {
        var d = (e.decision || '').toLowerCase();
        if (d === 'pass' || d === 'allow') counts.pass++;
        else if (d === 'block')  counts.block++;
        else if (d === 'reject') counts.reject++;
    });

    nzChart2 = destroyChart(nzChart2);
    var ctx = document.getElementById('nzDecisionsChart');
    if (!ctx) return;

    var hasData = (counts.pass + counts.block + counts.reject) > 0;
    nzChart2 = new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Pass', 'Block', 'Reject'],
            datasets: [{
                data: hasData ? [counts.pass, counts.block, counts.reject] : [1],
                backgroundColor: hasData ? ['#059669','#dc2626','#d97706'] : ['#e5e7eb'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    display: true, position: 'bottom',
                    labels: { font: { size: 10 }, boxWidth: 12, padding: 8 }
                }
            }
        }
    });
}

// ── Top Protocols ────────────────────────────────────────────────────────────
function renderProtocolsChart(logs) {
    var topN   = parseInt($('#nzProtoTopN').val()) || 5;
    var counts = {};
    logs.forEach(function(e) {
        if (!e.protocol) return;
        var p = e.protocol.toUpperCase();
        counts[p] = (counts[p] || 0) + 1;
    });

    var sorted = Object.keys(counts).sort(function(a,b){ return counts[b]-counts[a]; });
    if (topN > 0) sorted = sorted.slice(0, topN);

    var palette = ['#2563eb','#059669','#d97706','#7c3aed','#0891b2','#dc2626','#f59e0b','#10b981','#6366f1','#ec4899'];

    nzChart3 = destroyChart(nzChart3);
    var ctx = document.getElementById('nzProtocolsChart');
    if (!ctx) return;
    nzChart3 = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: sorted,
            datasets: [{
                label: 'Events',
                data: sorted.map(function(k){ return counts[k]; }),
                backgroundColor: sorted.map(function(k,i){ return palette[i % palette.length]; }),
                borderRadius: 3, borderSkipped: false
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.05)' }, ticks: { font: { size: 10 }, precision: 0 } },
                y: { grid: { display: false }, ticks: { font: { size: 10 } } }
            }
        }
    });
}

// ── Zone Pairs ───────────────────────────────────────────────────────────────
function renderZonePairsChart(logs) {
    var topN   = parseInt($('#nzZonePairsTopN').val()) || 5;
    var counts = {};
    logs.forEach(function(e) {
        var sz = (e.source_zone && e.source_zone !== 'UNKNOWN' && e.source_zone !== '') ? e.source_zone : (e.source_ip || '?');
        var dz = (e.destination_zone && e.destination_zone !== 'UNKNOWN' && e.destination_zone !== '') ? e.destination_zone : (e.destination_ip || '?');
        var pair = sz + ' → ' + dz;
        counts[pair] = (counts[pair] || 0) + 1;
    });

    var sorted = Object.keys(counts).sort(function(a,b){ return counts[b]-counts[a]; });
    if (topN > 0) sorted = sorted.slice(0, topN);

    nzChart4 = destroyChart(nzChart4);
    var ctx = document.getElementById('nzZonePairsChart');
    if (!ctx) return;
    nzChart4 = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: sorted,
            datasets: [{
                label: 'Events',
                data: sorted.map(function(k){ return counts[k]; }),
                backgroundColor: '#7c3aed',
                borderRadius: 3, borderSkipped: false
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.05)' }, ticks: { font: { size: 10 }, precision: 0 } },
                y: { grid: { display: false }, ticks: { font: { size: 10 } } }
            }
        }
    });
}

// ── Table ────────────────────────────────────────────────────────────────────
function applyTableFilters() {
    var logs   = getFilteredLogs();
    var search = ($('#nzSearch').val() || '').toLowerCase();
    var dec    = ($('#nzFilterDecision').val() || '').toLowerCase();
    var proto  = ($('#nzFilterProtocol').val() || '').toLowerCase();
    var zone   = ($('#nzFilterZone').val() || '');

    nzTableData = logs.filter(function(e) {
        if (dec) {
            var d = (e.decision || '').toLowerCase();
            if (d === 'allow') d = 'pass';
            if (d !== dec) return false;
        }
        if (proto && (e.protocol || '').toLowerCase() !== proto) return false;
        if (zone && e.source_zone !== zone && e.destination_zone !== zone) return false;
        if (search) {
            var hay = [e.source_ip, e.source_zone, e.destination_ip, e.destination_zone,
                       e.protocol, e.reason, e.timestamp].join(' ').toLowerCase();
            if (hay.indexOf(search) === -1) return false;
        }
        return true;
    });

    nzTableData.sort(function(a, b) {
        var va = nzSortCol === 'ts' ? (a.ts || 0) : String(a[nzSortCol] || '').toLowerCase();
        var vb = nzSortCol === 'ts' ? (b.ts || 0) : String(b[nzSortCol] || '').toLowerCase();
        if (va < vb) return nzSortDir === 'asc' ? -1 : 1;
        if (va > vb) return nzSortDir === 'asc' ? 1 : -1;
        return 0;
    });

    nzPage = 1;
    renderTable();
}

function renderTable() {
    nzPageSize = parseInt($('#nzPageSize').val()) || 25;
    var total  = nzTableData.length;
    var start  = (nzPage - 1) * nzPageSize;
    var end    = Math.min(start + nzPageSize, total);
    var page   = nzTableData.slice(start, end);

    var html = '';
    if (page.length === 0) {
        html = '<tr><td colspan="9" class="text-center text-muted" style="padding:2rem;">{{ lang._("No data matching filters") }}</td></tr>';
    } else {
        page.forEach(function(e) {
            var dec     = (e.decision || '').toLowerCase();
            var decDisp = (dec === 'allow') ? 'PASS' : dec.toUpperCase();
            var cls     = (dec === 'pass' || dec === 'allow') ? 'success' : (dec === 'block' ? 'danger' : 'warning');

            var srcIP   = e.source_ip || '';
            var srcZone = (e.source_zone && e.source_zone !== 'UNKNOWN' && e.source_zone !== '') ? e.source_zone : '';
            var dstIP   = e.destination_ip || '';
            var dstZone = (e.destination_zone && e.destination_zone !== 'UNKNOWN' && e.destination_zone !== '') ? e.destination_zone : '';
            var proto   = (e.protocol || '').toUpperCase();
            var port    = e.port || '';
            var reason  = e.reason || '';
            var ts      = e.timestamp || '--';

            var srcZoneHtml = srcZone
                ? '<span class="label label-info">' + nzEsc(srcZone) + '</span>'
                : '<span class="text-muted">-</span>';
            var dstZoneHtml = dstZone
                ? '<span class="label label-info">' + nzEsc(dstZone) + '</span>'
                : '<span class="text-muted">-</span>';

            html += '<tr>' +
                '<td style="white-space:nowrap;"><small>' + nzEsc(ts) + '</small></td>' +
                '<td><code>' + nzEsc(srcIP || '-') + '</code></td>' +
                '<td>' + srcZoneHtml + '</td>' +
                '<td><code>' + nzEsc(dstIP || '-') + '</code></td>' +
                '<td>' + dstZoneHtml + '</td>' +
                '<td><small>' + nzEsc(proto || '-') + '</small></td>' +
                '<td><small>' + nzEsc(port || '-') + '</small></td>' +
                '<td><span class="label label-' + cls + '">' + nzEsc(decDisp) + '</span></td>' +
                '<td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + nzEsc(reason) + '"><small>' + nzEsc(reason || '-') + '</small></td>' +
                '</tr>';
        });
    }

    $('#nzDecisionsBody').html(html);

    if (total > 0) {
        $('#nzTableInfo').text('{{ lang._("Showing") }} ' + (start+1) + '-' + end + ' {{ lang._("of") }} ' + total);
    } else {
        $('#nzTableInfo').text('{{ lang._("No results") }}');
    }

    renderPagination(total);
}

function renderPagination(total) {
    var pages = Math.ceil(total / nzPageSize);
    if (pages <= 1) { $('#nzPagination').html(''); return; }

    var html = '<ul class="pagination pagination-sm" style="margin:0;">';
    html += '<li class="' + (nzPage <= 1 ? 'disabled' : '') + '"><a href="#" data-page="' + (nzPage-1) + '">&laquo;</a></li>';

    var rangeStart = Math.max(1, nzPage - 2);
    var rangeEnd   = Math.min(pages, nzPage + 2);

    if (rangeStart > 1) {
        html += '<li><a href="#" data-page="1">1</a></li>';
        if (rangeStart > 2) html += '<li class="disabled"><a>&hellip;</a></li>';
    }
    for (var i = rangeStart; i <= rangeEnd; i++) {
        html += '<li class="' + (i === nzPage ? 'active' : '') + '"><a href="#" data-page="' + i + '">' + i + '</a></li>';
    }
    if (rangeEnd < pages) {
        if (rangeEnd < pages - 1) html += '<li class="disabled"><a>&hellip;</a></li>';
        html += '<li><a href="#" data-page="' + pages + '">' + pages + '</a></li>';
    }

    html += '<li class="' + (nzPage >= pages ? 'disabled' : '') + '"><a href="#" data-page="' + (nzPage+1) + '">&raquo;</a></li>';
    html += '</ul>';
    $('#nzPagination').html(html);
}

function setSortCol(col) {
    if (nzSortCol === col) {
        nzSortDir = (nzSortDir === 'asc') ? 'desc' : 'asc';
    } else {
        nzSortCol = col;
        nzSortDir = (col === 'ts') ? 'desc' : 'asc';
    }
    updateSortIcons();
    applyTableFilters();
}

function updateSortIcons() {
    $('.nz-sort-icon').removeClass('fa-sort-asc fa-sort-desc').addClass('fa-sort');
    $('.nz-sort-hdr').removeClass('nz-active');
    var $hdr = $('.nz-sort-hdr[data-col="' + nzSortCol + '"]');
    $hdr.addClass('nz-active');
    $hdr.find('.nz-sort-icon').removeClass('fa-sort').addClass(nzSortDir === 'asc' ? 'fa-sort-asc' : 'fa-sort-desc');
}

// ── Filter dropdowns ─────────────────────────────────────────────────────────
function updateFilterDropdowns(logs) {
    var protos = {}, zones = {};
    logs.forEach(function(e) {
        if (e.protocol) protos[e.protocol.toLowerCase()] = 1;
        if (e.source_zone && e.source_zone !== 'UNKNOWN' && e.source_zone !== '') zones[e.source_zone] = 1;
        if (e.destination_zone && e.destination_zone !== 'UNKNOWN' && e.destination_zone !== '') zones[e.destination_zone] = 1;
    });

    var curProto = $('#nzFilterProtocol').val();
    var pHtml = '<option value="">{{ lang._("All Protocols") }}</option>';
    Object.keys(protos).sort().forEach(function(p) {
        pHtml += '<option value="' + nzEsc(p) + '"' + (curProto === p ? ' selected' : '') + '>' + nzEsc(p.toUpperCase()) + '</option>';
    });
    $('#nzFilterProtocol').html(pHtml);

    var curZone = $('#nzFilterZone').val();
    var zHtml = '<option value="">{{ lang._("All Zones") }}</option>';
    Object.keys(zones).sort().forEach(function(z) {
        zHtml += '<option value="' + nzEsc(z) + '"' + (curZone === z ? ' selected' : '') + '>' + nzEsc(z) + '</option>';
    });
    $('#nzFilterZone').html(zHtml);
}

// ── Data loading ─────────────────────────────────────────────────────────────
function loadServiceStatus() {
    ajaxCall('/api/netzones/service/status', {}, function(data) {
        if (data && data.running) {
            $('#nzServiceBadge').removeClass('label-default label-danger').addClass('label-success').text('RUNNING');
            $('#nzMetricService').text('{{ lang._("Running") }}').css('color','#059669');
        } else {
            $('#nzServiceBadge').removeClass('label-default label-success').addClass('label-danger').text('STOPPED');
            $('#nzMetricService').text('{{ lang._("Stopped") }}').css('color','#dc2626');
        }
    }).fail(function() {
        $('#nzServiceBadge').removeClass('label-success label-danger').addClass('label-default').text('{{ lang._("Unknown") }}');
        $('#nzMetricService').text('?');
    });
}

function loadStats() {
    ajaxCall('/api/netzones/management/dashboard_stats', {}, function(data) {
        if (!data || data.status !== 'ok' || !data.data) return;
        var s = data.data;

        var za = (s.zones && s.zones.active) ? s.zones.active : 0;
        var zt = (s.zones && s.zones.total)  ? s.zones.total  : 0;
        $('#nzMetricZones').text(za + ' / ' + zt);

        var pa = (s.policies && s.policies.active) ? s.policies.active : 0;
        var pt = (s.policies && s.policies.total)  ? s.policies.total  : 0;
        $('#nzMetricPolicies').text(pa + ' / ' + pt);

        var tot = s.total_events || 0;
        var lh  = s.last_hour_count || 0;
        $('#nzMetricEvents').text(tot);
        $('#nzMetricEventsLabel').text(tot + ' {{ lang._("total") }} · ' + lh + ' {{ lang._("last hour") }}');
    }).fail(function() {});
}

function loadRelationships() {
    ajaxCall('/api/netzones/management/dashboard_zone_relationships', {}, function(data) {
        if (!data || data.status !== 'ok' || !data.relationships || !data.relationships.length) {
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
                '<span class="pull-right" style="color:' + cls + ';font-weight:600;font-size:.8em;">' + nzEsc((r.action||'').toUpperCase()) + '</span>' +
                '</div>';
        });
        $('#nzRelationships').html(html);
    }).fail(function() {
        $('#nzRelationships').html('<div class="text-muted text-center" style="font-size:.82em;">{{ lang._("Unavailable") }}</div>');
    });
}

function updateDashboard() {
    var logs = getFilteredLogs();
    renderTimelineChart(logs);
    renderDecisionsChart(logs);
    renderProtocolsChart(logs);
    renderZonePairsChart(logs);
    applyTableFilters();
}

function loadDashboard() {
    loadServiceStatus();
    loadStats();
    loadRelationships();
    ajaxCall('/api/netzones/management/dashboard_logs', {}, function(data) {
        if (data && data.status === 'ok' && Array.isArray(data.data)) {
            nzAllLogs = data.data;
            updateFilterDropdowns(nzAllLogs);
            updateDashboard();
        } else {
            $('#nzDecisionsBody').html('<tr><td colspan="9" class="text-center text-muted">{{ lang._("No recent activity") }}</td></tr>');
        }
    }).fail(function() {
        $('#nzDecisionsBody').html('<tr><td colspan="9" class="text-center text-warning">{{ lang._("Unavailable") }}</td></tr>');
    });
    $('#nzLastUpdated').text(new Date().toLocaleTimeString());
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

// ── Bootstrap ────────────────────────────────────────────────────────────────
$(function() {
    loadDashboard();
    setInterval(loadDashboard, 60000);

    $('#nzRefresh').click(loadDashboard);
    $('#nzStartBtn').click(function()   { controlService('start'); });
    $('#nzRestartBtn').click(function() { controlService('restart'); });
    $('#nzStopBtn').click(function()    { controlService('stop'); });

    // Global time range → re-render everything
    $('#nzTimeRange').change(updateDashboard);

    // Per-chart filters
    $('#nzTimelineGranularity').change(function() { renderTimelineChart(getFilteredLogs()); });
    $('#nzProtoTopN').change(function()           { renderProtocolsChart(getFilteredLogs()); });
    $('#nzZonePairsTopN').change(function()       { renderZonePairsChart(getFilteredLogs()); });

    // Table filters
    var searchTimer;
    $('#nzSearch').on('input', function() {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(applyTableFilters, 300);
    });
    $('#nzFilterDecision, #nzFilterProtocol, #nzFilterZone, #nzPageSize').change(applyTableFilters);

    // Sortable headers
    $(document).on('click', '.nz-sort-hdr', function() {
        setSortCol($(this).data('col'));
    });

    // Pagination
    $(document).on('click', '#nzPagination a[data-page]', function(e) {
        e.preventDefault();
        var p     = parseInt($(this).data('page'));
        var pages = Math.ceil(nzTableData.length / nzPageSize);
        if (p >= 1 && p <= pages && p !== nzPage) {
            nzPage = p;
            renderTable();
        }
    });

    // Initial sort icon state
    updateSortIcons();
});
</script>
