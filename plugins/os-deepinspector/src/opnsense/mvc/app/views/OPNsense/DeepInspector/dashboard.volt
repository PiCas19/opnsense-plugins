{# dashboard.volt - Deep Packet Inspector Dashboard #}
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"/>
<script src="/ui/js/chart.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>

<div id="notifications" style="position:fixed;top:20px;right:20px;z-index:9999;min-width:300px;"></div>

<!-- ── Toolbar ──────────────────────────────────────────────────────────────── -->
<div class="content-box" style="padding:.75rem 1.25rem;margin-bottom:1rem;">
    <div class="row" style="align-items:center;">
        <div class="col-md-2">
            <span id="serviceStatus" class="badge badge-secondary">{{ lang._('Loading...') }}</span>
        </div>
        <div class="col-md-4">
            <label style="font-size:.8em;margin:0 .5rem 0 0;">{{ lang._('Time Range') }}</label>
            <select class="form-control form-control-sm" id="globalTimeRange" style="display:inline-block;width:auto;">
                <option value="last30s">{{ lang._('Last 30s') }}</option>
                <option value="last15m">{{ lang._('Last 15m') }}</option>
                <option value="last1h">{{ lang._('Last 1h') }}</option>
                <option value="last24h" selected>{{ lang._('Last 24h') }}</option>
                <option value="today">{{ lang._('Today') }}</option>
                <option value="thisweek">{{ lang._('This Week') }}</option>
                <option value="thismonth">{{ lang._('This Month') }}</option>
                <option value="last90d">{{ lang._('Last 90 days') }}</option>
            </select>
        </div>
        <div class="col-md-6 text-right">
            <span class="text-muted" style="font-size:.8em;">
                {{ lang._('Updated') }}: <strong id="lastUpdated">--</strong>
            </span>
            <button class="btn btn-default btn-sm" id="refreshDash" style="margin-left:.5rem;">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
            <button class="btn btn-default btn-sm" id="exportStats" style="margin-left:.25rem;">
                <i class="fa fa-download"></i> {{ lang._('Export JSON') }}
            </button>
        </div>
    </div>
</div>

<!-- ── Metric cards ─────────────────────────────────────────────────────────── -->
<div class="row">
    <div class="col-md-3">
        <div class="metric-card">
            <div class="metric-icon"><i class="fa fa-search"></i></div>
            <div class="metric-content">
                <div class="metric-value" id="packetsAnalyzed">0</div>
                <div class="metric-label">{{ lang._('Packets Analyzed') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="metric-card">
            <div class="metric-icon" style="color:#dc3545;"><i class="fa fa-shield"></i></div>
            <div class="metric-content">
                <div class="metric-value" id="threatsDetected">0</div>
                <div class="metric-label">{{ lang._('Threats Detected') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="metric-card">
            <div class="metric-icon" style="color:#dc3545;"><i class="fa fa-exclamation-triangle"></i></div>
            <div class="metric-content">
                <div class="metric-value" id="criticalAlerts">0</div>
                <div class="metric-label">{{ lang._('Critical Alerts') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="metric-card">
            <div class="metric-icon" style="color:#28a745;"><i class="fa fa-exchange"></i></div>
            <div class="metric-content">
                <div class="metric-value" id="activeProtocols">0</div>
                <div class="metric-label">{{ lang._('Active Protocols') }}</div>
            </div>
        </div>
    </div>
</div>

<!-- ── Charts row 1: Timeline / Protocol / Threat Types ─────────────────────── -->
<div class="row">
    <div class="col-md-5">
        <div class="chart-container">
            <div class="chart-header">
                <h5>{{ lang._('Threat Timeline') }}</h5>
                <div>
                    <label style="font-size:.78em;margin:0 .3rem 0 0;">{{ lang._('Granularity') }}</label>
                    <select class="form-control form-control-sm" id="timelineGranularity" style="display:inline-block;width:auto;font-size:.78em;">
                        <option value="auto" selected>{{ lang._('Auto') }}</option>
                        <option value="minute">{{ lang._('Per Minute') }}</option>
                        <option value="hour">{{ lang._('Per Hour') }}</option>
                        <option value="day">{{ lang._('Per Day') }}</option>
                    </select>
                </div>
            </div>
            <div style="position:relative;height:220px;">
                <canvas id="threatTimelineChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="chart-container">
            <div class="chart-header">
                <h5>{{ lang._('Protocol Distribution') }}</h5>
                <div>
                    <label style="font-size:.78em;margin:0 .3rem 0 0;">{{ lang._('Min packets') }}</label>
                    <select class="form-control form-control-sm" id="protocolThreshold" style="display:inline-block;width:auto;font-size:.78em;">
                        <option value="0" selected>0</option>
                        <option value="10">10</option>
                        <option value="100">100</option>
                        <option value="1000">1000</option>
                    </select>
                </div>
            </div>
            <div style="position:relative;height:220px;">
                <canvas id="protocolChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="chart-container">
            <div class="chart-header">
                <h5>{{ lang._('Threat Types') }}</h5>
                <div>
                    <select class="form-control form-control-sm" id="threatTypesTopN" style="display:inline-block;width:auto;font-size:.78em;">
                        <option value="5" selected>Top 5</option>
                        <option value="10">Top 10</option>
                        <option value="20">Top 20</option>
                        <option value="0">{{ lang._('All') }}</option>
                    </select>
                </div>
            </div>
            <div style="position:relative;height:220px;">
                <canvas id="threatTypesChart"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- ── Charts row 2: Severity / Industrial / Performance ────────────────────── -->
<div class="row">
    <div class="col-md-4">
        <div class="chart-container">
            <div class="chart-header">
                <h5>{{ lang._('Severity Distribution') }}</h5>
                <div style="font-size:.75em;">
                    <label><input type="checkbox" class="sev-toggle" value="critical" checked> Critical</label>
                    <label style="margin-left:.4rem;"><input type="checkbox" class="sev-toggle" value="high" checked> High</label>
                    <label style="margin-left:.4rem;"><input type="checkbox" class="sev-toggle" value="medium" checked> Med</label>
                    <label style="margin-left:.4rem;"><input type="checkbox" class="sev-toggle" value="low" checked> Low</label>
                </div>
            </div>
            <div style="position:relative;height:200px;">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="chart-container">
            <div class="chart-header">
                <h5>{{ lang._('Industrial / SCADA Events') }}</h5>
                <div>
                    <label style="font-size:.78em;">
                        <input type="checkbox" id="hideZeroIndustrial"> {{ lang._('Hide zeros') }}
                    </label>
                </div>
            </div>
            <div style="position:relative;height:200px;">
                <canvas id="industrialChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="chart-container">
            <h5>{{ lang._('Engine Performance') }}</h5>
            <table class="table table-sm" style="margin-top:.25rem;">
                <tr><td>{{ lang._('Status') }}</td><td><strong id="engineStatus">--</strong></td></tr>
                <tr><td>{{ lang._('PID') }}</td><td><strong id="enginePid">--</strong></td></tr>
                <tr><td>{{ lang._('Uptime') }}</td><td><strong id="engineUptime">--</strong></td></tr>
                <tr><td>{{ lang._('CPU') }}</td><td><strong id="cpuUsage">--</strong></td></tr>
                <tr><td>{{ lang._('Memory') }}</td><td><strong id="memUsage">--</strong></td></tr>
                <tr><td>{{ lang._('Interfaces') }}</td><td><strong id="monitoredInterfaces">--</strong></td></tr>
                <tr><td>{{ lang._('Signatures') }}</td><td><strong id="signaturesVersion">--</strong></td></tr>
            </table>
        </div>
    </div>
</div>

<!-- ── Recent Threats table + Top Sources + Service controls ─────────────────── -->
<div class="row">
    <div class="col-md-8">
        <div class="chart-container">
            <div class="row" style="margin-bottom:.75rem;align-items:flex-end;">
                <div class="col-md-3">
                    <label style="font-size:.82em;">{{ lang._('Severity') }}</label>
                    <select class="form-control form-control-sm" id="severityFilter">
                        <option value="all">{{ lang._('All') }}</option>
                        <option value="critical">{{ lang._('Critical') }}</option>
                        <option value="high">{{ lang._('High') }}</option>
                        <option value="medium">{{ lang._('Medium') }}</option>
                        <option value="low">{{ lang._('Low') }}</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <label style="font-size:.82em;">{{ lang._('Threat Type') }}</label>
                    <select class="form-control form-control-sm" id="threatTypeFilter">
                        <option value="all">{{ lang._('All') }}</option>
                        <option value="sql_injection">SQL Injection</option>
                        <option value="command_injection">Command Injection</option>
                        <option value="script_injection">Script Injection</option>
                        <option value="malware">Malware</option>
                        <option value="crypto_mining">Crypto Mining</option>
                        <option value="industrial_threat">Industrial</option>
                        <option value="scada_attack">SCADA</option>
                    </select>
                </div>
                <div class="col-md-5 text-right" style="padding-top:1.2rem;">
                    <h5 style="display:inline;margin-right:.5rem;">{{ lang._('Recent Threats') }}</h5>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-sm">
                    <thead>
                        <tr>
                            <th>{{ lang._('Time') }}</th>
                            <th>{{ lang._('Source IP') }}</th>
                            <th>{{ lang._('Dest IP') }}</th>
                            <th>{{ lang._('Type') }}</th>
                            <th>{{ lang._('Sev.') }}</th>
                            <th>{{ lang._('Proto') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="threatTableBody">
                        <tr><td colspan="7" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="chart-container" style="margin-bottom:1rem;">
            <div class="chart-header">
                <h5>{{ lang._('Top Threat Sources') }}</h5>
                <select class="form-control form-control-sm" id="topSourcesN" style="display:inline-block;width:auto;font-size:.78em;">
                    <option value="5">Top 5</option>
                    <option value="10" selected>Top 10</option>
                    <option value="20">Top 20</option>
                    <option value="50">Top 50</option>
                </select>
            </div>
            <div id="topSources" style="max-height:300px;overflow-y:auto;margin-top:.5rem;"></div>
        </div>
        <div class="chart-container">
            <h5>{{ lang._('Service Controls') }}</h5>
            <div class="btn-group-vertical" style="width:100%;">
                <button class="btn btn-success btn-sm" id="startService" style="margin-bottom:.3rem;">
                    <i class="fa fa-play"></i> {{ lang._('Start') }}
                </button>
                <button class="btn btn-warning btn-sm" id="restartService" style="margin-bottom:.3rem;">
                    <i class="fa fa-refresh"></i> {{ lang._('Restart') }}
                </button>
                <button class="btn btn-danger btn-sm" id="stopService">
                    <i class="fa fa-stop"></i> {{ lang._('Stop') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- ── Attack Map ────────────────────────────────────────────────────────────── -->
<div class="row">
    <div class="col-md-9">
        <div class="chart-container">
            <div class="chart-header">
                <h5>{{ lang._('Attack Map') }}</h5>
                <span id="mapRateLimitedBadge" class="badge badge-warning" style="display:none;">
                    {{ lang._('Partial map – GeoIP temporarily unavailable') }}
                </span>
            </div>
            <div id="attackMap" style="height:420px;border-radius:6px;overflow:hidden;"></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="chart-container" style="height:468px;">
            <h5>{{ lang._('Unknown / Private Sources') }}</h5>
            <p class="text-muted" style="font-size:.8em;">{{ lang._('Private/local IPs not plotted on map') }}</p>
            <div id="privateSources" style="max-height:360px;overflow-y:auto;"></div>
        </div>
    </div>
</div>

<!-- ── Threat detail modal ───────────────────────────────────────────────────── -->
<div class="modal fade" id="threatModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ lang._('Threat Details') }}</h5>
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
            </div>
            <div class="modal-body" id="threatModalBody">
                <div class="text-center"><i class="fa fa-spinner fa-spin"></i></div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-warning" id="modalMarkFPBtn" style="display:none;">
                    <i class="fa fa-flag"></i> {{ lang._('Mark as False Positive') }}
                </button>
                <button type="button" class="btn btn-danger" id="modalBlockBtn" style="display:none;">
                    <i class="fa fa-ban"></i> {{ lang._('Block Source IP') }}
                </button>
                <button type="button" class="btn btn-secondary" data-dismiss="modal">{{ lang._('Close') }}</button>
            </div>
        </div>
    </div>
</div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
var allThreats   = [];
var allProtocols = {};
var allThreatTypes = {};
var sevCounts    = { critical: 0, high: 0, medium: 0, low: 0 };
var leafletMap   = null;
var markersLayer = null;
var _currentModalThreat = null;

// ── Init ──────────────────────────────────────────────────────────────────────
$(document).ready(function () {
    if (typeof Chart !== 'undefined') initCharts();
    initMap();
    loadDashboardData();

    setInterval(loadDashboardData, 60000);

    $('#refreshDash').click(loadDashboardData);
    $('#globalTimeRange').change(loadDashboardData);
    $('#exportStats').click(exportStats);

    $('#startService').click(function ()   { controlService('start'); });
    $('#restartService').click(function () { controlService('restart'); });
    $('#stopService').click(function ()    { controlService('stop'); });

    $('#severityFilter, #threatTypeFilter').change(applyThreatFilters);

    // Per-chart client-side filters
    $('#threatTypesTopN').change(renderThreatTypesChart);
    $('#protocolThreshold').change(renderProtocolChart);
    $('#topSourcesN').change(function () { updateTopSources(allThreats); });
    $('#timelineGranularity').change(function () { updateThreatTimeline(allThreats); });
    $(document).on('change', '.sev-toggle', renderSeverityChart);
    $('#hideZeroIndustrial').change(renderIndustrialChart);
});

// ── Charts init ───────────────────────────────────────────────────────────────
function initCharts() {
    window.dashProtocolChart = new Chart(
        document.getElementById('protocolChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#007bff','#28a745','#ffc107','#dc3545','#17a2b8','#6f42c1','#fd7e14','#20c997','#e83e8c','#adb5bd'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { font: { size: 10 } } } } }
    });

    window.dashThreatTypesChart = new Chart(
        document.getElementById('threatTypesChart').getContext('2d'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Count', data: [], backgroundColor: '#dc3545' }] },
        options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } } }
    });

    window.dashTimelineChart = new Chart(
        document.getElementById('threatTimelineChart').getContext('2d'), {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Threats', data: [], borderColor: '#dc3545', backgroundColor: 'rgba(220,53,69,0.08)', tension: 0.3, fill: true }] },
        options: { responsive: true, maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
            plugins: { legend: { display: false } } }
    });

    window.dashSeverityChart = new Chart(
        document.getElementById('severityChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['Critical','High','Medium','Low'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#dc3545','#fd7e14','#ffc107','#28a745'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { font: { size: 10 } } } } }
    });

    window.dashIndustrialChart = new Chart(
        document.getElementById('industrialChart').getContext('2d'), {
        type: 'bar',
        data: { labels: ['Modbus','DNP3','OPC-UA','SCADA'], datasets: [{ label: 'Events', data: [0,0,0,0], backgroundColor: ['#6f42c1','#17a2b8','#fd7e14','#dc3545'] }] },
        options: { responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } }
    });
}

// ── Leaflet map init ──────────────────────────────────────────────────────────
function initMap() {
    if (typeof L === 'undefined') return;
    leafletMap = L.map('attackMap', { zoomControl: true }).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://carto.com/">CartoDB</a>',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(leafletMap);
    markersLayer = L.layerGroup().addTo(leafletMap);
}

// ── Data loading ──────────────────────────────────────────────────────────────
function loadDashboardData() {
    $('#lastUpdated').text(new Date().toLocaleString());

    ajaxCall('/api/deepinspector/settings/stats', {}, function (data) {
        if (data.status !== 'ok' || !data.data) return;
        var d = data.data;

        allThreats     = d.recent_threats      || [];
        allProtocols   = d.protocols_analyzed  || {};
        allThreatTypes = d.threat_types        || {};

        // Severity counts from recent_threats
        sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
        allThreats.forEach(function (t) {
            var s = (t.severity || 'medium').toLowerCase();
            if (sevCounts.hasOwnProperty(s)) sevCounts[s]++;
        });

        updateMetrics(d);
        renderProtocolChart();
        renderThreatTypesChart();
        updateThreatTimeline(allThreats);
        renderSeverityChart();
        renderIndustrialChart();
        applyThreatFilters();
        updateTopSources(allThreats);
        updateSystemInfo(d.system_info || {});
        updateMap(allThreats);
    });

    ajaxCall('/api/deepinspector/service/status', {}, function (data) {
        if (data.status !== 'ok') return;
        if (data.running) {
            $('#serviceStatus').removeClass('badge-secondary badge-danger').addClass('badge-success').text('{{ lang._("Running") }}');
        } else {
            $('#serviceStatus').removeClass('badge-secondary badge-success').addClass('badge-danger').text('{{ lang._("Stopped") }}');
        }
    });
}

// ── Metrics ───────────────────────────────────────────────────────────────────
function updateMetrics(d) {
    $('#packetsAnalyzed').text(fmtNum(d.packets_analyzed || 0));
    $('#threatsDetected').text(fmtNum(d.threats_detected || 0));
    $('#criticalAlerts').text(fmtNum(d.critical_alerts || sevCounts.critical || 0));
    $('#activeProtocols').text(Object.keys(allProtocols).length);
}

// ── Chart renderers (client-side filtered) ────────────────────────────────────
function renderProtocolChart() {
    if (!window.dashProtocolChart) return;
    var threshold = parseInt($('#protocolThreshold').val()) || 0;
    var labels = [], values = [];
    Object.keys(allProtocols).forEach(function (k) {
        if (allProtocols[k] >= threshold) { labels.push(k); values.push(allProtocols[k]); }
    });
    window.dashProtocolChart.data.labels = labels;
    window.dashProtocolChart.data.datasets[0].data = values;
    window.dashProtocolChart.update();
}

function renderThreatTypesChart() {
    if (!window.dashThreatTypesChart) return;
    var topN  = parseInt($('#threatTypesTopN').val()) || 0;
    var pairs = Object.entries(allThreatTypes).sort(function (a, b) { return b[1] - a[1]; });
    if (topN > 0) pairs = pairs.slice(0, topN);
    window.dashThreatTypesChart.data.labels = pairs.map(function (p) { return p[0]; });
    window.dashThreatTypesChart.data.datasets[0].data = pairs.map(function (p) { return p[1]; });
    window.dashThreatTypesChart.update();
}

function updateThreatTimeline(threats) {
    if (!window.dashTimelineChart) return;
    var granularity = $('#timelineGranularity').val();
    var timeRange   = $('#globalTimeRange').val();

    // Determine auto granularity
    if (granularity === 'auto') {
        if (['last30s','last15m','last1h'].indexOf(timeRange) >= 0) granularity = 'minute';
        else if (['last24h','today'].indexOf(timeRange) >= 0) granularity = 'hour';
        else granularity = 'day';
    }

    var now       = Date.now();
    var buckets   = {};
    var rangeMs   = timeRangeToMs(timeRange);
    var startTime = now - rangeMs;

    if (granularity === 'minute') {
        var minutes = Math.min(60, Math.ceil(rangeMs / 60000));
        for (var i = minutes - 1; i >= 0; i--) {
            var dt = new Date(now - i * 60000);
            var key = dt.getHours().toString().padStart(2,'0') + ':' + dt.getMinutes().toString().padStart(2,'0');
            buckets[key] = 0;
        }
        threats.forEach(function (t) {
            var ts = new Date(t.timestamp).getTime();
            if (ts >= startTime) {
                var d2 = new Date(ts);
                var k = d2.getHours().toString().padStart(2,'0') + ':' + d2.getMinutes().toString().padStart(2,'0');
                if (buckets.hasOwnProperty(k)) buckets[k]++;
            }
        });
    } else if (granularity === 'day') {
        var days = Math.min(90, Math.ceil(rangeMs / 86400000));
        for (var i = days - 1; i >= 0; i--) {
            var dt = new Date(now - i * 86400000);
            var key = (dt.getMonth()+1).toString().padStart(2,'0') + '/' + dt.getDate().toString().padStart(2,'0');
            buckets[key] = 0;
        }
        threats.forEach(function (t) {
            var ts = new Date(t.timestamp).getTime();
            if (ts >= startTime) {
                var d2 = new Date(ts);
                var k = (d2.getMonth()+1).toString().padStart(2,'0') + '/' + d2.getDate().toString().padStart(2,'0');
                if (buckets.hasOwnProperty(k)) buckets[k]++;
            }
        });
    } else { // hour
        var hours = Math.min(24, Math.ceil(rangeMs / 3600000));
        for (var i = hours - 1; i >= 0; i--) {
            var dt = new Date(now - i * 3600000);
            var key = dt.getHours().toString().padStart(2,'0') + ':00';
            buckets[key] = 0;
        }
        threats.forEach(function (t) {
            var ts = new Date(t.timestamp).getTime();
            if (ts >= startTime) {
                var d2 = new Date(ts);
                var k = d2.getHours().toString().padStart(2,'0') + ':00';
                if (buckets.hasOwnProperty(k)) buckets[k]++;
            }
        });
    }

    window.dashTimelineChart.data.labels = Object.keys(buckets);
    window.dashTimelineChart.data.datasets[0].data = Object.values(buckets);
    window.dashTimelineChart.update();
}

function timeRangeToMs(range) {
    var map = {
        'last30s':  30000,
        'last15m':  900000,
        'last1h':   3600000,
        'last24h':  86400000,
        'today':    (Date.now() - new Date().setHours(0,0,0,0)),
        'thisweek': 7 * 86400000,
        'thismonth':30 * 86400000,
        'last90d':  90 * 86400000
    };
    return map[range] || 86400000;
}

function renderSeverityChart() {
    if (!window.dashSeverityChart) return;
    var visible = {};
    $('.sev-toggle').each(function () { visible[$(this).val()] = $(this).is(':checked'); });
    var labels = [], data = [], colors = [];
    var allLabels  = ['Critical','High','Medium','Low'];
    var allKeys    = ['critical','high','medium','low'];
    var allColors  = ['#dc3545','#fd7e14','#ffc107','#28a745'];
    for (var i = 0; i < 4; i++) {
        if (visible[allKeys[i]] !== false) {
            labels.push(allLabels[i]);
            data.push(sevCounts[allKeys[i]] || 0);
            colors.push(allColors[i]);
        }
    }
    window.dashSeverityChart.data.labels = labels;
    window.dashSeverityChart.data.datasets[0].data   = data;
    window.dashSeverityChart.data.datasets[0].backgroundColor = colors;
    window.dashSeverityChart.update();
}

function renderIndustrialChart() {
    if (!window.dashIndustrialChart) return;
    var hideZero = $('#hideZeroIndustrial').is(':checked');
    var protocols = allProtocols;
    var types     = allThreatTypes;
    var raw = [
        { label: 'Modbus', v: protocols['modbus'] || protocols['Modbus'] || 0, color: '#6f42c1' },
        { label: 'DNP3',   v: protocols['dnp3']   || protocols['DNP3']   || 0, color: '#17a2b8' },
        { label: 'OPC-UA', v: protocols['opcua']  || protocols['OPC-UA'] || protocols['OPCUA'] || 0, color: '#fd7e14' },
        { label: 'SCADA',  v: types['scada_attack'] || types['industrial_threat'] || 0, color: '#dc3545' }
    ];
    if (hideZero) raw = raw.filter(function (r) { return r.v > 0; });
    window.dashIndustrialChart.data.labels = raw.map(function (r) { return r.label; });
    window.dashIndustrialChart.data.datasets[0].data = raw.map(function (r) { return r.v; });
    window.dashIndustrialChart.data.datasets[0].backgroundColor = raw.map(function (r) { return r.color; });
    window.dashIndustrialChart.update();
}

// ── Threats table ─────────────────────────────────────────────────────────────
function applyThreatFilters() {
    var sev  = $('#severityFilter').val();
    var type = $('#threatTypeFilter').val();
    var filtered = allThreats.filter(function (t) {
        if (sev  !== 'all' && (t.severity   || '').toLowerCase() !== sev)  return false;
        if (type !== 'all' && (t.threat_type || '').toLowerCase() !== type) return false;
        return true;
    });
    renderThreatsTable(filtered);
}

function renderThreatsTable(threats) {
    var tbody = $('#threatTableBody');
    tbody.empty();
    if (threats.length === 0) {
        tbody.html('<tr><td colspan="7" class="text-center text-muted">{{ lang._("No threats match current filters") }}</td></tr>');
        return;
    }
    threats.forEach(function (t) {
        tbody.append(
            '<tr>' +
            '<td style="font-size:.8em;font-family:monospace">' + fmtTime(t.timestamp) + '</td>' +
            '<td><code>' + (t.source_ip || 'N/A') + '</code></td>' +
            '<td><code>' + (t.destination_ip || 'N/A') + '</code></td>' +
            '<td style="font-size:.85em">' + (t.threat_type || 'N/A') + '</td>' +
            '<td><span class="badge ' + sevClass(t.severity) + '">' + (t.severity || 'N/A') + '</span></td>' +
            '<td>' + (t.protocol || 'N/A') + '</td>' +
            '<td>' +
            '<button class="btn btn-xs btn-primary" onclick="viewThreatDetails(\'' + (t.id || '') + '\')" title="{{ lang._("Details") }}">' +
            '<i class="fa fa-eye"></i></button> ' +
            '<button class="btn btn-xs btn-danger" onclick="blockSource(\'' + (t.source_ip || '') + '\')" title="{{ lang._("Block IP") }}">' +
            '<i class="fa fa-ban"></i></button>' +
            '</td>' +
            '</tr>'
        );
    });
}

// ── Top Threat Sources ────────────────────────────────────────────────────────
function updateTopSources(threats) {
    var topN = parseInt($('#topSourcesN').val()) || 10;
    var counts = {};
    threats.forEach(function (t) {
        if (t.source_ip) counts[t.source_ip] = (counts[t.source_ip] || 0) + 1;
    });
    var sorted = Object.entries(counts).sort(function (a, b) { return b[1] - a[1]; }).slice(0, topN);
    var container = $('#topSources');
    container.empty();
    if (sorted.length === 0) {
        container.html('<div class="text-muted text-center p-2">{{ lang._("No data") }}</div>');
        return;
    }
    sorted.forEach(function (entry) {
        var ip = entry[0], count = entry[1];
        container.append(
            '<div class="d-flex justify-content-between align-items-center mb-1">' +
            '<code style="font-size:.85em">' + ip + '</code>' +
            '<div>' +
            '<span class="badge badge-danger" style="margin-right:.3rem;">' + count + '</span>' +
            '<button class="btn btn-xs btn-danger" onclick="blockSource(\'' + ip + '\')" title="{{ lang._("Block") }}">' +
            '<i class="fa fa-ban"></i></button>' +
            '</div>' +
            '</div>'
        );
    });
}

// ── System Info ───────────────────────────────────────────────────────────────
function updateSystemInfo(info) {
    $('#engineStatus').text(info.engine_status || '--');
    $('#enginePid').text(info.pid || '--');
    $('#engineUptime').text(info.uptime || '--');
    $('#cpuUsage').text(info.cpu_usage || '--');
    $('#memUsage').text(info.memory_usage || '--');
    $('#monitoredInterfaces').text(info.interfaces || 'N/A');
    $('#signaturesVersion').text(info.signatures_version || '--');
}

// ── Attack Map ────────────────────────────────────────────────────────────────
function updateMap(threats) {
    if (!leafletMap || !markersLayer) return;
    markersLayer.clearLayers();

    // Collect unique source IPs
    var ipCounts = {};
    var ipLastThreat = {};
    threats.forEach(function (t) {
        if (!t.source_ip) return;
        ipCounts[t.source_ip] = (ipCounts[t.source_ip] || 0) + 1;
        ipLastThreat[t.source_ip] = t;
    });

    var allIPs    = Object.keys(ipCounts);
    var privateIPs = [];
    var publicIPs  = [];

    allIPs.forEach(function (ip) {
        if (isPrivateIP(ip)) privateIPs.push(ip);
        else publicIPs.push(ip);
    });

    // Render private sources sidebar
    var psContainer = $('#privateSources');
    psContainer.empty();
    if (privateIPs.length === 0) {
        psContainer.html('<div class="text-muted text-center p-2">{{ lang._("None") }}</div>');
    } else {
        privateIPs.forEach(function (ip) {
            psContainer.append(
                '<div class="d-flex justify-content-between align-items-center mb-1">' +
                '<code style="font-size:.82em">' + ip + '</code>' +
                '<span class="badge badge-secondary">' + ipCounts[ip] + '</span>' +
                '</div>'
            );
        });
    }

    if (publicIPs.length === 0) {
        $('#mapRateLimitedBadge').hide();
        return;
    }

    // Fetch GeoIP for public IPs
    ajaxCall('/api/deepinspector/statistics/geoip', { ips: publicIPs.join(',') }, function (data) {
        if (data.rate_limited) {
            $('#mapRateLimitedBadge').show();
        } else {
            $('#mapRateLimitedBadge').hide();
        }

        if (data.status !== 'ok' || !data.data) return;

        Object.keys(data.data).forEach(function (ip) {
            var geo = data.data[ip];
            if (!geo) return; // private or unresolved

            var threat  = ipLastThreat[ip] || {};
            var sev     = (threat.severity || 'low').toLowerCase();
            var count   = ipCounts[ip] || 1;
            var color   = { critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#28a745' }[sev] || '#6c757d';

            var marker = L.circleMarker([geo.lat, geo.lon], {
                radius: Math.min(4 + Math.log(count + 1) * 3, 18),
                color: color,
                fillColor: color,
                fillOpacity: 0.75,
                weight: 1
            });

            marker.bindPopup(
                '<strong>' + ip + '</strong><br>' +
                (geo.country ? geo.country + ' (' + geo.countryCode + ')' : '') + '<br>' +
                '{{ lang._("Attacks") }}: <strong>' + count + '</strong><br>' +
                '{{ lang._("Last type") }}: ' + (threat.threat_type || 'N/A') + '<br>' +
                '{{ lang._("Severity") }}: <span style="color:' + color + '">' + (sev || 'N/A') + '</span><br><br>' +
                '<button class="btn btn-xs btn-danger" onclick="blockSource(\'' + ip + '\');leafletMap.closePopup();">' +
                '<i class=\'fa fa-ban\'></i> {{ lang._("Block IP") }}</button>'
            );

            markersLayer.addLayer(marker);
        });
    });
}

// Detect private/loopback/link-local IPs
function isPrivateIP(ip) {
    var privateRanges = [
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./,
        /^127\./,
        /^169\.254\./,
        /^::1$/,
        /^fc00:/i,
        /^fe80:/i
    ];
    return privateRanges.some(function (r) { return r.test(ip); });
}

// ── Threat Details Modal ──────────────────────────────────────────────────────
function viewThreatDetails(threatId) {
    if (!threatId) return;
    $('#threatModalBody').html('<div class="text-center"><i class="fa fa-spinner fa-spin"></i></div>');
    $('#modalBlockBtn, #modalMarkFPBtn').hide();
    $('#threatModal').modal('show');

    ajaxCall('/api/deepinspector/alerts/threatDetails/' + threatId, {}, function (data) {
        if (data.status === 'ok' && data.data) {
            var d = data.data;
            _currentModalThreat = d;
            $('#threatModalBody').html(
                '<div class="row">' +
                '<div class="col-md-6">' +
                '<h6>{{ lang._("Basic Information") }}</h6>' +
                '<p><strong>ID:</strong> <code>' + (d.id || threatId) + '</code></p>' +
                '<p><strong>{{ lang._("Timestamp") }}:</strong> ' + fmtTime(d.timestamp) + '</p>' +
                '<p><strong>{{ lang._("Source IP") }}:</strong> <code>' + (d.source_ip || 'N/A') + '</code></p>' +
                '<p><strong>{{ lang._("Destination IP") }}:</strong> <code>' + (d.destination_ip || 'N/A') + '</code></p>' +
                '<p><strong>{{ lang._("Source Port") }}:</strong> ' + (d.source_port || '-') + '</p>' +
                '<p><strong>{{ lang._("Destination Port") }}:</strong> ' + (d.destination_port || '-') + '</p>' +
                '</div>' +
                '<div class="col-md-6">' +
                '<h6>{{ lang._("Analysis Results") }}</h6>' +
                '<p><strong>{{ lang._("Threat Type") }}:</strong> ' + (d.threat_type || 'N/A') + '</p>' +
                '<p><strong>{{ lang._("Severity") }}:</strong> <span class="badge ' + sevClass(d.severity) + '">' + (d.severity || 'N/A') + '</span></p>' +
                '<p><strong>{{ lang._("Protocol") }}:</strong> ' + (d.protocol || 'N/A') + '</p>' +
                '<p><strong>{{ lang._("Detection Method") }}:</strong> ' + (d.detection_method || 'N/A') + '</p>' +
                '<p><strong>{{ lang._("Industrial Context") }}:</strong> ' + (d.industrial_context ? 'Yes' : 'No') + '</p>' +
                '<hr><h6>{{ lang._("Description") }}</h6>' +
                '<p>' + (d.description || 'N/A') + '</p>' +
                '</div>' +
                '</div>'
            );
            $('#modalBlockBtn').show().off('click').on('click', function () {
                blockSource(d.source_ip);
                $('#threatModal').modal('hide');
            });
            $('#modalMarkFPBtn').show().off('click').on('click', function () {
                markFalsePositive(d.id);
                $('#threatModal').modal('hide');
            });
        } else {
            $('#threatModalBody').html('<div class="alert alert-warning">{{ lang._("Threat details not available") }}</div>');
        }
    });
}

function blockSource(ip) {
    if (!ip) return;
    if (!confirm('{{ lang._("Block IP") }} ' + ip + '?')) return;
    ajaxCall('/api/deepinspector/service/blockIP', { ip: ip }, function (data) {
        if (data.status === 'ok') {
            showNotification('{{ lang._("IP") }} ' + ip + ' {{ lang._("blocked successfully") }}', 'success');
        } else {
            showNotification('{{ lang._("Failed to block IP") }}: ' + (data.message || ''), 'error');
        }
    });
}

function markFalsePositive(alertId) {
    if (!alertId) return;
    ajaxCall('/api/deepinspector/alerts/markFalsePositive', { alert_id: alertId }, function (data) {
        if (data.status === 'ok') {
            showNotification('{{ lang._("Alert marked as false positive") }}', 'success');
        } else {
            showNotification('{{ lang._("Failed to mark false positive") }}: ' + (data.message || ''), 'error');
        }
    });
}

// ── Service controls ──────────────────────────────────────────────────────────
function controlService(action) {
    var btn = $('#' + action + 'Service');
    btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i>');
    ajaxCall('/api/deepinspector/service/' + action, {}, function (data) {
        btn.prop('disabled', false);
        if (action === 'start')   btn.html('<i class="fa fa-play"></i> {{ lang._("Start") }}');
        if (action === 'restart') btn.html('<i class="fa fa-refresh"></i> {{ lang._("Restart") }}');
        if (action === 'stop')    btn.html('<i class="fa fa-stop"></i> {{ lang._("Stop") }}');
        if (data.status === 'ok') {
            showNotification('{{ lang._("Service") }} ' + action + ' {{ lang._("completed") }}', 'success');
            setTimeout(loadDashboardData, 2000);
        } else {
            showNotification('{{ lang._("Service") }} ' + action + ' {{ lang._("failed") }}', 'error');
        }
    });
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportStats() {
    ajaxCall('/api/deepinspector/settings/stats', {}, function (data) {
        if (data.status !== 'ok') return;
        var content = JSON.stringify(data.data, null, 2);
        var blob = new Blob([content], { type: 'application/json' });
        var link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'deepinspector_stats_' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.json';
        link.click();
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function sevClass(s) {
    switch ((s || '').toLowerCase()) {
        case 'critical': return 'badge-danger';
        case 'high':     return 'badge-warning';
        case 'medium':   return 'badge-info';
        case 'low':      return 'badge-success';
        default:         return 'badge-secondary';
    }
}
function fmtNum(n)  { return new Intl.NumberFormat().format(n || 0); }
function fmtTime(t) { return t ? new Date(t).toLocaleString() : '--'; }

function showNotification(message, type) {
    var cls = type === 'success' ? 'alert-success' : 'alert-danger';
    var n = $('<div class="alert ' + cls + ' alert-dismissible fade show" role="alert">' +
        message +
        '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
        '</div>');
    $('#notifications').append(n);
    setTimeout(function () { n.alert('close'); }, 5000);
}
</script>

<style>
.metric-card {
    background:#fff;border-radius:8px;padding:1.25rem;
    box-shadow:0 2px 4px rgba(0,0,0,.08);margin-bottom:1rem;
    display:flex;align-items:center;gap:1rem;
}
.metric-icon  { font-size:2rem;color:#2563eb;width:2.5rem;text-align:center;flex-shrink:0; }
.metric-value { font-size:1.75rem;font-weight:700;color:#1f2937;line-height:1.1; }
.metric-label { font-size:.78rem;color:#6b7280;text-transform:uppercase;letter-spacing:.04em; }

.chart-container {
    background:#fff;border-radius:8px;padding:1rem;
    box-shadow:0 2px 4px rgba(0,0,0,.08);margin-bottom:1rem;
}
.chart-header {
    display:flex;justify-content:space-between;align-items:center;
    margin-bottom:.65rem;
}
.chart-header h5 { margin:0;font-size:.92rem;font-weight:600;color:#374151; }

#attackMap { background:#1a1a2e; }
</style>
