{# statistics.volt - Deep Packet Inspector Statistics #}
<script src="/ui/js/chart.min.js"></script>

<script>
$(document).ready(function() {
    if (typeof Chart !== 'undefined') {
        initCharts();
    }
    loadStats();
    setInterval(loadStats, 30000);

    $('#refreshStats').click(function() { loadStats(); });
    $('#exportStats').click(function() { exportStats(); });
    $('#severityFilter, #threatTypeFilter, #timeRangeFilter').change(function() { applyFilters(); });
});

// ── Chart instances ──────────────────────────────────────────────────────────

function initCharts() {
    window.protocolChart = new Chart(
        document.getElementById('protocolChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#007bff','#28a745','#ffc107','#dc3545','#17a2b8','#6f42c1','#fd7e14','#20c997','#e83e8c','#adb5bd'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
    });

    window.threatTypesChart = new Chart(
        document.getElementById('threatTypesChart').getContext('2d'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Count', data: [], backgroundColor: ['#dc3545','#fd7e14','#ffc107','#6f42c1','#17a2b8','#28a745'] }] },
        options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } } }
    });

    window.timelineChart = new Chart(
        document.getElementById('timelineChart').getContext('2d'), {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Threats', data: [], borderColor: '#dc3545', backgroundColor: 'rgba(220,53,69,0.08)', tension: 0.3, fill: true }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }, plugins: { legend: { display: false } } }
    });

    window.severityChart = new Chart(
        document.getElementById('severityChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['Critical','High','Medium','Low'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#dc3545','#fd7e14','#ffc107','#28a745'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
    });

    window.industrialChart = new Chart(
        document.getElementById('industrialChart').getContext('2d'), {
        type: 'bar',
        data: { labels: ['Modbus','DNP3','OPC-UA','SCADA'], datasets: [{ label: 'Events', data: [0,0,0,0], backgroundColor: ['#6f42c1','#17a2b8','#fd7e14','#dc3545'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } }
    });
}

// ── Data loading ─────────────────────────────────────────────────────────────

var allThreats = [];

function loadStats() {
    $('#lastUpdated').text(new Date().toLocaleString());
    ajaxCall("/api/deepinspector/settings/stats", {}, function(data) {
        if (data.status !== 'ok' || !data.data) return;
        var d = data.data;
        allThreats = d.recent_threats || [];
        updateMetrics(d);
        updateCharts(d);
        applyFilters();
        updateTopSources(allThreats);
        updatePerformance(d.system_info || {});
    });
}

function updateMetrics(d) {
    $('#packetsAnalyzed').text(formatNumber(d.packets_analyzed || 0));
    $('#threatsDetected').text(formatNumber(d.threats_detected || 0));
    var rate = d.packets_analyzed > 0
        ? ((d.threats_detected / d.packets_analyzed) * 100).toFixed(2)
        : '0.00';
    $('#detectionRate').text(rate + '%');
    var protocols = d.protocols_analyzed || {};
    $('#activeProtocols').text(Object.keys(protocols).length);
}

function updateCharts(d) {
    // Protocol distribution
    if (window.protocolChart) {
        var p = d.protocols_analyzed || {};
        var pLabels = Object.keys(p);
        var pValues = Object.values(p);
        if (pLabels.length > 0) {
            window.protocolChart.data.labels = pLabels;
            window.protocolChart.data.datasets[0].data = pValues;
            window.protocolChart.update();
        }
    }

    // Threat types horizontal bar
    if (window.threatTypesChart) {
        var t = d.threat_types || {};
        var tLabels = Object.keys(t);
        var tValues = Object.values(t);
        if (tLabels.length > 0) {
            window.threatTypesChart.data.labels = tLabels;
            window.threatTypesChart.data.datasets[0].data = tValues;
            window.threatTypesChart.update();
        }
    }

    // Timeline: 24h hourly buckets from recent_threats
    if (window.timelineChart) {
        var threats = d.recent_threats || [];
        var now = Date.now();
        var buckets = {};
        for (var i = 23; i >= 0; i--) {
            var dt = new Date(now - i * 3600000);
            buckets[dt.getHours().toString().padStart(2,'0') + ':00'] = 0;
        }
        threats.forEach(function(t) {
            var ts = new Date(t.timestamp);
            if ((now - ts.getTime()) <= 86400000) {
                var label = ts.getHours().toString().padStart(2,'0') + ':00';
                if (buckets.hasOwnProperty(label)) buckets[label]++;
            }
        });
        window.timelineChart.data.labels = Object.keys(buckets);
        window.timelineChart.data.datasets[0].data = Object.values(buckets);
        window.timelineChart.update();
    }

    // Severity distribution from recent_threats
    if (window.severityChart) {
        var threats = d.recent_threats || [];
        var sev = { critical: 0, high: 0, medium: 0, low: 0 };
        threats.forEach(function(t) {
            var s = (t.severity || 'medium').toLowerCase();
            if (sev.hasOwnProperty(s)) sev[s]++;
        });
        window.severityChart.data.datasets[0].data = [sev.critical, sev.high, sev.medium, sev.low];
        window.severityChart.update();
    }

    // Industrial protocols from threat_types or protocols_analyzed
    if (window.industrialChart) {
        var protocols = d.protocols_analyzed || {};
        var types = d.threat_types || {};
        window.industrialChart.data.datasets[0].data = [
            protocols['modbus'] || protocols['Modbus'] || 0,
            protocols['dnp3']   || protocols['DNP3']   || 0,
            protocols['opcua']  || protocols['OPC-UA'] || protocols['OPCUA'] || 0,
            types['scada_attack'] || types['industrial_threat'] || 0
        ];
        window.industrialChart.update();
    }
}

// ── Threats table with filters ───────────────────────────────────────────────

function applyFilters() {
    var severity  = $('#severityFilter').val();
    var type      = $('#threatTypeFilter').val();
    var timeRange = parseInt($('#timeRangeFilter').val()) || 0;
    var now       = Date.now();

    var filtered = allThreats.filter(function(t) {
        if (severity !== 'all' && (t.severity || '').toLowerCase() !== severity) return false;
        if (type !== 'all' && (t.threat_type || '').toLowerCase() !== type) return false;
        if (timeRange > 0) {
            var age = now - new Date(t.timestamp).getTime();
            if (age > timeRange * 3600000) return false;
        }
        return true;
    });

    renderThreatsTable(filtered);
}

function renderThreatsTable(threats) {
    var tbody = $('#threatsBody');
    tbody.empty();
    if (threats.length === 0) {
        tbody.html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No threats match the current filters") }}</td></tr>');
        return;
    }
    threats.forEach(function(t) {
        tbody.append(
            '<tr>' +
            '<td style="font-family:monospace;font-size:.85em">' + new Date(t.timestamp).toLocaleString() + '</td>' +
            '<td><code>' + (t.source_ip || 'N/A') + '</code></td>' +
            '<td><code>' + (t.destination_ip || 'N/A') + '</code></td>' +
            '<td>' + (t.threat_type || 'N/A') + '</td>' +
            '<td><span class="badge ' + sevClass(t.severity) + '">' + (t.severity || 'N/A') + '</span></td>' +
            '<td>' + (t.protocol || 'N/A') + '</td>' +
            '</tr>'
        );
    });
}

function updateTopSources(threats) {
    var counts = {};
    threats.forEach(function(t) {
        if (t.source_ip) counts[t.source_ip] = (counts[t.source_ip] || 0) + 1;
    });
    var sorted = Object.entries(counts).sort(function(a,b){ return b[1]-a[1]; }).slice(0,10);
    var container = $('#topSources');
    container.empty();
    if (sorted.length === 0) {
        container.html('<div class="text-muted text-center p-2">{{ lang._("No data") }}</div>');
        return;
    }
    sorted.forEach(function(entry) {
        var ip = entry[0], count = entry[1];
        container.append(
            '<div class="d-flex justify-content-between align-items-center mb-2">' +
            '<code style="font-size:.9em">' + ip + '</code>' +
            '<span class="badge badge-danger">' + count + '</span>' +
            '</div>'
        );
    });
}

function updatePerformance(info) {
    $('#cpuUsage').text(info.cpu_usage || 'N/A');
    $('#memUsage').text(info.memory_usage || 'N/A');
    $('#engineStatus').text(info.engine_status || 'N/A');
    $('#engineUptime').text(info.uptime || 'N/A');
}

// ── Export ───────────────────────────────────────────────────────────────────

function exportStats() {
    ajaxCall("/api/deepinspector/settings/stats", {}, function(data) {
        if (data.status !== 'ok') return;
        var content = JSON.stringify(data.data, null, 2);
        var blob = new Blob([content], { type: 'application/json' });
        var link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'deepinspector_stats_' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.json';
        link.click();
    });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function sevClass(s) {
    switch ((s || '').toLowerCase()) {
        case 'critical': return 'badge-danger';
        case 'high':     return 'badge-warning';
        case 'medium':   return 'badge-info';
        case 'low':      return 'badge-success';
        default:         return 'badge-secondary';
    }
}

function formatNumber(n) { return new Intl.NumberFormat().format(n || 0); }
</script>

<div id="notifications" style="position:fixed;top:20px;right:20px;z-index:9999;min-width:280px;"></div>

<!-- ── Toolbar ───────────────────────────────────────────────────────────── -->
<div class="content-box" style="padding:1rem 1.5rem;margin-bottom:1rem;">
    <div class="row" style="align-items:center;">
        <div class="col-md-8">
            <span class="text-muted" style="font-size:.85em;">
                {{ lang._('Last updated') }}: <strong id="lastUpdated">--</strong>
            </span>
        </div>
        <div class="col-md-4 text-right">
            <button class="btn btn-default btn-sm" id="refreshStats">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
            <button class="btn btn-default btn-sm" id="exportStats" style="margin-left:.5rem;">
                <i class="fa fa-download"></i> {{ lang._('Export JSON') }}
            </button>
        </div>
    </div>
</div>

<!-- ── Metrics ───────────────────────────────────────────────────────────── -->
<div class="row">
    <div class="col-md-3">
        <div class="stat-metric-card">
            <div class="stat-metric-icon text-primary"><i class="fa fa-search"></i></div>
            <div>
                <div class="stat-metric-value" id="packetsAnalyzed">0</div>
                <div class="stat-metric-label">{{ lang._('Packets Analyzed') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-metric-card">
            <div class="stat-metric-icon text-danger"><i class="fa fa-exclamation-triangle"></i></div>
            <div>
                <div class="stat-metric-value" id="threatsDetected">0</div>
                <div class="stat-metric-label">{{ lang._('Threats Detected') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-metric-card">
            <div class="stat-metric-icon text-warning"><i class="fa fa-percent"></i></div>
            <div>
                <div class="stat-metric-value" id="detectionRate">0%</div>
                <div class="stat-metric-label">{{ lang._('Detection Rate') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-metric-card">
            <div class="stat-metric-icon text-success"><i class="fa fa-exchange"></i></div>
            <div>
                <div class="stat-metric-value" id="activeProtocols">0</div>
                <div class="stat-metric-label">{{ lang._('Active Protocols') }}</div>
            </div>
        </div>
    </div>
</div>

<!-- ── Charts row 1: Protocol / Threat Types / Timeline ──────────────────── -->
<div class="row">
    <div class="col-md-4">
        <div class="content-box stat-chart-box">
            <h5>{{ lang._('Protocol Distribution') }}</h5>
            <div style="position:relative;height:240px;">
                <canvas id="protocolChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="content-box stat-chart-box">
            <h5>{{ lang._('Threat Types') }}</h5>
            <div style="position:relative;height:240px;">
                <canvas id="threatTypesChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="content-box stat-chart-box">
            <h5>{{ lang._('Threat Timeline (24h)') }}</h5>
            <div style="position:relative;height:240px;">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- ── Charts row 2: Severity / Industrial ───────────────────────────────── -->
<div class="row">
    <div class="col-md-4">
        <div class="content-box stat-chart-box">
            <h5>{{ lang._('Severity Distribution') }}</h5>
            <div style="position:relative;height:220px;">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="content-box stat-chart-box">
            <h5>{{ lang._('Industrial / SCADA Events') }}</h5>
            <div style="position:relative;height:220px;">
                <canvas id="industrialChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="content-box stat-chart-box">
            <h5>{{ lang._('Engine Performance') }}</h5>
            <table class="table table-sm" style="margin-top:.5rem;">
                <tr>
                    <td>{{ lang._('Status') }}</td>
                    <td><strong id="engineStatus">--</strong></td>
                </tr>
                <tr>
                    <td>{{ lang._('Uptime') }}</td>
                    <td><strong id="engineUptime">--</strong></td>
                </tr>
                <tr>
                    <td>{{ lang._('CPU') }}</td>
                    <td><strong id="cpuUsage">--</strong></td>
                </tr>
                <tr>
                    <td>{{ lang._('Memory') }}</td>
                    <td><strong id="memUsage">--</strong></td>
                </tr>
            </table>
        </div>
    </div>
</div>

<!-- ── Threats table + Top sources ───────────────────────────────────────── -->
<div class="row">
    <div class="col-md-8">
        <div class="content-box" style="padding:1rem;">
            <div class="row" style="margin-bottom:.75rem;align-items:flex-end;">
                <div class="col-md-4">
                    <label style="font-size:.85em;">{{ lang._('Severity') }}</label>
                    <select class="form-control form-control-sm" id="severityFilter">
                        <option value="all">{{ lang._('All') }}</option>
                        <option value="critical">{{ lang._('Critical') }}</option>
                        <option value="high">{{ lang._('High') }}</option>
                        <option value="medium">{{ lang._('Medium') }}</option>
                        <option value="low">{{ lang._('Low') }}</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <label style="font-size:.85em;">{{ lang._('Threat Type') }}</label>
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
                <div class="col-md-4">
                    <label style="font-size:.85em;">{{ lang._('Time Range') }}</label>
                    <select class="form-control form-control-sm" id="timeRangeFilter">
                        <option value="0">{{ lang._('All') }}</option>
                        <option value="1">{{ lang._('Last 1h') }}</option>
                        <option value="6">{{ lang._('Last 6h') }}</option>
                        <option value="24" selected>{{ lang._('Last 24h') }}</option>
                    </select>
                </div>
            </div>
            <h5>{{ lang._('Recent Threats') }}</h5>
            <div class="table-responsive">
                <table class="table table-striped table-sm">
                    <thead>
                        <tr>
                            <th>{{ lang._('Time') }}</th>
                            <th>{{ lang._('Source IP') }}</th>
                            <th>{{ lang._('Destination IP') }}</th>
                            <th>{{ lang._('Threat Type') }}</th>
                            <th>{{ lang._('Severity') }}</th>
                            <th>{{ lang._('Protocol') }}</th>
                        </tr>
                    </thead>
                    <tbody id="threatsBody">
                        <tr><td colspan="6" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="content-box" style="padding:1rem;">
            <h5>{{ lang._('Top Threat Sources') }}</h5>
            <div id="topSources" style="max-height:340px;overflow-y:auto;"></div>
        </div>
    </div>
</div>

<style>
.stat-metric-card {
    background: #fff;
    border-radius: 6px;
    padding: 1.25rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.1);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
}
.stat-metric-icon {
    font-size: 2rem;
    width: 2.5rem;
    text-align: center;
    flex-shrink: 0;
}
.stat-metric-value {
    font-size: 1.75rem;
    font-weight: 700;
    color: #1f2937;
    line-height: 1.1;
}
.stat-metric-label {
    font-size: .78rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: .04em;
}
.stat-chart-box {
    padding: 1rem;
    margin-bottom: 1rem;
}
.stat-chart-box h5 {
    margin-top: 0;
    margin-bottom: .75rem;
    font-size: .95rem;
    font-weight: 600;
    color: #374151;
}
</style>
