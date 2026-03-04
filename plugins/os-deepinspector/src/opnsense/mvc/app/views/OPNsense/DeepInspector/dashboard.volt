{# dashboard.volt - Deep Packet Inspector Dashboard #}
<link rel="stylesheet" href="/ui/css/leaflet.css"/>
<script src="/ui/js/chart.min.js"></script>
<script src="/ui/js/leaflet.js"></script>

<div id="notifications" style="position:fixed;bottom:24px;right:24px;z-index:9999;min-width:280px;max-width:380px;pointer-events:none;"></div>

<!-- ── Toolbar ──────────────────────────────────────────────────────────────── -->
<div class="content-box" style="padding:.65rem 1.25rem;margin-bottom:1rem;">
    <div class="row" style="align-items:center;">
        <div class="col-md-2">
            <span id="serviceStatus" class="badge badge-secondary">{{ lang._('Loading...') }}</span>
        </div>
        <div class="col-md-10 text-right">
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

<!-- ── Metric cards ──────────────────────────────────────────────────────────── -->
<div class="row">
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon"><i class="fa fa-search"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="packetsAnalyzed">0</div>
                <div class="di-metric-label">{{ lang._('Packets Analyzed') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon" style="color:#dc3545;"><i class="fa fa-shield"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="threatsDetected">0</div>
                <div class="di-metric-label">{{ lang._('Threats Detected') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon" style="color:#fd7e14;"><i class="fa fa-exclamation-triangle"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="criticalAlerts">0</div>
                <div class="di-metric-label">{{ lang._('Critical Alerts') }}</div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-metric-card">
            <div class="di-metric-icon" style="color:#28a745;"><i class="fa fa-exchange"></i></div>
            <div class="di-metric-content">
                <div class="di-metric-value" id="activeProtocols">0</div>
                <div class="di-metric-label">{{ lang._('Active Protocols') }}</div>
            </div>
        </div>
    </div>
</div>

<!-- ── Charts row 1: Timeline | Protocol | Threat Types ─────────────────────── -->
<div class="row">
    <div class="col-md-6">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Threat Timeline') }}</span>
                <div style="display:flex;gap:.3rem;align-items:center;">
                    <select class="form-control di-inline-sel" id="timelineRange">
                        <option value="last30s">30s</option>
                        <option value="last15m">15m</option>
                        <option value="last1h">1h</option>
                        <option value="last24h" selected>24h</option>
                        <option value="today">Today</option>
                        <option value="thisweek">7d</option>
                        <option value="thismonth">30d</option>
                        <option value="last90d">90d</option>
                    </select>
                    <select class="form-control di-inline-sel" id="timelineGranularity">
                        <option value="auto" selected>Auto</option>
                        <option value="minute">{{ lang._('Per min') }}</option>
                        <option value="hour">{{ lang._('Per hour') }}</option>
                        <option value="day">{{ lang._('Per day') }}</option>
                    </select>
                </div>
            </div>
            <div style="position:relative;height:210px;"><canvas id="threatTimelineChart"></canvas></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Protocol Distribution') }}</span>
                <select class="form-control di-inline-sel" id="protocolThreshold">
                    <option value="0" selected>Min 0</option>
                    <option value="10">Min 10</option>
                    <option value="100">Min 100</option>
                    <option value="1000">Min 1000</option>
                </select>
            </div>
            <div style="position:relative;height:210px;"><canvas id="protocolChart"></canvas></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Threat Types') }}</span>
                <div style="display:flex;gap:.3rem;">
                    <select class="form-control di-inline-sel" id="threatTypesRange">
                        <option value="last30s">30s</option>
                        <option value="last15m">15m</option>
                        <option value="last1h">1h</option>
                        <option value="last24h" selected>24h</option>
                        <option value="today">Today</option>
                        <option value="thisweek">7d</option>
                        <option value="thismonth">30d</option>
                        <option value="last90d">90d</option>
                    </select>
                    <select class="form-control di-inline-sel" id="threatTypesTopN">
                        <option value="5" selected>Top 5</option>
                        <option value="10">Top 10</option>
                        <option value="20">Top 20</option>
                        <option value="0">{{ lang._('All') }}</option>
                    </select>
                </div>
            </div>
            <div style="position:relative;height:210px;"><canvas id="threatTypesChart"></canvas></div>
        </div>
    </div>
</div>

<!-- ── Charts row 2: Severity | Top Sources | Industrial | Performance ─────── -->
<div class="row">
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr" style="flex-wrap:wrap;gap:.3rem;">
                <span class="di-chart-title">{{ lang._('Severity') }}</span>
                <div style="display:flex;gap:.3rem;align-items:center;">
                    <select class="form-control di-inline-sel" id="severityRange">
                        <option value="last30s">30s</option>
                        <option value="last15m">15m</option>
                        <option value="last1h">1h</option>
                        <option value="last24h" selected>24h</option>
                        <option value="today">Today</option>
                        <option value="thisweek">7d</option>
                        <option value="thismonth">30d</option>
                        <option value="last90d">90d</option>
                    </select>
                    <div style="font-size:.72em;white-space:nowrap;">
                        <label style="margin:0;"><input type="checkbox" class="sev-toggle" value="critical" checked> Crit</label>
                        <label style="margin:0 0 0 .3rem;"><input type="checkbox" class="sev-toggle" value="high" checked> High</label>
                        <label style="margin:0 0 0 .3rem;"><input type="checkbox" class="sev-toggle" value="medium" checked> Med</label>
                        <label style="margin:0 0 0 .3rem;"><input type="checkbox" class="sev-toggle" value="low" checked> Low</label>
                    </div>
                </div>
            </div>
            <div style="position:relative;height:190px;"><canvas id="severityChart"></canvas></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Top Threat Sources') }}</span>
                <div style="display:flex;gap:.3rem;">
                    <select class="form-control di-inline-sel" id="sourcesRange">
                        <option value="last30s">30s</option>
                        <option value="last15m">15m</option>
                        <option value="last1h">1h</option>
                        <option value="last24h" selected>24h</option>
                        <option value="today">Today</option>
                        <option value="thisweek">7d</option>
                        <option value="thismonth">30d</option>
                        <option value="last90d">90d</option>
                    </select>
                    <select class="form-control di-inline-sel" id="topSourcesN">
                        <option value="5">Top 5</option>
                        <option value="10" selected>Top 10</option>
                        <option value="20">Top 20</option>
                        <option value="50">Top 50</option>
                    </select>
                </div>
            </div>
            <div id="topSources" style="max-height:196px;overflow-y:auto;margin-top:.25rem;"></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Industrial / SCADA') }}</span>
                <label style="font-size:.76em;margin:0;white-space:nowrap;">
                    <input type="checkbox" id="hideZeroIndustrial"> {{ lang._('Hide zeros') }}
                </label>
            </div>
            <div style="position:relative;height:190px;"><canvas id="industrialChart"></canvas></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr"><span class="di-chart-title">{{ lang._('Engine Performance') }}</span></div>
            <table class="table table-condensed" style="font-size:.82em;margin:.25rem 0 0 0;">
                <tr><td style="color:#6b7280;">{{ lang._('Status') }}</td><td><strong id="engineStatus">--</strong></td></tr>
                <tr><td style="color:#6b7280;">{{ lang._('PID') }}</td><td><strong id="enginePid">--</strong></td></tr>
                <tr><td style="color:#6b7280;">{{ lang._('Uptime') }}</td><td><strong id="engineUptime">--</strong></td></tr>
                <tr><td style="color:#6b7280;">{{ lang._('CPU') }}</td><td><strong id="cpuUsage">--</strong></td></tr>
                <tr><td style="color:#6b7280;">{{ lang._('Memory') }}</td><td><strong id="memUsage">--</strong></td></tr>
                <tr><td style="color:#6b7280;">{{ lang._('Interfaces') }}</td><td><strong id="monitoredInterfaces">--</strong></td></tr>
                <tr><td style="color:#6b7280;">{{ lang._('Signatures') }}</td><td><strong id="signaturesVersion">--</strong></td></tr>
            </table>
        </div>
    </div>
</div>

<!-- ── Recent Threats (col-9) | Service Controls (col-3) ────────────────────── -->
<div class="row">
    <div class="col-md-9">
        <div class="di-chart-box">
            <div class="di-chart-hdr" style="margin-bottom:.75rem;flex-wrap:wrap;gap:.4rem;">
                <span class="di-chart-title">{{ lang._('Recent Threats') }}</span>
                <div style="display:flex;gap:.4rem;align-items:center;flex-wrap:wrap;margin-left:auto;">
                    <select class="form-control di-inline-sel" id="threatsRange">
                        <option value="last30s">30s</option>
                        <option value="last15m">15m</option>
                        <option value="last1h">1h</option>
                        <option value="last24h" selected>24h</option>
                        <option value="today">Today</option>
                        <option value="thisweek">7d</option>
                        <option value="thismonth">30d</option>
                        <option value="last90d">90d</option>
                    </select>
                    <input type="text" class="form-control input-sm" id="threatSearch"
                           placeholder="{{ lang._('Search...') }}" style="width:130px;height:26px;font-size:.82em;">
                    <select class="form-control di-inline-sel" id="severityFilter" style="width:90px;">
                        <option value="all">{{ lang._('All sev.') }}</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <select class="form-control di-inline-sel" id="threatTypeFilter" style="width:120px;">
                        <option value="all">{{ lang._('All types') }}</option>
                        <option value="sql_injection">SQL Injection</option>
                        <option value="command_injection">Cmd Injection</option>
                        <option value="script_injection">Script Injection</option>
                        <option value="malware">Malware</option>
                        <option value="crypto_mining">Crypto Mining</option>
                        <option value="industrial_threat">Industrial</option>
                        <option value="scada_attack">SCADA</option>
                    </select>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-condensed threats-table" style="font-size:.85em;">
                    <thead>
                        <tr>
                            <th class="sortable" data-col="timestamp" style="cursor:pointer;white-space:nowrap;">{{ lang._('Time') }} <i class="fa fa-sort text-muted"></i></th>
                            <th class="sortable" data-col="source_ip" style="cursor:pointer;white-space:nowrap;">{{ lang._('Source IP') }} <i class="fa fa-sort text-muted"></i></th>
                            <th class="sortable" data-col="destination_ip" style="cursor:pointer;white-space:nowrap;">{{ lang._('Dest IP') }} <i class="fa fa-sort text-muted"></i></th>
                            <th class="sortable" data-col="threat_type" style="cursor:pointer;white-space:nowrap;">{{ lang._('Type') }} <i class="fa fa-sort text-muted"></i></th>
                            <th class="sortable" data-col="severity" style="cursor:pointer;white-space:nowrap;">{{ lang._('Sev.') }} <i class="fa fa-sort text-muted"></i></th>
                            <th class="sortable" data-col="protocol" style="cursor:pointer;white-space:nowrap;">{{ lang._('Proto') }} <i class="fa fa-sort text-muted"></i></th>
                            <th style="width:90px;">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="threatTableBody">
                        <tr><td colspan="7" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
            <div id="threatsPager"></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box">
            <div class="di-chart-hdr"><span class="di-chart-title">{{ lang._('Service Controls') }}</span></div>
            <div class="btn-group-vertical" style="width:100%;margin-top:.5rem;">
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

<!-- ── Attack Map (col-9) | Private Sources (col-3) ─────────────────────────── -->
<div class="row">
    <div class="col-md-9">
        <div class="di-chart-box">
            <div class="di-chart-hdr">
                <span class="di-chart-title">{{ lang._('Attack Map') }}</span>
                <span id="mapRateLimitedBadge" class="label label-warning" style="display:none;font-size:.78em;">
                    {{ lang._('Partial map – GeoIP temporarily unavailable') }}
                </span>
            </div>
            <div id="attackMap" style="height:380px;border-radius:4px;overflow:hidden;"></div>
            <div id="mapLegend" style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;padding:.4rem 0 0 0;font-size:.76em;color:#555;">
                <div style="display:flex;align-items:center;gap:.3rem;"><span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:#dc3545;border:1px solid rgba(0,0,0,.15);"></span> Critical</div>
                <div style="display:flex;align-items:center;gap:.3rem;"><span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:#fd7e14;border:1px solid rgba(0,0,0,.15);"></span> High</div>
                <div style="display:flex;align-items:center;gap:.3rem;"><span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:#ffc107;border:1px solid rgba(0,0,0,.15);"></span> Medium</div>
                <div style="display:flex;align-items:center;gap:.3rem;"><span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:#28a745;border:1px solid rgba(0,0,0,.15);"></span> Low</div>
                <span class="text-muted" style="margin-left:.25rem;font-style:italic;">{{ lang._('Size = attack count') }}</span>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="di-chart-box" style="height:452px;">
            <div class="di-chart-hdr"><span class="di-chart-title">{{ lang._('Attack Origins') }}</span></div>
            <div id="mapSidebar" style="max-height:400px;overflow-y:auto;margin-top:.25rem;"></div>
        </div>
    </div>
</div>

<!-- ── Threat Detail Modal ───────────────────────────────────────────────────── -->
<div class="modal fade" id="threatModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title">{{ lang._('Threat Details') }}</h4>
            </div>
            <div class="modal-body" id="threatModalBody">
                <div class="text-center"><i class="fa fa-spinner fa-spin fa-2x"></i></div>
            </div>
            <div class="modal-footer">
                <!-- False Positive reason row (hidden until FP button clicked) -->
                <div id="fpReasonRow" style="display:none;float:left;width:60%;">
                    <div class="input-group input-group-sm">
                        <input type="text" class="form-control" id="fpReasonInput"
                               placeholder="{{ lang._('Reason (optional)') }}" maxlength="200">
                        <span class="input-group-btn">
                            <button class="btn btn-warning btn-sm" id="modalConfirmFPBtn">
                                <i class="fa fa-check"></i> {{ lang._('Confirm') }}
                            </button>
                        </span>
                    </div>
                </div>
                <button type="button" class="btn btn-warning btn-sm" id="modalMarkFPBtn" style="display:none;">
                    <i class="fa fa-flag"></i> {{ lang._('Mark as False Positive') }}
                </button>
                <button type="button" class="btn btn-danger btn-sm" id="modalBlockBtn" style="display:none;">
                    <i class="fa fa-ban"></i> {{ lang._('Block Source IP') }}
                </button>
                <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">{{ lang._('Close') }}</button>
            </div>
        </div>
    </div>
</div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
var allThreats      = [];
var allProtocols    = {};
var allThreatTypes  = {};
var sevCounts       = { critical:0, high:0, medium:0, low:0 };
var filteredThreats = [];
var threatsPage     = 1;
var threatsPerPage  = 20;
var leafletMap      = null;
var markersLayer    = null;
var _modalThreatId  = null;
var _modalThreatIP  = null;
var blockedIPs      = {};
var fpAlertIds      = {};
var threatsSortCol  = null;
var threatsSortDir  = 'asc';
var threatsSearch   = '';

// ── Init ──────────────────────────────────────────────────────────────────────
$(document).ready(function () {
    if (typeof Chart !== 'undefined') initCharts();
    initMap();
    loadDashboardData();
    loadBlockedIPs();
    loadFPAlertIds();
    setInterval(loadDashboardData, 60000);
    setInterval(loadBlockedIPs, 60000);
    setInterval(loadFPAlertIds, 60000);

    $('#refreshDash').click(loadDashboardData);
    $('#exportStats').click(exportStats);

    $('#threatSearch').on('input', function() {
        threatsSearch = $(this).val();
        threatsPage = 1;
        applyThreatFilters();
    });

    $(document).on('click', '.threats-table th.sortable', function() {
        var col = $(this).data('col');
        if (threatsSortCol === col) { threatsSortDir = threatsSortDir === 'asc' ? 'desc' : 'asc'; }
        else { threatsSortCol = col; threatsSortDir = 'asc'; }
        threatsPage = 1;
        updateThreatSortHeaders();
        applyThreatFilters();
    });

    $('#startService').click(function ()   { controlService('start'); });
    $('#restartService').click(function () { controlService('restart'); });
    $('#stopService').click(function ()    { controlService('stop'); });

    $('#severityFilter, #threatTypeFilter, #threatsRange').change(function () { threatsPage = 1; applyThreatFilters(); });
    $('#threatTypesTopN, #threatTypesRange').change(renderThreatTypesChart);
    $('#protocolThreshold').change(renderProtocolChart);
    $('#topSourcesN, #sourcesRange').change(renderTopSources);
    $('#timelineGranularity, #timelineRange').change(function () { updateThreatTimeline(allThreats); });
    $(document).on('change', '.sev-toggle', renderSeverityChart);
    $('#severityRange').change(renderSeverityChart);
    $('#hideZeroIndustrial').change(renderIndustrialChart);

    // Modal FP flow
    $('#modalMarkFPBtn').click(function () {
        $(this).hide();
        $('#fpReasonRow').show();
        $('#fpReasonInput').val('').focus();
    });
    $('#modalConfirmFPBtn').click(function () {
        var reason = $('#fpReasonInput').val().trim();
        markFalsePositive(_modalThreatId, reason);
        $('#threatModal').modal('hide');
    });
    $('#fpReasonInput').keypress(function (e) {
        if (e.which === 13) $('#modalConfirmFPBtn').click();
    });

    // Modal block flow
    $('#modalBlockBtn').click(function () {
        if (_modalThreatIP) {
            if (blockedIPs[_modalThreatIP]) { unblockSource(_modalThreatIP); }
            else                            { blockSource(_modalThreatIP); }
            $('#threatModal').modal('hide');
        }
    });

    $('#threatModal').on('hidden.bs.modal', function () {
        $('#fpReasonRow').hide();
        $('#fpReasonInput').val('');
        $('#modalBlockBtn').removeClass('btn-warning').addClass('btn-danger')
            .html('<i class="fa fa-ban"></i> {{ lang._("Block Source IP") }}');
    });
});

// ── Charts init ───────────────────────────────────────────────────────────────
function initCharts() {
    window.dashProtocolChart = new Chart(
        document.getElementById('protocolChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels:[], datasets:[{ data:[], backgroundColor:['#007bff','#28a745','#ffc107','#dc3545','#17a2b8','#6f42c1','#fd7e14','#20c997','#e83e8c','#adb5bd'] }] },
        options: { responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'bottom', labels:{ font:{size:9} } } } }
    });

    window.dashThreatTypesChart = new Chart(
        document.getElementById('threatTypesChart').getContext('2d'), {
        type: 'bar',
        data: { labels:[], datasets:[{ label:'Count', data:[], backgroundColor:'#dc3545' }] },
        options: { responsive:true, maintainAspectRatio:false, indexAxis:'y',
            plugins:{ legend:{ display:false } },
            scales:{ x:{ beginAtZero:true, ticks:{ stepSize:1 } } } }
    });

    window.dashTimelineChart = new Chart(
        document.getElementById('threatTimelineChart').getContext('2d'), {
        type: 'line',
        data: { labels:[], datasets:[{ label:'Threats', data:[], borderColor:'#dc3545', backgroundColor:'rgba(220,53,69,0.08)', tension:0.3, fill:true }] },
        options: { responsive:true, maintainAspectRatio:false,
            scales:{ y:{ beginAtZero:true, ticks:{ stepSize:1 } } },
            plugins:{ legend:{ display:false } } }
    });

    window.dashSeverityChart = new Chart(
        document.getElementById('severityChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels:['Critical','High','Medium','Low'], datasets:[{ data:[0,0,0,0], backgroundColor:['#dc3545','#fd7e14','#ffc107','#28a745'] }] },
        options: { responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'bottom', labels:{ font:{size:9} } } } }
    });

    window.dashIndustrialChart = new Chart(
        document.getElementById('industrialChart').getContext('2d'), {
        type: 'bar',
        data: { labels:['Modbus','DNP3','OPC-UA','SCADA'], datasets:[{ label:'Events', data:[0,0,0,0], backgroundColor:['#6f42c1','#17a2b8','#fd7e14','#dc3545'] }] },
        options: { responsive:true, maintainAspectRatio:false,
            plugins:{ legend:{ display:false } },
            scales:{ y:{ beginAtZero:true, ticks:{ stepSize:1 } } } }
    });
}

// ── Leaflet map ───────────────────────────────────────────────────────────────
function initMap() {
    if (typeof L === 'undefined') return;
    leafletMap = L.map('attackMap', { zoomControl:true }).setView([20,0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        subdomains: ['a','b','c'],
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

        allThreats   = d.recent_threats     || [];
        allProtocols = d.protocols_analyzed || {};

        // Use threat_types from API; fallback: compute from recent_threats
        allThreatTypes = d.threat_types || {};
        if (Object.keys(allThreatTypes).length === 0 && allThreats.length > 0) {
            allThreats.forEach(function (t) {
                var tt = (t.threat_type || 'unknown').toLowerCase();
                allThreatTypes[tt] = (allThreatTypes[tt] || 0) + 1;
            });
        }

        // Severity counts from recent_threats
        sevCounts = { critical:0, high:0, medium:0, low:0 };
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
        renderTopSources();
        threatsPage = 1;
        applyThreatFilters();
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

// ── Charts ────────────────────────────────────────────────────────────────────
function renderProtocolChart() {
    if (!window.dashProtocolChart) return;
    var threshold = parseInt($('#protocolThreshold').val()) || 0;
    var labels = [], values = [];
    Object.keys(allProtocols).forEach(function (k) {
        if ((allProtocols[k] || 0) >= threshold) { labels.push(k); values.push(allProtocols[k]); }
    });
    window.dashProtocolChart.data.labels = labels;
    window.dashProtocolChart.data.datasets[0].data = values;
    window.dashProtocolChart.update();
}

function renderThreatTypesChart() {
    if (!window.dashThreatTypesChart) return;
    var filtered = filterThreatsByRange($('#threatTypesRange').val() || 'last24h');
    var types = {};
    filtered.forEach(function(t){ var tt=(t.threat_type||'unknown').toLowerCase(); types[tt]=(types[tt]||0)+1; });
    var topN  = parseInt($('#threatTypesTopN').val()) || 0;
    var pairs = Object.entries(types).sort(function(a,b){ return b[1]-a[1]; });
    if (topN > 0) pairs = pairs.slice(0, topN);
    window.dashThreatTypesChart.data.labels = pairs.map(function(p){ return p[0]; });
    window.dashThreatTypesChart.data.datasets[0].data = pairs.map(function(p){ return p[1]; });
    window.dashThreatTypesChart.update();
}

function updateThreatTimeline(threats) {
    if (!window.dashTimelineChart) return;
    var granularity = $('#timelineGranularity').val();
    var timeRange   = $('#timelineRange').val() || 'last24h';
    if (granularity === 'auto') {
        if (timeRange === 'last30s' || timeRange === 'last15m' || timeRange === 'last1h') granularity = 'minute';
        else if (timeRange === 'last24h' || timeRange === 'today') granularity = 'hour';
        else granularity = 'day';
    }
    var now      = Date.now();
    var rangeMs  = timeRangeToMs(timeRange);
    var startTs  = now - rangeMs;
    var buckets  = {};

    if (granularity === 'minute') {
        var mins = Math.min(60, Math.ceil(rangeMs / 60000));
        for (var i = mins-1; i >= 0; i--) {
            var dt = new Date(now - i*60000);
            buckets[dt.getHours().toString().padStart(2,'0')+':'+dt.getMinutes().toString().padStart(2,'0')] = 0;
        }
        threats.forEach(function(t){ var ts=new Date(t.timestamp).getTime(); if(ts>=startTs){ var d2=new Date(ts); var k=d2.getHours().toString().padStart(2,'0')+':'+d2.getMinutes().toString().padStart(2,'0'); if(k in buckets) buckets[k]++; } });
    } else if (granularity === 'day') {
        var days = Math.min(90, Math.ceil(rangeMs/86400000));
        for (var i = days-1; i >= 0; i--) {
            var dt = new Date(now - i*86400000);
            buckets[(dt.getMonth()+1).toString().padStart(2,'0')+'/'+dt.getDate().toString().padStart(2,'0')] = 0;
        }
        threats.forEach(function(t){ var ts=new Date(t.timestamp).getTime(); if(ts>=startTs){ var d2=new Date(ts); var k=(d2.getMonth()+1).toString().padStart(2,'0')+'/'+d2.getDate().toString().padStart(2,'0'); if(k in buckets) buckets[k]++; } });
    } else {
        var hrs = Math.min(24, Math.ceil(rangeMs/3600000));
        for (var i = hrs-1; i >= 0; i--) {
            var dt = new Date(now - i*3600000);
            buckets[dt.getHours().toString().padStart(2,'0')+':00'] = 0;
        }
        threats.forEach(function(t){ var ts=new Date(t.timestamp).getTime(); if(ts>=startTs){ var d2=new Date(ts); var k=d2.getHours().toString().padStart(2,'0')+':00'; if(k in buckets) buckets[k]++; } });
    }
    window.dashTimelineChart.data.labels = Object.keys(buckets);
    window.dashTimelineChart.data.datasets[0].data = Object.values(buckets);
    window.dashTimelineChart.update();
}

function timeRangeToMs(range) {
    var map = { last30s:30000, last15m:900000, last1h:3600000, last24h:86400000,
                today:(Date.now()-new Date().setHours(0,0,0,0)),
                thisweek:7*86400000, thismonth:30*86400000, last90d:90*86400000 };
    return map[range] || 86400000;
}

function filterThreatsByRange(range) {
    var cutoff = Date.now() - timeRangeToMs(range);
    return allThreats.filter(function(t) { return new Date(t.timestamp).getTime() >= cutoff; });
}

function renderSeverityChart() {
    if (!window.dashSeverityChart) return;
    var filtered = filterThreatsByRange($('#severityRange').val() || 'last24h');
    var sc = { critical:0, high:0, medium:0, low:0 };
    filtered.forEach(function(t) { var s=(t.severity||'').toLowerCase(); if(sc.hasOwnProperty(s)) sc[s]++; });
    var labels=[], data=[], colors=[];
    var aL=['Critical','High','Medium','Low'], aK=['critical','high','medium','low'], aC=['#dc3545','#fd7e14','#ffc107','#28a745'];
    $('.sev-toggle').each(function(i) { if($(this).is(':checked')){ labels.push(aL[i]); data.push(sc[aK[i]]||0); colors.push(aC[i]); } });
    window.dashSeverityChart.data.labels = labels;
    window.dashSeverityChart.data.datasets[0].data = data;
    window.dashSeverityChart.data.datasets[0].backgroundColor = colors;
    window.dashSeverityChart.update();
}

function renderIndustrialChart() {
    if (!window.dashIndustrialChart) return;
    var hideZero = $('#hideZeroIndustrial').is(':checked');
    var p = allProtocols, t = allThreatTypes;
    var raw = [
        { label:'Modbus', v: p['modbus']||p['Modbus']||0,                                color:'#6f42c1' },
        { label:'DNP3',   v: p['dnp3']||p['DNP3']||0,                                    color:'#17a2b8' },
        { label:'OPC-UA', v: p['opcua']||p['OPC-UA']||p['OPCUA']||0,                     color:'#fd7e14' },
        { label:'SCADA',  v: t['scada_attack']||t['industrial_threat']||0,               color:'#dc3545' }
    ];
    if (hideZero) raw = raw.filter(function(r){ return r.v>0; });
    window.dashIndustrialChart.data.labels = raw.map(function(r){ return r.label; });
    window.dashIndustrialChart.data.datasets[0].data = raw.map(function(r){ return r.v; });
    window.dashIndustrialChart.data.datasets[0].backgroundColor = raw.map(function(r){ return r.color; });
    window.dashIndustrialChart.update();
}

// ── Top Threat Sources ────────────────────────────────────────────────────────
function renderTopSources() {
    var topN     = parseInt($('#topSourcesN').val()) || 10;
    var filtered = filterThreatsByRange($('#sourcesRange').val() || 'last24h');
    var counts   = {};
    filtered.forEach(function(t){ if(t.source_ip) counts[t.source_ip]=(counts[t.source_ip]||0)+1; });
    var sorted = Object.entries(counts).sort(function(a,b){ return b[1]-a[1]; }).slice(0,topN);
    var $c = $('#topSources').empty();
    if (sorted.length === 0) { $c.html('<div class="text-muted text-center" style="font-size:.82em;padding:.5rem;">No data</div>'); return; }
    sorted.forEach(function(e) {
        $c.append(
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem;">' +
            '<code style="font-size:.82em;">' + esc(e[0]) + '</code>' +
            '<span class="label label-danger">' + e[1] + '</span>' +
            '</div>'
        );
    });
}

// ── Threats table with pagination ─────────────────────────────────────────────
function applyThreatFilters() {
    var sev    = $('#severityFilter').val();
    var type   = $('#threatTypeFilter').val();
    var search = threatsSearch.toLowerCase().trim();
    var cutoff = Date.now() - timeRangeToMs($('#threatsRange').val() || 'last24h');
    filteredThreats = allThreats.filter(function(t) {
        if (new Date(t.timestamp).getTime() < cutoff) return false;
        if (sev  !== 'all' && (t.severity   ||'').toLowerCase() !== sev)  return false;
        if (type !== 'all' && (t.threat_type||'').toLowerCase() !== type) return false;
        if (search) {
            var h = [t.source_ip, t.destination_ip, t.threat_type, t.severity, t.protocol].join(' ').toLowerCase();
            if (h.indexOf(search) < 0) return false;
        }
        return true;
    });
    if (threatsSortCol) {
        var col = threatsSortCol, dir = threatsSortDir;
        filteredThreats.sort(function(a, b) {
            var va = (a[col]||'').toLowerCase(), vb = (b[col]||'').toLowerCase();
            return dir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
        });
    }
    renderThreatsTable();
}

function renderThreatsTable() {
    updateThreatSortHeaders();
    var tbody = $('#threatTableBody').empty();
    if (filteredThreats.length === 0) {
        tbody.html('<tr><td colspan="7" class="text-center text-muted">{{ lang._("No threats match current filters") }}</td></tr>');
        $('#threatsPager').empty();
        return;
    }
    var start  = (threatsPage-1) * threatsPerPage;
    var page   = filteredThreats.slice(start, start + threatsPerPage);
    page.forEach(function(t) {
        var isBlocked = !!(t.source_ip && blockedIPs[t.source_ip]);
        var blockBtn = t.source_ip ? (
            isBlocked
            ? '<button class="btn btn-xs btn-default" title="{{ lang._("Unblock") }}" onclick="unblockSource(\'' + esc(t.source_ip) + '\')" style="margin-left:2px;"><i class="fa fa-unlock"></i></button>'
            : '<button class="btn btn-xs btn-danger" title="{{ lang._("Block") }}" onclick="blockSource(\'' + esc(t.source_ip) + '\')" style="margin-left:2px;"><i class="fa fa-ban"></i></button>'
        ) : '';
        tbody.append(
            '<tr>' +
            '<td style="font-size:.8em;font-family:monospace;white-space:nowrap;">' + fmtTime(t.timestamp) + '</td>' +
            '<td><code style="font-size:.85em;">' + esc(t.source_ip||'N/A') + '</code></td>' +
            '<td><code style="font-size:.85em;">' + esc(t.destination_ip||'N/A') + '</code></td>' +
            '<td style="font-size:.82em;">' + esc(t.threat_type||'N/A') + '</td>' +
            '<td><span class="label ' + sevClass(t.severity) + '">' + esc(t.severity||'N/A') + '</span></td>' +
            '<td style="font-size:.82em;">' + esc(t.protocol||'N/A') + '</td>' +
            '<td style="white-space:nowrap;">' +
            '<button class="btn btn-xs btn-primary" onclick="viewThreatDetails(\'' + esc(t.id||'') + '\')">' +
            '<i class="fa fa-eye"></i></button>' +
            blockBtn +
            '</td>' +
            '</tr>'
        );
    });
    renderPager('threatsPager', filteredThreats.length, threatsPage, threatsPerPage, function(p){
        threatsPage = p; renderThreatsTable();
    });
}

// ── System Info ───────────────────────────────────────────────────────────────
function updateSystemInfo(info) {
    $('#engineStatus').text(info.engine_status||'--');
    $('#enginePid').text(info.pid||'--');
    $('#engineUptime').text(info.uptime||'--');
    $('#cpuUsage').text(info.cpu_usage||'--');
    $('#memUsage').text(info.memory_usage||'--');
    $('#monitoredInterfaces').text(info.interfaces||'N/A');
    $('#signaturesVersion').text(info.signatures_version||'--');
    if (info.engine_status === 'Active') {
        $('#serviceStatus').removeClass('badge-secondary badge-danger').addClass('badge-success').text('{{ lang._("Running") }}');
    }
}

// ── Attack Map ────────────────────────────────────────────────────────────────
function updateMap(threats) {
    if (!leafletMap || !markersLayer) return;
    markersLayer.clearLayers();

    var ipCounts = {}, ipLast = {};
    threats.forEach(function(t){ if(!t.source_ip) return; ipCounts[t.source_ip]=(ipCounts[t.source_ip]||0)+1; ipLast[t.source_ip]=t; });

    var privateIPs=[], publicIPs=[];
    Object.keys(ipCounts).forEach(function(ip){ if(isPrivateIP(ip)) privateIPs.push(ip); else publicIPs.push(ip); });

    var privateCount = privateIPs.reduce(function(s,ip){ return s + ipCounts[ip]; }, 0);

    if (publicIPs.length === 0) {
        $('#mapRateLimitedBadge').hide();
        renderMapSidebar({}, privateCount);
        return;
    }

    // GeoIP lookup — pass IPs in URL query string so PHP reads via $_GET
    var ipsQS = encodeURIComponent(publicIPs.join(','));
    ajaxCall('/api/deepinspector/statistics/geoip?ips=' + ipsQS, {}, function(data) {
        if (data.rate_limited) { $('#mapRateLimitedBadge').show(); } else { $('#mapRateLimitedBadge').hide(); }
        if (data.status !== 'ok' || !data.data) { renderMapSidebar({}, privateCount); return; }

        var countryCounts = {};
        Object.keys(data.data).forEach(function(ip) {
            var geo = data.data[ip];
            if (!geo || !geo.lat || !geo.lon) return;
            var threat = ipLast[ip] || {};
            var sev    = (threat.severity||'low').toLowerCase();
            var count  = ipCounts[ip] || 1;
            var color  = ({critical:'#dc3545',high:'#fd7e14',medium:'#ffc107',low:'#28a745'})[sev] || '#6c757d';

            var marker = L.marker([geo.lat, geo.lon], { icon: makeMarkerIcon(count, color) });
            marker.bindPopup(
                '<strong>' + esc(ip) + '</strong><br>' +
                (geo.country ? esc(geo.country) + ' (' + esc(geo.countryCode) + ')' : '') + '<br>' +
                'Attacks: <strong>' + count + '</strong><br>' +
                'Last: ' + esc(threat.threat_type||'N/A') + '<br>' +
                '<span style="color:'+color+'">&#9632; ' + esc(sev) + '</span>'
            );
            markersLayer.addLayer(marker);

            var cname = geo.country || 'Unknown';
            countryCounts[cname] = (countryCounts[cname] || 0) + count;
        });

        renderMapSidebar(countryCounts, privateCount);
    });
}

function makeMarkerIcon(count, color) {
    var size = Math.round(Math.max(30, Math.min(54, 24 + Math.log(count + 1) * 7)));
    var fs   = Math.max(10, Math.round(size * 0.38));
    return L.divIcon({
        html: '<div style="width:'+size+'px;height:'+size+'px;border-radius:50%;background:'+color+
              ';border:2px solid rgba(0,0,0,.25);display:flex;align-items:center;justify-content:center;'+
              'color:#fff;font-weight:700;font-size:'+fs+'px;box-shadow:0 2px 6px rgba(0,0,0,.4);'+
              'cursor:pointer;">'+count+'</div>',
        className:   '',
        iconSize:    [size, size],
        iconAnchor:  [Math.round(size/2), Math.round(size/2)],
        popupAnchor: [0, -Math.round(size/2)]
    });
}

function renderMapSidebar(countryCounts, privateCount) {
    var $sb = $('#mapSidebar').empty();
    var entries = Object.entries(countryCounts).sort(function(a,b){ return b[1]-a[1]; });
    if (privateCount > 0) entries.push(['Private / LAN', privateCount]);
    entries.sort(function(a,b){ return b[1]-a[1]; });
    var grandTotal = entries.reduce(function(s,e){ return s+e[1]; }, 0);
    if (grandTotal === 0) { $sb.html('<div class="text-muted text-center" style="font-size:.82em;padding:.5rem;">No data</div>'); return; }
    entries.forEach(function(e) {
        var pct = Math.round(e[1] / grandTotal * 100);
        $sb.append(
            '<div style="margin-bottom:.5rem;">' +
            '<div style="display:flex;justify-content:space-between;font-size:.8em;margin-bottom:2px;">' +
            '<span>' + esc(e[0]) + '</span>' +
            '<span><strong>' + e[1] + '</strong> <span class="text-muted">(' + pct + '%)</span></span>' +
            '</div>' +
            '<div style="background:#e9ecef;border-radius:3px;height:6px;">' +
            '<div style="background:#2563eb;border-radius:3px;height:6px;width:' + pct + '%;"></div>' +
            '</div>' +
            '</div>'
        );
    });
}

function isPrivateIP(ip) {
    return [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./, /^169\.254\./, /^::1$/, /^fc00:/i, /^fe80:/i]
        .some(function(r){ return r.test(ip); });
}

// ── Threat Detail Modal ───────────────────────────────────────────────────────
function viewThreatDetails(threatId) {
    if (!threatId) return;
    _modalThreatId = null; _modalThreatIP = null;
    $('#threatModalBody').html('<div class="text-center"><i class="fa fa-spinner fa-spin fa-2x"></i></div>');
    $('#modalBlockBtn, #modalMarkFPBtn').hide();
    $('#fpReasonRow').hide(); $('#fpReasonInput').val('');
    $('#threatModal').modal('show');

    ajaxCall('/api/deepinspector/alerts/threatdetails/' + threatId, {}, function(data) {
        if (data.status === 'ok' && data.data) {
            var d = data.data;
            _modalThreatId = d.id || threatId;
            _modalThreatIP = d.source_ip || null;
            $('#threatModalBody').html(
                '<div class="row">' +
                '<div class="col-md-6">' +
                '<h6><strong>{{ lang._("Basic Information") }}</strong></h6>' +
                '<p><strong>ID:</strong> <code style="font-size:.8em;">' + esc(d.id||threatId) + '</code></p>' +
                '<p><strong>{{ lang._("Timestamp") }}:</strong> ' + fmtTime(d.timestamp) + '</p>' +
                '<p><strong>{{ lang._("Source IP") }}:</strong> <code>' + esc(d.source_ip||'N/A') + '</code></p>' +
                '<p><strong>{{ lang._("Destination IP") }}:</strong> <code>' + esc(d.destination_ip||'N/A') + '</code></p>' +
                '<p><strong>{{ lang._("Src Port") }}:</strong> ' + esc(d.source_port||'-') + '</p>' +
                '<p><strong>{{ lang._("Dst Port") }}:</strong> ' + esc(d.destination_port||'-') + '</p>' +
                '</div>' +
                '<div class="col-md-6">' +
                '<h6><strong>{{ lang._("Analysis") }}</strong></h6>' +
                '<p><strong>{{ lang._("Type") }}:</strong> ' + esc(d.threat_type||'N/A') + '</p>' +
                '<p><strong>{{ lang._("Severity") }}:</strong> <span class="label ' + sevClass(d.severity) + '">' + esc(d.severity||'N/A') + '</span></p>' +
                '<p><strong>{{ lang._("Protocol") }}:</strong> ' + esc(d.protocol||'N/A') + '</p>' +
                '<p><strong>{{ lang._("Detection Method") }}:</strong> ' + esc(d.detection_method||'N/A') + '</p>' +
                '<p><strong>{{ lang._("Industrial") }}:</strong> ' + (d.industrial_context ? 'Yes' : 'No') + '</p>' +
                '<hr><h6><strong>{{ lang._("Description") }}</strong></h6>' +
                '<p>' + esc(d.description||'N/A') + '</p>' +
                '</div>' +
                '</div>'
            );
            if (fpAlertIds[_modalThreatId]) {
                $('#modalMarkFPBtn').hide();
            } else {
                $('#modalMarkFPBtn').show();
            }
            if (_modalThreatIP) {
                if (blockedIPs[_modalThreatIP]) {
                    $('#modalBlockBtn').removeClass('btn-danger').addClass('btn-warning')
                        .html('<i class="fa fa-unlock"></i> {{ lang._("Unblock Source IP") }}').show();
                } else {
                    $('#modalBlockBtn').removeClass('btn-warning').addClass('btn-danger')
                        .html('<i class="fa fa-ban"></i> {{ lang._("Block Source IP") }}').show();
                }
            }
        } else {
            $('#threatModalBody').html('<div class="alert alert-warning">{{ lang._("Threat details not available") }}</div>');
        }
    });
}

// ── Actions ───────────────────────────────────────────────────────────────────
function blockSource(ip) {
    if (!ip) return;
    ajaxCall('/api/deepinspector/service/blockip', { ip: ip }, function(data) {
        if (data.status === 'ok') {
            blockedIPs[ip] = true;
            showNotification('{{ lang._("IP") }} ' + esc(ip) + ' {{ lang._("blocked successfully") }}', 'success');
            renderThreatsTable();
        } else {
            showNotification('{{ lang._("Failed to block IP") }}: ' + esc(data.message||''), 'error');
        }
    });
}

function unblockSource(ip) {
    if (!ip) return;
    ajaxCall('/api/deepinspector/service/unblockip', { ip: ip }, function(data) {
        if (data.status === 'ok') {
            delete blockedIPs[ip];
            showNotification('{{ lang._("IP") }} ' + esc(ip) + ' {{ lang._("unblocked") }}', 'success');
            renderThreatsTable();
        } else {
            showNotification('{{ lang._("Failed to unblock IP") }}: ' + esc(data.message||''), 'error');
        }
    });
}

function loadBlockedIPs() {
    ajaxCall('/api/deepinspector/service/listblocked', {}, function(data) {
        blockedIPs = {};
        if (data.status === 'ok' && Array.isArray(data.data)) {
            data.data.filter(Boolean).forEach(function(ip){ blockedIPs[ip] = true; });
        }
    });
}

function loadFPAlertIds() {
    ajaxCall('/api/deepinspector/alerts/listfalsepositives', {}, function(data) {
        fpAlertIds = {};
        if (data.status === 'ok' && Array.isArray(data.data)) {
            data.data.forEach(function(fp){ if (fp.alert_id) fpAlertIds[fp.alert_id] = true; });
        }
    });
}

function updateThreatSortHeaders() {
    $('.threats-table th.sortable').each(function() {
        var col = $(this).data('col');
        var $i  = $(this).find('i');
        $i.removeClass('fa-sort fa-sort-asc fa-sort-desc text-muted');
        if (col === threatsSortCol) { $i.addClass(threatsSortDir === 'asc' ? 'fa-sort-asc' : 'fa-sort-desc'); }
        else                       { $i.addClass('fa-sort text-muted'); }
    });
}

function markFalsePositive(alertId, reason) {
    if (!alertId) return;
    ajaxCall('/api/deepinspector/alerts/markfalsepositive', { alert_id: alertId, reason: reason||'' }, function(data) {
        if (data.status === 'ok') {
            fpAlertIds[alertId] = true;
            showNotification('{{ lang._("Alert marked as false positive") }}', 'success');
            renderThreatsTable();
        } else {
            showNotification('{{ lang._("Failed") }}: ' + esc(data.message||''), 'error');
        }
    });
}

function controlService(action) {
    var labels = { start:'{{ lang._("Start") }}', restart:'{{ lang._("Restart") }}', stop:'{{ lang._("Stop") }}' };
    var icons  = { start:'fa-play', restart:'fa-refresh', stop:'fa-stop' };
    var btn = $('#' + action + 'Service');
    btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i>');
    ajaxCall('/api/deepinspector/service/' + action, {}, function(data) {
        btn.prop('disabled', false).html('<i class="fa ' + icons[action] + '"></i> ' + labels[action]);
        if (data.status === 'ok') {
            showNotification('{{ lang._("Service") }} ' + action + ' {{ lang._("completed") }}', 'success');
            setTimeout(loadDashboardData, 2000);
        } else {
            showNotification('{{ lang._("Service") }} ' + action + ' {{ lang._("failed") }}', 'error');
        }
    });
}

function exportStats() {
    ajaxCall('/api/deepinspector/settings/stats', {}, function(data) {
        if (data.status !== 'ok') return;
        var content = JSON.stringify(data.data, null, 2);
        var blob = new Blob([content], { type:'application/json' });
        var link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'deepinspector_stats_' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.json';
        link.click();
    });
}

// ── Pagination helper ─────────────────────────────────────────────────────────
function renderPager(containerId, total, page, perPage, onPage) {
    var totalPages = Math.ceil(total / perPage);
    var $c = $('#' + containerId).empty();
    if (totalPages <= 1) return;
    var from = (page-1)*perPage+1, to = Math.min(page*perPage, total);
    var html = '<div style="margin-top:.5rem;overflow:hidden;">' +
               '<small class="text-muted" style="float:left;line-height:28px;">Showing ' + from + '–' + to + ' of ' + total + '</small>' +
               '<ul class="pagination pagination-sm" style="float:right;margin:0;">';
    html += '<li class="' + (page===1?'disabled':'') + '"><a href="#" data-p="'+(page-1)+'">&laquo;</a></li>';
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
function sevClass(s) {
    var m = { critical:'label-danger', high:'label-warning', medium:'label-info', low:'label-success' };
    return m[(s||'').toLowerCase()] || 'label-default';
}
function fmtNum(n)  { return new Intl.NumberFormat().format(n||0); }
function fmtTime(t) { return t ? new Date(t).toLocaleString() : '--'; }
function esc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function showNotification(message, type) {
    var isSuccess = (type === 'success');
    var icon = isSuccess ? 'fa-check' : 'fa-exclamation-circle';
    var cls  = isSuccess ? 'alert-success' : 'alert-danger';
    var $n = $('<div style="pointer-events:all;margin-top:.4rem;border-radius:3px;box-shadow:0 2px 10px rgba(0,0,0,.28);">' +
               '<div class="alert ' + cls + ' alert-dismissible" style="margin:0;padding:.6rem .9rem;">' +
               '<button type="button" class="close" data-dismiss="alert" style="top:0;right:4px;">' +
               '<span>&times;</span></button>' +
               '<i class="fa ' + icon + '" style="margin-right:.45rem;"></i>' +
               message + '</div></div>');
    $('#notifications').append($n);
    setTimeout(function () { $n.find('.alert').alert('close'); $n.remove(); }, 4000);
}
</script>

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
    display:inline-block; height:24px; padding:1px 4px;
    font-size:.76em; width:auto !important;
}

/* Dark fallback shown until tiles load */
#attackMap { background:#1a1a2e; }
</style>
