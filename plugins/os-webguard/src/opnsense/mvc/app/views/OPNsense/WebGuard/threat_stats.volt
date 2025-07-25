{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <div class="period-selector">
                    <select id="periodSelect" class="form-control" style="width: auto; display: inline-block;">
                        <option value="1h">{{ lang._('Last Hour') }}</option>
                        <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                        <option value="7d">{{ lang._('Last 7 Days') }}</option>
                        <option value="30d">{{ lang._('Last 30 Days') }}</option>
                    </select>
                </div>
            </div>
        </div>
    </div>

    <!-- Summary Cards -->
    <div class="row">
        <div class="col-md-3">
            <div class="stats-card">
                <div class="stats-icon bg-danger">
                    <i class="fa fa-exclamation-triangle"></i>
                </div>
                <div class="stats-content">
                    <div class="stats-value" id="totalThreats">0</div>
                    <div class="stats-label">{{ lang._('Total Threats') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stats-card">
                <div class="stats-icon bg-warning">
                    <i class="fa fa-shield"></i>
                </div>
                <div class="stats-content">
                    <div class="stats-value" id="blockedThreats">0</div>
                    <div class="stats-label">{{ lang._('Blocked') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stats-card">
                <div class="stats-icon bg-info">
                    <i class="fa fa-eye"></i>
                </div>
                <div class="stats-content">
                    <div class="stats-value" id="detectedThreats">0</div>
                    <div class="stats-label">{{ lang._('Detected') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stats-card">
                <div class="stats-icon bg-success">
                    <i class="fa fa-globe"></i>
                </div>
                <div class="stats-content">
                    <div class="stats-value" id="uniqueIPs">0</div>
                    <div class="stats-label">{{ lang._('Unique IPs') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts Row -->
    <div class="row">
        <div class="col-md-6">
            <div class="chart-card">
                <h3>{{ lang._('Threats by Type') }}</h3>
                <canvas id="threatTypeChart"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="chart-card">
                <h3>{{ lang._('Severity Distribution') }}</h3>
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-12">
            <div class="chart-card">
                <h3>{{ lang._('Threat Timeline') }}</h3>
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Top IPs and Patterns -->
    <div class="row">
        <div class="col-md-6">
            <div class="table-card">
                <h3>{{ lang._('Top Source IPs') }}</h3>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>{{ lang._('IP Address') }}</th>
                            <th>{{ lang._('Threats') }}</th>
                            <th>{{ lang._('Last Seen') }}</th>
                        </tr>
                    </thead>
                    <tbody id="topIPsTable">
                        <!-- Dynamic content -->
                    </tbody>
                </table>
            </div>
        </div>
        <div class="col-md-6">
            <div class="table-card">
                <h3>{{ lang._('Attack Patterns') }}</h3>
                <div id="attackPatterns">
                    <!-- Dynamic content -->
                </div>
            </div>
        </div>
    </div>
</div>

<script src="/ui/js/chart.min.js"></script>
<script>
$(document).ready(function() {
    let threatTypeChart = null;
    let severityChart = null;
    let timelineChart = null;
    let currentPeriod = '24h';

    // Initialize
    console.log('Initializing stats page at', new Date().toISOString());
    loadStatsData();
    initCharts();

    // Period selector
    $('#periodSelect').change(function() {
        currentPeriod = $(this).val();
        console.log('Period changed to:', currentPeriod);
        loadStatsData();
        updateCharts();
    });

    function loadStatsData() {
        console.log('Loading stats data for period:', currentPeriod);
        ajaxCall('/api/webguard/threats/getStats', { period: currentPeriod }, function(data) {
            console.log('API response for getStats:', data);
            if (data && data.status === 'ok') {
                updateSummaryCards(data);
                updateTopIPs(data.top_source_ips || {});
                updateAttackPatterns(data.patterns || {});
            } else {
                console.log('No valid data from API, showing empty state');
                updateSummaryCards({});
                updateTopIPs({});
                updateAttackPatterns({});
            }
        }).fail(function(xhr, status, error) {
            console.error('Failed to load stats:', error, 'Status:', status, 'Response:', xhr.responseText);
            updateSummaryCards({});
            updateTopIPs({});
            updateAttackPatterns({});
        });
    }

    function updateSummaryCards(data) {
        console.log('Updating summary cards with data:', data);
        $('#totalThreats').text(formatNumber(data.total_threats || 0));
        $('#blockedThreats').text(formatNumber(data.blocked_today || 0));
        $('#detectedThreats').text(formatNumber((data.total_threats || 0) - (data.blocked_today || 0)));
        $('#uniqueIPs').text(formatNumber(Object.keys(data.top_source_ips || {}).length));
    }

    function updateTopIPs(topIPs) {
        console.log('Updating top IPs with data:', topIPs);
        const tbody = $('#topIPsTable');
        tbody.empty();
        if (Object.keys(topIPs).length === 0) {
            tbody.append('<tr><td colspan="3" class="text-center text-muted">{{ lang._("No data available") }}</td></tr>');
            return;
        }
        Object.entries(topIPs).slice(0, 10).forEach(([ip, value]) => {
            const count = typeof value === 'object' ? (value.count || 1) : value;
            const lastSeen = typeof value === 'object' && value.last_seen ? formatTime(value.last_seen) : '{{ lang._("Recently") }}';
            tbody.append(`
                <tr>
                    <td><code>${ip}</code></td>
                    <td><span class="badge badge-danger">${count}</span></td>
                    <td>${lastSeen}</td>
                </tr>
            `);
        });
    }

    function updateAttackPatterns(patterns) {
        console.log('Updating attack patterns with data:', patterns);
        let html = '';
        if (patterns.sql_injection_patterns && Object.keys(patterns.sql_injection_patterns).length) {
            html += '<h5><i class="fa fa-database text-danger"></i> {{ lang._("SQL Injection Patterns") }}</h5>';
            html += '<ul class="pattern-list">';
            Object.entries(patterns.sql_injection_patterns).forEach(([pattern, count]) => {
                html += `<li>${pattern.replace(/_/g, ' ')}: <strong>${count}</strong></li>`;
            });
            html += '</ul>';
        }
        if (patterns.xss_patterns && Object.keys(patterns.xss_patterns).length) {
            html += '<h5><i class="fa fa-code text-warning"></i> {{ lang._("XSS Patterns") }}</h5>';
            html += '<ul class="pattern-list">';
            Object.entries(patterns.xss_patterns).forEach(([pattern, count]) => {
                html += `<li>${pattern.replace(/_/g, ' ')}: <strong>${count}</strong></li>`;
            });
            html += '</ul>';
        }
        $('#attackPatterns').html(html || '<p class="text-center text-muted">{{ lang._("No patterns detected") }}</p>');
    }

    function initCharts() {
        console.log('Initializing charts');
        // Threat Type Chart
        const ctx1 = document.getElementById('threatTypeChart');
        if (ctx1) {
            threatTypeChart = new Chart(ctx1.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { padding: 15, usePointStyle: true }
                        }
                    }
                }
            });
        } else {
            console.error('Canvas element #threatTypeChart not found');
        }

        // Severity Chart
        const ctx2 = document.getElementById('severityChart');
        if (ctx2) {
            severityChart = new Chart(ctx2.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        label: 'Threats',
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#dc3545', '#ffc107', '#17a2b8', '#28a745']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { stepSize: 5 }
                        }
                    }
                }
            });
        } else {
            console.error('Canvas element #severityChart not found');
        }

        // Timeline Chart
        const ctx3 = document.getElementById('timelineChart');
        if (ctx3) {
            timelineChart = new Chart(ctx3.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Threats',
                        data: [],
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: true, position: 'top' }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { stepSize: 2 }
                        },
                        x: { ticks: { maxTicksLimit: 12 } }
                    }
                }
            });
        } else {
            console.error('Canvas element #timelineChart not found');
        }

        updateCharts();
    }

    function updateCharts() {
        console.log('Updating charts for period:', currentPeriod);
        ajaxCall('/api/webguard/threats/getStats', { period: currentPeriod }, function(data) {
            console.log('getStats response for charts:', data);
            if (data && data.status === 'ok' && threatTypeChart) {
                const threatsByType = data.threats_by_type || {};
                threatTypeChart.data.labels = Object.keys(threatsByType);
                threatTypeChart.data.datasets[0].data = Object.values(threatsByType);
                threatTypeChart.update();
            }
            if (data && data.status === 'ok' && severityChart) {
                const severityData = data.threats_by_severity || {};
                severityChart.data.datasets[0].data = [
                    severityData.critical || 0,
                    severityData.high || 0,
                    severityData.medium || 0,
                    severityData.low || 0
                ];
                severityChart.update();
            }
        }).fail(function(xhr, status, error) {
            console.error('Failed to update stats charts:', error, 'Status:', status, 'Response:', xhr.responseText);
            if (threatTypeChart) {
                threatTypeChart.data.labels = [];
                threatTypeChart.data.datasets[0].data = [];
                threatTypeChart.update();
            }
            if (severityChart) {
                severityChart.data.datasets[0].data = [0, 0, 0, 0];
                severityChart.update();
            }
        });

        ajaxCall('/api/webguard/threats/getTimeline', { period: currentPeriod }, function(data) {
            console.log('getTimeline response:', data);
            if (data && data.status === 'ok' && data.timeline && timelineChart) {
                timelineChart.data.labels = data.timeline.labels || [];
                timelineChart.data.datasets[0].data = data.timeline.threats || [];
                timelineChart.update();
            }
        }).fail(function(xhr, status, error) {
            console.error('Failed to update timeline chart:', error, 'Status:', status, 'Response:', xhr.responseText);
            if (timelineChart) {
                timelineChart.data.labels = [];
                timelineChart.data.datasets[0].data = [];
                timelineChart.update();
            }
        });
    }

    function formatNumber(num) {
        return new Intl.NumberFormat().format(num);
    }

    function formatTime(timestamp) {
        if (!timestamp) return '--';
        try {
            const date = typeof timestamp === 'string' ? new Date(timestamp) : new Date(timestamp * 1000);
            return date.toLocaleTimeString();
        } catch (e) {
            return '--';
        }
    }
});
</script>

<style>
.stats-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
    transition: transform 0.2s ease;
}

.stats-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
}

.stats-icon {
    width: 60px;
    height: 60px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 1rem;
    color: white;
    font-size: 1.5rem;
}

.stats-content {
    flex: 1;
}

.stats-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
    line-height: 1;
}

.stats-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.25rem;
}

.chart-card, .table-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.chart-card h3, .table-card h3 {
    margin-top: 0;
    margin-bottom: 1rem;
    color: #1f2937;
    font-size: 1.2rem;
}

.chart-card canvas {
    max-height: 300px;
}

.pattern-list {
    list-style: none;
    padding: 0;
    margin: 0;
}

.pattern-list li {
    padding: 0.5rem 0;
    border-bottom: 1px solid #f3f4f6;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.pattern-list li:last-child {
    border-bottom: none;
}

.period-selector {
    display: inline-block;
}

.table th {
    border-top: none;
    font-weight: 600;
    color: #374151;
}

.badge-danger {
    background-color: #dc3545;
}

/* Responsive adjustments */
@media (max-width: 768px) {
    .stats-card {
        flex-direction: column;
        text-align: center;
    }
    
    .stats-icon {
        margin-right: 0;
        margin-bottom: 1rem;
    }
    
    .chart-card canvas {
        max-height: 250px;
    }
}
</style>