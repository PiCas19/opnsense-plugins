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
                    <button id="refreshBtn" class="btn btn-primary" style="margin-left: 10px;">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
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
                <div id="threatTypeNoData" class="no-data-message" style="display: none;">
                    <p class="text-muted">{{ lang._('No threat data available') }}</p>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="chart-card">
                <h3>{{ lang._('Severity Distribution') }}</h3>
                <canvas id="severityChart"></canvas>
                <div id="severityNoData" class="no-data-message" style="display: none;">
                    <p class="text-muted">{{ lang._('No severity data available') }}</p>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-12">
            <div class="chart-card">
                <h3>{{ lang._('Threat Timeline') }}</h3>
                <canvas id="timelineChart"></canvas>
                <div id="timelineNoData" class="no-data-message" style="display: none;">
                    <p class="text-muted">{{ lang._('No timeline data available') }}</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Top IPs and Patterns -->
    <div class="row">
        <div class="col-md-6">
            <div class="table-card">
                <h3>{{ lang._('Top Source IPs') }}</h3>
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>{{ lang._('IP Address') }}</th>
                                <th>{{ lang._('Threats') }}</th>
                                <th>{{ lang._('Country') }}</th>
                                <th>{{ lang._('Last Seen') }}</th>
                            </tr>
                        </thead>
                        <tbody id="topIPsTable">
                            <!-- Dynamic content -->
                        </tbody>
                    </table>
                </div>
                <div id="topIPsNoData" class="no-data-message" style="display: none;">
                    <p class="text-muted">{{ lang._('No IP data available') }}</p>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="table-card">
                <h3>{{ lang._('Attack Patterns') }}</h3>
                <div id="attackPatterns">
                    <!-- Dynamic content -->
                </div>
                <div id="patternsNoData" class="no-data-message" style="display: none;">
                    <p class="text-muted">{{ lang._('No attack patterns detected') }}</p>
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
    let refreshInterval = null;
    
    // Initialize
    loadStatsData();
    initCharts();
    
    // Auto refresh every 30 seconds
    refreshInterval = setInterval(function() {
        loadStatsData();
        updateCharts();
    }, 30000);
    
    // Period selector
    $('#periodSelect').change(function() {
        currentPeriod = $(this).val();
        loadStatsData();
        updateCharts();
    });
    
    // Manual refresh button
    $('#refreshBtn').click(function() {
        $(this).find('i').addClass('fa-spin');
        loadStatsData();
        updateCharts();
        setTimeout(() => {
            $(this).find('i').removeClass('fa-spin');
        }, 1000);
    });
    
    function loadStatsData() {
        console.log('Loading stats data for period:', currentPeriod);
        
        ajaxCall('/api/webguard/threats/getStats', {period: currentPeriod}, function(data, status) {
            console.log('Stats API response:', data, 'Status:', status);
            
            if (data && status === 'success') {
                updateSummaryCards(data);
                updateTopIPs(data.top_source_ips || {});
                updateAttackPatterns(data);
            } else {
                console.error('Failed to load stats data:', status);
                // Show error state or fallback data
                showErrorState();
            }
        });
    }
    
    function updateSummaryCards(data) {
        $('#totalThreats').text(formatNumber(data.total_threats || 0));
        $('#blockedThreats').text(formatNumber(data.blocked_threats || data.blocked_today || 0));
        
        const detected = (data.total_threats || 0) - (data.blocked_threats || data.blocked_today || 0);
        $('#detectedThreats').text(formatNumber(Math.max(0, detected)));
        
        const uniqueIPs = Object.keys(data.top_source_ips || {}).length;
        $('#uniqueIPs').text(formatNumber(uniqueIPs));
    }
    
    function updateTopIPs(topIPs) {
        const tbody = $('#topIPsTable');
        tbody.empty();
        
        if (!topIPs || Object.keys(topIPs).length === 0) {
            $('#topIPsNoData').show();
            return;
        }
        
        $('#topIPsNoData').hide();
        
        // Sort IPs by threat count and take top 10
        const sortedIPs = Object.entries(topIPs)
            .sort(([,a], [,b]) => (b.count || b) - (a.count || a))
            .slice(0, 10);
        
        sortedIPs.forEach(([ip, data]) => {
            const count = typeof data === 'object' ? data.count : data;
            const country = typeof data === 'object' ? data.country : 'Unknown';
            const lastSeen = typeof data === 'object' ? formatTimestamp(data.last_seen) : '{{ lang._("Recently") }}';
            
            // Validate IP format
            if (isValidIP(ip)) {
                tbody.append(`
                    <tr>
                        <td><code>${escapeHtml(ip)}</code></td>
                        <td><span class="badge badge-danger">${formatNumber(count)}</span></td>
                        <td>${escapeHtml(country)}</td>
                        <td>${lastSeen}</td>
                    </tr>
                `);
            }
        });
        
        if (tbody.children().length === 0) {
            $('#topIPsNoData').show();
        }
    }
    
    function updateAttackPatterns(data) {
        const patterns = data.patterns || {};
        let html = '';
        let hasPatterns = false;
        
        // SQL Injection patterns
        if (patterns.sql_injection_patterns && Object.keys(patterns.sql_injection_patterns).length > 0) {
            html += '<div class="pattern-section">';
            html += '<h5><i class="fa fa-database text-danger"></i> {{ lang._("SQL Injection Patterns") }}</h5>';
            html += '<ul class="pattern-list">';
            Object.entries(patterns.sql_injection_patterns).forEach(([pattern, count]) => {
                html += `<li>${escapeHtml(pattern.replace(/_/g, ' '))}: <strong>${formatNumber(count)}</strong></li>`;
            });
            html += '</ul></div>';
            hasPatterns = true;
        }
        
        // XSS patterns
        if (patterns.xss_patterns && Object.keys(patterns.xss_patterns).length > 0) {
            html += '<div class="pattern-section">';
            html += '<h5><i class="fa fa-code text-warning"></i> {{ lang._("XSS Patterns") }}</h5>';
            html += '<ul class="pattern-list">';
            Object.entries(patterns.xss_patterns).forEach(([pattern, count]) => {
                html += `<li>${escapeHtml(pattern.replace(/_/g, ' '))}: <strong>${formatNumber(count)}</strong></li>`;
            });
            html += '</ul></div>';
            hasPatterns = true;
        }
        
        // Directory traversal patterns
        if (patterns.directory_traversal_patterns && Object.keys(patterns.directory_traversal_patterns).length > 0) {
            html += '<div class="pattern-section">';
            html += '<h5><i class="fa fa-folder-open text-info"></i> {{ lang._("Directory Traversal") }}</h5>';
            html += '<ul class="pattern-list">';
            Object.entries(patterns.directory_traversal_patterns).forEach(([pattern, count]) => {
                html += `<li>${escapeHtml(pattern.replace(/_/g, ' '))}: <strong>${formatNumber(count)}</strong></li>`;
            });
            html += '</ul></div>';
            hasPatterns = true;
        }
        
        if (hasPatterns) {
            $('#attackPatterns').html(html);
            $('#patternsNoData').hide();
        } else {
            $('#attackPatterns').empty();
            $('#patternsNoData').show();
        }
    }
    
    function initCharts() {
        // Threat Type Chart
        const ctx1 = document.getElementById('threatTypeChart').getContext('2d');
        threatTypeChart = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40', '#FF6384', '#36A2EB']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
        
        // Severity Chart
        const ctx2 = document.getElementById('severityChart').getContext('2d');
        severityChart = new Chart(ctx2, {
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
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { 
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
        
        // Timeline Chart
        const ctx3 = document.getElementById('timelineChart').getContext('2d');
        timelineChart = new Chart(ctx3, {
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
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    y: { 
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    },
                    x: {
                        ticks: {
                            maxTicksLimit: 10
                        }
                    }
                }
            }
        });
        
        updateCharts();
    }
    
    function updateCharts() {
        console.log('Updating charts for period:', currentPeriod);
        
        // Update threat type and severity charts
        ajaxCall('/api/webguard/threats/getStats', {period: currentPeriod}, function(data, status) {
            if (data && status === 'success') {
                // Threat type chart
                if (data.threats_by_type && Object.keys(data.threats_by_type).length > 0) {
                    threatTypeChart.data.labels = Object.keys(data.threats_by_type);
                    threatTypeChart.data.datasets[0].data = Object.values(data.threats_by_type);
                    threatTypeChart.update();
                    $('#threatTypeChart').show();
                    $('#threatTypeNoData').hide();
                } else {
                    $('#threatTypeChart').hide();
                    $('#threatTypeNoData').show();
                }
                
                // Severity chart
                if (data.threats_by_severity) {
                    const severityData = data.threats_by_severity;
                    const hasData = Object.values(severityData).some(val => val > 0);
                    
                    if (hasData) {
                        severityChart.data.datasets[0].data = [
                            severityData.critical || 0,
                            severityData.high || 0,
                            severityData.medium || 0,
                            severityData.low || 0
                        ];
                        severityChart.update();
                        $('#severityChart').show();
                        $('#severityNoData').hide();
                    } else {
                        $('#severityChart').hide();
                        $('#severityNoData').show();
                    }
                }
            }
        });
        
        // Update timeline chart
        ajaxCall('/api/webguard/threats/getTimeline', {period: currentPeriod}, function(data, status) {
            console.log('Timeline API response:', data, 'Status:', status);
            
            if (data && status === 'success' && data.status === 'ok' && data.timeline) {
                const timeline = data.timeline;
                if (timeline.labels && timeline.threats && timeline.labels.length > 0) {
                    timelineChart.data.labels = timeline.labels;
                    timelineChart.data.datasets[0].data = timeline.threats;
                    timelineChart.update();
                    $('#timelineChart').show();
                    $('#timelineNoData').hide();
                } else {
                    $('#timelineChart').hide();
                    $('#timelineNoData').show();
                }
            } else {
                console.warn('Timeline data not available or malformed');
                $('#timelineChart').hide();
                $('#timelineNoData').show();
            }
        });
    }
    
    function showErrorState() {
        // Show error messages or fallback data
        $('#totalThreats, #blockedThreats, #detectedThreats, #uniqueIPs').text('N/A');
        $('#topIPsNoData, #patternsNoData, #threatTypeNoData, #severityNoData, #timelineNoData').show();
    }
    
    function formatNumber(num) {
        if (typeof num !== 'number' || isNaN(num)) return '0';
        return new Intl.NumberFormat().format(num);
    }
    
    function formatTimestamp(timestamp) {
        if (!timestamp) return '{{ lang._("Recently") }}';
        try {
            const date = new Date(timestamp * 1000); // Assuming Unix timestamp
            return date.toLocaleString();
        } catch (e) {
            return '{{ lang._("Recently") }}';
        }
    }
    
    function isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Cleanup on page unload
    $(window).on('beforeunload', function() {
        if (refreshInterval) {
            clearInterval(refreshInterval);
        }
    });
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

.pattern-section {
    margin-bottom: 1.5rem;
}

.pattern-section:last-child {
    margin-bottom: 0;
}

.pattern-section h5 {
    margin-bottom: 0.5rem;
    color: #374151;
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

.no-data-message {
    text-align: center;
    padding: 2rem;
}

.no-data-message p {
    margin: 0;
    font-style: italic;
}

.period-selector {
    display: inline-block;
}

.table-responsive {
    overflow-x: auto;
}

.table th {
    border-top: none;
    font-weight: 600;
    color: #374151;
}

.badge-danger {
    background-color: #dc3545;
}

.fa-spin {
    animation: fa-spin 1s infinite linear;
}

@keyframes fa-spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(359deg); }
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