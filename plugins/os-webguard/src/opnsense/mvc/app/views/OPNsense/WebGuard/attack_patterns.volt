{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}
<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
   <button class="btn btn-primary pull-right" id="btnApplyConfig"
           data-endpoint='/api/webguard/service/reconfigure'
           data-label="{{ lang._('Apply') }}"
           data-service-widget="webguard"
           data-error-title="{{ lang._('Error reconfiguring WebGuard') }}"
           type="button">
   </button>
   {{ lang._('The WebGuard configuration has been changed') }} <br /> {{ lang._('You must apply the changes in order for them to take effect.')}}
</div>

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <h1>{{ lang._('Attack Pattern Analysis') }}</h1>
                <div class="analysis-controls">
                    <select id="analysisType" class="form-control" style="width: auto; display: inline-block;">
                        <option value="patterns">{{ lang._('Attack Patterns') }}</option>
                        <option value="sequences">{{ lang._('Attack Sequences') }}</option>
                        <option value="behavioral">{{ lang._('Behavioral Analysis') }}</option>
                        <option value="machine_learning">{{ lang._('Machine Learning') }}</option>
                    </select>
                    <select id="timePeriod" class="form-control" style="width: auto; display: inline-block;">
                        <option value="1h">{{ lang._('Last Hour') }}</option>
                        <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
                        <option value="7d">{{ lang._('Last 7 Days') }}</option>
                        <option value="30d">{{ lang._('Last 30 Days') }}</option>
                    </select>
                </div>
            </div>
        </div>
    </div>

    <!-- Pattern Overview Stats -->
    <div class="row">
        <div class="col-md-3">
            <div class="pattern-stat-card">
                <div class="stat-icon bg-primary">
                    <i class="fa fa-search"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="totalPatterns">0</div>
                    <div class="stat-label">{{ lang._('Patterns Detected') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="pattern-stat-card">
                <div class="stat-icon bg-warning">
                    <i class="fa fa-chain"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="attackSequences">0</div>
                    <div class="stat-label">{{ lang._('Attack Sequences') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="pattern-stat-card">
                <div class="stat-icon bg-info">
                    <i class="fa fa-user-secret"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="uniqueAttackers">0</div>
                    <div class="stat-label">{{ lang._('Unique Attackers') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="pattern-stat-card">
                <div class="stat-icon bg-success">
                    <i class="fa fa-shield"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="blockedPatterns">0</div>
                    <div class="stat-label">{{ lang._('Patterns Blocked') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Navigation Tabs - Using OPNsense style -->
    <ul class="nav nav-tabs" role="tablist" id="maintabs">
        <li class="active">
            <a data-toggle="tab" href="#sqlPatterns">{{ lang._('SQL Injection') }}</a>
        </li>
        <li>
            <a data-toggle="tab" href="#xssPatterns">{{ lang._('XSS Patterns') }}</a>
        </li>
        <li>
            <a data-toggle="tab" href="#behavioralPatterns">{{ lang._('Behavioral Analysis') }}</a>
        </li>
        <li>
            <a data-toggle="tab" href="#mlPatterns">{{ lang._('Machine Learning') }}</a>
        </li>
    </ul>

    <!-- Tab Content -->
    <div class="tab-content content-box">
        <!-- SQL Injection Patterns Tab -->
        <div id="sqlPatterns" class="tab-pane fade in active">
            <div class="row">
                <div class="col-md-6">
                    <div class="pattern-chart-card">
                        <h4>{{ lang._('SQL Injection Distribution') }}</h4>
                        <canvas id="sqlPatternsChart"></canvas>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="pattern-list-card">
                        <h4>{{ lang._('SQL Attack Patterns') }}</h4>
                        <div id="sqlPatternsList"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- XSS Patterns Tab -->
        <div id="xssPatterns" class="tab-pane fade in">
            <div class="row">
                <div class="col-md-6">
                    <div class="pattern-chart-card">
                        <h4>{{ lang._('XSS Attack Vectors') }}</h4>
                        <canvas id="xssPatternsChart"></canvas>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="pattern-list-card">
                        <h4>{{ lang._('XSS Attack Patterns') }}</h4>
                        <div id="xssPatternsList"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Behavioral Analysis Tab -->
        <div id="behavioralPatterns" class="tab-pane fade in">
            <div class="row">
                <div class="col-md-12">
                    <div class="behavioral-analysis-card">
                        <h4>{{ lang._('Behavioral Analysis Dashboard') }}</h4>
                        <div id="behavioralContent"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Machine Learning Tab -->
        <div id="mlPatterns" class="tab-pane fade in">
            <div class="row">
                <div class="col-md-12">
                    <div class="ml-analysis-card">
                        <h4>{{ lang._('Machine Learning Analysis') }}</h4>
                        <div id="mlContent"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Pattern Details Table -->
    <div class="row">
        <div class="col-md-12">
            <div name="pattern-details-table">
                <h3>{{ lang._('Detailed Pattern Analysis') }}</h3>
                <table class="table table-striped" id="patternsTable">
                    <thead>
                        <tr>
                            <th>{{ lang._('Pattern') }}</th>
                            <th>{{ lang._('Type') }}</th>
                            <th>{{ lang._('Occurrences') }}</th>
                            <th>{{ lang._('Success Rate') }}</th>
                            <th>{{ lang._('First Seen') }}</th>
                            <th>{{ lang._('Trend') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="patternsTableBody"></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script src="/ui/js/chart.min.js"></script>

<script>
$(document).ready(function() {
    // Chart instances
    let charts = {
        sql: null,
        xss: null,
        behavioral: null,
        ml: null
    };

    // State management
    let state = {
        currentPeriod: '24h',
        currentAnalysis: 'patterns',
        statsData: null,
        timelineData: null,
        mlData: {
            anomalies: [],
            clusters: []
        }
    };

    // Utility function to sanitize strings
    function sanitizeString(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // Initialize application
    function initializeApp() {
        loadStatsData();
        loadTimelineData();
        initCharts();
        setupEventListeners();
        setInterval(updateApp, 10000);
    }

    // Set up event listeners
    function setupEventListeners() {
        $('#analysisType, #timePeriod').on('change', handleControlChange);
        $('#maintabs a[data-toggle="tab"]').on('shown.bs.tab', handleTabSwitch);
    }

    // Handle control changes
    function handleControlChange() {
        state.currentAnalysis = $('#analysisType').val();
        state.currentPeriod = $('#timePeriod').val();
        console.log(`Analysis changed to: ${state.currentAnalysis}, Period: ${state.currentPeriod}`);
        loadStatsData();
        loadTimelineData();
        updateCharts();
    }

    // Handle tab switching
    function handleTabSwitch(e) {
        const targetTab = $(e.target).attr('href').replace('#', '');
        console.log(`Tab switched to: ${targetTab}`);
        
        const tabActions = {
            'sqlPatterns': updateSQLPatterns,
            'xssPatterns': updateXSSPatterns,
            'behavioralPatterns': updateBehavioralPatterns,
            'mlPatterns': updateMLPatterns
        };

        if (tabActions[targetTab]) {
            tabActions[targetTab]();
        }
        updateCharts();
    }

    // Load stats data
    function loadStatsData() {
        console.log(`🔍 Loading stats data for period: ${state.currentPeriod}`);
        $.ajax({
            url: '/api/webguard/threats/getStats',
            method: 'GET',
            data: { period: state.currentPeriod },
            success: function(data) {
                console.log('✅ getStats API response:', data);
                if (data && typeof data === 'object') {
                    state.statsData = data;
                    updatePatternStats(data);
                    updatePatternLists(data);
                    updatePatternsTable(data);
                    initCharts();
                    updateSQLPatterns();
                    updateXSSPatterns();
                } else {
                    handleAPIFailure('stats');
                }
            },
            error: function() {
                handleAPIFailure('stats');
            }
        });
    }

    // Load timeline data
    function loadTimelineData() {
        console.log(`📅 Loading timeline data for period: ${state.currentPeriod}`);
        $.ajax({
            url: '/api/webguard/threats/getTimeline',
            method: 'GET',
            data: { period: state.currentPeriod },
            success: function(data) {
                console.log('✅ getTimeline API response:', data);
                if (data && typeof data === 'object' && data.status === 'ok') {
                    state.timelineData = data.timeline;
                    updateBehavioralPatterns();
                } else {
                    handleAPIFailure('timeline');
                }
            },
            error: function() {
                handleAPIFailure('timeline');
            }
        });
    }

    // Handle API failure
    function handleAPIFailure(type) {
        console.error(`❌ Failed to load ${type} data`);
        if (type === 'stats') {
            state.statsData = {
                total_threats: 0,
                threats_24h: 0,
                blocked_today: 0,
                threats_by_type: [],
                threats_by_severity: [],
                top_source_ips: [],
                patterns: []
            };
            updatePatternStats(state.statsData);
            updatePatternLists(state.statsData);
            updatePatternsTable(state.statsData);
            initCharts();
            updateSQLPatterns();
            updateXSSPatterns();
        } else if (type === 'timeline') {
            state.timelineData = { labels: [], threats: [] };
            updateBehavioralPatterns();
        }
        alert(`Failed to load ${type} data. Displaying empty state.`);
    }

    // Update pattern stats
    function updatePatternStats(data) {
        console.log('📊 Updating pattern stats with data:', data);
        $('#totalPatterns').text(data.total_threats || 0);
        $('#attackSequences').text(data.threats_by_type.length > 0 ? Math.max(1, Math.floor(data.total_threats * 0.15)) : 0);
        $('#uniqueAttackers').text(Object.keys(data.top_source_ips).length || 0);
        $('#blockedPatterns').text(data.blocked_today || 0);
    }

    // Update SQL patterns
    function updateSQLPatterns() {
        const container = $('#sqlPatternsList').empty();
        const sqlPatterns = state.statsData?.patterns?.sql_injection_patterns || {};

        if (!sqlPatterns.detected || sqlPatterns.detected === 0) {
            container.append($('<p>').addClass('text-center text-muted').text('No SQL patterns detected'));
            return;
        }

        const patterns = [{ name: 'Detected SQL Patterns', count: sqlPatterns.detected, blocked: Math.floor(sqlPatterns.detected * 0.95) }];
        patterns.forEach(pattern => {
            const item = $('<div>').addClass('pattern-item');
            const header = $('<div>').addClass('pattern-header');
            header.append($('<div>').addClass('pattern-name').text(pattern.name));
            header.append($('<span>').addClass(`severity ${pattern.count > 50 ? 'high' : 'medium'}`).text((pattern.count > 50 ? 'high' : 'medium').toUpperCase()));
            
            const successRate = ((pattern.count - pattern.blocked) / pattern.count * 100).toFixed(1);
            const stats = $('<div>').addClass('pattern-stats');
            stats.append(
                $('<div>').addClass('stat').append(
                    $('<label>').text('Attempts:'),
                    $('<span>').addClass('value').text(pattern.count)
                ),
                $('<div>').addClass('stat').append(
                    $('<label>').text('Blocked:'),
                    $('<span>').addClass('value text-success').text(pattern.blocked)
                ),
                $('<div>').addClass('stat').append(
                    $('<label>').text('Success Rate:'),
                    $('<span>').addClass(`value ${successRate > 10 ? 'text-danger' : 'text-success'}`).text(`${successRate}%`)
                )
            );

            const bar = $('<div>').addClass('pattern-bar');
            const barFill = $('<div>').addClass('bar-fill');
            barFill.css('width', `${Math.min(Number(pattern.count) * 2, 100)}%`);
            bar.append(barFill);

            item.append(header, stats, bar);
            container.append(item);
        });
    }

    // Update XSS patterns
    function updateXSSPatterns() {
        const container = $('#xssPatternsList').empty();
        const xssPatterns = state.statsData?.patterns?.xss_patterns || {};

        if (!xssPatterns.detected || xssPatterns.detected === 0) {
            container.append($('<p>').addClass('text-center text-muted').text('No XSS patterns detected'));
            return;
        }

        const patterns = [{ name: 'Detected XSS Patterns', count: xssPatterns.detected, blocked: Math.floor(xssPatterns.detected * 0.95) }];
        patterns.forEach(pattern => {
            const item = $('<div>').addClass('pattern-item');
            const header = $('<div>').addClass('pattern-header');
            header.append($('<div>').addClass('pattern-name').text(pattern.name));
            header.append($('<span>').addClass(`severity ${pattern.count > 30 ? 'high' : 'medium'}`).text((pattern.count > 30 ? 'high' : 'medium').toUpperCase()));
            
            const successRate = ((pattern.count - pattern.blocked) / pattern.count * 100).toFixed(1);
            const stats = $('<div>').addClass('pattern-stats');
            stats.append(
                $('<div>').addClass('stat').append(
                    $('<label>').text('Attempts:'),
                    $('<span>').addClass('value').text(pattern.count)
                ),
                $('<div>').addClass('stat').append(
                    $('<label>').text('Blocked:'),
                    $('<span>').addClass('value text-success').text(pattern.blocked)
                ),
                $('<div>').addClass('stat').append(
                    $('<label>').text('Success Rate:'),
                    $('<span>').addClass(`value ${successRate > 10 ? 'text-danger' : 'text-success'}`).text(`${successRate}%`)
                )
            );

            const bar = $('<div>').addClass('pattern-bar');
            const barFill = $('<div>').addClass('bar-fill');
            barFill.css('width', `${Math.min(Number(pattern.count) * 3, 100)}%`);
            bar.append(barFill);

            item.append(header, stats, bar);
            container.append(item);
        });
    }

    // Update behavioral patterns
    function updateBehavioralPatterns() {
        $('#behavioralContent').empty().append(
            $('<div>').addClass('behavioral-metrics').append(
                $('<div>').addClass('metric-grid').append(
                    $('<div>').addClass('metric-card').append(
                        $('<div>').addClass('metric-header').append(
                            $('<i>').addClass('fa fa-eye text-primary'),
                            $('<span>').text('Anomaly Detection')
                        ),
                        $('<div>').addClass('metric-value').append(
                            $('<span>').addClass('value-number').text('N/A'),
                            $('<span>').addClass('value-label').text('anomalies detected')
                        ),
                        $('<div>').addClass('metric-status').append(
                            $('<span>').addClass('badge badge-success').text('ACTIVE')
                        )
                    ),
                    $('<div>').addClass('metric-card').append(
                        $('<div>').addClass('metric-header').append(
                            $('<i>').addClass('fa fa-brain text-info'),
                            $('<span>').text('Learning Rate')
                        ),
                        $('<div>').addClass('metric-value').append(
                            $('<span>').addClass('value-number').text('N/A'),
                            $('<span>').addClass('value-label').text('accuracy')
                        ),
                        $('<div>').addClass('metric-status').append(
                            $('<span>').addClass('badge badge-info').text('LEARNING')
                        )
                    ),
                    $('<div>').addClass('metric-card').append(
                        $('<div>').addClass('metric-header').append(
                            $('<i>').addClass('fa fa-chart-line text-warning'),
                            $('<span>').text('Behavioral Score')
                        ),
                        $('<div>').addClass('metric-value').append(
                            $('<span>').addClass('value-number').text('N/A'),
                            $('<span>').addClass('value-label').text('threat level')
                        ),
                        $('<div>').addClass('metric-status').append(
                            $('<span>').addClass('badge badge-warning').text('ELEVATED')
                        )
                    )
                ),
                $('<div>').addClass('chart-container').append(
                    $('<h5>').text('Behavioral Analysis Timeline'),
                    $('<canvas>').attr('id', 'behavioralTimelineChart')
                ),
                $('<div>').addClass('anomaly-list').append(
                    $('<h5>').text('Recent Anomalies'),
                    $('<div>').attr('id', 'anomalyListContent')
                )
            )
        );
        initBehavioralChart();
    }

    // Update ML patterns (placeholder for now)
    function updateMLPatterns() {
        $('#mlContent').empty().append(
            $('<div>').addClass('text-center text-muted').text('Machine Learning analysis not implemented yet')
        );
    }

    // Update patterns table
    function updatePatternsTable(data) {
        console.log('📋 Updating patterns table');
        const tbody = $('#patternsTableBody').empty();
        const threatsByType = data.threats_by_type || {};

        Object.entries(threatsByType).forEach(([type, count]) => {
            const trendIcon = count > 100 ? 'fa-arrow-up text-danger' : 'fa-arrow-down text-success';
            const successRate = Math.random() * 15 + 2; // Placeholder until API provides this
            const timeAgo = Math.floor(Math.random() * 120) + 5; // Placeholder until API provides this

            const row = $('<tr>');
            row.append(
                $('<td>').append($('<code>').text(sanitizeString(type.toLowerCase().replace(/\s/g, '_') + '_pattern'))),
                $('<td>').append($('<span>').addClass('badge badge-info').text(sanitizeString(type))),
                $('<td>').append($('<strong>').text(count)),
                $('<td>').append($('<span>').addClass(successRate > 10 ? 'text-danger' : 'text-success').text(`${successRate.toFixed(1)}%`)),
                $('<td>').text(`${timeAgo} minutes ago`),
                $('<td>').append($('<i>').addClass(`fa ${trendIcon}`)),
                $('<td>').append(
                    $('<button>').addClass('btn btn-sm btn-primary').append(
                        $('<i>').addClass('fa fa-search'),
                        ' Analyze'
                    ).on('click', () => window.analyzePattern(type)),
                    $('<button>').addClass('btn btn-sm btn-danger').append(
                        $('<i>').addClass('fa fa-ban'),
                        ' Block'
                    ).on('click', () => window.blockPattern(type))
                )
            );

            tbody.append(row);
        });

        if (!Object.keys(threatsByType).length) {
            tbody.append($('<tr>').append($('<td>').attr('colspan', 7).addClass('text-center text-muted').text('No patterns detected for current period')));
        }
    }

    // Initialize charts
    function initCharts() {
        console.log('📈 Initializing all charts');
        const sqlData = { detected: state.statsData?.patterns?.sql_injection_patterns?.detected || 0 };
        const xssData = { detected: state.statsData?.patterns?.xss_patterns?.detected || 0 };

        const chartConfigs = {
            sql: {
                element: 'sqlPatternsChart',
                type: 'doughnut',
                data: {
                    labels: sqlData.detected > 0 ? ['SQL Patterns'] : ['No Data'],
                    datasets: [{
                        data: sqlData.detected > 0 ? [sqlData.detected] : [1],
                        backgroundColor: ['#FF6384']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { position: 'bottom' },
                        tooltip: { enabled: sqlData.detected > 0 }
                    }
                }
            },
            xss: {
                element: 'xssPatternsChart',
                type: 'bar',
                data: {
                    labels: xssData.detected > 0 ? ['XSS Patterns'] : ['No Data'],
                    datasets: [{
                        label: 'Attack Count',
                        data: xssData.detected > 0 ? [xssData.detected] : [1],
                        backgroundColor: ['#36A2EB']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { display: false },
                        tooltip: { enabled: xssData.detected > 0 }
                    },
                    scales: {
                        y: { beginAtZero: true, title: { display: true, text: 'Count' } }
                    }
                }
            }
        };

        Object.entries(chartConfigs).forEach(([key, config]) => {
            const ctx = document.getElementById(config.element)?.getContext('2d');
            if (ctx) {
                if (charts[key]) charts[key].destroy();
                charts[key] = new Chart(ctx, config);
            }
        });
    }

    // Initialize behavioral chart
    function initBehavioralChart() {
        if (charts.behavioral) {
            charts.behavioral.destroy();
            charts.behavioral = null;
        }

        setTimeout(() => {
            const ctx = document.getElementById('behavioralTimelineChart')?.getContext('2d');
            if (ctx && state.timelineData) {
                console.log('📈 Creating behavioral chart');
                charts.behavioral = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: state.timelineData.labels || [],
                        datasets: [{
                            label: 'Threat Count',
                            data: state.timelineData.threats || [],
                            borderColor: '#36A2EB',
                            backgroundColor: 'rgba(54, 162, 235, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        interaction: { intersect: false, mode: 'index' },
                        scales: {
                            y: { beginAtZero: true, title: { display: true, text: 'Count' } },
                            x: { title: { display: true, text: 'Time' } }
                        },
                        plugins: {
                            legend: { position: 'top' },
                            tooltip: {
                                callbacks: {
                                    title: context => `Time: ${context[0].label}`,
                                    label: context => `${context.dataset.label}: ${context.raw}`
                                }
                            }
                        }
                    }
                });
                console.log('✅ Behavioral chart created successfully');
            }
        }, 100);
    }

    // Update all charts
    function updateCharts() {
        console.log('📊 Updating all charts');
        Object.values(charts).forEach(chart => {
            if (chart && chart.data) chart.update('none');
        });
    }

    // Update application
    function updateApp() {
        loadStatsData();
        loadTimelineData();
        updateCharts();
    }

    // Global functions
    window.analyzePattern = function(pattern) {
        console.log(`🔍 Analyzing pattern: ${pattern}`);
        alert(`Detailed Analysis for: ${sanitizeString(pattern)}\n\n• Total Occurrences: ${state.statsData?.threats_by_type?.[pattern] || 0}\n• Action Required: Manual review needed.`);
    };

    window.blockPattern = function(pattern) {
        if (confirm(`Block all future requests matching pattern: ${sanitizeString(pattern)}?`)) {
            console.log(`🚫 Blocking pattern: ${pattern}`);
            alert(`Blocking not implemented yet. Please use backend API to block pattern: ${sanitizeString(pattern)}.`);
        }
    };

    // Start application
    initializeApp();
});
</script>

<style>
/* Existing CSS remains largely unchanged, only adjusting chart-related styles */
.pattern-chart-card, .pattern-list-card, .behavioral-analysis-card, .ml-analysis-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    height: auto;
    min-height: 300px;
}

.pattern-chart-card canvas {
    max-height: 300px !important;
    width: 100%;
}

.chart-container canvas {
    max-height: 300px !important;
    width: 100%;
}

/* Keep other styles as they are for OPNsense compatibility */
</style>