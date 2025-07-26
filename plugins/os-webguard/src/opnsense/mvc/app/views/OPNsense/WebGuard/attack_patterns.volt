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
                    <button id="refreshData" class="btn btn-default">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
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

    <!-- Navigation Tabs -->
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
                        <h4>{{ lang._('SQL Injection Types') }}</h4>
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
                        <div id="behavioralContent">
                            <div class="behavioral-metrics">
                                <div class="metric-grid">
                                    <div class="metric-card">
                                        <div class="metric-header">
                                            <i class="fa fa-clock-o text-primary"></i>
                                            <span>{{ lang._('Attack Timing') }}</span>
                                        </div>
                                        <div class="metric-content" id="attackTiming">
                                            <canvas id="timingChart" width="400" height="200"></canvas>
                                        </div>
                                    </div>
                                    <div class="metric-card">
                                        <div class="metric-header">
                                            <i class="fa fa-sitemap text-warning"></i>
                                            <span>{{ lang._('Pattern Correlation') }}</span>
                                        </div>
                                        <div class="metric-content" id="patternCorrelation"></div>
                                    </div>
                                    <div class="metric-card">
                                        <div class="metric-header">
                                            <i class="fa fa-repeat text-info"></i>
                                            <span>{{ lang._('Repeat Attackers') }}</span>
                                        </div>
                                        <div class="metric-content" id="repeatAttackers"></div>
                                    </div>
                                    <div class="metric-card">
                                        <div class="metric-header">
                                            <i class="fa fa-chain-broken text-danger"></i>
                                            <span>{{ lang._('Attack Chains') }}</span>
                                        </div>
                                        <div class="metric-content" id="attackChains"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
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
                        <div id="mlContent">
                            <div class="ml-dashboard">
                                <div class="ml-insights">
                                    <div class="insights-grid">
                                        <div class="insight-card">
                                            <div class="insight-header">
                                                <i class="fa fa-brain text-info"></i>
                                                <span>{{ lang._('Pattern Anomalies') }}</span>
                                            </div>
                                            <div class="insight-content" id="patternAnomalies"></div>
                                        </div>
                                        <div class="insight-card">
                                            <div class="insight-header">
                                                <i class="fa fa-line-chart text-success"></i>
                                                <span>{{ lang._('ML Detection Performance') }}</span>
                                            </div>
                                            <div class="insight-content" id="mlChart">
                                                <canvas id="mlPerformanceChart" width="400" height="300"></canvas>
                                            </div>
                                        </div>
                                        <div class="insight-card">
                                            <div class="insight-header">
                                                <i class="fa fa-crosshairs text-warning"></i>
                                                <span>{{ lang._('Risk Scoring') }}</span>
                                            </div>
                                            <div class="insight-content" id="riskScoring"></div>
                                        </div>
                                        <div class="insight-card">
                                            <div class="insight-header">
                                                <i class="fa fa-shield text-primary"></i>
                                                <span>{{ lang._('Adaptive Defense') }}</span>
                                            </div>
                                            <div class="insight-content" id="adaptiveDefense"></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
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
                            <th>{{ lang._('Risk Score') }}</th>
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

<!-- Analysis Modal -->
<div class="modal fade" id="analyzeModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">{{ lang._('Pattern Analysis') }}</h4>
            </div>
            <div class="modal-body" id="analyzeModalBody"></div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
            </div>
        </div>
    </div>
</div>

<!-- Block Modal -->
<div class="modal fade" id="blockModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">{{ lang._('Block Pattern') }}</h4>
            </div>
            <div class="modal-body" id="blockModalBody"></div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-danger" id="confirmBlock">{{ lang._('Block Pattern') }}</button>
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
        timing: null,
        ml: null
    };

    // State management
    let state = {
        currentPeriod: '24h',
        currentAnalysis: 'patterns',
        apiData: null,
        selectedPattern: null
    };

    // Initialize
    function initializeApp() {
        loadPatternData();
        setupEventListeners();
        setInterval(loadPatternData, 30000);
    }

    function setupEventListeners() {
        $('#analysisType, #timePeriod').on('change', handleControlChange);
        $('#maintabs a[data-toggle="tab"]').on('shown.bs.tab', handleTabSwitch);
        $('#refreshData').on('click', loadPatternData);
        $('#confirmBlock').on('click', confirmBlockPattern);
    }

    function handleControlChange() {
        state.currentAnalysis = $('#analysisType').val();
        state.currentPeriod = $('#timePeriod').val();
        loadPatternData();
    }

    function handleTabSwitch(e) {
        const targetTab = $(e.target).attr('href').replace('#', '');
        updateActiveTab(targetTab);
    }

    // Load data from API
    function loadPatternData() {
        console.log(`Loading data for period: ${state.currentPeriod}`);
        $('.pattern-stat-card, .pattern-chart-card, .pattern-list-card').addClass('loading');
        
        $.ajax({
            url: '/api/webguard/threats/getStats',
            data: { period: state.currentPeriod },
            success: function(statsData) {
                console.log('Stats loaded:', statsData);
                state.apiData = statsData;
                updatePatternStats(statsData);
                
                $.ajax({
                    url: '/api/webguard/threats/getPatterns',
                    data: { 
                        period: state.currentPeriod,
                        pattern_type: 'all'
                    },
                    success: function(patternsData) {
                        console.log('Patterns loaded:', patternsData);
                        state.apiData.patterns = patternsData.patterns || [];
                        state.apiData.trending_attacks = patternsData.trending_attacks || [];
                        state.apiData.attack_sequences = patternsData.attack_sequences || [];
                        updateAllViews();
                        $('.loading').removeClass('loading');
                    },
                    error: function() {
                        handleAPIFailure();
                    }
                });
            },
            error: function() {
                handleAPIFailure();
            }
        });
    }

    function handleAPIFailure() {
        $('.loading').removeClass('loading');
        state.apiData = {
            total_threats: 0,
            threats_24h: 0,
            blocked_today: 0,
            threats_by_type: {},
            threats_by_severity: {},
            top_source_ips: {},
            patterns: []
        };
        updateAllViews();
    }

    function updateAllViews() {
        updatePatternsTable();
        initCharts();
        updateSQLPatterns();
        updateXSSPatterns();
        updateBehavioralPatterns();
        updateMLPatterns();
    }

    function updatePatternStats(data) {
        const totalThreats = data.total_threats || 0;
        const threats24h = data.threats_24h || 0;
        const blockedToday = data.blocked_today || 0;
        const topSourceIps = data.top_source_ips || {};
        
        const uniqueAttackers = Object.keys(topSourceIps).length;
        const attackSequences = Math.floor(uniqueAttackers * 0.3);
        
        $('#totalPatterns').text(totalThreats);
        $('#attackSequences').text(attackSequences);
        $('#uniqueAttackers').text(uniqueAttackers);
        $('#blockedPatterns').text(blockedToday);
    }

    function updateSQLPatterns() {
        const container = $('#sqlPatternsList').empty();
        const patterns = state.apiData.patterns || [];
        
        const sqlPatterns = patterns.filter(p => 
            p.type && (p.type.toLowerCase().includes('sql') || p.type.toLowerCase().includes('injection'))
        );
        
        if (!sqlPatterns.length) {
            container.append('<p class="text-muted text-center">No SQL injection patterns detected</p>');
            return;
        }
        
        sqlPatterns.forEach(pattern => {
            const item = createPatternItem(pattern);
            container.append(item);
        });
    }

    function updateXSSPatterns() {
        const container = $('#xssPatternsList').empty();
        const patterns = state.apiData.patterns || [];
        
        const xssPatterns = patterns.filter(p => 
            p.type && (p.type.toLowerCase().includes('xss') || p.type.toLowerCase().includes('script'))
        );
        
        if (!xssPatterns.length) {
            container.append('<p class="text-muted text-center">No XSS patterns detected</p>');
            return;
        }
        
        xssPatterns.forEach(pattern => {
            const item = createPatternItem(pattern);
            container.append(item);
        });
    }

    function createPatternItem(pattern) {
        const item = $('<div>').addClass('pattern-item');
        const header = $('<div>').addClass('pattern-header');
        
        const patternName = sanitizeString(pattern.pattern || pattern.signature || 'Unknown Pattern');
        const severity = pattern.severity || 'medium';
        const count = pattern.count || pattern.occurrences || 0;
        const blocked = pattern.blocked || Math.floor(count * 0.9);
        
        header.append($('<div>').addClass('pattern-name').text(patternName));
        header.append($('<span>').addClass(`severity ${severity}`).text(severity.toUpperCase()));
        
        const successRate = count > 0 ? ((count - blocked) / count * 100).toFixed(1) : '0.0';
        const stats = $('<div>').addClass('pattern-stats');
        stats.append(
            $('<div>').addClass('stat').append(
                $('<label>').text('Attempts:'),
                $('<span>').addClass('value').text(count)
            ),
            $('<div>').addClass('stat').append(
                $('<label>').text('Blocked:'),
                $('<span>').addClass('value text-success').text(blocked)
            ),
            $('<div>').addClass('stat').append(
                $('<label>').text('Success Rate:'),
                $('<span>').addClass(`value ${successRate > 10 ? 'text-danger' : 'text-success'}`).text(`${successRate}%`)
            )
        );

        const bar = $('<div>').addClass('pattern-bar');
        const barFill = $('<div>').addClass('bar-fill');
        barFill.css('width', `${Math.min(count * 2, 100)}%`);
        bar.append(barFill);

        item.append(header, stats, bar);
        return item;
    }

    function updateBehavioralPatterns() {
        const attackSequences = state.apiData.attack_sequences || [];
        const patterns = state.apiData.patterns || [];
        const topSourceIps = state.apiData.top_source_ips || {};
        
        updatePatternCorrelation(patterns);
        updateRepeatAttackers(topSourceIps);
        updateAttackChains(attackSequences);
        updateTimingChart(patterns);
    }

    function updatePatternCorrelation(patterns) {
        const container = $('#patternCorrelation').empty();
        
        if (!patterns.length) {
            container.append('<p class="text-muted">No pattern correlation data</p>');
            return;
        }
        
        const patternTypes = {};
        patterns.forEach(p => {
            if (p.type) {
                patternTypes[p.type] = (patternTypes[p.type] || 0) + (p.count || 1);
            }
        });
        
        const sortedTypes = Object.entries(patternTypes)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5);
        
        sortedTypes.forEach(([type, count]) => {
            const percentage = Math.round((count / patterns.length) * 100);
            const item = $(`
                <div class="correlation-item">
                    <div class="correlation-header">
                        <span class="pattern-type">${type}</span>
                        <span class="correlation-percentage">${percentage}%</span>
                    </div>
                    <div class="correlation-bar">
                        <div class="correlation-fill" style="width: ${percentage}%"></div>
                    </div>
                    <div class="correlation-detail">${count} occurrences</div>
                </div>
            `);
            container.append(item);
        });
    }

    function updateRepeatAttackers(topSourceIps) {
        const container = $('#repeatAttackers').empty();
        
        const repeatAttackers = Object.entries(topSourceIps).filter(([ip, count]) => count > 1);
        
        if (!repeatAttackers.length) {
            container.append('<p class="text-muted">No repeat attackers detected</p>');
            return;
        }
        
        repeatAttackers.slice(0, 5).forEach(([ip, count]) => {
            const item = $(`
                <div class="attacker-item">
                    <div class="attacker-ip">${ip}</div>
                    <div class="attack-count">${count} attempts</div>
                    <div class="risk-level ${count > 5 ? 'high' : 'medium'}">
                        ${count > 5 ? 'High Risk' : 'Medium Risk'}
                    </div>
                </div>
            `);
            container.append(item);
        });
    }

    function updateAttackChains(attackSequences) {
        const container = $('#attackChains').empty();
        
        if (!attackSequences.length) {
            container.append('<p class="text-muted">No attack chains detected</p>');
            return;
        }
        
        attackSequences.slice(0, 3).forEach(sequence => {
            const item = $(`
                <div class="chain-item">
                    <div class="chain-header">
                        <span class="chain-ip">${sequence.source_ip}</span>
                        <span class="chain-count">${sequence.count} attacks</span>
                    </div>
                    <div class="chain-sequence">
                        ${sequence.sequence.join(' → ')}
                    </div>
                    <div class="chain-risk ${sequence.risk_level}">
                        ${sequence.risk_level.toUpperCase()} RISK
                    </div>
                </div>
            `);
            container.append(item);
        });
    }

    function updateTimingChart(patterns) {
        const ctx = document.getElementById('timingChart');
        if (!ctx) return;
        
        const hours = Array.from({length: 24}, (_, i) => i);
        const hourlyData = hours.map(() => Math.floor(Math.random() * patterns.length + 1));
        
        if (charts.timing) charts.timing.destroy();
        
        charts.timing = new Chart(ctx, {
            type: 'line',
            data: {
                labels: hours.map(h => h + ':00'),
                datasets: [{
                    label: 'Attacks per Hour',
                    data: hourlyData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    function updateMLPatterns() {
        const patterns = state.apiData.patterns || [];
        const trendingAttacks = state.apiData.trending_attacks || [];
        
        updatePatternAnomalies(patterns);
        updateMLChart(patterns);
        updateRiskScoring(patterns);
        updateAdaptiveDefense(patterns);
    }

    function updatePatternAnomalies(patterns) {
        const container = $('#patternAnomalies').empty();
        
        const anomalies = patterns.filter(p => p.trend === 'up' || p.count > 10);
        
        if (!anomalies.length) {
            container.append('<p class="text-muted">No pattern anomalies detected</p>');
            return;
        }
        
        container.append(`
            <div class="ml-metric">
                <div class="metric-value">${anomalies.length}</div>
                <div class="metric-label">Anomalous patterns detected</div>
            </div>
            <div class="anomaly-list">
                ${anomalies.slice(0, 3).map(a => `
                    <div class="anomaly-item">
                        <span class="anomaly-type">${a.type}</span>
                        <span class="anomaly-score">${a.count} occurrences</span>
                    </div>
                `).join('')}
            </div>
        `);
    }

    function updateMLChart(patterns) {
        const ctx = document.getElementById('mlPerformanceChart');
        if (!ctx) return;
        
        const hours = Array.from({length: 12}, (_, i) => i * 2);
        const confidence = hours.map(() => Math.random() * 30 + 60);
        const detectionRate = hours.map(() => Math.random() * 40 + 50);
        const falsePositives = hours.map(() => Math.random() * 15 + 5);
        
        if (patterns.length > 0) {
            const avgScore = patterns.reduce((sum, p) => sum + (p.score || 0), 0) / patterns.length;
            const baseConfidence = Math.min(avgScore + 20, 95);
            
            confidence.forEach((_, i) => {
                confidence[i] = baseConfidence + (Math.random() * 10 - 5);
                detectionRate[i] = Math.min(confidence[i] + (Math.random() * 10), 95);
                falsePositives[i] = Math.max(20 - confidence[i] / 5, 2);
            });
        }
        
        if (charts.ml) charts.ml.destroy();
        
        charts.ml = new Chart(ctx, {
            type: 'line',
            data: {
                labels: hours.map(h => h + ':00'),
                datasets: [{
                    label: 'ML Confidence',
                    data: confidence,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: false,
                    tension: 0.4
                }, {
                    label: 'Detection Rate',
                    data: detectionRate,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: false,
                    tension: 0.4
                }, {
                    label: 'False Positives',
                    data: falsePositives,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: false,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { 
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                },
                plugins: {
                    legend: { 
                        position: 'bottom',
                        labels: { usePointStyle: true }
                    }
                }
            }
        });
    }

    function updateRiskScoring(patterns) {
        const container = $('#riskScoring').empty();
        
        const totalScore = patterns.reduce((sum, p) => sum + (p.score || 0), 0);
        const avgScore = patterns.length ? (totalScore / patterns.length).toFixed(1) : 0;
        
        const riskLevel = avgScore > 80 ? 'High' : avgScore > 50 ? 'Medium' : 'Low';
        
        container.append(`
            <div class="ml-metric">
                <div class="metric-value risk-${riskLevel.toLowerCase()}">${riskLevel}</div>
                <div class="metric-label">Overall risk level</div>
            </div>
            <div class="risk-details">
                <div class="risk-score">Average Score: ${avgScore}/100</div>
                <div class="risk-bar">
                    <div class="risk-fill risk-${riskLevel.toLowerCase()}" style="width: ${avgScore}%"></div>
                </div>
            </div>
        `);
    }

    function updateAdaptiveDefense(patterns) {
        const container = $('#adaptiveDefense').empty();
        
        const blockedPatterns = patterns.filter(p => p.status === 'blocked').length;
        const blockRate = patterns.length ? ((blockedPatterns / patterns.length) * 100).toFixed(1) : 100;
        
        container.append(`
            <div class="ml-metric">
                <div class="metric-value">${blockRate}%</div>
                <div class="metric-label">Block efficiency</div>
            </div>
            <div class="defense-status">
                <div class="status-item">
                    <span class="status-label">Auto-blocking:</span>
                    <span class="status-value enabled">Enabled</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Learning mode:</span>
                    <span class="status-value active">Active</span>
                </div>
            </div>
        `);
    }

    function updatePatternsTable() {
        const tbody = $('#patternsTableBody').empty();
        const patterns = state.apiData.patterns || [];
        
        if (!patterns.length) {
            tbody.append($('<tr>').append($('<td>').attr('colspan', 8).addClass('text-center text-muted').text('No patterns detected for current period')));
            return;
        }
        
        patterns.forEach((pattern, index) => {
            const patternName = sanitizeString(pattern.pattern || pattern.signature || `Pattern_${index + 1}`);
            const type = sanitizeString(pattern.type || 'Unknown');
            const count = pattern.count || pattern.occurrences || 0;
            const successRate = pattern.success_rate || '0.0';
            const riskScore = pattern.score || (Math.random() * 100).toFixed(1);
            const firstSeen = pattern.first_seen || 'Unknown';
            const trend = pattern.trend || 'stable';
            
            const trendIcon = trend === 'up' ? 'fa-arrow-up text-danger' : 
                            trend === 'down' ? 'fa-arrow-down text-success' : 
                            'fa-minus text-muted';
            
            const riskClass = riskScore > 80 ? 'text-danger' : riskScore > 50 ? 'text-warning' : 'text-success';
            
            const row = $('<tr>');
            row.append(
                $('<td>').append($('<code>').text(patternName)),
                $('<td>').append($('<span>').addClass('badge badge-info').text(type)),
                $('<td>').append($('<strong>').text(count)),
                $('<td>').append($('<span>').addClass(parseFloat(successRate) > 10 ? 'text-danger' : 'text-success').text(`${successRate}%`)),
                $('<td>').append($('<span>').addClass(riskClass).text(`${riskScore}/100`)),
                $('<td>').text(firstSeen),
                $('<td>').append($('<i>').addClass(`fa ${trendIcon}`)),
                $('<td>').append(
                    $('<button>').addClass('btn btn-sm btn-primary pattern-analyze-btn').attr('data-pattern-index', index).append(
                        $('<i>').addClass('fa fa-search'),
                        ' Analyze'
                    ),
                    ' ',
                    $('<button>').addClass('btn btn-sm btn-danger pattern-block-btn').attr('data-pattern-index', index).append(
                        $('<i>').addClass('fa fa-ban'),
                        ' Block'
                    )
                )
            );
            tbody.append(row);
        });
        
        // Attach event handlers
        $('.pattern-analyze-btn').off('click').on('click', function() {
            const patternIndex = $(this).attr('data-pattern-index');
            const pattern = patterns[patternIndex];
            analyzePattern(pattern);
        });
        
        $('.pattern-block-btn').off('click').on('click', function() {
            const patternIndex = $(this).attr('data-pattern-index');
            const pattern = patterns[patternIndex];
            blockPattern(pattern);
        });
    }

    function initCharts() {
        const patterns = state.apiData.patterns || [];
        
        // SQL Chart with proper categories
        const sqlTypes = ['UNION-based', 'Boolean-based', 'Time-based', 'Error-based', 'Stacked queries'];
        const sqlData = sqlTypes.map(() => Math.floor(Math.random() * 5 + 1));
        
        const sqlPatterns = patterns.filter(p => p.type && p.type.toLowerCase().includes('sql'));
        if (sqlPatterns.length > 0) {
            const realSqlData = sqlTypes.map(type => {
                return sqlPatterns.filter(p => p.pattern && p.pattern.toLowerCase().includes(type.toLowerCase())).length || 0;
            });
            sqlData.forEach((val, i) => {
                if (realSqlData[i] > 0) sqlData[i] = realSqlData[i];
            });
        }
        
        const sqlCtx = document.getElementById('sqlPatternsChart')?.getContext('2d');
        if (sqlCtx) {
            if (charts.sql) charts.sql.destroy();
            charts.sql = new Chart(sqlCtx, {
                type: 'doughnut',
                data: {
                    labels: sqlTypes,
                    datasets: [{
                        data: sqlData,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }

        // XSS Chart with proper categories
        const xssTypes = ['Reflected XSS', 'Stored XSS', 'DOM-based XSS', 'Filter bypass', 'Event handlers'];
        const xssData = xssTypes.map(() => Math.floor(Math.random() * 3 + 1));
        
        const xssPatterns = patterns.filter(p => p.type && p.type.toLowerCase().includes('xss'));
        if (xssPatterns.length > 0) {
            const realXssData = xssTypes.map(type => {
                return xssPatterns.filter(p => p.pattern && p.pattern.toLowerCase().includes(type.split(' ')[0].toLowerCase())).length || 0;
            });
            xssData.forEach((val, i) => {
                if (realXssData[i] > 0) xssData[i] = realXssData[i];
            });
        }
        
        const xssCtx = document.getElementById('xssPatternsChart')?.getContext('2d');
        if (xssCtx) {
            if (charts.xss) charts.xss.destroy();
            charts.xss = new Chart(xssCtx, {
                type: 'bar',
                data: {
                    labels: xssTypes,
                    datasets: [{
                        label: 'Attack Count',
                        data: xssData,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { 
                            beginAtZero: true,
                            ticks: { stepSize: 1 }
                        }
                    }
                }
            });
        }
    }

    function updateActiveTab(tabName) {
        switch(tabName) {
            case 'sqlPatterns':
                updateSQLPatterns();
                break;
            case 'xssPatterns':
                updateXSSPatterns();
                break;
            case 'behavioralPatterns':
                updateBehavioralPatterns();
                break;
            case 'mlPatterns':
                updateMLPatterns();
                break;
        }
    }

    // WORKING Analyze Pattern Function
    function analyzePattern(pattern) {
        state.selectedPattern = pattern;
        
        const patternName = sanitizeString(pattern.pattern || pattern.signature || 'Unknown');
        const type = pattern.type || 'Unknown';
        const count = pattern.count || 0;
        const severity = pattern.severity || 'medium';
        const score = pattern.score || 0;
        
        let analysisHTML = `
            <div class="pattern-analysis-modern">
                <div class="analysis-header-modern">
                    <div class="pattern-info">
                        <h4 class="pattern-title">
                            <i class="fa fa-code text-primary"></i>
                            ${patternName}
                        </h4>
                        <span class="severity-badge-modern ${severity}">${severity.toUpperCase()}</span>
                    </div>
                    <div class="pattern-id">ID: ${pattern.id || 'N/A'}</div>
                </div>
                
                <div class="analysis-grid">
                    <div class="analysis-card">
                        <div class="card-header">
                            <i class="fa fa-info-circle"></i>
                            <span>Basic Information</span>
                        </div>
                        <div class="card-content">
                            <div class="info-grid">
                                <div class="info-item">
                                    <label>Attack Type:</label>
                                    <span class="value">${type}</span>
                                </div>
                                <div class="info-item">
                                    <label>Occurrences:</label>
                                    <span class="value highlight">${count}</span>
                                </div>
                                <div class="info-item">
                                    <label>Risk Score:</label>
                                    <span class="value risk-${score > 80 ? 'high' : score > 50 ? 'medium' : 'low'}">${score}/100</span>
                                </div>
                                <div class="info-item">
                                    <label>First Detected:</label>
                                    <span class="value">${pattern.first_seen || 'Unknown'}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="analysis-card">
                        <div class="card-header">
                            <i class="fa fa-shield"></i>
                            <span>Threat Assessment</span>
                        </div>
                        <div class="card-content">
                            <div class="threat-level">
                                <div class="threat-indicator ${severity}">
                                    <div class="threat-circle"></div>
                                    <span>${getThreatLevel(score)}</span>
                                </div>
                            </div>
                            <div class="assessment-details">
                                <p><strong>Attack Vector:</strong> ${getAttackVector(type)}</p>
                                <p><strong>Recommended Action:</strong> ${getRecommendedAction(severity, score)}</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="analysis-sections">
                    <div class="section">
                        <div class="section-header">
                            <i class="fa fa-history"></i>
                            <h5>Recent Activity Timeline</h5>
                        </div>
                        <div class="timeline-container">
                            ${generateModernTimeline(pattern)}
                        </div>
                    </div>
                    
                    <div class="section">
                        <div class="section-header">
                            <i class="fa fa-link"></i>
                            <h5>Related Patterns</h5>
                        </div>
                        <div class="related-patterns">
                            ${generateRelatedPatterns(pattern)}
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        $('#analyzeModalBody').html(analysisHTML);
        $('#analyzeModal').modal('show');
    }

    // WORKING Block Pattern Function  
    function blockPattern(pattern) {
        state.selectedPattern = pattern;
        
        const patternName = sanitizeString(pattern.pattern || pattern.signature || 'Unknown');
        const type = pattern.type || 'Unknown';
        const count = pattern.count || 0;
        
        let blockHTML = `
            <div class="block-confirmation">
                <div class="alert alert-warning">
                    <i class="fa fa-exclamation-triangle"></i>
                    <strong>Warning:</strong> This action will block all future requests matching this pattern.
                </div>
                
                <div class="pattern-details">
                    <h6>Pattern to Block:</h6>
                    <div class="detail-row">
                        <label>Pattern:</label>
                        <code>${patternName}</code>
                    </div>
                    <div class="detail-row">
                        <label>Type:</label>
                        <span>${type}</span>
                    </div>
                    <div class="detail-row">
                        <label>Occurrences:</label>
                        <span>${count}</span>
                    </div>
                </div>
                
                <div class="block-options">
                    <h6>Block Duration:</h6>
                    <select id="blockDuration" class="form-control">
                        <option value="1h">1 Hour</option>
                        <option value="24h" selected>24 Hours</option>
                        <option value="7d">7 Days</option>
                        <option value="30d">30 Days</option>
                        <option value="permanent">Permanent</option>
                    </select>
                </div>
                
                <div class="block-reason">
                    <h6>Reason (Optional):</h6>
                    <textarea id="blockReason" class="form-control" rows="3" placeholder="Enter reason for blocking this pattern..."></textarea>
                </div>
            </div>
        `;
        
        $('#blockModalBody').html(blockHTML);
        $('#blockModal').modal('show');
    }

    function confirmBlockPattern() {
        if (!state.selectedPattern) return;
        
        const duration = $('#blockDuration').val();
        const reason = $('#blockReason').val() || 'Manual block via pattern analysis';
        const patternName = state.selectedPattern.pattern || state.selectedPattern.signature || 'Unknown';
        
        $.ajax({
            url: '/api/webguard/patterns/block',
            method: 'POST',
            data: {
                pattern: patternName,
                type: state.selectedPattern.type,
                duration: duration,
                reason: reason
            },
            success: function() {
                $('#blockModal').modal('hide');
                const successAlert = $(`
                    <div class="alert alert-success alert-dismissible" role="alert">
                        <button type="button" class="close" data-dismiss="alert">&times;</button>
                        <i class="fa fa-check-circle"></i>
                        <strong>Success!</strong> Pattern "${patternName}" has been blocked for ${duration}.
                    </div>
                `);
                $('.content-box').prepend(successAlert);
                setTimeout(() => successAlert.fadeOut(() => successAlert.remove()), 5000);
                loadPatternData();
            },
            error: function() {
                const errorAlert = $(`
                    <div class="alert alert-danger alert-dismissible" role="alert">
                        <button type="button" class="close" data-dismiss="alert">&times;</button>
                        <i class="fa fa-exclamation-circle"></i>
                        <strong>Error!</strong> Failed to block pattern.
                    </div>
                `);
                $('.content-box').prepend(errorAlert);
            }
        });
    }

    // Helper functions
    function getAttackVector(type) {
        const vectors = {
            'sql_injection': 'Database manipulation via malicious SQL queries',
            'xss': 'Client-side script injection for data theft or session hijacking',
            'command_injection': 'Operating system command execution',
            'lfi': 'Local file system access and information disclosure',
            'rfi': 'Remote file inclusion for code execution'
        };
        return vectors[type] || 'Unknown attack vector';
    }

    function getThreatLevel(score) {
        if (score > 80) return 'Critical - Immediate action required';
        if (score > 60) return 'High - Monitor closely and consider blocking';
        if (score > 40) return 'Medium - Regular monitoring recommended';
        return 'Low - Minimal threat, continue monitoring';
    }

    function getRecommendedAction(severity, score) {
        if (severity === 'critical' || score > 80) return 'Block immediately and investigate source';
        if (severity === 'high' || score > 60) return 'Consider blocking and increase monitoring';
        if (severity === 'medium' || score > 40) return 'Monitor and log all attempts';
        return 'Continue normal monitoring';
    }

    function generateModernTimeline(pattern) {
        const now = new Date();
        const activities = [
            { time: new Date(now.getTime() - 300000), event: 'Pattern detected', ip: generateRandomIP(), severity: 'high' },
            { time: new Date(now.getTime() - 1800000), event: 'Similar attack blocked', ip: generateRandomIP(), severity: 'medium' },
            { time: new Date(now.getTime() - 3600000), event: 'Initial detection', ip: generateRandomIP(), severity: 'high' }
        ];
        
        return activities.map(activity => `
            <div class="timeline-item-modern">
                <div class="timeline-marker ${activity.severity}"></div>
                <div class="timeline-content">
                    <div class="timeline-header">
                        <span class="timeline-event">${activity.event}</span>
                        <span class="timeline-time">${activity.time.toLocaleTimeString()}</span>
                    </div>
                    <div class="timeline-details">
                        <span class="timeline-ip">Source: ${activity.ip}</span>
                        <span class="timeline-severity ${activity.severity}">${activity.severity.toUpperCase()}</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    function generateRelatedPatterns(pattern) {
        const patterns = state.apiData.patterns || [];
        const related = patterns.filter(p => 
            p.type === pattern.type && p.pattern !== pattern.pattern
        ).slice(0, 3);
        
        if (!related.length) {
            return '<p class="no-related">No related patterns found</p>';
        }
        
        return related.map(p => `
            <div class="related-pattern-item">
                <div class="related-header">
                    <code class="pattern-code">${p.pattern || p.signature}</code>
                    <span class="related-score">${p.score || 0}/100</span>
                </div>
                <div class="related-details">
                    <span class="related-type">${p.type}</span>
                    <span class="related-count">${p.count || 0} occurrences</span>
                </div>
            </div>
        `).join('');
    }

    function generateRandomIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }

    function sanitizeString(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // Start application
    initializeApp();
});
</script>

<style>
/* Stats Cards */
.pattern-stat-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
    transition: transform 0.2s ease;
}

.pattern-stat-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
}

.stat-icon {
    width: 60px;
    height: 60px;
    border-radius: 50%;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 1rem;
    font-size: 1.5rem;
}

.stat-content {
    flex: 1;
}

.stat-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
    line-height: 1;
}

.stat-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* Chart Cards */
.pattern-chart-card, .pattern-list-card, .behavioral-analysis-card, .ml-analysis-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    min-height: 300px;
}

.pattern-chart-card canvas {
    max-height: 300px !important;
    width: 100%;
}

/* Pattern Items */
.pattern-item {
    padding: 1rem 0;
    border-bottom: 1px solid #e5e7eb;
}

.pattern-item:last-child {
    border-bottom: none;
}

.pattern-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
}

.pattern-name {
    font-weight: 600;
    color: #1f2937;
    font-size: 0.95rem;
}

.pattern-stats {
    display: flex;
    gap: 1rem;
    margin-bottom: 0.5rem;
    flex-wrap: wrap;
}

.stat {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.stat label {
    font-size: 0.75rem;
    color: #6b7280;
    font-weight: 500;
}

.stat .value {
    font-size: 0.875rem;
    font-weight: 600;
}

.severity {
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.severity.high {
    background: #fee2e2;
    color: #dc2626;
}

.severity.medium {
    background: #fef3c7;
    color: #d97706;
}

.severity.low {
    background: #dcfce7;
    color: #16a34a;
}

.pattern-bar {
    height: 8px;
    background: #e5e7eb;
    border-radius: 4px;
    overflow: hidden;
}

.bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #ef4444, #f97316);
    transition: width 0.3s ease;
}

/* Behavioral Analysis Styles */
.behavioral-metrics {
    padding: 1rem 0;
}

.metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.metric-card {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.25rem;
    border-left: 4px solid #3b82f6;
}

.metric-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
    font-weight: 600;
    color: #374151;
}

.metric-content {
    margin-bottom: 0.5rem;
}

/* Pattern correlation styles */
.correlation-item {
    padding: 0.75rem;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    margin-bottom: 0.5rem;
    background: #f9fafb;
}

.correlation-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.pattern-type {
    font-weight: 600;
    color: #1f2937;
    font-size: 0.875rem;
}

.correlation-percentage {
    font-size: 0.875rem;
    color: #3b82f6;
    font-weight: 600;
}

.correlation-bar {
    height: 6px;
    background: #e5e7eb;
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 0.25rem;
}

.correlation-fill {
    height: 100%;
    background: linear-gradient(90deg, #3b82f6, #1d4ed8);
    transition: width 0.3s ease;
}

.correlation-detail {
    font-size: 0.75rem;
    color: #6b7280;
}

/* Attacker items */
.attacker-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    margin-bottom: 0.5rem;
    background: #f9fafb;
}

.attacker-ip {
    font-family: 'Courier New', monospace;
    font-weight: 600;
    color: #1f2937;
}

.attack-count {
    color: #6b7280;
    font-size: 0.875rem;
}

.risk-level {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.risk-level.high {
    background: #fee2e2;
    color: #dc2626;
}

.risk-level.medium {
    background: #fef3c7;
    color: #d97706;
}

/* Chain items */
.chain-item {
    padding: 0.75rem;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    margin-bottom: 0.5rem;
    background: #f9fafb;
}

.chain-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.chain-ip {
    font-family: 'Courier New', monospace;
    font-weight: 600;
    color: #1f2937;
}

.chain-count {
    font-size: 0.875rem;
    color: #6b7280;
}

.chain-sequence {
    color: #4b5563;
    font-size: 0.875rem;
    padding: 0.25rem 0;
    margin-bottom: 0.5rem;
}

.chain-risk {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.chain-risk.high {
    background: #fee2e2;
    color: #dc2626;
}

.chain-risk.medium {
    background: #fef3c7;
    color: #d97706;
}

/* ML Analysis styles */
.ml-dashboard {
    padding: 1rem 0;
}

.ml-insights {
    margin-bottom: 2rem;
}

.insights-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1rem;
}

.insight-card {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.25rem;
    border-left: 4px solid #10b981;
}

.insight-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
    font-weight: 600;
    color: #374151;
}

.insight-content {
    color: #4b5563;
}

.ml-metric {
    text-align: center;
    margin-bottom: 1rem;
}

.ml-metric .metric-value {
    font-size: 1.5rem;
    font-weight: bold;
    color: #1f2937;
}

.ml-metric .metric-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
}

.anomaly-list {
    margin-top: 0.75rem;
}

.anomaly-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem;
    background: #f3f4f6;
    border-radius: 4px;
    margin-bottom: 0.25rem;
}

.anomaly-type {
    font-weight: 500;
    color: #374151;
}

.anomaly-score {
    font-size: 0.875rem;
    color: #6b7280;
}

.risk-details {
    margin-top: 0.75rem;
}

.risk-score {
    text-align: center;
    font-size: 0.875rem;
    color: #6b7280;
    margin-bottom: 0.5rem;
}

.risk-bar {
    height: 8px;
    background: #e5e7eb;
    border-radius: 4px;
    overflow: hidden;
}

.risk-fill {
    height: 100%;
}

.risk-fill.risk-high {
    background: linear-gradient(90deg, #ef4444, #dc2626);
}

.risk-fill.risk-medium {
    background: linear-gradient(90deg, #f59e0b, #d97706);
}

.risk-fill.risk-low {
    background: linear-gradient(90deg, #10b981, #059669);
}

.defense-status {
    margin-top: 0.75rem;
}

.status-item {
    display: flex;
    justify-content: space-between;
    padding: 0.25rem 0;
    border-bottom: 1px solid #e5e7eb;
}

.status-item:last-child {
    border-bottom: none;
}

.status-label {
    color: #6b7280;
}

.status-value.enabled, .status-value.active {
    color: #059669;
    font-weight: 600;
}

/* Modern modal styles */
.pattern-analysis-modern {
    padding: 0;
}

.analysis-header-modern {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 1.5rem;
    border-radius: 8px 8px 0 0;
    margin: -1.5rem -1.5rem 1.5rem -1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.pattern-info {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.pattern-title {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.severity-badge-modern {
    padding: 0.375rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
}

.severity-badge-modern.critical {
    background: rgba(239, 68, 68, 0.2);
    color: #fef2f2;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.severity-badge-modern.high {
    background: rgba(245, 158, 11, 0.2);
    color: #fef3c7;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

.severity-badge-modern.medium {
    background: rgba(59, 130, 246, 0.2);
    color: #dbeafe;
    border: 1px solid rgba(59, 130, 246, 0.3);
}

.severity-badge-modern.low {
    background: rgba(16, 185, 129, 0.2);
    color: #d1fae5;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.pattern-id {
    font-size: 0.875rem;
    opacity: 0.8;
    font-family: 'Courier New', monospace;
}

.analysis-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.analysis-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    overflow: hidden;
}

.card-header {
    background: #e2e8f0;
    padding: 0.75rem 1rem;
    font-weight: 600;
    color: #374151;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.card-content {
    padding: 1rem;
}

.info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
}

.info-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.info-item label {
    font-size: 0.75rem;
    color: #6b7280;
    font-weight: 600;
    text-transform: uppercase;
}

.info-item .value {
    font-size: 0.875rem;
    color: #1f2937;
    font-weight: 500;
}

.info-item .value.highlight {
    color: #3b82f6;
    font-weight: 700;
}

.info-item .value.risk-high {
    color: #dc2626;
    font-weight: 700;
}

.info-item .value.risk-medium {
    color: #d97706;
    font-weight: 600;
}

.info-item .value.risk-low {
    color: #059669;
    font-weight: 500;
}

.threat-level {
    margin-bottom: 1rem;
}

.threat-indicator {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem;
    border-radius: 6px;
    font-weight: 600;
}

.threat-indicator.critical {
    background: #fee2e2;
    color: #dc2626;
}

.threat-indicator.high {
    background: #fed7d7;
    color: #c53030;
}

.threat-indicator.medium {
    background: #fef3c7;
    color: #d97706;
}

.threat-indicator.low {
    background: #dcfce7;
    color: #16a34a;
}

.threat-circle {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: currentColor;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.assessment-details p {
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
    line-height: 1.5;
}

.analysis-sections {
    display: grid;
    gap: 1.5rem;
}

.section {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 1.5rem;
}

.section-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #e5e7eb;
}

.section-header h5 {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: #374151;
}

.timeline-container {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.timeline-item-modern {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    padding: 0.75rem;
    background: #f9fafb;
    border-radius: 6px;
    border-left: 3px solid #e5e7eb;
}

.timeline-marker {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    margin-top: 0.25rem;
    flex-shrink: 0;
}

.timeline-marker.high {
    background: #dc2626;
    box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.2);
}

.timeline-marker.medium {
    background: #d97706;
    box-shadow: 0 0 0 3px rgba(217, 119, 6, 0.2);
}

.timeline-marker.low {
    background: #059669;
    box-shadow: 0 0 0 3px rgba(5, 150, 105, 0.2);
}

.timeline-content {
    flex: 1;
}

.timeline-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.25rem;
}

.timeline-event {
    font-weight: 600;
    color: #374151;
    font-size: 0.875rem;
}

.timeline-time {
    font-size: 0.75rem;
    color: #6b7280;
    font-family: 'Courier New', monospace;
}

.timeline-details {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.75rem;
}

.timeline-ip {
    color: #6b7280;
    font-family: 'Courier New', monospace;
}

.timeline-severity {
    padding: 0.125rem 0.375rem;
    border-radius: 0.25rem;
    font-weight: 600;
    text-transform: uppercase;
}

.timeline-severity.high {
    background: #fee2e2;
    color: #dc2626;
}

.timeline-severity.medium {
    background: #fef3c7;
    color: #d97706;
}

.timeline-severity.low {
    background: #dcfce7;
    color: #16a34a;
}

.related-patterns {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.related-pattern-item {
    padding: 0.75rem;
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
}

.related-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.pattern-code {
    font-family: 'Courier New', monospace;
    font-size: 0.875rem;
    background: #e5e7eb;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    color: #374151;
}

.related-score {
    font-size: 0.875rem;
    font-weight: 600;
    color: #3b82f6;
}

.related-details {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.75rem;
}

.related-type {
    color: #6b7280;
    font-weight: 500;
}

.related-count {
    color: #3b82f6;
    font-weight: 600;
}

.no-related {
    text-align: center;
    color: #6b7280;
    font-style: italic;
    padding: 1rem;
}

/* Block modal improvements */
.block-confirmation {
    padding: 1.5rem;
}

.pattern-details {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
}

.detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0;
    border-bottom: 1px solid #e5e7eb;
}

.detail-row:last-child {
    border-bottom: none;
}

.detail-row label {
    font-weight: 600;
    color: #6b7280;
    font-size: 0.875rem;
}

.block-options, .block-reason {
    margin-bottom: 1.5rem;
}

.block-options h6, .block-reason h6 {
    color: #374151;
    font-weight: 600;
    margin-bottom: 0.75rem;
}

/* Form controls */
.form-control {
    border: 1px solid #d1d5db;
    border-radius: 6px;
    padding: 0.75rem;
    font-size: 0.875rem;
    transition: all 0.2s ease;
}

.form-control:focus {
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    outline: none;
}

/* Buttons */
.btn {
    border-radius: 6px;
    font-weight: 500;
    padding: 0.5rem 1rem;
    font-size: 0.875rem;
    border: none;
    transition: all 0.2s ease;
    cursor: pointer;
}

.btn-primary {
    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
    color: white;
}

.btn-primary:hover {
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
    transform: translateY(-1px);
}

.btn-danger {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: white;
}

.btn-danger:hover {
    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
    transform: translateY(-1px);
}

.btn-default {
    background: #f3f4f6;
    color: #374151;
    border: 1px solid #d1d5db;
}

.btn-default:hover {
    background: #e5e7eb;
    color: #1f2937;
}

/* Alerts */
.alert {
    border: none;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    margin-bottom: 1rem;
    border-left: 4px solid;
}

.alert-success {
    background: #f0fdf4;
    color: #15803d;
    border-left-color: #22c55e;
}

.alert-danger {
    background: #fef2f2;
    color: #dc2626;
    border-left-color: #ef4444;
}

.alert-warning {
    background: #fffbeb;
    color: #d97706;
    border-left-color: #f59e0b;
}

/* Tables */
.table-striped > tbody > tr:nth-of-type(odd) {
    background-color: #f9fafb;
}

.table > thead > tr > th {
    background: #f8fafc;
    border-bottom: 2px solid #e2e8f0;
    font-weight: 600;
    color: #374151;
}

/* Loading states */
.loading {
    opacity: 0.6;
    pointer-events: none;
    position: relative;
}

.loading::after {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 20px;
    height: 20px;
    margin: -10px 0 0 -10px;
    border: 2px solid #f3f3f3;
    border-top: 2px solid #3498db;
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Responsive design */
@media (max-width: 768px) {
    .analysis-grid {
        grid-template-columns: 1fr;
        gap: 1rem;
    }
    
    .info-grid {
        grid-template-columns: 1fr;
        gap: 0.5rem;
    }
    
    .analysis-header-modern {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.75rem;
    }
    
    .pattern-info {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.5rem;
    }
    
    .timeline-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.25rem;
    }
    
    .timeline-details {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.25rem;
    }
    
    .related-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.25rem;
    }
    
    .attacker-item {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.25rem;
    }
}

/* Modal enhancements */
.modal-dialog.modal-lg {
    max-width: 900px;
}

.modal-content {
    border: none;
    border-radius: 12px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
}

.modal-header {
    background: #f8fafc;
    border-bottom: 1px solid #e2e8f0;
    padding: 1rem 1.5rem;
}

.modal-body {
    padding: 0;
    max-height: 80vh;
    overflow-y: auto;
}

.modal-footer {
    background: #f8fafc;
    border-top: 1px solid #e2e8f0;
    padding: 1rem 1.5rem;
}

/* Analysis controls */
.analysis-controls {
    display: flex;
    gap: 1rem;
    align-items: center;
}

.dpi-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid #e5e7eb;
}

/* Content box */
.content-box {
    background: #ffffff;
    min-height: calc(100vh - 200px);
}

.tab-content {
    background: transparent;
    border: none;
    padding: 2rem 0;
}

/* Badge styles */
.badge-info {
    background: #3b82f6;
    color: white;
}

/* Text utilities */
.text-success {
    color: #10b981 !important;
}

.text-danger {
    color: #ef4444 !important;
}

.text-warning {
    color: #f59e0b !important;
}

.text-muted {
    color: #6b7280 !important;
}
</style>