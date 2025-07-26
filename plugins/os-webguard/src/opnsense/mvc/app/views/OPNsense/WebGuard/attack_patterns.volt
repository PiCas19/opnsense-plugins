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
        apiData: {
            threats_by_type: {},
            anomalies: [],
            blockedPatterns: new Set()
        },
        mlModels: {
            anomalyDetector: { name: 'Isolation Forest', accuracy: 0, lastTrained: null, status: 'inactive' },
            patternClassifier: { name: 'Random Forest Classifier', accuracy: 0, lastTrained: null, status: 'inactive' },
            sequencePredictor: { name: 'LSTM Neural Network', accuracy: 0, lastTrained: null, status: 'inactive' }
        },
        mlData: {
            trainingSet: [],
            predictions: [],
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
        loadRealData();
        initCharts();
        setupEventListeners();
    }

    // Load real data (placeholder for your method)
    function loadRealData() {
        // Placeholder: Replace with your real data source (e.g., API call or getStats method)
        // Example: const realData = getStats(); // Assume this returns real data
        const realData = {
            threats_by_type: {
                'SQL Injection': { patterns: {}, count: 0 },
                'XSS Attack': { patterns: {}, count: 0 }
            },
            anomalies: [],
            blockedPatterns: []
        };
        updateStateWithRealData(realData);
    }

    // Update state with real data
    function updateStateWithRealData(data) {
        state.apiData.threats_by_type = data.threats_by_type || {};
        state.apiData.anomalies = data.anomalies || [];
        state.apiData.blockedPatterns = new Set(data.blockedPatterns || []);
        updatePatternStats(state.apiData);
        updatePatternsTable(state.apiData);
        updateSQLPatterns();
        updateXSSPatterns();
        updateBehavioralPatterns();
        updateMLPatterns();
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
        loadRealData(); // Reload data based on new period
        initCharts();
    }

    // Handle tab switching
    function handleTabSwitch(e) {
        const targetTab = $(e.target).attr('href').replace('#', ');
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
    }

    // Update pattern stats
    function updatePatternStats(data) {
        const threatsByType = data.threats_by_type || {};
        const totalPatterns = Object.values(threatsByType).reduce((sum, type) => sum + (type.count || 0), 0);
        const uniqueAttackers = data.uniqueAttackers || 0; // Replace with real data
        const blockedPatterns = data.blockedPatterns.size || 0;

        $('#totalPatterns').text(totalPatterns);
        $('#attackSequences').text(data.attackSequences || 0); // Replace with real data
        $('#uniqueAttackers').text(uniqueAttackers);
        $('#blockedPatterns').text(blockedPatterns);
    }

    // Update SQL patterns
    function updateSQLPatterns() {
        const container = $('#sqlPatternsList').empty();
        const sqlData = state.apiData.threats_by_type['SQL Injection']?.patterns || {};

        if (Object.keys(sqlData).length === 0) {
            container.append($('<p>').addClass('text-center text-muted').text('No SQL patterns detected'));
            return;
        }

        Object.entries(sqlData).forEach(([name, count]) => {
            const item = $('<div>').addClass('pattern-item');
            item.append($('<div>').text(`${name}: ${count} occurrences`));
            container.append(item);
        });
    }

    // Update XSS patterns
    function updateXSSPatterns() {
        const container = $('#xssPatternsList').empty();
        const xssData = state.apiData.threats_by_type['XSS Attack']?.patterns || {};

        if (Object.keys(xssData).length === 0) {
            container.append($('<p>').addClass('text-center text-muted').text('No XSS patterns detected'));
            return;
        }

        Object.entries(xssData).forEach(([name, count]) => {
            const item = $('<div>').addClass('pattern-item');
            item.append($('<div>').text(`${name}: ${count} occurrences`));
            container.append(item);
        });
    }

    // Update behavioral patterns
    function updateBehavioralPatterns() {
        $('#behavioralContent').empty().append(
            $('<div>').text('Behavioral analysis data will be populated with real data.')
        );
    }

    // Update ML patterns
    function updateMLPatterns() {
        $('#mlContent').empty().append(
            $('<div>').text('ML analysis data will be populated with real data.')
        );
    }

    // Update patterns table
    function updatePatternsTable(data) {
        const tbody = $('#patternsTableBody').empty();
        const threatsByType = data.threats_by_type || {};

        Object.entries(threatsByType).forEach(([type, info]) => {
            const count = info.count || 0;
            const row = $('<tr>');
            row.append(
                $('<td>').append($('<code>').text(type.toLowerCase().replace(/\s/g, '_') + '_pattern')),
                $('<td>').append($('<span>').addClass('badge badge-info').text(type)),
                $('<td>').append($('<strong>').text(count)),
                $('<td>').text('N/A'), // Replace with real success rate
                $('<td>').text('N/A'), // Replace with real first seen
                $('<td>').append($('<i>').addClass('fa fa-arrow-right')),
                $('<td>').append(
                    $('<button>').addClass('btn btn-sm btn-primary analyze-btn').append(
                        $('<i>').addClass('fa fa-search'),
                        ' Analyze'
                    ).data('pattern', type),
                    $('<button>').addClass('btn btn-sm btn-danger block-btn').append(
                        $('<i>').addClass('fa fa-ban'),
                        ' Block'
                    ).data('pattern', type)
                )
            );

            tbody.append(row);
        });

        if (!Object.keys(threatsByType).length) {
            tbody.append($('<tr>').append($('<td>').attr('colspan', 7).addClass('text-center text-muted').text('No patterns detected for current period')));
        }

        // Add event listeners for dynamic buttons
        $('.analyze-btn').off('click').on('click', function() {
            const pattern = $(this).data('pattern');
            analyzePattern(pattern);
        });
        $('.block-btn').off('click').on('click', function() {
            const pattern = $(this).data('pattern');
            blockPattern(pattern);
        });
    }

    // Initialize charts
    function initCharts() {
        const sqlData = state.apiData.threats_by_type['SQL Injection']?.patterns || {};
        const xssData = state.apiData.threats_by_type['XSS Attack']?.patterns || {};

        if (Object.keys(sqlData).length > 0) {
            const ctx = document.getElementById('sqlPatternsChart')?.getContext('2d');
            if (ctx && charts.sql) charts.sql.destroy();
            charts.sql = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(sqlData),
                    datasets: [{ data: Object.values(sqlData), backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56'] }]
                },
                options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
            });
        }

        if (Object.keys(xssData).length > 0) {
            const ctx = document.getElementById('xssPatternsChart')?.getContext('2d');
            if (ctx && charts.xss) charts.xss.destroy();
            charts.xss = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(xssData),
                    datasets: [{ label: 'Attack Count', data: Object.values(xssData), backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56'] }]
                },
                options: { responsive: true, scales: { y: { beginAtZero: true } } }
            });
        }
    }

    // Analyze pattern function (awaiting real data)
    window.analyzePattern = function(pattern) {
        console.log(`🔍 Analyzing pattern: ${pattern} at 01:48 PM CEST, July 26, 2025`);
        // Placeholder: Replace with real data from your method
        const analysis = {
            occurrences: 0,
            successRate: 0,
            severity: 'Unknown',
            anomalies: [],
            mlConfidence: 0
        };
        alert(`Analyzing ${pattern}:\n\nOccurrences: ${analysis.occurrences}\nSuccess Rate: ${analysis.successRate}%\nSeverity: ${analysis.severity}\nAnomalies: ${analysis.anomalies.length}\nML Confidence: ${analysis.mlConfidence}%`);
    };

    // Block pattern function (awaiting real data)
    window.blockPattern = function(pattern) {
        if (confirm(`Block all future requests matching pattern: ${pattern}?`)) {
            console.log(`🚫 Blocking pattern: ${pattern} at 01:48 PM CEST, July 26, 2025`);
            const button = event.target;
            button.disabled = true;
            button.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Blocking...';

            setTimeout(() => {
                // Placeholder: Update with real blocking logic
                state.apiData.blockedPatterns.add(pattern);
                alert(`Pattern "${pattern}" blocked successfully.`);
                button.disabled = false;
                button.innerHTML = '<i class="fa fa-ban"></i> Block';
                updatePatternsTable(state.apiData);
                updateSQLPatterns();
                updateXSSPatterns();
            }, 2000);
        }
    };

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
    height: auto; /* Remove fixed height */
    min-height: 300px;
}

.pattern-chart-card canvas {
    max-height: 300px !important; /* Ensure canvas doesn't stretch */
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

.metric-value {
    margin-bottom: 0.5rem;
}

.value-number {
    font-size: 1.5rem;
    font-weight: bold;
    color: #1f2937;
    display: block;
}

.value-label {
    font-size: 0.875rem;
    color: #6b7280;
}

.metric-status {
    display: flex;
    justify-content: flex-start;
}

.chart-container {
    margin: 2rem 0;
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.5rem;
}

.chart-container h5 {
    margin-bottom: 1rem;
    color: #374151;
    font-weight: 600;
}

.chart-container canvas {
    max-height: 300px !important; /* Ensure canvas doesn't stretch */
    width: 100%;
}

.anomaly-list {
    margin-top: 2rem;
}

.anomaly-list h5 {
    margin-bottom: 1rem;
    color: #374151;
    font-weight: 600;
}

.anomaly-item {
    padding: 0.75rem;
    background: white;
    border-radius: 6px;
    margin-bottom: 0.5rem;
    border-left: 4px solid #f59e0b;
}

.anomaly-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.25rem;
}

.anomaly-type {
    font-weight: 600;
    color: #1f2937;
}

.anomaly-score {
    font-size: 0.875rem;
    color: #6b7280;
}

.anomaly-details {
    font-size: 0.875rem;
    color: #4b5563;
}

.anomaly-ip, .anomaly-time {
    margin-right: 1rem;
}

/* ML Dashboard Styles */
.ml-dashboard {
    padding: 1rem 0;
}

.ml-models-status, .ml-insights, .ml-predictions {
    margin-bottom: 2rem;
}

.models-grid, .insights-grid, .predictions-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
}

.model-card, .insight-card, .prediction-item {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.25rem;
    border-left: 4px solid #3b82f6;
}

.model-header, .insight-header, .prediction-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
    font-weight: 600;
    color: #374151;
}

.model-name, .insight-title, .prediction-type {
    flex-grow: 1;
}

.model-metrics, .insight-content, .prediction-content {
    font-size: 0.875rem;
    color: #4b5563;
}

.insight-confidence, .prediction-probability {
    font-weight: 600;
    color: #1f2937;
    margin-top: 0.5rem;
}

.prediction-time {
    font-size: 0.75rem;
    color: #6b7280;
}
</style>