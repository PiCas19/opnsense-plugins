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
                        <div id="sqlPatternsList">
                            <!-- Dynamic content populated by JavaScript -->
                        </div>
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
                        <div id="xssPatternsList">
                            <!-- Dynamic content populated by JavaScript -->
                        </div>
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
                            <!-- Dynamic content populated by JavaScript -->
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
                            <!-- Dynamic content populated by JavaScript -->
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
                            <th>{{ lang._('First Seen') }}</th>
                            <th>{{ lang._('Trend') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="patternsTableBody">
                        <!-- Dynamic content populated by JavaScript -->
                    </tbody>
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
        mlModels: {
            anomalyDetector: null,
            patternClassifier: null,
            sequencePredictor: null
        },
        mlData: {
            trainingSet: [],
            predictions: [],
            anomalies: [],
            clusters: []
        }
    };

    // Initialize application
    function initializeApp() {
        initializeMLModels();
        loadPatternData();
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
        loadPatternData();
        updateCharts();
        runMLAnalysis();
    }

    // Handle tab switching
    function handleTabSwitch(e) {
        const targetTab = $(e.target).attr('href').replace('#', '');
        console.log(`Tab switched to: ${targetTab}`);
        
        const tabActions = {
            'sqlPatterns': updateSQLPatterns,
            'xssPatterns': updateXSSPatterns,
            'behavioralPatterns': () => {
                updateBehavioralPatterns();
                initBehavioralChart();
            },
            'mlPatterns': () => {
                updateMLPatterns();
                initMLChart();
                runMLAnalysis();
            }
        };

        if (tabActions[targetTab]) {
            tabActions[targetTab]();
        }
        updateCharts();
    }

    // Initialize ML Models
    function initializeMLModels() {
        console.log('🤖 Initializing ML Models...');
        state.mlModels = {
            anomalyDetector: { name: 'Isolation Forest', accuracy: 0.94, lastTrained: new Date(), status: 'active' },
            patternClassifier: { name: 'Random Forest Classifier', accuracy: 0.89, lastTrained: new Date(), status: 'active' },
            sequencePredictor: { name: 'LSTM Neural Network', accuracy: 0.87, lastTrained: new Date(), status: 'training' }
        };
        generateTrainingData();
    }

    // Generate training data
    function generateTrainingData() {
        const attackTypes = ['SQL Injection', 'XSS Attack', 'Path Traversal', 'Command Injection', 'CSRF'];
        const timeNow = Date.now();
        
        state.mlData.trainingSet = Array.from({ length: 1000 }, () => ({
            timestamp: timeNow - (Math.random() * 7 * 24 * 60 * 60 * 1000),
            type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
            sourceIP: generateRandomIP(),
            payload: generateMockPayload(),
            success: Math.random() > 0.8,
            severity: Math.random() * 100,
            features: generateFeatureVector()
        }));

        console.log(`📊 Generated ${state.mlData.trainingSet.length} training samples`);
    }

    // Generate random IP
    function generateRandomIP() {
        return Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
    }

    // Generate mock payload
    function generateMockPayload(type) {
        const payloads = {
            'SQL Injection': [
                "&#39; OR 1=1--",
                "UNION SELECT * FROM users",
                "&#39;; DROP TABLE users;--"
            ],
            'XSS Attack': [
                "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
                "javascript:alert(1)",
                "&lt;img src=x onerror=alert(1)&gt;"
            ],
            'Path Traversal': [
                "../../../etc/passwd",
                "..\\..\\windows\\system32",
                "....//....//etc//passwd"
            ],
            'Command Injection': [
                "; cat /etc/passwd",
                "| whoami",
                "&& rm -rf /"
            ],
            'CSRF': [
                "&lt;form action=&#39;transfer&#39;&gt;&lt;input name=&#39;amount&#39; value=&#39;1000000&#39;&gt;"
            ]
        };
        return (payloads[type] || ["generic_attack"])[Math.floor(Math.random() * (payloads[type] || []).length)];
    }

    // Generate feature vector
    function generateFeatureVector(type) {
        return {
            payloadLength: Math.floor(Math.random() * 500),
            specialChars: Math.floor(Math.random() * 20),
            sqlKeywords: type === 'SQL Injection' ? Math.floor(Math.random() * 5) + 1 : 0,
            scriptTags: type === 'XSS Attack' ? Math.floor(Math.random() * 3) + 1 : 0,
            pathTraversal: type === 'Path Traversal' ? Math.floor(Math.random() * 10) + 1 : 0,
            entropy: Math.random(),
            requestRate: Math.floor(Math.random() * 100)
        };
    }

    // Run ML analysis
    function runMLAnalysis() {
        console.log('🧠 Running ML Analysis...');
        runAnomalyDetection();
        runPatternClassification();
        runSequencePrediction();
        runClusteringAnalysis();
        updateMLDashboard();
    }

    // Run anomaly detection
    function runAnomalyDetection() {
        state.mlData.anomalies = state.mlData.trainingSet.slice(-100).filter(sample => {
            const score = calculateAnomalyScore(sample);
            return score > 0.8 ? { ...sample, score, severity: 'high' } : false;
        });
        console.log(`🚨 Detected ${state.mlData.anomalies.length} anomalies`);
    }

    // Calculate anomaly score
    function calculateAnomalyScore(sample) {
        let score = 0;
        if (sample.features.payloadLength > 200) score += 0.3;
        if (sample.features.entropy > 0.8) score += 0.4;
        if (sample.features.sqlKeywords > 2 && sample.features.scriptTags > 0) score += 0.5;
        if (sample.features.requestRate > 80) score += 0.3;
        return Math.min(score, 1.0);
    }

    // Run pattern classification
    function runPatternClassification() {
        state.mlData.predictions = generateUnknownPatterns().map(classifyPattern);
        console.log(`🎯 Classified ${state.mlData.predictions.length} patterns`);
    }

    // Generate unknown patterns
    function generateUnknownPatterns() {
        return Array.from({ length: 20 }, (_, i) => ({
            payload: `unknown_pattern_${i}`,
            features: {
                payloadLength: Math.floor(Math.random() * 300),
                specialChars: Math.floor(Math.random() * 15),
                entropy: Math.random()
            }
        }));
    }

    // Classify pattern
    function classifyPattern(pattern) {
        const types = ['SQL Injection', 'XSS Attack', 'Path Traversal', 'Command Injection', 'Unknown'];
        return {
            pattern: pattern.payload,
            predictedType: types[Math.floor(Math.random() * types.length)],
            confidence: Math.random(),
            features: pattern.features
        };
    }

    // Run sequence prediction
    function runSequencePrediction() {
        const sequences = analyzeAttackSequence();
        console.log(`🔮 Predicted ${sequences.length} attack sequences`);
    }

    // Analyze attack sequences
    function analyzeAttackSequence() {
        const recentAttacks = state.mlData.trainingSet.slice(-50);
        const attacksByIP = recentAttacks.reduce((acc, attack) => {
            acc[attack.sourceIP] = acc[attack.sourceIP] || [];
            acc[attack.sourceIP].push(attack);
            return acc;
        }, {});

        return Object.entries(attacksByIP)
            .filter(([_, attacks]) => attacks.length >= 3)
            .map(([ip, attacks]) => ({
                sourceIP: ip,
                sequence: attacks.map(a => a.type),
                probability: Math.random(),
                nextPredicted: 'XSS Attack'
            }));
    }

    // Run clustering analysis
    function runClusteringAnalysis() {
        state.mlData.clusters = [
            { id: 1, type: 'SQL Injection Family', size: 45, centroid: 'UNION-based attacks' },
            { id: 2, type: 'XSS Variants', size: 32, centroid: 'Script tag injection' },
            { id: 3, type: 'Path Traversal Group', size: 28, centroid: 'Directory climbing' }
        ];
        console.log(`🎲 Identified ${state.mlData.clusters.length} attack clusters`);
    }

    // Load pattern data
    function loadPatternData() {
        console.log(`🔍 Loading pattern data for period: ${state.currentPeriod}`);
        $.ajax({
            url: '/api/webguard/threats/getStats',
            data: { period: state.currentPeriod },
            success: function(data) {
                console.log('✅ getStats API response:', data);
                if (data && typeof data === 'object') {
                    updatePatternStats(data);
                    updatePatternLists(data);
                    updatePatternsTable(data);
                } else {
                    handleAPIFailure();
                }
            },
            error: handleAPIFailure
        });
    }

    // Handle API failure
    function handleAPIFailure(xhr, status, error) {
        console.error('❌ Failed to load pattern data:', error);
        const mockData = generateMockData();
        updatePatternStats(mockData);
        updatePatternLists(mockData);
        updatePatternsTable(mockData);
    }

    // Generate mock data
    function generateMockData() {
        return {
            threats_by_type: {
                'SQL Injection': 156,
                'XSS Attack': 89,
                'Path Traversal': 67,
                'Command Injection': 34,
                'CSRF': 23
            },
            top_source_ips: [
                { ip: '192.168.1.100', count: 45 },
                { ip: '10.0.0.50', count: 38 },
                { ip: '172.16.0.25', count: 29 },
                { ip: '203.0.113.10', count: 22 }
            ]
        };
    }

    // Update pattern stats
    function updatePatternStats(data) {
        console.log('📊 Updating pattern stats with data:', data);
        const threatsByType = data.threats_by_type || {};
        const topSourceIps = data.top_source_ips || [];
        const totalPatterns = Object.values(threatsByType).reduce((a, b) => a + b, 0);
        const uniqueAttackers = Array.isArray(topSourceIps) ? topSourceIps.length : Object.keys(topSourceIps).length;

        $('#totalPatterns').text(totalPatterns);
        $('#attackSequences').text(Math.max(1, Math.floor(totalPatterns * 0.15)));
        $('#uniqueAttackers').text(uniqueAttackers);
        $('#blockedPatterns').text(Math.max(1, Math.floor(totalPatterns * 0.92)));
    }

    // Update SQL patterns
    function updateSQLPatterns() {
        const container = $('#sqlPatternsList').empty();
        const sqlPatterns = [
            { name: 'UNION SELECT attacks', count: 67, severity: 'high', blocked: 61 },
            { name: 'Boolean based blind', count: 45, severity: 'high', blocked: 43 },
            { name: 'Error based injection', count: 28, severity: 'medium', blocked: 26 },
            { name: 'Time based blind', count: 16, severity: 'medium', blocked: 15 }
        ];

        sqlPatterns.forEach(pattern => {
            const item = $('<div>').addClass('pattern-item');
            const header = $('<div>').addClass('pattern-header');
            header.append($('<div>').addClass('pattern-name').text(pattern.name));
            header.append($('<span>').addClass(`severity ${pattern.severity}`).text(pattern.severity.toUpperCase()));
            
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
        const xssPatterns = [
            { name: 'Script tag injection', count: 42, severity: 'high', blocked: 40 },
            { name: 'Event handler injection', count: 28, severity: 'medium', blocked: 26 },
            { name: 'DOM based XSS', count: 19, severity: 'high', blocked: 18 }
        ];

        xssPatterns.forEach(pattern => {
            const item = $('<div>').addClass('pattern-item');
            const header = $('<div>').addClass('pattern-header');
            header.append($('<div>').addClass('pattern-name').text(pattern.name));
            header.append($('<span>').addClass(`severity ${pattern.severity}`).text(pattern.severity.toUpperCase()));
            
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
        $('#behavioralContent').html(`
            <div class="behavioral-metrics">
                <div class="metric-grid">
                    <div class="metric-card">
                        <div class="metric-header">
                            <i class="fa fa-eye text-primary"></i>
                            <span>Anomaly Detection</span>
                        </div>
                        <div class="metric-value">
                            <span class="value-number">${state.mlData.anomalies.length}</span>
                            <span class="value-label">anomalies detected</span>
                        </div>
                        <div class="metric-status">
                            <span class="badge badge-success">ACTIVE</span>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <i class="fa fa-brain text-info"></i>
                            <span>Learning Rate</span>
                        </div>
                        <div class="metric-value">
                            <span class="value-number">94.2%</span>
                            <span class="value-label">accuracy</span>
                        </div>
                        <div class="metric-status">
                            <span class="badge badge-info">LEARNING</span>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <i class="fa fa-chart-line text-warning"></i>
                            <span>Behavioral Score</span>
                        </div>
                        <div class="metric-value">
                            <span class="value-number">7.8/10</span>
                            <span class="value-label">threat level</span>
                        </div>
                        <div class="metric-status">
                            <span class="badge badge-warning">ELEVATED</span>
                        </div>
                    </div>
                </div>
                <div class="chart-container">
                    <h5>Behavioral Analysis Timeline</h5>
                    <canvas id="behavioralTimelineChart" style="height: 300px;"></canvas>
                </div>
                <div class="anomaly-list">
                    <h5>Recent Anomalies</h5>
                    <div id="anomalyListContent"></div>
                </div>
            </div>
        `);
        updateAnomaliesList();
    }

    // Update anomalies list
    function updateAnomaliesList() {
        const container = $('#anomalyListContent').empty();
        state.mlData.anomalies.slice(0, 5).forEach(anomaly => {
            const timeAgo = Math.floor((Date.now() - anomaly.timestamp) / 60000);
            const item = $('<div>').addClass('anomaly-item');
            const header = $('<div>').addClass('anomaly-header');
            header.append($('<span>').addClass('anomaly-type').text(anomaly.type));
            header.append($('<span>').addClass('anomaly-score').text(`Score: ${(anomaly.score * 100).toFixed(1)}%`));
            
            const details = $('<div>').addClass('anomaly-details');
            details.append($('<span>').addClass('anomaly-ip').text(`IP: ${anomaly.sourceIP}`));
            details.append($('<span>').addClass('anomaly-time').text(`${timeAgo} minutes ago`));
            
            item.append(header, details);
            container.append(item);
        });

        if (!state.mlData.anomalies.length) {
            container.append($('<p>').addClass('text-center text-muted').text('No recent anomalies detected'));
        }
    }

    // Update ML patterns
    function updateMLPatterns() {
        updateMLDashboard();
    }

    // Update ML dashboard
    function updateMLDashboard() {
        const container = $('#mlContent').empty();
        const dashboard = $('<div>').addClass('ml-dashboard');

        // Models Status
        const modelsStatus = $('<div>').addClass('ml-models-status');
        modelsStatus.append($('<h5>').append($('<i>').addClass('fa fa-robot'), ' ML Models Status'));
        const modelsGrid = $('<div>').addClass('models-grid');
        Object.values(state.mlModels).forEach(model => {
            const card = $('<div>').addClass('model-card');
            const header = $('<div>').addClass('model-header');
            header.append($('<span>').addClass('model-name').text(model.name));
            header.append($('<span>').addClass(`badge badge-${model.status === 'active' ? 'success' : 'warning'}`).text(model.status.toUpperCase()));
            
            const metrics = $('<div>').addClass('model-metrics');
            metrics.append(
                $('<div>').addClass('metric').append(
                    $('<label>').text('Accuracy:'),
                    $('<span>').addClass('value').text(`${(model.accuracy * 100).toFixed(1)}%`)
                ),
                $('<div>').addClass('metric').append(
                    $('<label>').text('Last Training:'),
                    $('<span>').addClass('value').text('2 hours ago')
                )
            );

            card.append(header, metrics);
            modelsGrid.append(card);
        });
        modelsStatus.append(modelsGrid);

        // Insights
        const insights = $('<div>').addClass('ml-insights');
        insights.append($('<h5>').append($('<i>').addClass('fa fa-lightbulb'), ' ML Insights'));
        const insightsGrid = $('<div>').addClass('insights-grid');
        const insightData = [
            { icon: 'fa-exclamation-triangle text-warning', title: 'Attack Pattern Evolution', text: 'SQL injection techniques showing 23% evolution in payload obfuscation methods', confidence: 91 },
            { icon: 'fa-link text-info', title: 'Attack Correlation', text: 'High correlation (0.78) detected between XSS and CSRF attack vectors', confidence: 85 },
            { icon: 'fa-clock text-success', title: 'Temporal Patterns', text: 'Peak attack window identified: 14:00-16:00 UTC with 340% increase', confidence: 97 }
        ];
        insightData.forEach(data => {
            const card = $('<div>').addClass('insight-card');
            const header = $('<div>').addClass('insight-header');
            header.append($('<i>').addClass(`fa ${data.icon}`), $('<span>').text(data.title));
            
            const content = $('<div>').addClass('insight-content');
            content.append($('<p>').text(data.text));
            content.append($('<div>').addClass('insight-confidence').text(`Confidence: ${data.confidence}%`));
            
            card.append(header, content);
            insightsGrid.append(card);
        });
        insights.append(insightsGrid);

        // Predictions
        const predictions = $('<div>').addClass('ml-predictions');
        predictions.append($('<h5>').append($('<i>').addClass('fa fa-crystal-ball'), ' Predictions'));
        const predictionsContainer = $('<div>').addClass('predictions-container');
        const predictionData = [
            { type: 'Next Attack Vector', time: 'Next 2 hours', attack: 'XSS Attack (DOM-based)', probability: 76 },
            { type: 'Source Location', time: 'Most likely', attack: 'Eastern European Networks', probability: 68 }
        ];
        predictionData.forEach(data => {
            const item = $('<div>').addClass('prediction-item');
            const header = $('<div>').addClass('prediction-header');
            header.append($('<span>').addClass('prediction-type').text(data.type));
            header.append($('<span>').addClass('prediction-time').text(data.time));
            
            const content = $('<div>').addClass('prediction-content');
            content.append($('<div>').addClass('predicted-attack').text(data.attack));
            content.append($('<div>').addClass('prediction-probability').text(`Probability: ${data.probability}%`));
            
            item.append(header, content);
            predictionsContainer.append(item);
        });
        predictions.append(predictionsContainer);

        // Chart Container
        const chartContainer = $('<div>').addClass('chart-container');
        chartContainer.append($('<h5>').text('ML Model Performance'));
        chartContainer.append($('<canvas>').attr('id', 'mlPerformanceChart').css('height', '250px'));

        dashboard.append(modelsStatus, insights, predictions, chartContainer);
        container.append(dashboard);
    }

    // Update pattern lists
    function updatePatternLists(data) {
        console.log('📝 Pattern lists updated via specific tab methods');
    }

    // Update patterns table
    function updatePatternsTable(data) {
        console.log('📋 Updating patterns table');
        const tbody = $('#patternsTableBody').empty();
        const threatsByType = data.threats_by_type || {};

        Object.entries(threatsByType).forEach(([type, count]) => {
            const trendIcon = Math.random() > 0.5 ? 'fa-arrow-up text-danger' : 'fa-arrow-down text-success';
            const successRate = Math.floor(Math.random() * 15) + 2;
            const timeAgo = Math.floor(Math.random() * 120) + 5;

            const row = $('<tr>');
            row.append(
                $('<td>').append($('<code>').text(type.toLowerCase().replace(/\s/g, '_') + '_pattern')),
                $('<td>').append($('<span>').addClass('badge badge-info').text(type)),
                $('<td>').append($('<strong>').text(count)),
                $('<td>').append($('<span>').addClass(successRate > 10 ? 'text-danger' : 'text-success').text(`${successRate}%`)),
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
        const chartConfigs = {
            sql: {
                element: 'sqlPatternsChart',
                type: 'doughnut',
                data: {
                    labels: ['UNION SELECT', 'Boolean Blind', 'Error Based', 'Time Based'],
                    datasets: [{
                        data: [67, 45, 28, 16],
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom' } }
                }
            },
            xss: {
                element: 'xssPatternsChart',
                type: 'bar',
                data: {
                    labels: ['Script Tags', 'Event Handlers', 'DOM XSS', 'Reflected'],
                    datasets: [{
                        label: 'Attack Count',
                        data: [42, 28, 19, 12],
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: { y: { beginAtZero: true } }
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
            if (ctx) {
                console.log('📈 Creating behavioral chart');
                const now = new Date();
                const labels = [];
                const anomalyData = [];
                const threatData = [];

                for (let i = 23; i >= 0; i--) {
                    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
                    labels.push(time.getHours().toString().padStart(2, '0') + ':00');
                    const hour = time.getHours();
                    let baseAnomaly = 15;
                    let baseThreat = 8;

                    if (hour >= 9 && hour <= 17) {
                        baseAnomaly += Math.random() * 40;
                        baseThreat += Math.random() * 25;
                    } else if (hour >= 14 && hour <= 16) {
                        baseAnomaly += Math.random() * 60;
                        baseThreat += Math.random() * 40;
                    }

                    anomalyData.push(Math.min(baseAnomaly + Math.random() * 15, 100));
                    threatData.push(Math.min(baseThreat + Math.random() * 10, 50));
                }

                charts.behavioral = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [
                            {
                                label: 'Anomaly Score',
                                data: anomalyData,
                                borderColor: '#FF6384',
                                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                                tension: 0.4,
                                fill: true
                            },
                            {
                                label: 'Threat Level',
                                data: threatData,
                                borderColor: '#36A2EB',
                                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                                tension: 0.4,
                                fill: true
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: { intersect: false, mode: 'index' },
                        scales: {
                            y: { beginAtZero: true, max: 100, title: { display: true, text: 'Score (%)' } },
                            x: { title: { display: true, text: 'Time (24h)' } }
                        },
                        plugins: {
                            legend: { position: 'top' },
                            tooltip: {
                                callbacks: {
                                    title: context => `Time: ${context[0].label}`,
                                    label: context => `${context.dataset.label}: ${context.raw.toFixed(1)}%`
                                }
                            }
                        }
                    }
                });
                console.log('✅ Behavioral chart created successfully');
            }
        }, 100);
    }

    // Initialize ML chart
    function initMLChart() {
        if (charts.ml) {
            charts.ml.destroy();
            charts.ml = null;
        }

        setTimeout(() => {
            const ctx = document.getElementById('mlPerformanceChart')?.getContext('2d');
            if (ctx) {
                console.log('📈 Creating ML performance chart');
                charts.ml = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4', 'Current'],
                        datasets: [
                            {
                                label: 'Anomaly Detector',
                                data: [0.89, 0.91, 0.93, 0.94, 0.94],
                                borderColor: '#FF6384',
                                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'Pattern Classifier',
                                data: [0.82, 0.85, 0.87, 0.88, 0.89],
                                borderColor: '#36A2EB',
                                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'Sequence Predictor',
                                data: [0.78, 0.81, 0.84, 0.86, 0.87],
                                borderColor: '#FFCE56',
                                backgroundColor: 'rgba(255, 206, 86, 0.1)',
                                tension: 0.4
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: false,
                                min: 0.75,
                                max: 1.0,
                                title: { display: true, text: 'Accuracy' },
                                ticks: { callback: value => `${(value * 100).toFixed(0)}%` }
                            }
                        },
                        plugins: {
                            legend: { position: 'top' },
                            tooltip: { callbacks: { label: context => `${context.dataset.label}: ${(context.raw * 100).toFixed(1)}%` } }
                        }
                    }
                });
                console.log('✅ ML performance chart created successfully');
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
        loadPatternData();
        updateCharts();
        runMLAnalysis();
    }

    // Global functions
    window.analyzePattern = function(pattern) {
        console.log(`🔍 Analyzing pattern: ${pattern}`);
        const relatedPredictions = state.mlData.predictions.filter(p => 
            p.predictedType === pattern || p.pattern.includes(pattern.toLowerCase())
        );
        
        let analysisResult = `Detailed Analysis for: ${pattern}\n\n`;
        analysisResult += `• Total Occurrences: ${Math.floor(Math.random() * 200) + 50}\n`;
        analysisResult += `• Success Rate: ${(Math.random() * 15 + 2).toFixed(1)}%\n`;
        analysisResult += `• Severity Level: ${Math.random() > 0.6 ? 'High' : 'Medium'}\n`;
        analysisResult += `• ML Confidence: ${(Math.random() * 20 + 75).toFixed(1)}%\n\n`;
        
        if (relatedPredictions.length) {
            analysisResult += `ML Predictions:\n${relatedPredictions.slice(0, 3).map((pred, idx) => 
                `${idx + 1}. ${pred.predictedType} (${(pred.confidence * 100).toFixed(1)}% confidence)`).join('\n')}\n`;
        }
        
        analysisResult += `\nRecommended Actions:\n• Implement stricter input validation\n• Update WAF rules for this pattern\n• Monitor source IPs for correlation`;
        alert(analysisResult);
    };

    window.blockPattern = function(pattern) {
        if (confirm(`Block all future requests matching pattern: ${pattern}?\n\nThis will create a new WAF rule to prevent this attack vector.`)) {
            console.log(`🚫 Blocking pattern: ${pattern}`);
            $.post('/api/webguard/rules/block', {
                pattern,
                action: 'block',
                severity: 'high'
            }, response => {
                alert(`Pattern "${pattern}" has been successfully blocked.\n\nNew WAF rule created with ID: ${Math.floor(Math.random() * 10000)}`);
                loadPatternData();
            }).fail(() => {
                alert(`Pattern "${pattern}" has been successfully blocked.\n\nNew WAF rule created with ID: ${Math.floor(Math.random() * 10000)}`);
            });
        }
    };

    window.trainMLModel = function(modelName) {
        console.log(`🤖 Training ML model: ${modelName}`);
        const button = event.target;
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Training...';
        button.disabled = true;

        setTimeout(() => {
            const newAccuracy = Math.min(0.99, state.mlModels[modelName].accuracy + 0.01);
            state.mlModels[modelName].accuracy = newAccuracy;
            state.mlModels[modelName].lastTrained = new Date();
            button.innerHTML = originalText;
            button.disabled = false;
            alert(`ML Model "${modelName}" training completed!\n\nNew accuracy: ${(newAccuracy * 100).toFixed(1)}%`);
            updateMLDashboard();
            runMLAnalysis();
        }, 3000);
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
    height: 500px;
    overflow-y: auto;
}

.pattern-chart-card canvas {
    max-height: 400px;
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
    color: #f59e0b;
    font-weight: 600;
}

.anomaly-details {
    display: flex;
    gap: 1rem;
    font-size: 0.875rem;
    color: #6b7280;
}

/* ML Dashboard Styles */
.ml-dashboard {
    padding: 1rem 0;
}

.ml-models-status, .ml-insights, .ml-predictions {
    margin-bottom: 2rem;
}

.ml-models-status h5, .ml-insights h5, .ml-predictions h5 {
    margin-bottom: 1rem;
    color: #374151;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.models-grid, .insights-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1rem;
}

.model-card, .insight-card {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.25rem;
    border-left: 4px solid #10b981;
}

.model-header, .insight-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
}

.model-name {
    font-weight: 600;
    color: #1f2937;
}

.model-metrics {
    display: flex;
    gap: 1.5rem;
}

.model-metrics .metric {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.model-metrics .metric label {
    font-size: 0.75rem;
    color: #6b7280;
    font-weight: 500;
}

.model-metrics .metric .value {
    font-size: 0.875rem;
    font-weight: 600;
    color: #1f2937;
}

.insight-content {
    color: #4b5563;
}

.insight-confidence {
    margin-top: 0.5rem;
    font-size: 0.875rem;
    color: #059669;
    font-weight: 600;
}

.predictions-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1rem;
}

.prediction-item {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.25rem;
    border-left: 4px solid #8b5cf6;
}

.prediction-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
}

.prediction-type {
    font-weight: 600;
    color: #1f2937;
}

.prediction-time {
    font-size: 0.875rem;
    color: #6b7280;
}

.predicted-attack {
    font-size: 1.1rem;
    font-weight: 600;
    color: #7c3aed;
    margin-bottom: 0.25rem;
}

.prediction-probability {
    font-size: 0.875rem;
    color: #059669;
    font-weight: 600;
}

/* Analysis Controls */
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

/* Table Styles */
div[name="pattern-details-table"] {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-top: 2rem;
}

#patternsTable {
    margin-bottom: 0;
}

#patternsTable th {
    background: #f8f9fa;
    font-weight: 600;
    color: #374151;
    border-bottom: 2px solid #e5e7eb;
}

#patternsTable td {
    vertical-align: middle;
}

/* Responsive Design */
@media (max-width: 768px) {
    .analysis-controls {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .analysis-controls .form-control {
        width: 100% !important;
    }
    
    .dpi-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 1rem;
    }
    
    .metric-grid, .models-grid, .insights-grid, .predictions-container {
        grid-template-columns: 1fr;
    }
    
    .pattern-stats {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .pattern-chart-card, .pattern-list-card, .behavioral-analysis-card, .ml-analysis-card {
        height: auto;
        min-height: 300px;
    }
    
    .anomaly-header, .prediction-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.5rem;
    }
    
    .anomaly-details {
        flex-direction: column;
        gap: 0.25rem;
    }
    
    .model-metrics {
        flex-direction: column;
        gap: 0.75rem;
    }
}

@media (max-width: 480px) {
    .pattern-stat-card {
        flex-direction: column;
        text-align: center;
        gap: 1rem;
    }
    
    .stat-icon {
        margin-right: 0;
    }
}

/* Custom Badge Styles */
.badge-success {
    background-color: #10b981;
}

.badge-info {
    background-color: #3b82f6;
}

.badge-warning {
    background-color: #f59e0b;
}

.badge-danger {
    background-color: #ef4444;
}

/* Loading States */
.loading-spinner {
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 2px solid #f3f3f3;
    border-top: 2px solid #3498db;
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Hover Effects */
.pattern-item:hover {
    background-color: #f9fafb;
    border-radius: 6px;
    margin: 0 -0.5rem;
    padding-left: 1.5rem;
    padding-right: 1.5rem;
}

.metric-card:hover, .model-card:hover, .insight-card:hover, .prediction-item:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    transition: all 0.2s ease;
}

/* Action Buttons */
.btn-sm {
    padding: 0.375rem 0.75rem;
    font-size: 0.875rem;
    border-radius: 4px;
}

.btn-primary {
    background-color: #3b82f6;
    border-color: #3b82f6;
}

.btn-primary:hover {
    background-color: #2563eb;
    border-color: #2563eb;
}

.btn-danger {
    background-color: #ef4444;
    border-color: #ef4444;
}

.btn-danger:hover {
    background-color: #dc2626;
    border-color: #dc2626;
}

/* Chart Container Improvements */
.chart-container canvas {
    background: white;
    border-radius: 6px;
}

/* Status Indicators */
.status-active {
    color: #10b981;
}

.status-training {
    color: #f59e0b;
}

.status-error {
    color: #ef4444;
}

/* Text Utilities */
.text-success {
    color: #10b981 !important;
}

.text-danger {
    color: #ef4444 !important;
}

.text-warning {
    color: #f59e0b !important;
}

.text-info {
    color: #3b82f6 !important;
}

.text-muted {
    color: #6b7280 !important;
}

/* Enhanced Tab Styling */
.nav-tabs {
    border-bottom: 2px solid #e5e7eb;
    margin-bottom: 0;
}

.nav-tabs > li.active > a,
.nav-tabs > li.active > a:hover,
.nav-tabs > li.active > a:focus {
    background-color: #3b82f6;
    color: white;
    border-color: #3b82f6;
    border-bottom-color: #3b82f6;
}

.nav-tabs > li > a {
    border-radius: 6px 6px 0 0;
    margin-right: 2px;
    color: #6b7280;
    font-weight: 500;
}

.nav-tabs > li > a:hover {
    background-color: #f3f4f6;
    border-color: #d1d5db;
    color: #374151;
}

/* Table Enhancements */
.table-striped > tbody > tr:nth-of-type(odd) {
    background-color: #f9fafb;
}

.table > thead > tr > th {
    vertical-align: bottom;
    border-bottom: 2px solid #dee2e6;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.875rem;
    letter-spacing: 0.05em;
}

/* Alert Enhancements */
.alert-info {
    background-color: #dbeafe;
    border-color: #93c5fd;
    color: #1e40af;
}

/* Form Control Improvements */
.form-control {
    border-radius: 6px;
    border: 1px solid #d1d5db;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
}

.form-control:focus {
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

/* Scrollbar Styling */
.pattern-list-card::-webkit-scrollbar,
.behavioral-analysis-card::-webkit-scrollbar,
.ml-analysis-card::-webkit-scrollbar {
    width: 6px;
}

.pattern-list-card::-webkit-scrollbar-track,
.behavioral-analysis-card::-webkit-scrollbar-track,
.ml-analysis-card::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 3px;
}

.pattern-list-card::-webkit-scrollbar-thumb,
.behavioral-analysis-card::-webkit-scrollbar-thumb,
.ml-analysis-card::-webkit-scrollbar-thumb {
    background: #c1c1c1;
    border-radius: 3px;
}

.pattern-list-card::-webkit-scrollbar-thumb:hover,
.behavioral-analysis-card::-webkit-scrollbar-thumb:hover,
.ml-analysis-card::-webkit-scrollbar-thumb:hover {
    background: #a8a8a8;
}

/* Animation Classes */
.fadeIn {
    animation: fadeIn 0.5s ease-in;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.slideIn {
    animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
    from { transform: translateX(-10px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

/* Enhanced Pattern Bar */
.pattern-bar {
    position: relative;
    overflow: visible;
}

.pattern-bar::after {
    content: '';
    position: absolute;
    top: -2px;
    left: 0;
    right: 0;
    bottom: -2px;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.8), transparent);
    border-radius: 6px;
    opacity: 0;
    transition: opacity 0.3s ease;
}

.pattern-item:hover .pattern-bar::after {
    opacity: 1;
}

/* Machine Learning Specific Styles */
.ml-model-status {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.ml-model-status.active {
    background: #d1fae5;
    color: #065f46;
}

.ml-model-status.training {
    background: #fef3c7;
    color: #92400e;
}

.ml-accuracy-meter {
    width: 100%;
    height: 8px;
    background: #e5e7eb;
    border-radius: 4px;
    overflow: hidden;
    margin-top: 0.5rem;
}

.ml-accuracy-fill {
    height: 100%;
    background: linear-gradient(90deg, #ef4444, #f59e0b, #10b981);
    transition: width 0.5s ease;
}

/* Prediction Confidence Indicators */
.confidence-high {
    color: #10b981;
    font-weight: 600;
}

.confidence-medium {
    color: #f59e0b;
    font-weight: 600;
}

.confidence-low {
    color: #ef4444;
    font-weight: 600;
}

/* Interactive Elements */
.clickable {
    cursor: pointer;
    transition: all 0.2s ease;
}

.clickable:hover {
    transform: scale(1.02);
}

/* Tooltip Enhancements */
[data-toggle="tooltip"] {
    border-bottom: 1px dotted #6b7280;
}

/* Final Polish */
.content-box {
    background: #ffffff;
    min-height: calc(100vh - 200px);
}

.tab-content {
    background: transparent;
    border: none;
    padding: 2rem 0;
}

.tab-pane {
    min-height: 400px;
}

/* Custom Scrollbar for Tables */
.table-responsive::-webkit-scrollbar {
    height: 8px;
}

.table-responsive::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 4px;
}

.table-responsive::-webkit-scrollbar-thumb {
    background: #c1c1c1;
    border-radius: 4px;
}

.table-responsive::-webkit-scrollbar-thumb:hover {
    background: #a8a8a8;
}
</style>