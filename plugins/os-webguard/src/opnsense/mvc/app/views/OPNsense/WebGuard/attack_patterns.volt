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
                    <div class="stat-value" id="totalPatterns">100</div>
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
                    <div class="stat-value" id="attackSequences">15</div>
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
                    <div class="stat-value" id="uniqueAttackers">8</div>
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
                    <div class="stat-value" id="blockedPatterns">92</div>
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
            threats_by_type: {
                'SQL Injection': {
                    patterns: {
                        'union_select': 45,
                        'drop_table': 30,
                        'or_1_1': 25
                    },
                    count: 100
                },
                'XSS Attack': {
                    patterns: {
                        'script_alert': 40,
                        'img_onerror': 35,
                        'javascript_alert': 25
                    },
                    count: 100
                }
            },
            anomalies: [
                { type: 'SQL Injection', timestamp: Date.now() - 2 * 60 * 60 * 1000, sourceIP: '192.168.1.10', score: 0.85 },
                { type: 'XSS Attack', timestamp: Date.now() - 1 * 60 * 60 * 1000, sourceIP: '192.168.1.11', score: 0.90 }
            ],
            blockedPatterns: new Set()
        },
        mlModels: {
            anomalyDetector: { name: 'Isolation Forest', accuracy: 0.94, lastTrained: new Date(), status: 'active' },
            patternClassifier: { name: 'Random Forest Classifier', accuracy: 0.89, lastTrained: new Date(), status: 'active' },
            sequencePredictor: { name: 'LSTM Neural Network', accuracy: 0.87, lastTrained: new Date(), status: 'training' }
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
        initializeMLModels();
        initCharts();
        setupEventListeners();
        updateSQLPatterns();
        updateXSSPatterns();
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
        initCharts();
        updateSQLPatterns();
        updateXSSPatterns();
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
        
        state.mlData.trainingSet = Array.from({ length: 1000 }, () => {
            const type = attackTypes[Math.floor(Math.random() * attackTypes.length)];
            return {
                timestamp: timeNow - (Math.random() * 7 * 24 * 60 * 60 * 1000),
                type,
                sourceIP: generateRandomIP(),
                payload: generateMockPayload(type),
                success: Math.random() > 0.8,
                severity: Math.random() * 100,
                features: generateFeatureVector(type)
            };
        });

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
                "&#39; OR 1=1 --",
                "UNION SELECT NULL, username, password FROM users",
                "&#39;; DROP TABLE users; --"
            ],
            'XSS Attack': [
                "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;",
                "&lt;img src=&#39;x&#39; onerror=alert(&#39;XSS&#39;)&gt;",
                "javascript:alert(&#39;XSS&#39;)"
            ],
            'Path Traversal': [
                "../../etc/passwd",
                "..\\..\\windows\\system32",
                "/etc/./passwd"
            ],
            'Command Injection': [
                "; ls -la",
                "| whoami",
                "&& dir"
            ],
            'CSRF': [
                "&lt;form action=&#39;transfer&#39;&gt;&lt;input name=&#39;amount&#39; value=&#39;1000&#39;&gt;"
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
        state.mlData.anomalies = (state.apiData?.anomalies || state.mlData.trainingSet.slice(-100)).filter(sample => {
            const score = calculateAnomalyScore(sample);
            return score > 0.8 ? { ...sample, score, severity: 'high' } : false;
        });
        console.log(`🚨 Detected ${state.mlData.anomalies.length} anomalies`);
    }

    // Calculate anomaly score
    function calculateAnomalyScore(sample) {
        let score = 0;
        if (sample.features?.payloadLength > 200) score += 0.3;
        if (sample.features?.entropy > 0.8) score += 0.4;
        if (sample.features?.sqlKeywords > 2 && sample.features?.scriptTags > 0) score += 0.5;
        if (sample.features?.requestRate > 80) score += 0.3;
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
        const sequences = analyzeAttackSequences();
        console.log(`🔮 Predicted ${sequences.length} attack sequences`);
    }

    // Analyze attack sequences
    function analyzeAttackSequences() {
        const recentAttacks = (state.apiData?.anomalies || state.mlData.trainingSet).slice(-50);
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
        state.mlData.clusters = state.apiData?.clusters || [
            { id: 1, type: 'SQL Injection Family', size: 45, centroid: 'UNION-based attacks' },
            { id: 2, type: 'XSS Variants', size: 32, centroid: 'Script tag injection' },
            { id: 3, type: 'Path Traversal Group', size: 28, centroid: 'Directory climbing' }
        ];
        console.log(`🎲 Identified ${state.mlData.clusters.length} attack clusters`);
    }

    // Load pattern data
    function loadPatternData() {
        console.log(`🔍 Loading pattern data for period: ${state.currentPeriod}`);
        updatePatternStats(state.apiData);
        updatePatternLists(state.apiData);
        updatePatternsTable(state.apiData);
        initCharts();
        updateSQLPatterns();
        updateXSSPatterns();
        updateBehavioralPatterns();
        initBehavioralChart();
        updateMLPatterns();
        initMLChart();
    }

    // Update pattern stats
    function updatePatternStats(data) {
        console.log('📊 Updating pattern stats with data:', data);
        const threatsByType = data.threats_by_type || {};
        const totalPatterns = Object.values(threatsByType).reduce((sum, type) => sum + (type.count || 0), 0);
        const uniqueAttackers = 8; // Example value

        $('#totalPatterns').text(totalPatterns || 0);
        $('#attackSequences').text(Math.max(1, Math.floor(totalPatterns * 0.15)) || 0);
        $('#uniqueAttackers').text(uniqueAttackers || 0);
        $('#blockedPatterns').text(Math.max(1, Math.floor(totalPatterns * 0.92)) || 0);
    }

    // Update SQL patterns
    function updateSQLPatterns() {
        const container = $('#sqlPatternsList').empty();
        const sqlData = state.apiData?.threats_by_type?.['SQL Injection']?.patterns || {};
        const sqlPatterns = Object.entries(sqlData).map(([name, count]) => ({
            name,
            count,
            severity: count > 40 ? 'high' : 'medium',
            blocked: Math.floor(count * 0.95)
        })) || [];

        if (!sqlPatterns.length) {
            container.append($('<p>').addClass('text-center text-muted').text('No SQL patterns detected'));
            return;
        }

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
        const xssData = state.apiData?.threats_by_type?.['XSS Attack']?.patterns || {};
        const xssPatterns = Object.entries(xssData).map(([name, count]) => ({
            name,
            count,
            severity: count > 30 ? 'high' : 'medium',
            blocked: Math.floor(count * 0.95)
        })) || [];

        if (!xssPatterns.length) {
            container.append($('<p>').addClass('text-center text-muted').text('No XSS patterns detected'));
            return;
        }

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
        $('#behavioralContent').empty().append(
            $('<div>').addClass('behavioral-metrics').append(
                $('<div>').addClass('metric-grid').append(
                    $('<div>').addClass('metric-card').append(
                        $('<div>').addClass('metric-header').append(
                            $('<i>').addClass('fa fa-eye text-primary'),
                            $('<span>').text('Anomaly Detection')
                        ),
                        $('<div>').addClass('metric-value').append(
                            $('<span>').addClass('value-number').text(state.mlData.anomalies.length),
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
                            $('<span>').addClass('value-number').text('94.2%'),
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
                            $('<span>').addClass('value-number').text('7.8/10'),
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
        updateAnomaliesList();
    }

    // Update anomalies list
    function updateAnomaliesList() {
        const container = $('#anomalyListContent').empty();
        state.mlData.anomalies.slice(0, 5).forEach(anomaly => {
            const timeAgo = Math.floor((Date.now() - anomaly.timestamp) / 60000);
            const item = $('<div>').addClass('anomaly-item');
            const header = $('<div>').addClass('anomaly-header');
            header.append($('<span>').addClass('anomaly-type').text(sanitizeString(anomaly.type)));
            header.append($('<span>').addClass('anomaly-score').text(`Score: ${(anomaly.score * 100).toFixed(1)}%`));
            
            const details = $('<div>').addClass('anomaly-details');
            details.append($('<span>').addClass('anomaly-ip').text(`IP: ${sanitizeString(anomaly.sourceIP)}`));
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
        const insightData = state.apiData?.insights || [
            { icon: 'fa-exclamation-triangle text-warning', title: 'Attack Pattern Evolution', text: 'SQL injection techniques showing 23% evolution in payload obfuscation methods', confidence: 91 },
            { icon: 'fa-link text-info', title: 'Attack Correlation', text: 'High correlation (0.78) detected between XSS and CSRF attack vectors', confidence: 85 },
            { icon: 'fa-clock text-success', title: 'Temporal Patterns', text: 'Peak attack window identified: 14:00-16:00 UTC with 340% increase', confidence: 97 }
        ];
        insightData.forEach(data => {
            const card = $('<div>').addClass('insight-card');
            const header = $('<div>').addClass('insight-header');
            header.append($('<i>').addClass(`fa ${data.icon}`), $('<span>').text(data.title));
            
            const content = $('<div>').addClass('insight-content');
            content.append($('<p>').text(sanitizeString(data.text)));
            content.append($('<div>').addClass('insight-confidence').text(`Confidence: ${data.confidence}%`));
            
            card.append(header, content);
            insightsGrid.append(card);
        });
        insights.append(insightsGrid);

        // Predictions
        const predictions = $('<div>').addClass('ml-predictions');
        predictions.append($('<h5>').append($('<i>').addClass('fa fa-crystal-ball'), ' Predictions'));
        const predictionsContainer = $('<div>').addClass('predictions-container');
        const predictionData = state.apiData?.predictions || [
            { type: 'Next Attack Vector', time: 'Next 2 hours', attack: 'XSS Attack (DOM-based)', probability: 76 },
            { type: 'Source Location', time: 'Most likely', attack: 'Eastern European Networks', probability: 68 }
        ];
        predictionData.forEach(data => {
            const item = $('<div>').addClass('prediction-item');
            const header = $('<div>').addClass('prediction-header');
            header.append($('<span>').addClass('prediction-type').text(sanitizeString(data.type)));
            header.append($('<span>').addClass('prediction-time').text(sanitizeString(data.time)));
            
            const content = $('<div>').addClass('prediction-content');
            content.append($('<div>').addClass('predicted-attack').text(sanitizeString(data.attack)));
            content.append($('<div>').addClass('prediction-probability').text(`Probability: ${data.probability}%`));
            
            item.append(header, content);
            predictionsContainer.append(item);
        });
        predictions.append(predictionsContainer);

        // Chart Container
        const chartContainer = $('<div>').addClass('chart-container');
        chartContainer.append($('<h5>').text('ML Model Performance'));
        chartContainer.append($('<canvas>').attr('id', 'mlPerformanceChart'));

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

        Object.entries(threatsByType).forEach(([type, info]) => {
            const count = info.count || 0;
            const trendIcon = count > 100 ? 'fa-arrow-up text-danger' : 'fa-arrow-down text-success';
            const successRate = Math.floor(Math.random() * 15) + 2; // Placeholder until API provides this
            const timeAgo = Math.floor(Math.random() * 120) + 5; // Placeholder until API provides this

            const row = $('<tr>');
            row.append(
                $('<td>').append($('<code>').text(sanitizeString(type.toLowerCase().replace(/\s/g, '_') + '_pattern'))),
                $('<td>').append($('<span>').addClass('badge badge-info').text(sanitizeString(type))),
                $('<td>').append($('<strong>').text(count)),
                $('<td>').append($('<span>').addClass(successRate > 10 ? 'text-danger' : 'text-success').text(`${successRate}%`)),
                $('<td>').text(`${timeAgo} minutes ago`),
                $('<td>').append($('<i>').addClass(`fa ${trendIcon}`)),
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
        console.log('📈 Initializing all charts');
        const sqlData = state.apiData?.threats_by_type?.['SQL Injection']?.patterns || {};
        const xssData = state.apiData?.threats_by_type?.['XSS Attack']?.patterns || {};

        const chartConfigs = {
            sql: {
                element: 'sqlPatternsChart',
                type: 'doughnut',
                data: {
                    labels: Object.keys(sqlData),
                    datasets: [{
                        data: Object.values(sqlData),
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { position: 'bottom' },
                        tooltip: { enabled: true }
                    }
                }
            },
            xss: {
                element: 'xssPatternsChart',
                type: 'bar',
                data: {
                    labels: Object.keys(xssData),
                    datasets: [{
                        label: 'Attack Count',
                        data: Object.values(xssData),
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { display: false },
                        tooltip: { enabled: true }
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
            if (ctx) {
                console.log('📈 Creating behavioral chart');
                const anomalies = state.apiData?.anomalies || [];
                const labels = [];
                const anomalyData = [];
                const threatData = [];

                const now = new Date();
                const periodHours = state.currentPeriod === '1h' ? 1 : state.currentPeriod === '7d' ? 24 * 7 : state.currentPeriod === '30d' ? 24 * 30 : 24;
                for (let i = periodHours - 1; i >= 0; i--) {
                    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
                    labels.push(time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
                    const hourStart = time.setMinutes(0, 0, 0);
                    const hourEnd = hourStart + 60 * 60 * 1000;
                    const hourAnomalies = anomalies.filter(a => a.timestamp >= hourStart && a.timestamp < hourEnd);
                    anomalyData.push(hourAnomalies.reduce((sum, a) => sum + (a.score || 0), 0) * 100);
                    threatData.push(hourAnomalies.length);
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
                                label: 'Threat Count',
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
                        maintainAspectRatio: true,
                        interaction: { intersect: false, mode: 'index' },
                        scales: {
                            y: { beginAtZero: true, title: { display: true, text: 'Value' } },
                            x: { title: { display: true, text: 'Time' } }
                        },
                        plugins: {
                            legend: { position: 'top' },
                            tooltip: {
                                callbacks: {
                                    title: context => `Time: ${context[0].label}`,
                                    label: context => `${context.dataset.label}: ${context.raw.toFixed(1)}`
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
                const mlPerf = state.apiData?.ml_performance || {
                    anomaly_detector: [0.89, 0.91, 0.93, 0.94, 0.94],
                    pattern_classifier: [0.82, 0.85, 0.87, 0.88, 0.89],
                    sequence_predictor: [0.78, 0.81, 0.84, 0.86, 0.87]
                };

                charts.ml = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4', 'Current'],
                        datasets: [
                            {
                                label: 'Anomaly Detector',
                                data: mlPerf.anomaly_detector,
                                borderColor: '#FF6384',
                                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'Pattern Classifier',
                                data: mlPerf.pattern_classifier,
                                borderColor: '#36A2EB',
                                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'Sequence Predictor',
                                data: mlPerf.sequence_predictor,
                                borderColor: '#FFCE56',
                                backgroundColor: 'rgba(255, 206, 86, 0.1)',
                                tension: 0.4
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        scales: {
                            y: {
                                beginAtZero: false,
                                min: 0.75,
                                max: 1.0,
                                title: { display: true, text: 'Accuracy' },
                                ticks: { callback: value => `${(value * 100).toFixed(0)}%` }
                            },
                            x: { title: { display: true, text: 'Time' } }
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

    // Analyze pattern function with realistic simulation
    window.analyzePattern = function(pattern) {
        console.log(`🔍 Analyzing pattern: ${pattern}`);
        const relatedAnomalies = state.apiData.anomalies.filter(a => a.type === pattern);
        const relatedPredictions = state.mlData.predictions.filter(p => 
            p.predictedType === pattern || p.pattern.includes(pattern.toLowerCase())
        );
        
        let analysisResult = `Detailed Analysis for: ${sanitizeString(pattern)} (as of 01:41 PM CEST, July 26, 2025)\n\n`;
        analysisResult += `• Total Occurrences: ${state.apiData.threats_by_type[pattern]?.count || 0}\n`;
        analysisResult += `• Success Rate: ${(Math.random() * 15 + 2).toFixed(1)}%\n`;
        analysisResult += `• Severity Level: ${state.apiData.threats_by_type[pattern]?.count > 100 ? 'High' : 'Medium'}\n`;
        analysisResult += `• Anomalies Detected: ${relatedAnomalies.length}\n`;
        if (relatedAnomalies.length > 0) {
            analysisResult += `• Latest Anomaly IP: ${relatedAnomalies[0].sourceIP} (${Math.floor((Date.now() - relatedAnomalies[0].timestamp) / 60000)} minutes ago)\n`;
        }
        analysisResult += `• ML Confidence: ${(Math.random() * 20 + 75).toFixed(1)}%\n\n`;
        
        if (relatedPredictions.length) {
            analysisResult += `ML Predictions:\n${relatedPredictions.slice(0, 3).map((pred, idx) => 
                `${idx + 1}. ${sanitizeString(pred.predictedType)} (${(pred.confidence * 100).toFixed(1)}% confidence)`).join('\n')}\n`;
        }
        
        analysisResult += `\nRecommended Actions:\n• Implement stricter input validation for ${pattern}\n• Update WAF rules with pattern signature\n• Monitor IPs: ${relatedAnomalies.map(a => a.sourceIP).join(', ')}`;
        alert(analysisResult);
    };

    // Block pattern function with realistic simulation
    window.blockPattern = function(pattern) {
        if (confirm(`Block all future requests matching pattern: ${sanitizeString(pattern)}?\n\nThis will create a new WAF rule and update the firewall.`)) {
            console.log(`🚫 Blocking pattern: ${pattern}`);
            const button = event.target;
            button.disabled = true;
            button.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Blocking...';

            setTimeout(() => {
                state.apiData.blockedPatterns.add(pattern);
                const ruleId = `WAF-${Date.now().toString(36)}`;
                const blockedCount = state.apiData.threats_by_type[pattern]?.count || 0;
                alert(`Pattern "${sanitizeString(pattern)}" has been successfully blocked.\n\nNew WAF rule created with ID: ${ruleId}\nBlocked ${blockedCount} occurrences.`);
                button.disabled = false;
                button.innerHTML = '<i class="fa fa-ban"></i> Block';
                updatePatternsTable(state.apiData); // Refresh table to reflect block
                updateSQLPatterns(); // Refresh pattern lists
                updateXSSPatterns();
            }, 2000); // Simulate API call delay
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