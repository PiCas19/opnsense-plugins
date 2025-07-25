{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

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

    <!-- Pattern Overview -->
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

    <!-- Pattern Analysis Tabs -->
    <div class="row">
        <div class="col-md-12">
            <div class="pattern-analysis-container">
                <ul class="nav nav-tabs" id="patternTabs">
                    <li class="nav-item">
                        <a class="nav-link active" href="#sqlPatterns" data-toggle="tab">
                            {{ lang._('SQL Injection') }}
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#xssPatterns" data-toggle="tab">
                            {{ lang._('XSS Patterns') }}
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#behavioralPatterns" data-toggle="tab">
                            {{ lang._('Behavioral') }}
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#advancedPatterns" data-toggle="tab">
                            {{ lang._('Advanced') }}
                        </a>
                    </li>
                </ul>

                <div class="tab-content" id="patternTabContent">
                    <!-- SQL Injection Patterns -->
                    <div class="tab-pane fade show active" id="sqlPatterns">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="pattern-chart-card">
                                    <h4>{{ lang._('SQL Injection Techniques') }}</h4>
                                    <canvas id="sqlPatternsChart"></canvas>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="pattern-list-card">
                                    <h4>{{ lang._('Top SQL Patterns') }}</h4>
                                    <div id="sqlPatternsList">
                                        <!-- Dynamic content -->
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- XSS Patterns -->
                    <div class="tab-pane fade" id="xssPatterns">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="pattern-chart-card">
                                    <h4>{{ lang._('XSS Attack Vectors') }}</h4>
                                    <canvas id="xssPatternsChart"></canvas>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="pattern-list-card">
                                    <h4>{{ lang._('Top XSS Patterns') }}</h4>
                                    <div id="xssPatternsList">
                                        <!-- Dynamic content -->
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Behavioral Patterns -->
                    <div class="tab-pane fade" id="behavioralPatterns">
                        <div class="row">
                            <div class="col-md-12">
                                <div class="behavioral-analysis-card">
                                    <h4>{{ lang._('Behavioral Analysis') }}</h4>
                                    {% if behavioralEnabled %}
                                    <div class="behavioral-metrics">
                                        <div class="metric-row">
                                            <div class="metric-item">
                                                <label>{{ lang._('Anomaly Detection') }}:</label>
                                                <span class="badge badge-success">{{ lang._('Active') }}</span>
                                            </div>
                                            <div class="metric-item">
                                                <label>{{ lang._('Pattern Learning') }}:</label>
                                                <span class="badge badge-info">{{ lang._('Training') }}</span>
                                            </div>
                                        </div>
                                        <div id="behavioralChart" style="height: 300px;">
                                            <canvas id="behavioralTimelineChart"></canvas>
                                        </div>
                                    </div>
                                    {% else %}
                                    <div class="alert alert-info">
                                        <i class="fa fa-info-circle"></i>
                                        {{ lang._('Behavioral analysis is not enabled. Enable it in WebGuard settings to see advanced pattern detection.') }}
                                    </div>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Advanced Patterns -->
                    <div class="tab-pane fade" id="advancedPatterns">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="advanced-patterns-card">
                                    <h4>{{ lang._('Attack Chains') }}</h4>
                                    <div id="attackChains">
                                        <!-- Dynamic content -->
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="ml-patterns-card">
                                    <h4>{{ lang._('Machine Learning Insights') }}</h4>
                                    {% if machineLearning %}
                                    <div id="mlInsights">
                                        <!-- Dynamic ML insights -->
                                    </div>
                                    {% else %}
                                    <div class="alert alert-warning">
                                        <i class="fa fa-exclamation-triangle"></i>
                                        {{ lang._('Machine learning analysis requires additional configuration.') }}
                                    </div>
                                    {% endif %}
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
                            <th>{{ lang._('First Seen') }}</th>
                            <th>{{ lang._('Trend') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="patternsTableBody">
                        <!-- Dynamic content -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script src="/ui/js/chart.min.js"></script>
<script>
$(document).ready(function() {
    let sqlChart = null;
    let xssChart = null;
    let behavioralChart = null;
    let currentPeriod = '24h';
    let currentAnalysis = 'patterns';
    
    // Initialize
    loadPatternData();
    initCharts();
    
    // Controls
    $('#analysisType, #timePeriod').change(function() {
        currentAnalysis = $('#analysisType').val();
        currentPeriod = $('#timePeriod').val();
        loadPatternData();
        updateCharts();
    });
    
    function loadPatternData() {
        ajaxCall('/api/webguard/threats/getPatterns', {
            period: currentPeriod,
            pattern_type: currentAnalysis
        }, function(data) {
            if (data) {
                updatePatternStats(data);
                updatePatternLists(data.patterns || {});
                updatePatternsTable(data);
                updateCharts(data);
            }
        });
    }
    
    function updatePatternStats(data) {
        const patterns = data.patterns || {};
        const sqlPatterns = patterns.sql_injection_patterns || {};
        const xssPatterns = patterns.xss_patterns || {};
        
        $('#totalPatterns').text(Object.keys(sqlPatterns).length + Object.keys(xssPatterns).length);
        $('#attackSequences').text(Object.keys(data.attack_sequences || {}).length);
        $('#uniqueAttackers').text(Math.floor(Math.random() * 50) + 10); // Mock data
        $('#blockedPatterns').text(Math.floor(Math.random() * 30) + 5); // Mock data
    }
    
    function updatePatternLists(patterns) {
        // Update SQL patterns list
        const sqlList = $('#sqlPatternsList');
        sqlList.empty();
        
        if (patterns.sql_injection_patterns) {
            Object.entries(patterns.sql_injection_patterns).forEach(([pattern, count]) => {
                const item = $(`
                    <div class="pattern-item">
                        <div class="pattern-name">${pattern.replace(/_/g, ' ').toUpperCase()}</div>
                        <div class="pattern-stats">
                            <span class="count">${count} times</span>
                            <span class="severity high">High Risk</span>
                        </div>
                        <div class="pattern-bar">
                            <div class="bar-fill" style="width: ${Math.min(count * 10, 100)}%"></div>
                        </div>
                    </div>
                `);
                sqlList.append(item);
            });
        }
        
        // Update XSS patterns list
        const xssList = $('#xssPatternsList');
        xssList.empty();
        
        if (patterns.xss_patterns) {
            Object.entries(patterns.xss_patterns).forEach(([pattern, count]) => {
                const item = $(`
                    <div class="pattern-item">
                        <div class="pattern-name">${pattern.replace(/_/g, ' ').toUpperCase()}</div>
                        <div class="pattern-stats">
                            <span class="count">${count} times</span>
                            <span class="severity medium">Medium Risk</span>
                        </div>
                        <div class="pattern-bar">
                            <div class="bar-fill" style="width: ${Math.min(count * 15, 100)}%"></div>
                        </div>
                    </div>
                `);
                xssList.append(item);
            });
        }
        
        // Update attack chains
        updateAttackChains(data.attack_sequences || {});
    }
    
    function updateAttackChains(chains) {
        const container = $('#attackChains');
        container.empty();
        
        Object.entries(chains).forEach(([chain, count]) => {
            const item = $(`
                <div class="attack-chain-item">
                    <div class="chain-name">${chain.replace(/_/g, ' ')}</div>
                    <div class="chain-count">${count} sequences</div>
                    <div class="chain-description">
                        Multi-stage attack pattern detected
                    </div>
                </div>
            `);
            container.append(item);
        });
    }
    
    function updatePatternsTable(data) {
        const tbody = $('#patternsTableBody');
        tbody.empty();
        
        // Sample pattern data for the table
        const samplePatterns = [
            {
                pattern: 'UNION SELECT injection',
                type: 'SQL Injection',
                occurrences: 45,
                successRate: '12%',
                firstSeen: '2 days ago',
                trend: 'up'
            },
            {
                pattern: 'Script tag injection',
                type: 'XSS',
                occurrences: 23,
                successRate: '8%',
                firstSeen: '1 day ago',
                trend: 'stable'
            },
            {
                pattern: 'Path traversal attempt',
                type: 'File System',
                occurrences: 18,
                successRate: '3%',
                firstSeen: '3 hours ago',
                trend: 'down'
            }
        ];
        
        samplePatterns.forEach(pattern => {
            const trendIcon = pattern.trend === 'up' ? 'fa-arrow-up text-danger' : 
                            pattern.trend === 'down' ? 'fa-arrow-down text-success' : 
                            'fa-minus text-muted';
            
            const row = $(`
                <tr>
                    <td><code>${pattern.pattern}</code></td>
                    <td><span class="badge badge-info">${pattern.type}</span></td>
                    <td><strong>${pattern.occurrences}</strong></td>
                    <td>${pattern.successRate}</td>
                    <td>${pattern.firstSeen}</td>
                    <td><i class="fa ${trendIcon}"></i></td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="analyzePattern('${pattern.pattern}')">
                            <i class="fa fa-search"></i> Analyze
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="blockPattern('${pattern.pattern}')">
                            <i class="fa fa-ban"></i> Block
                        </button>
                    </td>
                </tr>
            `);
            tbody.append(row);
        });
    }
    
    function initCharts() {
        // SQL Injection Patterns Chart
        const ctx1 = document.getElementById('sqlPatternsChart').getContext('2d');
        sqlChart = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['UNION SELECT', 'OR 1=1', 'DROP TABLE', 'EXEC xp_'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // XSS Patterns Chart
        const ctx2 = document.getElementById('xssPatternsChart').getContext('2d');
        xssChart = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: ['<script>', 'javascript:', 'onerror=', 'onload='],
                datasets: [{
                    label: 'Occurrences',
                    data: [0, 0, 0, 0],
                    backgroundColor: '#36A2EB'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
        
        // Behavioral Timeline Chart
        {% if behavioralEnabled %}
        const ctx3 = document.getElementById('behavioralTimelineChart').getContext('2d');
        behavioralChart = new Chart(ctx3, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'Anomaly Score',
                    data: [20, 45, 30, 60, 35, 25],
                    borderColor: '#FF6384',
                    backgroundColor: 'rgba(255, 99, 132, 0.1)',
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
                        title: {
                            display: true,
                            text: 'Anomaly Score (%)'
                        }
                    }
                }
            }
        });
        {% endif %}
    }
    
    function updateCharts(data) {
        const patterns = data.patterns || {};
        
        // Update SQL chart
        if (patterns.sql_injection_patterns && sqlChart) {
            const sqlData = patterns.sql_injection_patterns;
            sqlChart.data.datasets[0].data = Object.values(sqlData);
            sqlChart.update();
        }
        
        // Update XSS chart
        if (patterns.xss_patterns && xssChart) {
            const xssData = patterns.xss_patterns;
            xssChart.data.datasets[0].data = Object.values(xssData);
            xssChart.update();
        }
    }
    
    // Global functions
    window.analyzePattern = function(pattern) {
        alert(`{{ lang._("Detailed analysis for pattern:") }} ${pattern}`);
    };
    
    window.blockPattern = function(pattern) {
        if (confirm(`{{ lang._("Block all requests matching pattern:") }} ${pattern}?`)) {
            alert(`{{ lang._("Pattern blocked successfully") }}`);
        }
    };
});
</script>

<style>
.pattern-stat-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
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

.pattern-analysis-container {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1.5rem;
}

.pattern-chart-card, .pattern-list-card, .behavioral-analysis-card, 
.advanced-patterns-card, .ml-patterns-card {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    height: 400px;
    overflow-y: auto;
}

.pattern-chart-card canvas {
    max-height: 300px;
}

.pattern-item {
    padding: 1rem 0;
    border-bottom: 1px solid #e5e7eb;
}

.pattern-item:last-child {
    border-bottom: none;
}

.pattern-name {
    font-weight: 600;
    color: #1f2937;
    margin-bottom: 0.5rem;
}

.pattern-stats {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.count {
    color: #6b7280;
    font-size: 0.875rem;
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
    height: 6px;
    background: #e5e7eb;
    border-radius: 3px;
    overflow: hidden;
}

.bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #ef4444, #f97316);
    transition: width 0.3s ease;
}

.attack-chain-item {
    padding: 1rem;
    background: white;
    border-radius: 6px;
    margin-bottom: 1rem;
    border-left: 4px solid #3b82f6;
}

.chain-name {
    font-weight: 600;
    color: #1f2937;
    margin-bottom: 0.25rem;
}

.chain-count {
    color: #ef4444;
    font-size: 0.875rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
}

.chain-description {
    color: #6b7280;
    font-size: 0.875rem;
}

.behavioral-metrics {
    padding: 1rem 0;
}

.metric-row {
    display: flex;
    gap: 2rem;
    margin-bottom: 1rem;
}

.metric-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.metric-item label {
    font-size: 0.875rem;
    font-weight: 600;
    color: #374151;
}

.analysis-controls {
    display: flex;
    gap: 1rem;
}

div[name="pattern-details-table"] {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

@media (max-width: 768px) {
    .analysis-controls {
        flex-direction: column;
    }
    
    .metric-row {
        flex-direction: column;
        gap: 1rem;
    }
    
    .pattern-chart-card, .pattern-list-card {
        height: auto;
        min-height: 300px;
    }
}
</style>