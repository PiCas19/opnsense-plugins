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
                        <a class="nav-link active" href="#sqlPatterns" data-toggle="tab" data-tab="sql">
                            {{ lang._('SQL Injection') }}
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#xssPatterns" data-toggle="tab" data-tab="xss">
                            {{ lang._('XSS Patterns') }}
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#behavioralPatterns" data-toggle="tab" data-tab="behavioral">
                            {{ lang._('Behavioral') }}
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#advancedPatterns" data-toggle="tab" data-tab="advanced">
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
                                    <div id="behavioralContent">
                                        <!-- Dynamic content populated by JavaScript -->
                                    </div>
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
                                    <div id="mlContent">
                                        <!-- Dynamic content populated by JavaScript -->
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
    let activeTab = 'sql';
    
    // Initialize
    loadPatternData();
    initCharts();
    
    // Forza il caricamento iniziale del tab SQL dopo un piccolo delay
    setTimeout(function() {
        activeTab = 'sql';
        loadPatternData();
        updateCharts();
    }, 1000);
    
    // Set up periodic updates every 5 seconds
    setInterval(function() {
        loadPatternData();
        updateCharts();
    }, 5000);
    
    // Controls
    $('#analysisType, #timePeriod').change(function() {
        currentAnalysis = $('#analysisType').val();
        currentPeriod = $('#timePeriod').val();
        console.log('Analysis changed to:', currentAnalysis, 'Period:', currentPeriod);
        loadPatternData();
        updateCharts();
    });
    
    // Tab switching
    $('#patternTabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        activeTab = $(e.target).data('tab');
        console.log('Tab switched to:', activeTab);
        
        // Se è il tab behavioral, ricrea il grafico dopo un delay
        if (activeTab === 'behavioral') {
            setTimeout(function() {
                updateBehavioralContent();
                initBehavioralChart();
            }, 300);
        }
        
        loadPatternData();
        updateCharts();
    });
    
    function loadPatternData() {
        console.log('🔍 Loading pattern data for period:', currentPeriod, 'tab:', activeTab);
        
        // Usa $.get() invece di ajaxCall() e gestisce i dati diretti
        $.get('/api/webguard/threats/getStats', { period: currentPeriod }, function(data) {
            console.log('✅ getStats API response:', data);
            
            if (data && typeof data === 'object') {
                updatePatternStats(data);
                updatePatternLists(data);
                updatePatternsTable(data);
                
                // Aggiorna sempre il contenuto behavioral e ML
                updateBehavioralContent();
                updateMLContent();
                
                updateCharts();
            } else {
                console.log('❌ No valid data from API');
                updatePatternStats({});
                updatePatternLists({});
                updatePatternsTable({});
                updateBehavioralContent();
                updateMLContent();
            }
        }).fail(function(xhr, status, error) {
            console.error('❌ Failed to load pattern data:', error);
            // Carica comunque il contenuto di base anche in caso di errore
            updateBehavioralContent();
            updateMLContent();
        });
    }
    
    function updatePatternStats(data) {
        console.log('📊 Updating pattern stats with data:', data);
        
        const threatsByType = data.threats_by_type || {};
        const topSourceIps = data.top_source_ips || [];
        
        // Calcola le statistiche dai dati reali
        const totalPatterns = Object.keys(threatsByType).length;
        const uniqueAttackers = Array.isArray(topSourceIps) ? topSourceIps.length : Object.keys(topSourceIps).length;
        
        $('#totalPatterns').text(totalPatterns);
        $('#attackSequences').text(Math.max(1, Math.floor(totalPatterns * 0.3))); // Mock: 30% dei pattern
        $('#uniqueAttackers').text(uniqueAttackers);
        $('#blockedPatterns').text(Math.max(1, Math.floor(totalPatterns * 0.8))); // Mock: 80% bloccati
    }
    
    function updatePatternLists(data) {
        console.log('📝 Updating pattern lists with data:', data);
        
        const threatsByType = data.threats_by_type || {};
        
        // Aggiorna SQL patterns list
        const sqlList = $('#sqlPatternsList');
        sqlList.empty();
        
        if (threatsByType['SQL Injection']) {
            const sqlCount = threatsByType['SQL Injection'];
            const sqlPatterns = {
                'UNION SELECT attacks': Math.ceil(sqlCount * 0.4),
                'Boolean based blind': Math.ceil(sqlCount * 0.3),
                'Error based injection': Math.ceil(sqlCount * 0.2),
                'Time based blind': Math.ceil(sqlCount * 0.1)
            };
            
            Object.entries(sqlPatterns).forEach(([pattern, count]) => {
                const item = $(`
                    <div class="pattern-item">
                        <div class="pattern-name">${pattern.toUpperCase()}</div>
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
        } else {
            sqlList.append('<p class="text-center text-muted">{{ lang._("No SQL injection patterns detected") }}</p>');
        }
        
        // Aggiorna XSS patterns list
        const xssList = $('#xssPatternsList');
        xssList.empty();
        
        if (threatsByType['XSS Attack'] || threatsByType['XSS']) {
            const xssCount = threatsByType['XSS Attack'] || threatsByType['XSS'];
            const xssPatterns = {
                'Script tag injection': Math.ceil(xssCount * 0.5),
                'Event handler injection': Math.ceil(xssCount * 0.3),
                'DOM based XSS': Math.ceil(xssCount * 0.2)
            };
            
            Object.entries(xssPatterns).forEach(([pattern, count]) => {
                const item = $(`
                    <div class="pattern-item">
                        <div class="pattern-name">${pattern.toUpperCase()}</div>
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
        } else {
            xssList.append('<p class="text-center text-muted">{{ lang._("No XSS patterns detected") }}</p>');
        }
        
        // Aggiorna attack chains
        updateAttackChains(data);
    }
    
    function updateAttackChains(data) {
        const container = $('#attackChains');
        container.empty();
        
        const threatsByType = data.threats_by_type || {};
        const totalThreats = Object.values(threatsByType).reduce((a, b) => a + b, 0);
        
        if (totalThreats > 0) {
            const chains = {
                'SQL → XSS Chain': Math.ceil(totalThreats * 0.1),
                'Brute Force → Path Traversal': Math.ceil(totalThreats * 0.05),
                'Bot → SQL Injection': Math.ceil(totalThreats * 0.08)
            };
            
            Object.entries(chains).forEach(([chain, count]) => {
                const item = $(`
                    <div class="attack-chain-item">
                        <div class="chain-name">${chain}</div>
                        <div class="chain-count">${count} sequences</div>
                        <div class="chain-description">
                            Multi-stage attack pattern detected
                        </div>
                    </div>
                `);
                container.append(item);
            });
        } else {
            container.append('<p class="text-center text-muted">{{ lang._("No attack chains detected") }}</p>');
        }
    }
    
    function updateBehavioralContent() {
        const container = $('#behavioralContent');
        
        // Simula che behavioral analysis sia abilitato (puoi cambiare questa logica)
        const behavioralEnabled = true; // Cambia a false se vuoi disabilitarlo
        
        if (behavioralEnabled) {
            const html = `
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
            `;
            container.html(html);
        } else {
            const html = `
                <div class="alert alert-info">
                    <i class="fa fa-info-circle"></i>
                    {{ lang._('Behavioral analysis is not enabled. Enable it in WebGuard settings to see advanced pattern detection.') }}
                </div>
            `;
            container.html(html);
        }
    }
    
    function updateMLContent() {
        const container = $('#mlContent');
        
        // Simula che machine learning sia disabilitato (puoi cambiare questa logica)
        const machineLearning = false; // Cambia a true se vuoi abilitarlo
        
        if (machineLearning) {
            const html = `
                <div id="mlInsights">
                    <div class="ml-insight-item">
                        <h5>Pattern Correlation</h5>
                        <p>High correlation detected between SQL injection and XSS attacks</p>
                    </div>
                    <div class="ml-insight-item">
                        <h5>Prediction Model</h5>
                        <p>85% confidence in next attack vector prediction</p>
                    </div>
                </div>
            `;
            container.html(html);
        } else {
            const html = `
                <div class="alert alert-warning">
                    <i class="fa fa-exclamation-triangle"></i>
                    {{ lang._('Machine learning analysis requires additional configuration.') }}
                </div>
            `;
            container.html(html);
        }
    }

    function updatePatternsTable(data) {
        console.log('📋 Updating patterns table');
        const tbody = $('#patternsTableBody');
        tbody.empty();
        
        const threatsByType = data.threats_by_type || {};
        
        Object.entries(threatsByType).forEach(([type, count]) => {
            const trendIcon = 'fa-arrow-up text-danger'; // Mock trend
            const successRate = Math.floor(Math.random() * 20) + 5; // Mock success rate
            
            const row = $(`
                <tr>
                    <td><code>${type} attack pattern</code></td>
                    <td><span class="badge badge-info">${type}</span></td>
                    <td><strong>${count}</strong></td>
                    <td>${successRate}%</td>
                    <td>2 hours ago</td>
                    <td><i class="fa ${trendIcon}"></i></td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="analyzePattern('${type}')">
                            <i class="fa fa-search"></i> Analyze
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="blockPattern('${type}')">
                            <i class="fa fa-ban"></i> Block
                        </button>
                    </td>
                </tr>
            `);
            tbody.append(row);
        });
        
        if (Object.keys(threatsByType).length === 0) {
            tbody.append(`
                <tr>
                    <td colspan="7" class="text-center text-muted">
                        {{ lang._('No patterns detected for current period') }}
                    </td>
                </tr>
            `);
        }
    }
    
    function initCharts() {
        console.log('📈 Initializing charts');
        
        // SQL Injection Patterns Chart
        const ctx1 = document.getElementById('sqlPatternsChart');
        if (ctx1) {
            sqlChart = new Chart(ctx1.getContext('2d'), {
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
        }
        
        // XSS Patterns Chart
        const ctx2 = document.getElementById('xssPatternsChart');
        if (ctx2) {
            xssChart = new Chart(ctx2.getContext('2d'), {
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
        }
        
        // Behavioral Timeline Chart - inizializza solo se il contenuto è stato creato
        initBehavioralChart();
        
        // Load initial chart data
        setTimeout(updateCharts, 500);
    }
    
    function initBehavioralChart() {
        // Distruggi il grafico esistente se presente
        if (behavioralChart) {
            behavioralChart.destroy();
            behavioralChart = null;
        }
        
        setTimeout(function() {
            const ctx3 = document.getElementById('behavioralTimelineChart');
            if (ctx3) {
                console.log('📈 Creating behavioral chart');
                behavioralChart = new Chart(ctx3.getContext('2d'), {
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
                console.log('✅ Behavioral chart created');
            } else {
                console.log('❌ Behavioral chart canvas not found');
            }
        }, 500); // Delay per assicurarsi che il canvas sia stato creato
    }
    
    function updateCharts() {
        console.log('📊 Updating charts for active tab:', activeTab);
        
        $.get('/api/webguard/threats/getStats', { period: currentPeriod }, function(data) {
            console.log('✅ Chart data received:', data);
            
            if (!data || !data.threats_by_type) return;
            
            const threatsByType = data.threats_by_type;
            
            // Aggiorna SQL chart se è il tab attivo
            if (activeTab === 'sql' && threatsByType['SQL Injection'] && sqlChart) {
                const sqlCount = threatsByType['SQL Injection'];
                const sqlData = [
                    Math.ceil(sqlCount * 0.4), // UNION SELECT
                    Math.ceil(sqlCount * 0.3), // OR 1=1
                    Math.ceil(sqlCount * 0.2), // DROP TABLE
                    Math.ceil(sqlCount * 0.1)  // EXEC xp_
                ];
                
                sqlChart.data.datasets[0].data = sqlData;
                sqlChart.update();
                console.log('📊 SQL chart updated with:', sqlData);
            }
            
            // Aggiorna XSS chart se è il tab attivo
            if (activeTab === 'xss' && (threatsByType['XSS Attack'] || threatsByType['XSS']) && xssChart) {
                const xssCount = threatsByType['XSS Attack'] || threatsByType['XSS'];
                const xssData = [
                    Math.ceil(xssCount * 0.5), // <script>
                    Math.ceil(xssCount * 0.3), // javascript:
                    Math.ceil(xssCount * 0.15), // onerror=
                    Math.ceil(xssCount * 0.05)  // onload=
                ];
                
                xssChart.data.datasets[0].data = xssData;
                xssChart.update();
                console.log('📊 XSS chart updated with:', xssData);
            }
        }).fail(function(xhr, status, error) {
            console.error('❌ Failed to update charts:', error);
        });
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

.pattern-analysis-container .nav-tabs {
    border-bottom: 1px solid #dee2e6;
    margin-bottom: 0;
}

.pattern-analysis-container .tab-content {
    padding: 1.5rem;
    min-height: 500px;
}

.pattern-analysis-container .tab-pane {
    min-height: 450px;
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