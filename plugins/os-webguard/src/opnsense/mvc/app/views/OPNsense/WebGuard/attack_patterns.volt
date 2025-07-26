<style>
/* Modern Cyber Security Dashboard */
.security-dashboard {
    background: #0f172a;
    color: #f8fafc;
    border-radius: 16px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.3);
    overflow: hidden;
    font-family: 'Inter', sans-serif;
}

.dashboard-header {
    padding: 1.5rem 2rem;
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid #1e293b;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.dashboard-title {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.dashboard-title h1 {
    margin: 0;
    font-weight: 700;
    font-size: 1.5rem;
    background: linear-gradient(90deg, #60a5fa, #38bdf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.dashboard-controls {
    display: flex;
    gap: 1rem;
    align-items: center;
}

.time-selector {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 0.5rem 1rem;
    color: #f8fafc;
    font-weight: 500;
}

.refresh-btn {
    background: #1e40af;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 0.5rem 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    transition: all 0.2s;
}

.refresh-btn:hover {
    background: #1e3a8a;
    transform: translateY(-1px);
}

/* Stats Grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1.5rem;
    padding: 1.5rem 2rem;
}

.stat-card {
    background: #1e293b;
    border-radius: 12px;
    padding: 1.5rem;
    border-left: 4px solid;
    transition: all 0.3s ease;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 15px rgba(0,0,0,0.2);
}

.stat-card.critical {
    border-left-color: #ef4444;
}

.stat-card.high {
    border-left-color: #f97316;
}

.stat-card.medium {
    border-left-color: #f59e0b;
}

.stat-card.low {
    border-left-color: #10b981;
}

.stat-value {
    font-size: 2.5rem;
    font-weight: 700;
    margin: 0.5rem 0;
    background: linear-gradient(90deg, #e2e8f0, #94a3b8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.stat-label {
    font-size: 0.875rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.stat-trend {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.875rem;
    margin-top: 0.5rem;
}

.trend-up {
    color: #ef4444;
}

.trend-down {
    color: #10b981;
}

/* Main Content */
.dashboard-content {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    padding: 0 2rem 2rem;
}

@media (max-width: 1200px) {
    .dashboard-content {
        grid-template-columns: 1fr;
    }
}

/* Attack Patterns Section */
.attack-patterns {
    background: #1e293b;
    border-radius: 12px;
    padding: 1.5rem;
}

.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.section-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: #f8fafc;
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.pattern-tabs {
    display: flex;
    gap: 0.5rem;
    background: #0f172a;
    border-radius: 8px;
    padding: 0.25rem;
}

.pattern-tab {
    padding: 0.5rem 1rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: all 0.2s;
}

.pattern-tab.active {
    background: #1e40af;
    color: white;
}

.pattern-tab:not(.active):hover {
    background: #1e293b;
}

.pattern-list {
    display: grid;
    gap: 1rem;
    max-height: 500px;
    overflow-y: auto;
    padding-right: 0.5rem;
}

.pattern-item {
    background: #0f172a;
    border-radius: 8px;
    padding: 1.25rem;
    border: 1px solid #1e293b;
    transition: all 0.3s;
}

.pattern-item:hover {
    border-color: #3b82f6;
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
}

.pattern-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
}

.pattern-name {
    font-family: 'Roboto Mono', monospace;
    font-size: 0.95rem;
    color: #f8fafc;
    font-weight: 500;
}

.pattern-meta {
    display: flex;
    gap: 0.5rem;
}

.pattern-type {
    background: #334155;
    color: #e2e8f0;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
}

.pattern-severity {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.pattern-severity.critical {
    background: #7f1d1d;
    color: #fca5a5;
}

.pattern-severity.high {
    background: #7c2d12;
    color: #fdba74;
}

.pattern-severity.medium {
    background: #713f12;
    color: #fcd34d;
}

.pattern-severity.low {
    background: #065f46;
    color: #6ee7b7;
}

.pattern-details {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-top: 1rem;
}

.pattern-detail {
    display: flex;
    flex-direction: column;
}

.detail-label {
    font-size: 0.75rem;
    color: #94a3b8;
    margin-bottom: 0.25rem;
}

.detail-value {
    font-size: 0.875rem;
    font-weight: 600;
    color: #f8fafc;
}

.pattern-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 1rem;
}

.action-btn {
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    transition: all 0.2s;
    border: none;
}

.action-btn.analyze {
    background: #1e40af;
    color: white;
}

.action-btn.analyze:hover {
    background: #1e3a8a;
}

.action-btn.samples {
    background: #334155;
    color: #e2e8f0;
}

.action-btn.samples:hover {
    background: #475569;
}

/* Charts Section */
.charts-section {
    display: grid;
    gap: 1.5rem;
}

.chart-container {
    background: #1e293b;
    border-radius: 12px;
    padding: 1.5rem;
    height: 100%;
}

.chart-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.chart-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: #f8fafc;
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.chart-wrapper {
    height: 300px;
    position: relative;
}

/* Trending Attacks */
.trending-attacks {
    background: #1e293b;
    border-radius: 12px;
    padding: 1.5rem;
}

.trending-list {
    display: grid;
    gap: 1rem;
}

.trending-item {
    background: #0f172a;
    border-radius: 8px;
    padding: 1rem;
    border-left: 4px solid;
    transition: all 0.3s;
}

.trending-item.critical {
    border-left-color: #ef4444;
}

.trending-item.high {
    border-left-color: #f97316;
}

.trending-item.medium {
    border-left-color: #f59e0b;
}

.trending-item:hover {
    transform: translateX(5px);
}

.trending-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.trending-name {
    font-weight: 600;
    color: #f8fafc;
}

.trending-growth {
    font-size: 0.875rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.trending-growth.up {
    color: #ef4444;
}

.trending-growth.down {
    color: #10b981;
}

.trending-details {
    display: flex;
    gap: 1rem;
    font-size: 0.875rem;
    color: #94a3b8;
}

/* Attack Sequences */
.attack-sequences {
    background: #1e293b;
    border-radius: 12px;
    padding: 1.5rem;
}

.sequence-list {
    display: grid;
    gap: 1rem;
}

.sequence-item {
    background: #0f172a;
    border-radius: 8px;
    padding: 1rem;
    border-left: 4px solid #1e40af;
}

.sequence-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
}

.sequence-ip {
    font-family: 'Roboto Mono', monospace;
    font-weight: 600;
    color: #f8fafc;
}

.sequence-risk {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.sequence-risk.critical {
    background: #7f1d1d;
    color: #fca5a5;
}

.sequence-risk.high {
    background: #7c2d12;
    color: #fdba74;
}

.sequence-risk.medium {
    background: #713f12;
    color: #fcd34d;
}

.sequence-steps {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
}

.step {
    background: #334155;
    color: #e2e8f0;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.step-number {
    background: #1e40af;
    color: white;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.7rem;
    font-weight: 700;
}

.sequence-meta {
    display: flex;
    justify-content: space-between;
    font-size: 0.875rem;
    color: #94a3b8;
}

/* Custom scrollbar */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}

::-webkit-scrollbar-track {
    background: #1e293b;
    border-radius: 3px;
}

::-webkit-scrollbar-thumb {
    background: #334155;
    border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
    background: #475569;
}
</style>

<div class="security-dashboard">
    <!-- Dashboard Header -->
    <div class="dashboard-header">
        <div class="dashboard-title">
            <i class="fa fa-shield-alt"></i>
            <h1>WebGuard Attack Pattern Analysis</h1>
        </div>
        <div class="dashboard-controls">
            <select id="timePeriod" class="time-selector">
                <option value="1h">Last Hour</option>
                <option value="24h" selected>Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days</option>
            </select>
            <button id="refreshData" class="refresh-btn">
                <i class="fa fa-sync-alt"></i> Refresh
            </button>
        </div>
    </div>

    <!-- Stats Grid -->
    <div class="stats-grid">
        <div class="stat-card critical">
            <div class="stat-label">Critical Patterns</div>
            <div class="stat-value" id="criticalPatterns">0</div>
            <div class="stat-trend trend-up">
                <i class="fa fa-arrow-up"></i> 12% from yesterday
            </div>
        </div>
        <div class="stat-card high">
            <div class="stat-label">Attack Patterns</div>
            <div class="stat-value" id="totalPatterns">0</div>
            <div class="stat-trend trend-up">
                <i class="fa fa-arrow-up"></i> 8% from yesterday
            </div>
        </div>
        <div class="stat-card medium">
            <div class="stat-label">Blocked Attacks</div>
            <div class="stat-value" id="blockedPatterns">0</div>
            <div class="stat-trend trend-down">
                <i class="fa fa-arrow-down"></i> 5% from yesterday
            </div>
        </div>
        <div class="stat-card low">
            <div class="stat-label">Attack Types</div>
            <div class="stat-value" id="attackTypes">0</div>
            <div class="stat-trend trend-up">
                <i class="fa fa-arrow-up"></i> 3% from yesterday
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="dashboard-content">
        <!-- Attack Patterns Section -->
        <div class="attack-patterns">
            <div class="section-header">
                <h2 class="section-title">
                    <i class="fa fa-code"></i>
                    Attack Patterns
                </h2>
                <div class="pattern-tabs">
                    <div class="pattern-tab active" data-type="all">All</div>
                    <div class="pattern-tab" data-type="sql_injection">SQLi</div>
                    <div class="pattern-tab" data-type="xss">XSS</div>
                    <div class="pattern-tab" data-type="command_injection">CMD</div>
                    <div class="pattern-tab" data-type="path_traversal">LFI</div>
                </div>
            </div>
            <div class="pattern-list" id="patternList">
                <!-- Patterns will be loaded here -->
                <div class="text-center" style="padding: 2rem; color: #94a3b8;">
                    <i class="fa fa-spinner fa-spin"></i> Loading attack patterns...
                </div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="charts-section">
            <!-- Pattern Type Distribution -->
            <div class="chart-container">
                <div class="chart-header">
                    <h2 class="chart-title">
                        <i class="fa fa-chart-pie"></i>
                        Pattern Type Distribution
                    </h2>
                </div>
                <div class="chart-wrapper">
                    <canvas id="patternTypeChart"></canvas>
                </div>
            </div>

            <!-- Trending Attacks -->
            <div class="trending-attacks">
                <div class="section-header">
                    <h2 class="section-title">
                        <i class="fa fa-fire"></i>
                        Trending Attacks
                    </h2>
                </div>
                <div class="trending-list" id="trendingList">
                    <!-- Trending attacks will be loaded here -->
                </div>
            </div>

            <!-- Attack Sequences -->
            <div class="attack-sequences">
                <div class="section-header">
                    <h2 class="section-title">
                        <i class="fa fa-link"></i>
                        Attack Sequences
                    </h2>
                </div>
                <div class="sequence-list" id="sequenceList">
                    <!-- Attack sequences will be loaded here -->
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Pattern Detail Modal -->
<div class="modal fade" id="patternDetailModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content" style="background: #1e293b; color: #f8fafc;">
            <div class="modal-header" style="border-bottom: 1px solid #334155;">
                <h5 class="modal-title">Pattern Analysis</h5>
                <button type="button" class="close" data-dismiss="modal" style="color: #f8fafc;">&times;</button>
            </div>
            <div class="modal-body" id="patternDetailContent">
                <!-- Dynamic content will be loaded here -->
            </div>
            <div class="modal-footer" style="border-top: 1px solid #334155;">
                <button type="button" class="btn btn-secondary" data-dismiss="modal" style="background: #334155; border: none;">Close</button>
                <button type="button" class="btn btn-danger" id="blockPatternBtn" style="background: #7f1d1d; border: none;">
                    <i class="fa fa-ban"></i> Block Pattern
                </button>
            </div>
        </div>
    </div>
</div>

<script src="/ui/js/chart.min.js"></script>
<script>
$(document).ready(function() {
    // Chart instances
    let patternTypeChart = null;
    let currentPattern = null;

    // Load initial data
    loadPatternData();

    // Event listeners
    $('#timePeriod').change(loadPatternData);
    $('#refreshData').click(loadPatternData);
    $('.pattern-tab').click(function() {
        $('.pattern-tab').removeClass('active');
        $(this).addClass('active');
        filterPatterns($(this).data('type'));
    });

    function loadPatternData() {
        const period = $('#timePeriod').val();
        
        $.ajax({
            url: '/api/webguard/threats/getPatterns',
            data: { period: period },
            success: function(data) {
                updateDashboard(data);
            },
            error: function() {
                showError('Failed to load pattern data');
            }
        });
    }

    function updateDashboard(data) {
        updateStats(data);
        renderPatternList(data.patterns);
        renderTrendingAttacks(data.trending_attacks);
        renderAttackSequences(data.attack_sequences);
        initPatternTypeChart(data.patterns);
    }

    function updateStats(data) {
        const patterns = data.patterns || [];
        
        // Calculate stats
        const totalPatterns = patterns.length;
        const blockedPatterns = patterns.filter(p => p.action === 'block').length;
        const attackTypes = [...new Set(patterns.map(p => p.type))].length;
        const criticalPatterns = patterns.filter(p => p.severity === 'critical').length;
        
        // Update UI
        $('#totalPatterns').text(totalPatterns);
        $('#blockedPatterns').text(blockedPatterns);
        $('#attackTypes').text(attackTypes);
        $('#criticalPatterns').text(criticalPatterns);
    }

    function renderPatternList(patterns) {
        const $patternList = $('#patternList');
        $patternList.empty();
        
        if (patterns.length === 0) {
            $patternList.html('<div class="text-center" style="padding: 2rem; color: #94a3b8;">No attack patterns detected for selected period</div>');
            return;
        }
        
        patterns.forEach(pattern => {
            const patternItem = $(`
                <div class="pattern-item" data-type="${pattern.type}" data-severity="${pattern.severity}">
                    <div class="pattern-header">
                        <code class="pattern-name">${pattern.pattern.substring(0, 50)}${pattern.pattern.length > 50 ? '...' : ''}</code>
                        <div class="pattern-meta">
                            <span class="pattern-type">${pattern.type.replace('_', ' ')}</span>
                            <span class="pattern-severity ${pattern.severity}">${pattern.severity}</span>
                        </div>
                    </div>
                    <div class="pattern-details">
                        <div class="pattern-detail">
                            <span class="detail-label">Occurrences</span>
                            <span class="detail-value">${pattern.count}</span>
                        </div>
                        <div class="pattern-detail">
                            <span class="detail-label">Blocked</span>
                            <span class="detail-value">${pattern.blocked}</span>
                        </div>
                        <div class="pattern-detail">
                            <span class="detail-label">Risk Score</span>
                            <span class="detail-value">${pattern.score}/100</span>
                        </div>
                        <div class="pattern-detail">
                            <span class="detail-label">Last Seen</span>
                            <span class="detail-value">${pattern.last_seen}</span>
                        </div>
                    </div>
                    <div class="pattern-actions">
                        <button class="action-btn analyze analyze-pattern" data-pattern='${JSON.stringify(pattern)}'>
                            <i class="fa fa-search"></i> Analyze
                        </button>
                        <button class="action-btn samples view-samples" data-pattern='${JSON.stringify(pattern)}'>
                            <i class="fa fa-list"></i> Samples
                        </button>
                    </div>
                </div>
            `);
            
            $patternList.append(patternItem);
        });
        
        // Attach event handlers
        $('.analyze-pattern').click(function() {
            currentPattern = JSON.parse($(this).data('pattern'));
            showPatternDetail(currentPattern);
        });
    }

    function renderTrendingAttacks(trendingAttacks) {
        const $trendingList = $('#trendingList');
        $trendingList.empty();
        
        if (trendingAttacks.length === 0) {
            $trendingList.html('<div class="text-center" style="padding: 1rem; color: #94a3b8;">No trending attacks detected</div>');
            return;
        }
        
        trendingAttacks.forEach(attack => {
            const trendingItem = $(`
                <div class="trending-item ${attack.severity}">
                    <div class="trending-header">
                        <span class="trending-name">${attack.pattern.substring(0, 40)}${attack.pattern.length > 40 ? '...' : ''}</span>
                        <span class="trending-growth up">
                            <i class="fa fa-arrow-up"></i> ${attack.growth_rate}%
                        </span>
                    </div>
                    <div class="trending-details">
                        <span>${attack.type}</span>
                        <span>${attack.count} hits</span>
                    </div>
                </div>
            `);
            
            $trendingList.append(trendingItem);
        });
    }

    function renderAttackSequences(attackSequences) {
        const $sequenceList = $('#sequenceList');
        $sequenceList.empty();
        
        if (attackSequences.length === 0) {
            $sequenceList.html('<div class="text-center" style="padding: 1rem; color: #94a3b8;">No attack sequences detected</div>');
            return;
        }
        
        attackSequences.forEach(sequence => {
            const sequenceItem = $(`
                <div class="sequence-item">
                    <div class="sequence-header">
                        <span class="sequence-ip">${sequence.source_ip}</span>
                        <span class="sequence-risk ${sequence.risk_level}">${sequence.risk_level}</span>
                    </div>
                    <div class="sequence-steps">
                        ${sequence.sequence.map((step, index) => `
                            <div class="step">
                                <span class="step-number">${index + 1}</span>
                                ${step}
                            </div>
                        `).join('')}
                    </div>
                    <div class="sequence-meta">
                        <span>${sequence.count} steps</span>
                        <span>${sequence.duration}</span>
                    </div>
                </div>
            `);
            
            $sequenceList.append(sequenceItem);
        });
    }

    function filterPatterns(type) {
        if (type === 'all') {
            $('.pattern-item').show();
            return;
        }
        
        $('.pattern-item').each(function() {
            const $item = $(this);
            $item.toggle($item.data('type') === type);
        });
    }

    function initPatternTypeChart(patterns) {
        const ctx = document.getElementById('patternTypeChart').getContext('2d');
        
        // Group patterns by type
        const typeCounts = {};
        patterns.forEach(pattern => {
            const type = pattern.type || 'unknown';
            typeCounts[type] = (typeCounts[type] || 0) + 1;
        });
        
        // Prepare chart data
        const labels = Object.keys(typeCounts).map(t => t.replace('_', ' '));
        const data = Object.values(typeCounts);
        const backgroundColors = [
            '#ef4444', '#f97316', '#f59e0b', '#10b981', 
            '#0ea5e9', '#6366f1', '#8b5cf6', '#ec4899'
        ];
        
        // Destroy previous chart if exists
        if (patternTypeChart) {
            patternTypeChart.destroy();
        }
        
        // Create new chart
        patternTypeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: backgroundColors,
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            font: {
                                family: 'Inter'
                            },
                            padding: 20,
                            boxWidth: 12,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleColor: '#f8fafc',
                        bodyColor: '#e2e8f0',
                        borderColor: '#334155',
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                },
                cutout: '70%',
                animation: {
                    animateScale: true,
                    animateRotate: true
                }
            }
        });
    }

    function showPatternDetail(pattern) {
        $('#patternDetailContent').html(`
            <div style="padding: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                    <h4 style="margin: 0; font-weight: 600; color: #f8fafc;">
                        <code>${pattern.pattern}</code>
                    </h4>
                    <span class="pattern-severity ${pattern.severity}" style="font-size: 0.875rem;">
                        ${pattern.severity.toUpperCase()}
                    </span>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5rem; margin-bottom: 1.5rem;">
                    <div>
                        <div style="font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem;">Type</div>
                        <div style="font-weight: 600; color: #f8fafc;">${pattern.type.replace('_', ' ')}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem;">Occurrences</div>
                        <div style="font-weight: 600; color: #f8fafc;">${pattern.count}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem;">Blocked</div>
                        <div style="font-weight: 600; color: #f8fafc;">${pattern.blocked}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem;">Risk Score</div>
                        <div style="font-weight: 600; color: ${getRiskColor(pattern.score)}">${pattern.score}/100</div>
                    </div>
                    <div>
                        <div style="font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem;">First Seen</div>
                        <div style="font-weight: 600; color: #f8fafc;">${pattern.first_seen}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem;">Last Seen</div>
                        <div style="font-weight: 600; color: #f8fafc;">${pattern.last_seen}</div>
                    </div>
                </div>
                
                <div style="background: #0f172a; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem;">
                    <h5 style="margin-top: 0; margin-bottom: 0.75rem; color: #f8fafc;">
                        <i class="fa fa-info-circle"></i> Pattern Description
                    </h5>
                    <p style="margin: 0; color: #e2e8f0; font-size: 0.875rem;">
                        ${getPatternDescription(pattern.type, pattern.pattern)}
                    </p>
                </div>
                
                <div style="background: #0f172a; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem;">
                    <h5 style="margin-top: 0; margin-bottom: 0.75rem; color: #f8fafc;">
                        <i class="fa fa-exclamation-triangle"></i> Potential Impact
                    </h5>
                    <p style="margin: 0; color: #e2e8f0; font-size: 0.875rem;">
                        ${getPatternImpact(pattern.type)}
                    </p>
                </div>
                
                <div style="background: #0f172a; border-radius: 8px; padding: 1rem;">
                    <h5 style="margin-top: 0; margin-bottom: 0.75rem; color: #f8fafc;">
                        <i class="fa fa-shield-alt"></i> Recommended Mitigation
                    </h5>
                    <ul style="margin: 0; padding-left: 1.25rem; color: #e2e8f0; font-size: 0.875rem;">
                        ${getMitigationSteps(pattern.type).map(step => `<li>${step}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `);
        
        $('#patternDetailModal').modal('show');
    }

    // Block pattern handler
    $('#blockPatternBtn').click(function() {
        if (!currentPattern) return;
        
        $.ajax({
            url: '/api/webguard/threats/createRule',
            method: 'POST',
            data: {
                rule_name: `Block_${currentPattern.pattern.substring(0, 20)}_${Date.now()}`,
                pattern: currentPattern.pattern,
                action: 'block',
                duration: '30d',
                rule_description: `Blocking pattern: ${currentPattern.pattern}`
            },
            success: function() {
                $('#patternDetailModal').modal('hide');
                showAlert('Pattern blocked successfully', 'success');
                loadPatternData();
            },
            error: function() {
                showAlert('Failed to block pattern', 'danger');
            }
        });
    });

    // Helper functions
    function getRiskColor(score) {
        if (score >= 80) return '#ef4444';
        if (score >= 60) return '#f97316';
        if (score >= 40) return '#f59e0b';
        return '#10b981';
    }

    function getPatternDescription(type, pattern) {
        const descriptions = {
            'sql_injection': `This SQL injection pattern attempts to manipulate database queries by injecting malicious SQL code. The pattern "${pattern}" is a common SQLi attack signature.`,
            'xss': `This Cross-Site Scripting (XSS) pattern attempts to inject client-side scripts into web pages. The pattern "${pattern}" matches known XSS attack vectors.`,
            'command_injection': `This command injection pattern attempts to execute arbitrary operating system commands. The pattern "${pattern}" matches known command injection techniques.`,
            'path_traversal': `This path traversal pattern attempts to access files outside the web root directory. The pattern "${pattern}" matches known directory traversal attempts.`,
            'default': `This security pattern matches known malicious input patterns. The pattern "${pattern}" has been identified as potentially dangerous.`
        };
        
        return descriptions[type] || descriptions['default'];
    }

    function getPatternImpact(type) {
        const impacts = {
            'sql_injection': 'SQL injection can lead to unauthorized access to sensitive data, data corruption, or complete database compromise. Successful attacks may result in data breaches, privilege escalation, or complete system takeover.',
            'xss': 'XSS attacks can steal user sessions, deface websites, redirect users to malicious sites, or perform actions on behalf of users. Stored XSS can affect multiple users over time.',
            'command_injection': 'Command injection can lead to complete system compromise. Attackers may gain shell access, install malware, exfiltrate data, or use the server as part of a botnet.',
            'path_traversal': 'Path traversal can expose sensitive files including configuration files, credentials, or system files. This may lead to further system compromise or data leakage.',
            'default': 'This pattern indicates a potential security vulnerability that could be exploited to compromise system security or data integrity.'
        };
        
        return impacts[type] || impacts['default'];
    }

    function getMitigationSteps(type) {
        const mitigations = {
            'sql_injection': [
                'Use prepared statements with parameterized queries',
                'Implement strict input validation for all user-supplied data',
                'Apply the principle of least privilege for database accounts',
                'Enable WAF rules specifically for SQL injection protection',
                'Regularly update and patch database management systems'
            ],
            'xss': [
                'Implement proper output encoding for all dynamic content',
                'Use Content Security Policy (CSP) headers to restrict script execution',
                'Enable XSS protection in WAF rules',
                'Sanitize all user-supplied input before processing',
                'Use secure frameworks that automatically escape XSS by design'
            ],
            'command_injection': [
                'Avoid using user input in system commands when possible',
                'Use built-in language functions instead of executing shell commands',
                'Implement strict input validation with allow lists',
                'Enable command injection protection in WAF rules',
                'Run applications with minimal operating system privileges'
            ],
            'path_traversal': [
                'Validate user input before processing file operations',
                'Use chroot jails or safe directories to restrict file access',
                'Normalize and canonicalize paths before processing',
                'Enable path traversal protection in WAF rules',
                'Implement proper error handling that doesn\'t reveal filesystem structure'
            ],
            'default': [
                'Review the specific pattern and context where it was detected',
                'Implement proper input validation for the affected parameters',
                'Update WAF rules to specifically block this pattern',
                'Monitor for similar patterns that may indicate related attacks',
                'Consider security updates or patches for the affected components'
            ]
        };
        
        return mitigations[type] || mitigations['default'];
    }

    function showAlert(message, type) {
        const alert = $(`
            <div class="alert alert-${type}" style="position: fixed; top: 20px; right: 20px; z-index: 10000; min-width: 300px;">
                ${message}
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
        `);
        
        $('body').append(alert);
        setTimeout(() => alert.alert('close'), 5000);
    }

    function showError(message) {
        showAlert(message, 'danger');
    }
});
</script>