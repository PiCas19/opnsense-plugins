{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <div class="service-status">
                    <span id="serviceStatus" class="badge badge-secondary">{{ lang._('Loading...') }}</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Metric Cards Row -->
    <div class="row">
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-search"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="requestsAnalyzed">0</div>
                    <div class="metric-label">{{ lang._('Requests Analyzed') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-shield"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="threatsBlocked">0</div>
                    <div class="metric-label">{{ lang._('Threats Blocked') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-ban"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="ipsBlocked">0</div>
                    <div class="metric-label">{{ lang._('IPs Blocked') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-percent"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="blockingRate">0%</div>
                    <div class="metric-label">{{ lang._('Blocking Rate') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts Row -->
    <div class="row">
        <div class="col-md-6">
            <div class="chart-container">
                <h3>{{ lang._('Threat Timeline') }}</h3>
                <canvas id="threatTimelineChart"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="chart-container">
                <h3>{{ lang._('Threat Distribution') }}</h3>
                <canvas id="threatChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Main Content Row -->
    <div class="row">
        <div class="col-md-8">
            <div class="table-container">
                <h3>{{ lang._('Recent Threats') }}</h3>
                <table class="table table-striped" id="recentThreats">
                    <thead>
                        <tr>
                            <th>{{ lang._('Time') }}</th>
                            <th>{{ lang._('Source IP') }}</th>
                            <th>{{ lang._('Threat Type') }}</th>
                            <th>{{ lang._('Severity') }}</th>
                            <th>{{ lang._('Target') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="threatTableBody">
                        <!-- Dynamic content -->
                    </tbody>
                </table>
            </div>

            <!-- Real-time Feed -->
            <div class="table-container">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h3>{{ lang._('Real-time Threat Feed') }}</h3>
                    <div>
                        <button type="button" class="btn btn-sm btn-primary" id="toggleFeed">
                            <i class="fa fa-pause"></i> {{ lang._('Pause') }}
                        </button>
                        <button type="button" class="btn btn-sm btn-secondary" id="clearFeed">
                            <i class="fa fa-trash"></i> {{ lang._('Clear') }}
                        </button>
                    </div>
                </div>
                <div id="threatFeed" style="height: 200px; overflow-y: auto; border: 1px solid #e5e7eb; padding: 15px; background: #f9fafb; border-radius: 5px;">
                    <!-- Real-time feed content -->
                </div>
            </div>
        </div>

        <div class="col-md-4">
            <!-- System Information -->
            <div class="system-info">
                <h3>{{ lang._('System Information') }}</h3>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Service Status') }}:</span>
                    <span id="serviceStatusInfo" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Operation Mode') }}:</span>
                    <span id="operationMode" class="info-value">{{ currentMode|capitalize }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Uptime') }}:</span>
                    <span id="uptime" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('CPU Usage') }}:</span>
                    <span id="cpuUsage" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Memory Usage') }}:</span>
                    <span id="memoryUsage" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Threats Today') }}:</span>
                    <span id="threatsToday" class="info-value">{{ lang._('Unknown') }}</span>
                </div>
            </div>

            <!-- Service Controls -->
            <div class="service-controls">
                <h3>{{ lang._('Service Controls') }}</h3>
                <div class="btn-group-vertical" style="width: 100%;">
                    <button class="btn btn-success" id="startService" data-endpoint="/api/webguard/settings/start">
                        <i class="fa fa-play"></i> {{ lang._('Start Service') }}
                    </button>
                    <button class="btn btn-warning" id="restartService" data-endpoint="/api/webguard/settings/restart">
                        <i class="fa fa-refresh"></i> {{ lang._('Restart Service') }}
                    </button>
                    <button class="btn btn-danger" id="stopService" data-endpoint="/api/webguard/settings/stop">
                        <i class="fa fa-stop"></i> {{ lang._('Stop Service') }}
                    </button>
                    <button class="btn btn-primary" id="reloadService" data-endpoint="/api/webguard/settings/reload">
                        <i class="fa fa-cog"></i> {{ lang._('Reload Config') }}
                    </button>
                    <button class="btn btn-info" id="reconfigureAct" data-endpoint="/api/webguard/settings/reconfigure">
                        <i class="fa fa-cogs"></i> {{ lang._('Apply Changes') }}
                    </button>
                </div>
            </div>
            <div class="col-md-6">
                <!-- Quick Navigation -->
                <div class="quick-nav-controls">
                    <h3>{{ lang._('Threat Analysis') }}</h3>
                    <div class="nav-grid">
                        <a href="/ui/webguard/threats/stats" class="nav-item">
                            <div class="nav-icon">
                                <i class="fa fa-bar-chart"></i>
                            </div>
                            <div class="nav-content">
                                <div class="nav-title">{{ lang._('Statistics') }}</div>
                                <div class="nav-desc">{{ lang._('Detailed threat analytics') }}</div>
                            </div>
                        </a>
                        
                        <a href="/ui/webguard/threats/geo" class="nav-item">
                            <div class="nav-icon">
                                <i class="fa fa-globe"></i>
                            </div>
                            <div class="nav-content">
                                <div class="nav-title">{{ lang._('Geographic') }}</div>
                                <div class="nav-desc">{{ lang._('Geographic threat analysis') }}</div>
                            </div>
                        </a>
                        
                        <a href="/ui/webguard/threats/patterns" class="nav-item">
                            <div class="nav-icon">
                                <i class="fa fa-search"></i>
                            </div>
                            <div class="nav-content">
                                <div class="nav-title">{{ lang._('Patterns') }}</div>
                                <div class="nav-desc">{{ lang._('Attack pattern analysis') }}</div>
                            </div>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="threatDetailModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Threat Details') }}</h4>
            </div>
            <div class="modal-body" id="threatDetailContent">
                <!-- Populated by JavaScript -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
                <button type="button" class="btn btn-warning" id="markFalsePositive">
                    <i class="fa fa-times"></i> {{ lang._('Mark False Positive') }}
                </button>
                <button type="button" class="btn btn-success" id="whitelistIp">
                    <i class="fa fa-check"></i> {{ lang._('Whitelist IP') }}
                </button>
                <button type="button" class="btn btn-danger" id="blockIp">
                    <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Notifications area -->
<div id="notifications" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;"></div>

<!-- Chart.js CDN -->
<script src="/ui/js/chart.min.js"></script>

<script>
$(document).ready(function() {
    let feedActive = true;
    let lastThreatId = 0;
    let threatChart = null;
    let timelineChart = null;
    
    // Initialize dashboard
    loadDashboardData();
    initCharts();
    
    // Set up periodic updates
    setInterval(function() {
        loadDashboardData();
        if (feedActive) {
            loadThreatFeedFromStats();
        }
    }, 5000);
    
    // Auto-refresh recent threats every 30 seconds
    setInterval(loadRecentThreatsFromStats, 30000);
    
    // Service control buttons
    $('#startService, #stopService, #restartService, #reloadService, #reconfigureAct').click(function() {
        controlService($(this).data('endpoint'), $(this));
    });
    
    // Feed controls
    $('#toggleFeed').click(function() {
        feedActive = !feedActive;
        if (feedActive) {
            $(this).html('<i class="fa fa-pause"></i> {{ lang._("Pause") }}');
            loadThreatFeedFromStats();
        } else {
            $(this).html('<i class="fa fa-play"></i> {{ lang._("Resume") }}');
        }
    });
    
    $('#clearFeed').click(function() {
        $('#threatFeed').empty();
        lastThreatId = 0;
    });

    function loadDashboardData() {
        // Load main statistics - using your existing endpoint
        ajaxCall('/api/webguard/settings/stats', {}, function(data) {
            if (data.status === 'ok' && data.data) {
                updateMetrics(data.data);
                updateSystemInfo(data.data);
                updateThreatsToday(data.data);
            }
        });
        
        // Load recent threats from the stats data
        loadRecentThreatsFromStats();
    }

    function updateThreatsToday(data) {
        // Calculate threats today from recent_threats
        const recentThreats = data.recent_threats || [];
        const today = new Date().toDateString();
        let threatsToday = 0;
        
        recentThreats.forEach(function(threat) {
            const threatDate = new Date(threat.timestamp).toDateString();
            if (threatDate === today) {
                threatsToday++;
            }
        });
        
        $('#threatsToday').text(formatNumber(threatsToday));
    }

    function updateMetrics(data) {
        $('#requestsAnalyzed').text(formatNumber(data.requests_analyzed || 0));
        $('#threatsBlocked').text(formatNumber(data.threats_blocked || 0));
        $('#ipsBlocked').text(formatNumber(data.ips_blocked || 0));
        
        const blockingRate = data.requests_analyzed > 0 
            ? ((data.threats_blocked / data.requests_analyzed) * 100).toFixed(2)
            : 0;
        $('#blockingRate').text(blockingRate + '%');
    }

    function updateSystemInfo(data) {
        const systemInfo = data.system_info || {};
        
        $('#uptime').text(formatUptimeFromString(systemInfo.uptime || 'Unknown'));
        $('#cpuUsage').text(systemInfo.cpu_usage || 'Unknown');
        $('#memoryUsage').text(systemInfo.memory_usage || 'Unknown');
        
        // Update service status
        const isRunning = systemInfo.engine_status === 'Active';
        if (isRunning) {
            $('#serviceStatus').removeClass('badge-secondary badge-danger')
                             .addClass('badge-success')
                             .text('{{ lang._("Running") }}');
            $('#serviceStatusInfo').text('{{ lang._("Active") }}');
        } else {
            $('#serviceStatus').removeClass('badge-secondary badge-success')
                             .addClass('badge-danger')
                             .text('{{ lang._("Stopped") }}');
            $('#serviceStatusInfo').text('{{ lang._("Inactive") }}');
        }
    }

    function loadRecentThreatsFromStats() {
        // Fetch recent threats via dedicated API endpoint
        ajaxCall('/api/webguard/threats/getRecent', {}, function(response) {
            console.log('Recent threats response:', response); // Debug log
            
            const tbody = $('#threatTableBody');
            tbody.empty();
            
            // Handle different response formats
            let threats = [];
            if (response.status === 'ok' || response.result === 'ok') {
                threats = response.recent_threats || response.threats || response.data || [];
            }
            
            if (threats && threats.length > 0) {
                threats.slice(0, 10).forEach(function(threat) {
                    const severityClass = getSeverityClass(threat.severity);
                    const threatId = threat.id || threat.threat_id;
                    const sourceIp = threat.source_ip || threat.ip_address;
                    const threatType = threat.threat_type || threat.type;
                    const url = threat.url || threat.target || threat.description || '-';
                    
                    const row = $(`
                        <tr>
                            <td>${formatTimeFromISO(threat.timestamp)}</td>
                            <td><code>${sourceIp}</code></td>
                            <td>${threatType}</td>
                            <td><span class="badge ${severityClass}">${threat.severity || 'low'}</span></td>
                            <td>${url}</td>
                            <td>
                                <button class="btn btn-sm btn-primary view-threat-btn" data-threat-id="${threatId}">
                                    <i class="fa fa-eye"></i>
                                </button>
                                <button class="btn btn-sm btn-danger block-source-btn" data-source-ip="${sourceIp}">
                                    <i class="fa fa-ban"></i>
                                </button>
                            </td>
                        </tr>
                    `);
                    tbody.append(row);
                });
                
                // Event listeners per i pulsanti
                $('.view-threat-btn').off('click').on('click', function () {
                    const threatId = $(this).data('threat-id');
                    console.log('Viewing threat ID:', threatId); // Debug log

                    if (!threatId) {
                        showNotification('{{ lang._("Threat ID not found") }}', 'error');
                        return;
                    }

                    // Memorizza l'ID corrente
                    currentThreatId = threatId;

                    // Chiamata AJAX con gestione errori migliorata
                    $.ajax({
                        url: '/api/webguard/threats/getDetail/' + threatId,
                        type: 'GET',
                        dataType: 'json',
                        success: function (data) {
                            console.log('Threat detail response:', data); // Debug log
                            
                            if (data.result === 'ok' || data.status === 'ok') {
                                const threat = data.threat || data.data;
                                if (!threat) {
                                    showNotification('{{ lang._("Threat data not found") }}', 'error');
                                    return;
                                }
                                
                                displayThreatDetail(threat);
                            } else {
                                showNotification('{{ lang._("Failed to load threat details") }}: ' + (data.message || '{{ lang._("Unknown error") }}'), 'error');
                            }
                        },
                        error: function(xhr, status, error) {
                            console.error('Threat detail error:', {
                                status: xhr.status,
                                statusText: xhr.statusText,
                                responseText: xhr.responseText,
                                error: error
                            });
                            
                            // Fallback: usa i dati già disponibili dalla tabella
                            const rowData = $(this).closest('tr');
                            const fallbackThreat = {
                                id: threatId,
                                timestamp: rowData.find('td:eq(0)').text(),
                                source_ip: rowData.find('td:eq(1) code').text(),
                                threat_type: rowData.find('td:eq(2)').text(),
                                severity: rowData.find('td:eq(3) .badge').text().toLowerCase(),
                                url: rowData.find('td:eq(4)').text(),
                                description: 'Limited information available (API error)'
                            };
                            
                            displayThreatDetail(fallbackThreat);
                            showNotification('{{ lang._("Using limited threat information due to API error") }}', 'warning');
                        }.bind(this)
                    });
                });
                
                $('.block-source-btn').off('click').on('click', function() {
                    const sourceIP = $(this).data('source-ip');
                    if (confirm(`{{ lang._("Are you sure you want to block IP") }} ${sourceIP}?`)) {
                        ajaxCall("/api/webguard/settings/blockIP", {ip: sourceIP}, function(data) {
                            if (data.result === 'ok' || data.status === 'ok') {
                                showNotification(`{{ lang._("IP") }} ${sourceIP} {{ lang._("blocked successfully") }}`, 'success');
                            } else {
                                showNotification(`{{ lang._("Failed to block IP") }}: ${data.message || '{{ lang._("Unknown error") }}'}`, 'error');
                            }
                        });
                    }
                });
                
            } else {
                console.log('No threats found in response'); // Debug log
                tbody.append(`
                    <tr>
                        <td colspan="6" class="text-center text-muted">
                            {{ lang._('No recent threats') }}
                        </td>
                    </tr>
                `);
            }
        }).fail(function(xhr, status, error) {
            console.error('Failed to load recent threats:', error);
            console.error('Response:', xhr.responseText);
            
            const tbody = $('#threatTableBody');
            tbody.empty().append(`
                <tr>
                    <td colspan="6" class="text-center text-danger">
                        {{ lang._('Error loading threats') }}: ${error}
                    </td>
                </tr>
            `);
        });
    }


    function loadThreatFeedFromStats() {
        // Use dedicated feed API endpoint
        ajaxCall('/api/webguard/threats/getFeed', {sinceId: lastThreatId}, function(response) {
            if (response.status === 'ok' && response.recent_threats && response.recent_threats.length) {
                const feed = $('#threatFeed');
                response.recent_threats.forEach(function(threat) {
                    console.log('Processing threat:', threat);
                    const item = $(`
                        <div class="threat-feed-item ${threat.severity}">
                            <div class="threat-feed-time">${formatTimeFromISO(threat.timestamp)}</div>
                            <strong>${threat.type}</strong> from ${threat.source_ip} → ${threat.description}
                        </div>
                    `);
                    feed.prepend(item);
                });
                lastThreatId = response.last_id;
                // Keep only last 50 items
                feed.children().slice(50).remove();
            }
        });
    }


    function displayThreatDetail(threat) {
        let html = '<div class="threat-detail-section">';
        html += '<h5>{{ lang._("Basic Information") }}</h5>';
        html += '<div class="row">';
        html += '<div class="col-md-6"><strong>{{ lang._("Timestamp") }}:</strong> ' + formatTimeFromISO(threat.timestamp) + '</div>';
        html += '<div class="col-md-6"><strong>{{ lang._("Source IP") }}:</strong> ' + (threat.source_ip || threat.ip_address) + '</div>';
        html += '<div class="col-md-6"><strong>{{ lang._("Type") }}:</strong> ' + (threat.type || threat.threat_type) + '</div>';
        html += '<div class="col-md-6"><strong>{{ lang._("Severity") }}:</strong> <span class="badge ' + getSeverityClass(threat.severity) + '">' + (threat.severity || 'low') + '</span></div>';
        html += '<div class="col-md-6"><strong>{{ lang._("Target") }}:</strong> ' + (threat.target || threat.url || '-') + '</div>';
        html += '<div class="col-md-6"><strong>{{ lang._("Method") }}:</strong> ' + (threat.method || 'GET') + '</div>';
        html += '<div class="col-md-6"><strong>{{ lang._("Status") }}:</strong> ' + (threat.status || 'logged').toUpperCase() + '</div>';
        html += '<div class="col-md-6"><strong>{{ lang._("Score") }}:</strong> ' + (threat.score || 0) + '</div>';
        html += '</div></div>';

        if (threat.request_headers || threat.headers) {
            html += '<div class="threat-detail-section">';
            html += '<h5>{{ lang._("Request Headers") }}</h5>';
            html += '<pre>' + JSON.stringify(threat.request_headers || threat.headers, null, 2) + '</pre>';
            html += '</div>';
        }

        if (threat.payload || threat.request_body) {
            html += '<div class="threat-detail-section">';
            html += '<h5>{{ lang._("Payload") }}</h5>';
            html += '<pre>' + (threat.payload || threat.request_body) + '</pre>';
            html += '</div>';
        }

        if (threat.rule_matched || threat.rule) {
            html += '<div class="threat-detail-section">';
            html += '<h5>{{ lang._("Rule Matched") }}</h5>';
            html += '<p>' + (threat.rule_matched || threat.rule) + '</p>';
            html += '</div>';
        }

        if (threat.description) {
            html += '<div class="threat-detail-section">';
            html += '<h5>{{ lang._("Description") }}</h5>';
            html += '<p>' + threat.description + '</p>';
            html += '</div>';
        }

        $('#threatDetailContent').html(html);
        $('#threatDetailModal').modal('show');
    }



    function initCharts() {
        // Initialize Threat Distribution Chart
        const ctx1 = document.getElementById('threatChart').getContext('2d');
        threatChart = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'CSRF', 'File Upload', 'Other'],
                datasets: [{
                    data: [12, 8, 5, 3, 7],
                    backgroundColor: [
                        '#FF6384',
                        '#36A2EB',
                        '#FFCE56',
                        '#4BC0C0',
                        '#9966FF'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Initialize Timeline Chart
        const ctx2 = document.getElementById('threatTimelineChart').getContext('2d');
        timelineChart = new Chart(ctx2, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'Threats Detected',
                    data: [5, 12, 8, 15, 22, 18],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Requests Analyzed',
                    data: [150, 280, 200, 320, 450, 380],
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Load real chart data
        updateChartData();
    }

    function updateChartData() {
        // Try to load from ThreatsController, fallback to mock data from stats
        ajaxCall('/api/webguard/threats/getStats', {period: '24h'}, function(data) {
            if (data.status === 'ok' && data.threats_by_type && threatChart) {
                const labels = Object.keys(data.threats_by_type);
                const values = Object.values(data.threats_by_type);
                
                if (labels.length > 0) {
                    threatChart.data.labels = labels;
                    threatChart.data.datasets[0].data = values;
                    threatChart.update();
                }
            }
        }).fail(function() {
            // Fallback: generate chart data from stats
            updateChartsFromStats();
        });

        // Try timeline endpoint, with better fallback
        ajaxCall('/api/webguard/threats/getTimeline', {period: '24h'}, function(data) {
            if (data.status === 'ok' && data.timeline && timelineChart) {
                timelineChart.data.labels = data.timeline.labels;
                timelineChart.data.datasets[0].data = data.timeline.threats;
                timelineChart.data.datasets[1].data = data.timeline.requests;
                timelineChart.update();
            }
        }).fail(function() {
            // If getTimeline doesn't exist, keep default chart data or generate some
            console.log('Timeline endpoint not available, using default data');
        });
    }

    function updateChartsFromStats() {
        // Generate chart data from your existing stats
        ajaxCall('/api/webguard/settings/stats', {}, function(data) {
            if (data.status === 'ok' && data.data) {
                const threatTypes = data.data.threat_types || {};
                
                if (Object.keys(threatTypes).length > 0 && threatChart) {
                    const labels = Object.keys(threatTypes).map(key => key.replace('_', ' ').toUpperCase());
                    const values = Object.values(threatTypes);
                    
                    threatChart.data.labels = labels;
                    threatChart.data.datasets[0].data = values;
                    threatChart.update();
                }
            }
        });
    }

    function controlService(endpoint, button) {
        const originalText = button.html();
        
        button.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Processing...") }}');
        
        ajaxCall(endpoint, {}, function(data) {
            button.prop('disabled', false).html(originalText);
            
            if (data.result === 'ok' || data.status === 'ok') {
                showNotification(data.message || '{{ lang._("Operation completed successfully") }}', 'success');
                setTimeout(loadDashboardData, 2000);
            } else {
                showNotification(data.message || '{{ lang._("Operation failed") }}', 'error');
            }
        });
    }

    function viewThreatDetails(threatId) {
        window.open('/ui/webguard/threats/detail/' + threatId, '_blank');
    }

    function blockSource(sourceIP) {
        if (confirm(`{{ lang._("Are you sure you want to block IP") }} ${sourceIP}?`)) {
            ajaxCall("/api/webguard/settings/blockIP", {ip: sourceIP}, function(data) {
                if (data.result === 'ok' || data.status === 'ok') {
                    showNotification(`{{ lang._("IP") }} ${sourceIP} {{ lang._("blocked successfully") }}`, 'success');
                } else {
                    showNotification(`{{ lang._("Failed to block IP") }}: ${data.message || '{{ lang._("Unknown error") }}'}`, 'error');
                }
            });
        }
    }

    function getSeverityClass(severity) {
        if (!severity || typeof severity !== 'string') return 'badge-secondary';

        switch (severity.toLowerCase()) {
            case 'critical': return 'badge-danger';
            case 'high': return 'badge-warning';
            case 'medium': return 'badge-info';
            case 'low': return 'badge-success';
            default: return 'badge-secondary';
        }
    }
    
    function formatNumber(num) {
        return new Intl.NumberFormat().format(num);
    }

    function formatTimeFromISO(timestamp) {
        if (!timestamp) return '--';
        try {
            // Handle ISO string format from your data
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        } catch (e) {
            return timestamp; // Return as-is if parsing fails
        }
    }

    function formatTime(timestamp) {
        if (!timestamp) return '--';
        try {
            // Handle both Unix timestamp and ISO string
            const date = typeof timestamp === 'string' ? new Date(timestamp) : new Date(timestamp * 1000);
            return date.toLocaleTimeString();
        } catch (e) {
            return '--';
        }
    }

    function formatUptime(seconds) {
        if (seconds === 0 || seconds === '--') return '--';
        
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        if (days > 0) {
            return days + 'd ' + hours + 'h ' + minutes + 'm';
        } else if (hours > 0) {
            return hours + 'h ' + minutes + 'm';
        } else {
            return minutes + 'm';
        }
    }

    function formatUptimeFromString(uptimeStr) {
        if (uptimeStr === 'Unknown' || uptimeStr === 'N/A') return uptimeStr;
        
        // If it's already formatted, return as is
        if (uptimeStr.includes('d') || uptimeStr.includes('h') || uptimeStr.includes('m')) {
            return uptimeStr;
        }
        
        // If it's a number, format it
        const seconds = parseInt(uptimeStr);
        if (!isNaN(seconds)) {
            return formatUptime(seconds);
        }
        
        return uptimeStr;
    }

    function showNotification(message, type) {
        const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
        const notification = $(`
            <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
        `);
        
        $('#notifications').append(notification);
        setTimeout(() => notification.alert('close'), 5000);
    }
});
</script>

<style>
.dpi-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid #e5e7eb;
}

.metric-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
}

.metric-icon {
    font-size: 2rem;
    color: #2563eb;
    margin-right: 1rem;
}

.metric-content {
    flex: 1;
}

.metric-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
}

.metric-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.chart-container {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
    height: 400px;
}

.chart-container canvas {
    max-height: 300px;
}

.table-container {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.system-info {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
}

.info-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid #f3f4f6;
}

.info-item:last-child {
    border-bottom: none;
}

.info-label {
    font-weight: 600;
    color: #374151;
}

.info-value {
    color: #6b7280;
    font-family: monospace;
}

.service-controls {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.service-controls .btn {
    margin-bottom: 0.5rem;
}

.service-controls .btn:last-child {
    margin-bottom: 0;
}

.threat-feed-item {
    padding: 8px;
    margin: 4px 0;
    border-left: 3px solid;
    background: #ffffff;
    border-radius: 4px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05);
}

.threat-feed-item.critical { border-color: #dc3545; }
.threat-feed-item.high { border-color: #ffc107; }
.threat-feed-item.medium { border-color: #17a2b8; }
.threat-feed-item.low { border-color: #28a745; }

.threat-feed-time {
    font-size: 11px;
    color: #6c757d;
    margin-bottom: 2px;
}

.quick-nav-controls .nav-grid {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.quick-nav-controls .nav-item {
    display: flex;
    align-items: center;
    text-decoration: none;
    font-size: 0.95rem;
}

.quick-nav-controls .nav-icon {
    font-size: 1.2rem;
    margin-right: 0.75rem;
    flex-shrink: 0;
}

.quick-nav-controls .nav-content {
    display: flex;
    flex-direction: column;
}

.quick-nav-controls .nav-title {
    font-weight: 600;
    font-size: 1rem;
    line-height: 1.2;
}

.quick-nav-controls .nav-desc {
    font-size: 0.9rem;
    line-height: 1.2;
    opacity: 0.85;
}


.badge-danger { background-color: #dc3545; }
.badge-warning { background-color: #ffc107; color: #212529; }
.badge-info { background-color: #17a2b8; }
.badge-success { background-color: #28a745; }
.badge-secondary { background-color: #6c757d; }
</style>