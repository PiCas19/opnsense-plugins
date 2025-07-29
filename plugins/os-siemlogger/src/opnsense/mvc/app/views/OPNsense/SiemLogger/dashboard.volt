{#
 # Copyright (C) 2025 OPNsense SIEM Logger Plugin
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
                    <div class="metric-value" id="totalEvents">0</div>
                    <div class="metric-label">{{ lang._('Total Events') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-calendar"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="eventsToday">0</div>
                    <div class="metric-label">{{ lang._('Events Today') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-exclamation-circle"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="exportErrors">0</div>
                    <div class="metric-label">{{ lang._('Export Errors') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fa fa-hdd-o"></i>
                </div>
                <div class="metric-content">
                    <div class="metric-value" id="diskUsage">0%</div>
                    <div class="metric-label">{{ lang._('Disk Usage') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts Row -->
    <div class="row">
        <div class="col-md-6">
            <div class="chart-container">
                <h3>{{ lang._('Event Timeline') }}</h3>
                <canvas id="eventTimelineChart"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="chart-container">
                <h3>{{ lang._('Event Type Distribution') }}</h3>
                <canvas id="eventTypeChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Recent Events Row -->
    <div class="row">
        <div class="col-md-8">
            <div class="table-container">
                <h3>{{ lang._('Recent Events') }}</h3>
                <table class="table table-striped" id="recentEvents">
                    <thead>
                        <tr>
                            <th>{{ lang._('Timestamp') }}</th>
                            <th>{{ lang._('Source IP') }}</th>
                            <th>{{ lang._('Event Type') }}</th>
                            <th>{{ lang._('Severity') }}</th>
                            <th>{{ lang._('Message') }}</th>
                        </tr>
                    </thead>
                    <tbody id="eventTableBody">
                        <!-- Dynamic content -->
                    </tbody>
                </table>
            </div>

            <!-- Real-time Feed -->
            <div class="table-container">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h3>{{ lang._('Real-time Event Feed') }}</h3>
                    <div>
                        <button type="button" class="btn btn-sm btn-primary" id="toggleFeed">
                            <i class="fa fa-pause"></i> {{ lang._('Pause') }}
                        </button>
                        <button type="button" class="btn btn-sm btn-secondary" id="clearFeed">
                            <i class="fa fa-trash"></i> {{ lang._('Clear') }}
                        </button>
                    </div>
                </div>
                <div id="eventFeed" style="height: 200px; overflow-y: auto; border: 1px solid #e5e7eb; padding: 15px; background: #f9fafb; border-radius: 5px;">
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
                    <span class="info-label">{{ lang._('Log Level') }}:</span>
                    <span id="logLevel" class="info-value">{{ logLevel }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('SIEM Export') }}:</span>
                    <span id="exportEnabled" class="info-value">{{ exportEnabled ? lang._('Enabled') : lang._('Disabled') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Audit Enabled') }}:</span>
                    <span id="auditEnabled" class="info-value">{{ auditEnabled ? lang._('Yes') : lang._('No') }}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Max Log Size') }}:</span>
                    <span id="maxLogSize" class="info-value">{{ maxLogSize }} MB</span>
                </div>
                <div class="info-item">
                    <span class="info-label">{{ lang._('Retention Days') }}:</span>
                    <span id="retentionDays" class="info-value">{{ retentionDays }} days</span>
                </div>
            </div>

            <!-- Service Controls -->
            <div class="service-controls">
                <h3>{{ lang._('Service Controls') }}</h3>
                <div class="btn-group-vertical" style="width: 100%;">
                    <button class="btn btn-success" id="startService" data-endpoint="/api/siemlogger/service/start">
                        <i class="fa fa-play"></i> {{ lang._('Start Service') }}
                    </button>
                    <button class="btn btn-warning" id="restartService" data-endpoint="/api/siemlogger/service/restart">
                        <i class="fa fa-refresh"></i> {{ lang._('Restart Service') }}
                    </button>
                    <button class="btn btn-danger" id="stopService" data-endpoint="/api/siemlogger/service/stop">
                        <i class="fa fa-stop"></i> {{ lang._('Stop Service') }}
                    </button>
                    <button class="btn btn-info" id="testConnection" data-endpoint="/api/siemlogger/service/testConnection">
                        <i class="fa fa-plug"></i> {{ lang._('Test SIEM Connection') }}
                    </button>
                </div>
            </div>

            <!-- Quick Navigation -->
            <div class="quick-nav-controls">
                <h3>{{ lang._('Navigation') }}</h3>
                <div class="nav-grid">
                    <a href="/ui/siemlogger/index" class="nav-item">
                        <div class="nav-icon">
                            <i class="fa fa-cog"></i>
                        </div>
                        <div class="nav-content">
                            <div class="nav-title">{{ lang._('Settings') }}</div>
                            <div class="nav-desc">{{ lang._('Configure SIEM Logger') }}</div>
                        </div>
                    </a>
                    <a href="/ui/siemlogger/logging" class="nav-item">
                        <div class="nav-icon">
                            <i class="fa fa-list"></i>
                        </div>
                        <div class="nav-content">
                            <div class="nav-title">{{ lang._('Logs') }}</div>
                            <div class="nav-desc">{{ lang._('View all logs') }}</div>
                        </div>
                    </a>
                </div>
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
    let lastEventId = 0;
    let eventTypeChart = null;
    let timelineChart = null;

    // Initialize dashboard
    loadDashboardData();
    initCharts();

    // Set up periodic updates
    setInterval(function() {
        loadDashboardData();
        updateChartData();
        if (feedActive) {
            loadEventFeed();
        }
    }, 5000);

    // Auto-refresh recent events every 30 seconds
    setInterval(loadRecentEvents, 30000);

    // Service control buttons
    $('#startService, #restartService, #stopService, #testConnection').click(function() {
        controlService($(this).data('endpoint'), $(this));
    });

    // Feed controls
    $('#toggleFeed').click(function() {
        feedActive = !feedActive;
        if (feedActive) {
            $(this).html('<i class="fa fa-pause"></i> {{ lang._("Pause") }}');
            loadEventFeed();
        } else {
            $(this).html('<i class="fa fa-play"></i> {{ lang._("Resume") }}');
        }
    });

    $('#clearFeed').click(function() {
        $('#eventFeed').empty();
        lastEventId = 0;
    });

    function loadDashboardData() {
        // Load stats for metrics
        ajaxCall('/api/siemlogger/settings/stats', {}, function(data) {
            if (data.status === 'ok' && data.data) {
                updateMetrics(data.data);
                updateSystemInfo(data.data);
            }
        });

        // Load service status
        ajaxCall('/api/siemlogger/service/status', {}, function(data) {
            if (data.status === 'ok') {
                updateServiceStatus(data);
            }
        });

        // Load recent events
        loadRecentEvents();
    }

    function updateMetrics(data) {
        $('#totalEvents').text(formatNumber(data.total_events || 0));
        $('#eventsToday').text(formatNumber(data.events_today || 0));
        $('#exportErrors').text(formatNumber(data.export_errors || 0));
        $('#diskUsage').text((data.disk_usage || 0) + '%');
    }

    function updateSystemInfo(data) {
        $('#logLevel').text('{{ logLevel }}');
        $('#exportEnabled').text('{{ exportEnabled ? lang._("Enabled") : lang._("Disabled") }}');
        $('#auditEnabled').text('{{ auditEnabled ? lang._("Yes") : lang._("No") }}');
        $('#maxLogSize').text('{{ maxLogSize }} MB');
        $('#retentionDays').text('{{ retentionDays }} days');
    }

    function updateServiceStatus(data) {
        const isRunning = data.running;
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

    function loadRecentEvents() {
        ajaxCall('/api/siemlogger/service/getLogs', {'page': 1, 'limit': 10}, function(data) {
            if (data.status === 'ok' && data.data && data.data.logs) {
                const tbody = $('#eventTableBody');
                tbody.empty();
                if (data.data.logs.length > 0) {
                    data.data.logs.forEach(function(event) {
                        const severityClass = getSeverityClass(event.severity);
                        const message = event.message.length > 50 ? event.message.substring(0, 50) + '...' : event.message;
                        const row = `
                            <tr>
                                <td>${formatTimeFromISO(event.timestamp_iso || event.timestamp)}</td>
                                <td><code>${event.source_ip || 'Unknown'}</code></td>
                                <td>${event.event_type || 'Unknown'}</td>
                                <td><span class="badge ${severityClass}">${event.severity || 'info'}</span></td>
                                <td>${message || 'No message'}</td>
                            </tr>`;
                        tbody.append(row);
                    });
                } else {
                    tbody.append(`
                        <tr>
                            <td colspan="5" class="text-center text-muted">
                                {{ lang._('No recent events') }}
                            </td>
                        </tr>`);
                }
            }
        });
    }

    function loadEventFeed() {
        ajaxCall('/api/siemlogger/service/getLogs', {'page': 1, 'limit': 10, 'sinceId': lastEventId}, function(data) {
            if (data.status === 'ok' && data.data && data.data.logs && data.data.logs.length) {
                const feed = $('#eventFeed');
                data.data.logs.forEach(function(event) {
                    const item = `
                        <div class="threat-feed-item ${event.severity}">
                            <div class="threat-feed-time">${formatTimeFromISO(event.timestamp_iso || event.timestamp)}</div>
                            <strong>${event.event_type || 'Unknown'}</strong> from ${event.source_ip || 'Unknown'} → ${event.message || 'No message'}
                        </div>`;
                    feed.prepend(item);
                });
                lastEventId = data.data.logs[0].id || lastEventId + 1;
                feed.children().slice(50).remove();
            }
        });
    }

    function initCharts() {
        const ctx1 = document.getElementById('eventTypeChart').getContext('2d');
        eventTypeChart = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'DEBUG'],
                datasets: [{
                    data: [10, 5, 3, 2, 1],
                    backgroundColor: ['#36A2EB', '#FFCE56', '#FF6384', '#dc3545', '#6c757d']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
            }
        });

        const ctx2 = document.getElementById('eventTimelineChart').getContext('2d');
        timelineChart = new Chart(ctx2, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'Events Detected',
                    data: [5, 10, 15, 20, 25, 30],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'top' } },
                scales: { y: { beginAtZero: true } }
            }
        });

        setTimeout(updateChartData, 500);
    }

    function updateChartData() {
        ajaxCall('/api/siemlogger/settings/stats', {}, function(data) {
            if (data.status === 'ok' && data.data && data.data.event_types) {
                const labels = Object.keys(data.data.event_types);
                const values = Object.values(data.data.event_types);
                if (eventTypeChart) {
                    eventTypeChart.data.labels = labels.length ? labels : ['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'DEBUG'];
                    eventTypeChart.data.datasets[0].data = values.length ? values : [10, 5, 3, 2, 1];
                    eventTypeChart.update();
                }
            }
        });

        ajaxCall('/api/siemlogger/service/getLogs', {'page': 1, 'limit': 24}, function(data) {
            if (data.status === 'ok' && data.data && data.data.logs) {
                const labels = data.data.logs.map(event => formatTimeFromISO(event.timestamp_iso || event.timestamp)).reverse();
                const counts = data.data.logs.map((_, i) => data.data.logs.length - i).reverse();
                if (timelineChart) {
                    timelineChart.data.labels = labels.length ? labels : ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
                    timelineChart.data.datasets[0].data = counts.length ? counts : [5, 10, 15, 20, 25, 30];
                    timelineChart.update();
                }
            }
        });
    }

    function controlService(endpoint, button) {
        const originalText = button.html();
        button.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Processing...") }}');
        ajaxCall(endpoint, {}, function(data) {
            button.prop('disabled', false).html(originalText);
            if (data.status === 'ok') {
                showNotification(data.message || '{{ lang._("Operation completed successfully") }}', 'success');
                setTimeout(loadDashboardData, 2000);
            } else {
                showNotification(data.message || '{{ lang._("Operation failed") }}', 'error');
            }
        });
    }

    function getSeverityClass(severity) {
        if (!severity) return 'badge-secondary';
        switch (severity.toLowerCase()) {
            case 'critical': return 'badge-danger';
            case 'error': return 'badge-danger';
            case 'warning': return 'badge-warning';
            case 'info': return 'badge-info';
            case 'debug': return 'badge-secondary';
            default: return 'badge-secondary';
        }
    }

    function formatNumber(num) {
        return new Intl.NumberFormat().format(num);
    }

    function formatTimeFromISO(timestamp) {
        if (!timestamp) return '--';
        try {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        } catch (e) {
            return timestamp;
        }
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
    margin-bottom: 1rem;
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
.threat-feed-item.error { border-color: #dc3545; }
.threat-feed-item.warning { border-color: #ffc107; }
.threat-feed-item.info { border-color: #17a2b8; }
.threat-feed-item.debug { border-color: #6c757d; }

.threat-feed-time {
    font-size: 11px;
    color: #6c757d;
    margin-bottom: 2px;
}

.quick-nav-controls {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
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
    padding: 10px;
    border-radius: 5px;
    transition: background-color 0.2s;
}

.quick-nav-controls .nav-item:hover {
    background-color: #f8fafc;
    text-decoration: none;
}

.quick-nav-controls .nav-icon {
    font-size: 1.2rem;
    margin-right: 0.75rem;
    flex-shrink: 0;
    color: #2563eb;
}

.quick-nav-controls .nav-content {
    display: flex;
    flex-direction: column;
}

.quick-nav-controls .nav-title {
    font-weight: 600;
    font-size: 1rem;
    line-height: 1.2;
    color: #1f2937;
}

.quick-nav-controls .nav-desc {
    font-size: 0.9rem;
    line-height: 1.2;
    opacity: 0.85;
    color: #6b7280;
}

.badge-danger { background-color: #dc3545; }
.badge-warning { background-color: #ffc107; color: #212529; }
.badge-info { background-color: #17a2b8; }
.badge-success { background-color: #28a745; }
.badge-secondary { background-color: #6c757d; }
</style>