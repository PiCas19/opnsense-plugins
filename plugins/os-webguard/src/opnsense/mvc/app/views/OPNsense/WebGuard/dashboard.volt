{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="content-box-main">
        <div class="table-responsive">
            <div class="col-sm-12">
                <div class="pull-right">
                    <small>{{ lang._('full help') }}&nbsp;</small>
                    <a href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
                </div>
            </div>
            
            <!-- Service Status -->
            <div class="row">
                <div class="col-md-12">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-shield-alt"></i> {{ lang._('WebGuard Service Status') }}
                                <div class="pull-right">
                                    <button class="btn btn-primary btn-xs" id="reconfigureAct" 
                                            data-endpoint='/api/webguard/settings/reconfigure' 
                                            data-label="{{ lang._('Apply') }}" 
                                            data-error-title="{{ lang._('Error reconfiguring WebGuard') }}" 
                                            type="button">
                                        <i class="fa fa-cog"></i> {{ lang._('Apply') }}
                                    </button>
                                </div>
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="row">
                                <div class="col-md-3">
                                    <div class="info-box">
                                        <span class="info-box-icon bg-blue"><i class="fa fa-power-off"></i></span>
                                        <div class="info-box-content">
                                            <span class="info-box-text">{{ lang._('Service Status') }}</span>
                                            <span class="info-box-number" id="service-status">
                                                {% if isEnabled %}
                                                    <span class="text-success">{{ lang._('Enabled') }}</span>
                                                {% else %}
                                                    <span class="text-danger">{{ lang._('Disabled') }}</span>
                                                {% endif %}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="info-box">
                                        <span class="info-box-icon bg-green"><i class="fa fa-cogs"></i></span>
                                        <div class="info-box-content">
                                            <span class="info-box-text">{{ lang._('Operation Mode') }}</span>
                                            <span class="info-box-number" id="operation-mode">{{ currentMode|capitalize }}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="info-box">
                                        <span class="info-box-icon bg-yellow"><i class="fa fa-clock"></i></span>
                                        <div class="info-box-content">
                                            <span class="info-box-text">{{ lang._('Uptime') }}</span>
                                            <span class="info-box-number" id="uptime">--</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="info-box">
                                        <span class="info-box-icon bg-red"><i class="fa fa-exclamation-triangle"></i></span>
                                        <div class="info-box-content">
                                            <span class="info-box-text">{{ lang._('Threats Today') }}</span>
                                            <span class="info-box-number" id="threats-today">--</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="row" style="margin-top: 20px;">
                                <div class="col-md-12">
                                    <div class="btn-group" role="group">
                                        <button type="button" class="btn btn-success" id="startService" 
                                                data-endpoint="/api/webguard/settings/start">
                                            <i class="fa fa-play"></i> {{ lang._('Start') }}
                                        </button>
                                        <button type="button" class="btn btn-warning" id="stopService" 
                                                data-endpoint="/api/webguard/settings/stop">
                                            <i class="fa fa-stop"></i> {{ lang._('Stop') }}
                                        </button>
                                        <button type="button" class="btn btn-info" id="restartService" 
                                                data-endpoint="/api/webguard/settings/restart">
                                            <i class="fa fa-refresh"></i> {{ lang._('Restart') }}
                                        </button>
                                        <button type="button" class="btn btn-primary" id="reloadService" 
                                                data-endpoint="/api/webguard/settings/reload">
                                            <i class="fa fa-refresh"></i> {{ lang._('Reload') }}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Statistics Overview -->
            <div class="row">
                <div class="col-md-6">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title"><i class="fa fa-chart-line"></i> {{ lang._('Real-time Statistics') }}</h3>
                        </div>
                        <div class="panel-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="metric-box">
                                        <div class="metric-value" id="requests-analyzed">--</div>
                                        <div class="metric-label">{{ lang._('Requests Analyzed') }}</div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="metric-box">
                                        <div class="metric-value" id="threats-blocked">--</div>
                                        <div class="metric-label">{{ lang._('Threats Blocked') }}</div>
                                    </div>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="metric-box">
                                        <div class="metric-value" id="ips-blocked">--</div>
                                        <div class="metric-label">{{ lang._('IPs Blocked') }}</div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="metric-box">
                                        <div class="metric-value" id="cpu-usage">--</div>
                                        <div class="metric-label">{{ lang._('CPU Usage') }}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title"><i class="fa fa-chart-pie"></i> {{ lang._('Threat Distribution') }}</h3>
                        </div>
                        <div class="panel-body">
                            <canvas id="threatChart" width="400" height="200"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Recent Threats -->
            <div class="row">
                <div class="col-md-12">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-exclamation-triangle"></i> {{ lang._('Recent Threats') }}
                                <div class="pull-right">
                                    <a href="/ui/webguard/threats" class="btn btn-xs btn-default">
                                        {{ lang._('View All') }} <i class="fa fa-arrow-right"></i>
                                    </a>
                                </div>
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="table-responsive">
                                <table class="table table-condensed table-hover" id="recentThreatsTable">
                                    <thead>
                                        <tr>
                                            <th>{{ lang._('Time') }}</th>
                                            <th>{{ lang._('Source IP') }}</th>
                                            <th>{{ lang._('Threat Type') }}</th>
                                            <th>{{ lang._('Severity') }}</th>
                                            <th>{{ lang._('Target') }}</th>
                                            <th>{{ lang._('Action') }}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Populated by JavaScript -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Real-time Feed -->
            <div class="row">
                <div class="col-md-12">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-rss"></i> {{ lang._('Real-time Threat Feed') }}
                                <div class="pull-right">
                                    <button type="button" class="btn btn-xs btn-primary" id="toggleFeed">
                                        <i class="fa fa-pause"></i> {{ lang._('Pause') }}
                                    </button>
                                    <button type="button" class="btn btn-xs btn-default" id="clearFeed">
                                        <i class="fa fa-trash"></i> {{ lang._('Clear') }}
                                    </button>
                                </div>
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div id="threatFeed" style="height: 300px; overflow-y: auto; border: 1px solid #ddd; padding: 10px;">
                                <!-- Real-time feed content -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.metric-box {
    text-align: center;
    padding: 10px;
}

.metric-value {
    font-size: 24px;
    font-weight: bold;
    color: #337ab7;
}

.metric-label {
    font-size: 12px;
    color: #666;
    margin-top: 5px;
}

.info-box {
    display: block;
    min-height: 90px;
    background: #fff;
    width: 100%;
    box-shadow: 0 1px 1px rgba(0,0,0,0.1);
    border-radius: 2px;
    margin-bottom: 15px;
}

.info-box-icon {
    border-top-left-radius: 2px;
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
    border-bottom-left-radius: 2px;
    display: block;
    float: left;
    height: 90px;
    width: 90px;
    text-align: center;
    font-size: 45px;
    line-height: 90px;
    background: rgba(0,0,0,0.2);
}

.info-box-content {
    padding: 5px 10px;
    margin-left: 90px;
}

.info-box-text {
    text-transform: uppercase;
    font-weight: bold;
    font-size: 13px;
}

.info-box-number {
    display: block;
    font-weight: bold;
    font-size: 18px;
}

.bg-blue { background-color: #3c8dbc !important; }
.bg-green { background-color: #00a65a !important; }
.bg-yellow { background-color: #f39c12 !important; }
.bg-red { background-color: #dd4b39 !important; }

.threat-feed-item {
    padding: 5px;
    margin: 2px 0;
    border-left: 3px solid;
    background: #f9f9f9;
}

.threat-feed-item.critical { border-color: #d9534f; }
.threat-feed-item.high { border-color: #f0ad4e; }
.threat-feed-item.medium { border-color: #5bc0de; }
.threat-feed-item.low { border-color: #5cb85c; }

.threat-feed-time {
    font-size: 11px;
    color: #666;
}
</style>

<script>
$(document).ready(function() {
    let feedActive = true;
    let lastThreatId = 0;
    
    // Initialize dashboard
    loadStatistics();
    loadRecentThreats();
    initThreatChart();
    
    // Auto-refresh every 5 seconds
    setInterval(function() {
        loadStatistics();
        if (feedActive) {
            loadThreatFeed();
        }
    }, 5000);
    
    // Auto-refresh recent threats every 30 seconds
    setInterval(loadRecentThreats, 30000);
    
    // Service control buttons
    $('#startService, #stopService, #restartService, #reloadService').click(function() {
        let endpoint = $(this).data('endpoint');
        let button = $(this);
        
        button.prop('disabled', true);
        
        ajaxCall(endpoint, {}, function(data) {
            if (data.result === 'ok') {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("Success") }}',
                    message: data.message || '{{ lang._("Operation completed successfully") }}',
                    buttons: [{
                        label: '{{ lang._("Close") }}',
                        action: function(dialogRef) {
                            dialogRef.close();
                        }
                    }]
                });
                setTimeout(loadStatistics, 2000);
            } else {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: '{{ lang._("Error") }}',
                    message: data.message || '{{ lang._("Operation failed") }}',
                    buttons: [{
                        label: '{{ lang._("Close") }}',
                        action: function(dialogRef) {
                            dialogRef.close();
                        }
                    }]
                });
            }
            button.prop('disabled', false);
        });
    });
    
    // Feed controls
    $('#toggleFeed').click(function() {
        feedActive = !feedActive;
        if (feedActive) {
            $(this).html('<i class="fa fa-pause"></i> {{ lang._("Pause") }}');
            loadThreatFeed();
        } else {
            $(this).html('<i class="fa fa-play"></i> {{ lang._("Resume") }}');
        }
    });
    
    $('#clearFeed').click(function() {
        $('#threatFeed').empty();
        lastThreatId = 0;
    });
    
    function loadStatistics() {
        ajaxGet('/api/webguard/settings/getStats', {}, function(data) {
            $('#requests-analyzed').text(formatNumber(data.requests_analyzed || 0));
            $('#threats-blocked').text(formatNumber(data.threats_blocked || 0));
            $('#ips-blocked').text(formatNumber(data.ips_blocked || 0));
            $('#uptime').text(formatUptime(data.uptime || 0));
            $('#cpu-usage').text((data.cpu_usage || 0) + '%');
            $('#threats-today').text(formatNumber(data.threats_today || 0));
        });
    }
    
    function loadRecentThreats() {
        ajaxGet('/api/webguard/threats/get', {limit: 10}, function(data) {
            let tbody = $('#recentThreatsTable tbody');
            tbody.empty();
            
            if (data.threats && data.threats.length > 0) {
                data.threats.forEach(function(threat) {
                    let row = $('<tr>');
                    row.append('<td>' + formatTime(threat.timestamp) + '</td>');
                    row.append('<td>' + threat.source_ip + '</td>');
                    row.append('<td>' + threat.type + '</td>');
                    row.append('<td><span class="label label-' + getSeverityClass(threat.severity) + '">' + threat.severity + '</span></td>');
                    row.append('<td>' + threat.target + '</td>');
                    row.append('<td><a href="/ui/webguard/threats/detail/' + threat.id + '" class="btn btn-xs btn-default">Details</a></td>');
                    tbody.append(row);
                });
            } else {
                tbody.append('<tr><td colspan="6" class="text-center">{{ lang._("No recent threats") }}</td></tr>');
            }
        });
    }
    
    function loadThreatFeed() {
        ajaxGet('/api/webguard/threats/getFeed', {last_id: lastThreatId, limit: 20}, function(data) {
            if (data.threats && data.threats.length > 0) {
                let feed = $('#threatFeed');
                
                data.threats.forEach(function(threat) {
                    let item = $('<div class="threat-feed-item ' + threat.severity + '">');
                    item.append('<div class="threat-feed-time">' + formatTime(threat.timestamp) + '</div>');
                    item.append('<strong>' + threat.type + '</strong> from ' + threat.source_ip + ' → ' + threat.target);
                    
                    feed.prepend(item);
                    lastThreatId = Math.max(lastThreatId, threat.id);
                });
                
                // Keep only last 100 items
                feed.children().slice(100).remove();
                
                // Auto-scroll if needed
                if (feed.scrollTop() < 50) {
                    feed.scrollTop(0);
                }
            }
        });
    }
    
    function initThreatChart() {
        // Initialize Chart.js threat distribution chart
        let ctx = document.getElementById('threatChart').getContext('2d');
        window.threatChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'CSRF', 'File Upload', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
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
                legend: {
                    position: 'bottom'
                }
            }
        });
        
        // Load threat distribution data
        ajaxGet('/api/webguard/threats/getStats', {period: '24h'}, function(data) {
            if (data.threats_by_type) {
                let labels = Object.keys(data.threats_by_type);
                let values = Object.values(data.threats_by_type);
                
                window.threatChart.data.labels = labels;
                window.threatChart.data.datasets[0].data = values;
                window.threatChart.update();
            }
        });
    }
    
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    
    function formatUptime(seconds) {
        if (seconds === 0) return '--';
        
        let days = Math.floor(seconds / 86400);
        let hours = Math.floor((seconds % 86400) / 3600);
        let minutes = Math.floor((seconds % 3600) / 60);
        
        if (days > 0) {
            return days + 'd ' + hours + 'h ' + minutes + 'm';
        } else if (hours > 0) {
            return hours + 'h ' + minutes + 'm';
        } else {
            return minutes + 'm';
        }
    }
    
    function formatTime(timestamp) {
        let date = new Date(timestamp * 1000);
        return date.toLocaleTimeString();
    }
    
    function getSeverityClass(severity) {
        switch (severity.toLowerCase()) {
            case 'critical': return 'danger';
            case 'high': return 'warning';
            case 'medium': return 'info';
            case 'low': return 'success';
            default: return 'default';
        }
    }
});
</script>