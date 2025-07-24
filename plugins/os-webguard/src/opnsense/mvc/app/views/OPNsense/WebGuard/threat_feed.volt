{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <h1>{{ lang._('Real-time Threat Feed') }}</h1>
                <div class="feed-controls">
                    <button class="btn btn-primary" id="toggleFeed">
                        <i class="fa fa-pause"></i> {{ lang._('Pause') }}
                    </button>
                    <button class="btn btn-secondary" id="clearFeed">
                        <i class="fa fa-trash"></i> {{ lang._('Clear') }}
                    </button>
                    <button class="btn btn-info" id="exportFeed">
                        <i class="fa fa-download"></i> {{ lang._('Export') }}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Feed Stats -->
    <div class="row">
        <div class="col-md-3">
            <div class="feed-stat-card">
                <div class="stat-value" id="totalFeeds">0</div>
                <div class="stat-label">{{ lang._('Total Events') }}</div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="feed-stat-card">
                <div class="stat-value" id="activeFeeds">0</div>
                <div class="stat-label">{{ lang._('Active in Feed') }}</div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="feed-stat-card">
                <div class="stat-value" id="feedRate">0/min</div>
                <div class="stat-label">{{ lang._('Feed Rate') }}</div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="feed-stat-card">
                <div class="stat-value" id="lastUpdate">--</div>
                <div class="stat-label">{{ lang._('Last Update') }}</div>
            </div>
        </div>
    </div>

    <!-- Filters -->
    <div class="row">
        <div class="col-md-12">
            <div class="filter-card">
                <h4>{{ lang._('Filters') }}</h4>
                <div class="filter-row">
                    <div class="filter-group">
                        <label>{{ lang._('Severity') }}:</label>
                        <select id="severityFilter" class="form-control">
                            <option value="">{{ lang._('All') }}</option>
                            <option value="critical">{{ lang._('Critical') }}</option>
                            <option value="high">{{ lang._('High') }}</option>
                            <option value="medium">{{ lang._('Medium') }}</option>
                            <option value="low">{{ lang._('Low') }}</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>{{ lang._('Type') }}:</label>
                        <select id="typeFilter" class="form-control">
                            <option value="">{{ lang._('All Types') }}</option>
                            <option value="SQL Injection">{{ lang._('SQL Injection') }}</option>
                            <option value="XSS Attack">{{ lang._('XSS Attack') }}</option>
                            <option value="Brute Force">{{ lang._('Brute Force') }}</option>
                            <option value="Path Traversal">{{ lang._('Path Traversal') }}</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>{{ lang._('Source IP') }}:</label>
                        <input type="text" id="ipFilter" class="form-control" placeholder="192.168.1.1">
                    </div>
                    <div class="filter-group">
                        <button class="btn btn-primary" id="applyFilters">{{ lang._('Apply') }}</button>
                        <button class="btn btn-secondary" id="resetFilters">{{ lang._('Reset') }}</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Real-time Feed -->
    <div class="row">
        <div class="col-md-12">
            <div class="feed-container">
                <div class="feed-header">
                    <h3>{{ lang._('Live Threat Feed') }}</h3>
                    <div class="feed-status">
                        <span id="feedStatus" class="status-indicator active">{{ lang._('Active') }}</span>
                    </div>
                </div>
                <div id="threatFeed" class="threat-feed">
                    <!-- Dynamic content -->
                </div>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    let feedActive = true;
    let lastThreatId = 0;
    let feedItems = [];
    let filters = {
        severity: '',
        type: '',
        ip: ''
    };
    
    // Initialize
    startFeed();
    
    // Controls
    $('#toggleFeed').click(toggleFeed);
    $('#clearFeed').click(clearFeed);
    $('#exportFeed').click(exportFeed);
    $('#applyFilters').click(applyFilters);
    $('#resetFilters').click(resetFilters);
    
    function startFeed() {
        loadFeedData();
        setInterval(function() {
            if (feedActive) {
                loadFeedData();
            }
        }, 3000); // Update every 3 seconds
    }
    
    function loadFeedData() {
        ajaxCall('/api/webguard/threats/getFeed', {sinceId: lastThreatId}, function(response) {
            if (response.status === 'ok' && response.recent_threats && response.recent_threats.length) {
                response.recent_threats.forEach(function(threat) {
                    if (passesFilter(threat)) {
                        addFeedItem(threat);
                    }
                });
                lastThreatId = response.last_id;
                updateFeedStats();
                $('#lastUpdate').text(new Date().toLocaleTimeString());
            }
        });
    }
    
    function addFeedItem(threat) {
        const timestamp = new Date();
        const item = {
            ...threat,
            displayTime: timestamp
        };
        
        feedItems.unshift(item);
        
        // Keep only last 100 items
        if (feedItems.length > 100) {
            feedItems = feedItems.slice(0, 100);
        }
        
        renderFeedItems();
    }
    
    function renderFeedItems() {
        const feed = $('#threatFeed');
        feed.empty();
        
        feedItems.forEach(function(threat) {
            const severityClass = getSeverityClass(threat.severity);
            const timeAgo = getTimeAgo(threat.displayTime);
            
            const item = $(`
                <div class="threat-feed-item ${threat.severity}" data-threat-id="${threat.id}">
                    <div class="feed-item-header">
                        <div class="feed-item-time">${timeAgo}</div>
                        <div class="feed-item-severity">
                            <span class="badge ${severityClass}">${threat.severity}</span>
                        </div>
                    </div>
                    <div class="feed-item-content">
                        <div class="feed-item-type">${threat.threat_type || threat.type}</div>
                        <div class="feed-item-details">
                            <span class="source-ip"><i class="fa fa-globe"></i> ${threat.source_ip}</span>
                            <span class="method"><i class="fa fa-exchange"></i> ${threat.method || 'GET'}</span>
                        </div>
                        <div class="feed-item-description">${threat.description || 'Threat detected'}</div>
                    </div>
                    <div class="feed-item-actions">
                        <button class="btn btn-xs btn-primary" onclick="viewThreatDetails('${threat.id}')">
                            <i class="fa fa-eye"></i>
                        </button>
                        <button class="btn btn-xs btn-danger" onclick="blockIP('${threat.source_ip}')">
                            <i class="fa fa-ban"></i>
                        </button>
                    </div>
                </div>
            `);
            
            feed.append(item);
        });
    }
    
    function toggleFeed() {
        feedActive = !feedActive;
        const btn = $('#toggleFeed');
        const status = $('#feedStatus');
        
        if (feedActive) {
            btn.html('<i class="fa fa-pause"></i> {{ lang._("Pause") }}');
            status.removeClass('inactive').addClass('active').text('{{ lang._("Active") }}');
        } else {
            btn.html('<i class="fa fa-play"></i> {{ lang._("Resume") }}');
            status.removeClass('active').addClass('inactive').text('{{ lang._("Paused") }}');
        }
    }
    
    function clearFeed() {
        if (confirm('{{ lang._("Clear all feed items?") }}')) {
            feedItems = [];
            $('#threatFeed').empty();
            updateFeedStats();
        }
    }
    
    function exportFeed() {
        if (feedItems.length === 0) {
            alert('{{ lang._("No data to export") }}');
            return;
        }
        
        const csv = generateCSV(feedItems);
        downloadCSV(csv, `threat_feed_${new Date().toISOString().split('T')[0]}.csv`);
    }
    
    function applyFilters() {
        filters.severity = $('#severityFilter').val();
        filters.type = $('#typeFilter').val();
        filters.ip = $('#ipFilter').val();
        renderFeedItems();
    }
    
    function resetFilters() {
        filters = { severity: '', type: '', ip: '' };
        $('#severityFilter').val('');
        $('#typeFilter').val('');
        $('#ipFilter').val('');
        renderFeedItems();
    }
    
    function passesFilter(threat) {
        if (filters.severity && threat.severity !== filters.severity) return false;
        if (filters.type && (threat.threat_type || threat.type) !== filters.type) return false;
        if (filters.ip && !threat.source_ip.includes(filters.ip)) return false;
        return true;
    }
    
    function updateFeedStats() {
        $('#totalFeeds').text(feedItems.length);
        $('#activeFeeds').text(feedItems.filter(item => passesFilter(item)).length);
        
        // Calculate feed rate (items per minute)
        const now = new Date();
        const oneMinuteAgo = new Date(now - 60000);
        const recentItems = feedItems.filter(item => item.displayTime > oneMinuteAgo);
        $('#feedRate').text(recentItems.length + '/min');
    }
    
    function getSeverityClass(severity) {
        switch(severity?.toLowerCase()) {
            case 'critical': return 'badge-danger';
            case 'high': return 'badge-warning';
            case 'medium': return 'badge-info';
            case 'low': return 'badge-success';
            default: return 'badge-secondary';
        }
    }
    
    function getTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 60) return seconds + 's ago';
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return minutes + 'm ago';
        const hours = Math.floor(minutes / 60);
        return hours + 'h ago';
    }
    
    function generateCSV(items) {
        const headers = ['Time', 'Type', 'Severity', 'Source IP', 'Method', 'Description'];
        const rows = items.map(item => [
            item.displayTime.toISOString(),
            item.threat_type || item.type,
            item.severity,
            item.source_ip,
            item.method || 'GET',
            item.description || ''
        ]);
        
        return [headers, ...rows].map(row => 
            row.map(field => `"${field}"`).join(',')
        ).join('\n');
    }
    
    function downloadCSV(csv, filename) {
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        window.URL.revokeObjectURL(url);
    }
    
    // Global functions for buttons
    window.viewThreatDetails = function(threatId) {
        window.open('/ui/webguard/threats/detail/' + threatId, '_blank');
    };
    
    window.blockIP = function(ip) {
        if (confirm('{{ lang._("Block IP") }} ' + ip + '?')) {
            ajaxCall('/api/webguard/settings/blockIP', {ip: ip}, function(data) {
                if (data.result === 'ok' || data.status === 'ok') {
                    alert('{{ lang._("IP blocked successfully") }}');
                }
            });
        }
    };
});
</script>

<style>
.feed-stat-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    text-align: center;
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
    margin-top: 0.5rem;
}

.filter-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.filter-row {
    display: flex;
    gap: 1rem;
    align-items: end;
    flex-wrap: wrap;
}

.filter-group {
    display: flex;
    flex-direction: column;
    min-width: 150px;
}

.filter-group label {
    font-size: 0.875rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
}

.feed-container {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.feed-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem;
    border-bottom: 1px solid #e5e7eb;
}

.status-indicator {
    padding: 0.25rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.875rem;
    font-weight: 600;
}

.status-indicator.active {
    background: #10b981;
    color: white;
}

.status-indicator.inactive {
    background: #ef4444;
    color: white;
}

.threat-feed {
    max-height: 600px;
    overflow-y: auto;
    padding: 1rem;
}

.threat-feed-item {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 0.75rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    transition: all 0.3s ease;
}

.threat-feed-item:hover {
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    transform: translateY(-1px);
}

.threat-feed-item.critical { border-left: 4px solid #dc3545; }
.threat-feed-item.high { border-left: 4px solid #ffc107; }
.threat-feed-item.medium { border-left: 4px solid #17a2b8; }
.threat-feed-item.low { border-left: 4px solid #28a745; }

.feed-item-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.feed-item-time {
    font-size: 0.75rem;
    color: #6b7280;
}

.feed-item-type {
    font-weight: 600;
    color: #1f2937;
    margin-bottom: 0.25rem;
}

.feed-item-details {
    display: flex;
    gap: 1rem;
    margin-bottom: 0.25rem;
}

.feed-item-details span {
    font-size: 0.875rem;
    color: #6b7280;
}

.feed-item-details i {
    margin-right: 0.25rem;
}

.feed-item-description {
    font-size: 0.875rem;
    color: #4b5563;
}

.feed-item-actions {
    display: flex;
    gap: 0.5rem;
    flex-shrink: 0;
}

.feed-controls {
    display: flex;
    gap: 0.5rem;
}

@media (max-width: 768px) {
    .filter-row {
        flex-direction: column;
        align-items: stretch;
    }
    
    .filter-group {
        min-width: auto;
    }
    
    .threat-feed-item {
        flex-direction: column;
        gap: 1rem;
    }
    
    .feed-item-actions {
        align-self: flex-end;
    }
}
</style>