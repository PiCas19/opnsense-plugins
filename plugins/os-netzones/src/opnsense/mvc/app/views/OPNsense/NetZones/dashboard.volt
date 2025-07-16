<div class="dashboard-container">
  <div class="content-box">
    <div class="row dashboard-main">
      <!-- Service Status -->
      <div class="col-md-3">
        <div class="panel panel-default">
          <div class="panel-heading">
            <h6><i class="fa fa-server"></i> {{ lang._('Service Status') }}</h6>
          </div>
          <div class="panel-body text-center" id="serviceStatus">
            <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
          </div>
        </div>
      </div>

      <!-- Active Zones -->
      <div class="col-md-3">
        <div class="panel panel-default">
          <div class="panel-heading">
            <h6><i class="fa fa-shield"></i> {{ lang._('Zones') }}</h6>
          </div>
          <div class="panel-body text-center" id="zonesStatus">
            <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
          </div>
        </div>
      </div>

      <!-- Policy Activity -->
      <div class="col-md-3">
        <div class="panel panel-default">
          <div class="panel-heading">
            <h6><i class="fa fa-exchange"></i> {{ lang._('Policy Activity') }}</h6>
          </div>
          <div class="panel-body text-center" id="policyActivity">
            <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
          </div>
        </div>
      </div>

      <!-- Security Summary -->
      <div class="col-md-3">
        <div class="panel panel-default">
          <div class="panel-heading">
            <h6><i class="fa fa-exclamation-triangle"></i> {{ lang._('Security') }}</h6>
          </div>
          <div class="panel-body text-center" id="securitySummary">
            <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Zone Details -->
  <div class="content-box">
    <div class="row">
      <div class="col-md-8">
        <h5><i class="fa fa-list"></i> {{ lang._('Active Zones Overview') }}</h5>
        <div id="zonesOverview">
          <div class="text-center">
            <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading zones...') }}
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <!-- Zone Relationships Chart -->
        <h5><i class="fa fa-sitemap"></i> {{ lang._('Zone Relationships') }}</h5>
        <div id="zoneRelationships" style="min-height: 200px; margin-bottom: 20px;">
          <div class="text-center">
            <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
          </div>
        </div>

        <!-- Traffic Flow Indicator -->
        <div class="traffic-section">
          <h6><i class="fa fa-tachometer text-info"></i> {{ lang._('Traffic Flow') }}</h6>
          <div id="trafficFlow" style="margin-bottom: 20px;">
            <div class="text-center">
              <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
            </div>
          </div>
        </div>

        <!-- Top Blocked Sources -->
        <div class="blocked-sources-section">
          <h6><i class="fa fa-ban text-danger"></i> {{ lang._('Top Blocked Sources') }}</h6>
          <div id="topBlockedSources" class="small">
            <div class="text-center">
              <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Recent Activity -->
  <div class="content-box">
    <div class="row">
      <div class="col-md-8">
        <h5><i class="fa fa-history"></i> {{ lang._('Recent Policy Decisions') }}</h5>
        <div class="table-container" style="max-height: 400px; overflow-y: auto;">
          <table class="table table-striped table-condensed" id="recentDecisions">
            <thead>
              <tr>
                <th>{{ lang._('Time') }}</th>
                <th>{{ lang._('Source') }}</th>
                <th>{{ lang._('Destination') }}</th>
                <th>{{ lang._('Protocol') }}</th>
                <th>{{ lang._('Decision') }}</th>
                <th>{{ lang._('Zones') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colspan="6" class="text-center">
                  <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div class="col-md-4">
        <!-- Live Activity Monitor -->
        <div class="activity-monitor-section">
          <h6><i class="fa fa-bar-chart"></i> {{ lang._('Live Activity Monitor') }}</h6>
          <div id="liveActivityChart" style="height: 120px; margin-bottom: 25px;">
            <div class="text-center">
              <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
            </div>
          </div>
        </div>

        <!-- Protocol Distribution -->
        <div class="protocol-distribution-section">
          <h6><i class="fa fa-pie-chart"></i> {{ lang._('Protocol Distribution') }}</h6>
          <div id="protocolDistribution">
            <div class="text-center">
              <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Test Modal -->
  <div class="modal fade" id="testModal" tabindex="-1">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">{{ lang._('Test Zone Policy') }}</h5>
          <button type="button" class="close" data-dismiss="modal">&times;</button>
        </div>
        <div class="modal-body">
          <form id="testForm">
            <div class="form-group">
              <label>{{ lang._('Source IP') }}</label>
              <input type="text" class="form-control" id="testSrc" placeholder="192.168.1.100" required>
            </div>
            <div class="form-group">
              <label>{{ lang._('Destination IP') }}</label>
              <input type="text" class="form-control" id="testDst" placeholder="192.168.2.50" required>
            </div>
            <div class="form-group">
              <label>{{ lang._('Port') }}</label>
              <input type="number" class="form-control" id="testPort" placeholder="80" min="1" max="65535" required>
            </div>
            <div class="form-group">
              <label>{{ lang._('Protocol') }}</label>
              <select class="form-control" id="testProtocol">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="any">Any</option>
              </select>
            </div>
          </form>
          <div id="testResult" class="mt-3"></div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-dismiss="modal">{{ lang._('Close') }}</button>
          <button type="button" class="btn btn-primary" onclick="runTest()">{{ lang._('Run Test') }}</button>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
// Load dashboard data
function loadDashboard() {
  loadServiceStatus();
  loadZonesStatus();
  loadPolicyActivity();
  loadSecuritySummary();
  loadZonesOverview();
  loadRecentDecisions();
  loadZoneRelationships();
  loadTrafficFlow();
  loadTopBlockedSources();
  loadLiveActivityChart();
  loadProtocolDistribution();
}

function loadServiceStatus() {
  ajaxCall('/api/netzones/service/status', {}, function(data) {
    let html = '';
    if (data && typeof data === 'object' && data.running) {
      const socketPath = '/var/run/netzones.sock';
      html = `
        <div class="text-success">
          <i class="fa fa-check-circle fa-2x"></i><br>
          <strong>{{ lang._('RUNNING') }}</strong><br>
          <small>PID: ${data.pid || 'N/A'}</small><br>
          <small>Socket: ${socketPath}</small>
        </div>
      `;
    } else {
      html = `
        <div class="text-danger">
          <i class="fa fa-times-circle fa-2x"></i><br>
          <strong>{{ lang._('STOPPED') }}</strong><br>
          <small>Socket: Not Available</small>
        </div>
      `;
    }
    $('#serviceStatus').html(html);
  }).fail(function() {
    $('#serviceStatus').html(`
      <div class="text-warning">
        <i class="fa fa-exclamation-triangle fa-2x"></i><br>
        <strong>{{ lang._('UNKNOWN') }}</strong><br>
        <small>Status check failed</small>
      </div>
    `);
  });
}

function loadZonesStatus() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    let html = `
      <div>
        <div class="row">
          <div class="col-xs-6">
            <h3 class="text-primary mb-0">0</h3>
            <small>{{ lang._('Active') }}</small>
          </div>
          <div class="col-xs-6">
            <h3 class="text-muted mb-0">0</h3>
            <small>{{ lang._('Total') }}</small>
          </div>
        </div>
        <hr>
        <small class="text-muted">{{ lang._('Policies:') }} 0/0</small>
      </div>
    `;
    
    if (data && typeof data === 'object' && data.status === 'ok' && data.data && typeof data.data === 'object') {
      const stats = data.data;
      html = `
        <div>
          <div class="row">
            <div class="col-xs-6">
              <h3 class="text-primary mb-0">${stats.zones && typeof stats.zones === 'object' ? stats.zones.active || 0 : 0}</h3>
              <small>{{ lang._('Active') }}</small>
            </div>
            <div class="col-xs-6">
              <h3 class="text-muted mb-0">${stats.zones && typeof stats.zones === 'object' ? stats.zones.total || 0 : 0}</h3>
              <small>{{ lang._('Total') }}</small>
            </div>
          </div>
          <hr>
          <small class="text-muted">{{ lang._('Policies:') }} ${stats.policies && typeof stats.policies === 'object' ? stats.policies.active || 0 : 0}/${stats.policies && typeof stats.policies === 'object' ? stats.policies.total || 0 : 0}</small>
        </div>
      `;
    }
    $('#zonesStatus').html(html);
  }).fail(function() {
    $('#zonesStatus').html(`
      <div class="text-center text-warning">
        <i class="fa fa-exclamation-triangle"></i><br>
        <small>{{ lang._('Data unavailable') }}</small>
      </div>
    `);
  });
}

function loadPolicyActivity() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    let html = `
      <div>
        <h3 class="text-info mb-0">0</h3>
        <small>{{ lang._('Total Events') }}</small>
        <hr>
        <div class="row text-center">
          <div class="col-xs-4">
            <span class="badge badge-success">0</span><br>
            <small>{{ lang._('Allow') }}</small>
          </div>
          <div class="col-xs-4">
            <span class="badge badge-danger">0</span><br>
            <small>{{ lang._('Block') }}</small>
          </div>
          <div class="col-xs-4">
            <span class="badge badge-warning">0</span><br>
            <small>{{ lang._('Last Hour') }}</small>
          </div>
        </div>
      </div>
    `;
    
    if (data && data.status === 'ok' && data.data) {
      const stats = data.data;
      html = `
        <div>
          <h3 class="text-info mb-0">${stats.total_events || 0}</h3>
          <small>{{ lang._('Total Events') }}</small>
          <hr>
          <div class="row text-center">
            <div class="col-xs-4">
              <span class="badge badge-success">${stats.allow_events || 0}</span><br>
              <small>{{ lang._('Allow') }}</small>
            </div>
            <div class="col-xs-4">
              <span class="badge badge-danger">${stats.block_events || 0}</span><br>
              <small>{{ lang._('Block') }}</small>
            </div>
            <div class="col-xs-4">
              <span class="badge badge-warning">${stats.last_hour_count || 0}</span><br>
              <small>{{ lang._('Last Hour') }}</small>
            </div>
          </div>
        </div>
      `;
    }
    $('#policyActivity').html(html);
  });
}

function loadSecuritySummary() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    let html = `
      <div class="text-success">
        <i class="fa fa-shield fa-2x"></i><br>
        <strong>0%</strong><br>
        <small>{{ lang._('Block Rate') }}</small><br>
        <small class="text-muted">0 {{ lang._('blocked') }}</small>
      </div>
    `;
    
    if (data && data.status === 'ok' && data.data) {
      const stats = data.data;
      const blocked = stats.block_events || 0;
      const total = stats.total_events || 1;
      const blockRate = Math.round((blocked / total) * 100);
      
      let alertLevel = 'success';
      let icon = 'shield';
      if (blockRate > 20) alertLevel = 'warning';
      if (blockRate > 50) alertLevel = 'danger';
      
      html = `
        <div class="text-${alertLevel}">
          <i class="fa fa-${icon} fa-2x"></i><br>
          <strong>${blockRate}%</strong><br>
          <small>{{ lang._('Block Rate') }}</small><br>
          <small class="text-muted">${blocked} {{ lang._('blocked') }}</small>
        </div>
      `;
    }
    $('#securitySummary').html(html);
  });
}

function loadZonesOverview() {
  ajaxCall('/api/netzones/management/getZoneList', {}, function(data) {
    if (data && typeof data === 'object' && data.zones && Array.isArray(data.zones) && data.zones.length > 0) {
      let html = '<div class="row">';
      data.zones.forEach((zone, index) => {
        if (index % 2 === 0 && index > 0) html += '</div><div class="row">';
        html += `
          <div class="col-md-6 mb-3">
            <div class="panel panel-default">
              <div class="panel-body">
                <h6><i class="fa fa-shield text-primary"></i> ${zone.text || 'Unknown Zone'}</h6>
                <small class="text-muted">UUID: ${zone.value ? zone.value.substr(0, 8) + '...' : 'N/A'}</small>
              </div>
            </div>
          </div>
        `;
      });
      html += '</div>';
      $('#zonesOverview').html(html);
    } else {
      $('#zonesOverview').html('<div class="alert alert-info">{{ lang._("No active zones configured") }}</div>');
    }
  }).fail(function() {
    $('#zonesOverview').html('<div class="alert alert-warning">{{ lang._("Failed to load zones") }}</div>');
  });
}

function loadZoneRelationships() {
  ajaxCall('/api/netzones/dashboard/zoneRelationships', {}, function(data) {
    let html = '';
    if (data && data.status === 'ok' && data.relationships && data.relationships.length > 0) {
      html = '<div class="zone-flow-chart">';
      
      data.relationships.forEach(relationship => {
        const action = relationship.action.toLowerCase();
        const actionClass = action === 'pass' ? 'success' : action === 'block' ? 'danger' : 'warning';
        
        html += `
          <div class="zone-connection mb-2">
            <span class="badge badge-info">${relationship.source_zone}</span>
            <i class="fa fa-arrow-right text-muted mx-1"></i>
            <span class="badge badge-info">${relationship.destination_zone}</span>
            <span class="badge badge-${actionClass} pull-right">${relationship.action}</span>
          </div>
        `;
      });
      
      html += '</div>';
    } else {
      html = '<div class="text-muted text-center"><i class="fa fa-info-circle"></i><br>{{ lang._("No policies configured") }}</div>';
    }
    
    $('#zoneRelationships').html(html);
  });
}

function loadTrafficFlow() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    let html = `
      <div class="traffic-gauge text-center">
        <div class="gauge-container">
          <i class="fa fa-tachometer fa-2x text-muted"></i><br>
          <strong>0</strong> <small>pps</small>
        </div>
        <div class="mt-2">
          <small class="text-muted">{{ lang._('No activity') }}</small>
        </div>
      </div>
    `;
    
    if (data && data.status === 'ok' && data.data) {
      const stats = data.data;
      const lastHour = stats.last_hour_count || 0;
      const pps = Math.round(lastHour / 3600) || 0;
      
      let gaugeColor = 'success';
      let gaugeIcon = 'tachometer';
      if (pps > 10) gaugeColor = 'warning';
      if (pps > 50) gaugeColor = 'danger';
      
      html = `
        <div class="traffic-gauge text-center">
          <div class="gauge-container">
            <i class="fa fa-${gaugeIcon} fa-2x text-${gaugeColor}"></i><br>
            <strong>${pps}</strong> <small>pps</small>
          </div>
          <div class="mt-2">
            <small class="text-muted">${lastHour} {{ lang._('events/hour') }}</small>
          </div>
        </div>
      `;
    }
    
    $('#trafficFlow').html(html);
  });
}

function loadRecentDecisions() {
  ajaxCall('/api/netzones/dashboard/logs_list', {}, function(data) {
    if (data && typeof data === 'object' && data.status === 'ok' && data.data && Array.isArray(data.data) && data.data.length > 0) {
      let html = '';
      data.data.slice(0, 10).forEach(entry => {
        const decision = (entry.decision || 'unknown').toLowerCase();
        const decisionClass = decision === 'allow' || decision === 'pass' ? 'success' : 
                            decision === 'block' ? 'danger' : 'warning';
        html += `
          <tr>
            <td><small>${entry.timestamp || 'N/A'}</small></td>
            <td><code>${entry.src || 'unknown'}</code></td>
            <td><code>${entry.dst || 'unknown'}</code></td>
            <td><span class="label label-info">${entry.protocol || 'unknown'}</span></td>
            <td><span class="label label-${decisionClass}">${entry.decision || 'unknown'}</span></td>
            <td><small>${entry.source_zone || 'UNKNOWN'} → ${entry.destination_zone || 'UNKNOWN'}</small></td>
          </tr>
        `;
      });
      $('#recentDecisions tbody').html(html);
    } else {
      $('#recentDecisions tbody').html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No recent activity") }}</td></tr>');
    }
  }).fail(function() {
    $('#recentDecisions tbody').html('<tr><td colspan="6" class="text-center text-warning">{{ lang._("Failed to load activity") }}</td></tr>');
  });
}

function loadLiveActivityChart() {
  ajaxCall('/api/netzones/dashboard/traffic_patterns', { hours: 6 }, function(data) {
    let html = '';
    
    if (data && data.status === 'ok' && data.data && data.data.hourly) {
      const hourlyData = data.data.hourly;
      const values = Object.values(hourlyData);
      const maxValue = Math.max(...values, 1);
      
      html = '<div class="activity-chart-compact">';
      values.slice(-6).forEach((value, index) => {
        const height = Math.max((value / maxValue) * 100, 2);
        const hour = new Date(Date.now() - (5-index) * 3600000).getHours();
        html += `
          <div class="chart-bar-compact">
            <div class="chart-bar-container">
              <div class="chart-bar-fill" style="height: ${height}%;" title="${value} events at ${hour}:00"></div>
            </div>
            <div class="chart-bar-label">${hour}h</div>
          </div>
        `;
      });
      html += '</div>';
    } else {
      html = '<div class="text-muted text-center"><i class="fa fa-line-chart"></i><br><small>{{ lang._("No data") }}</small></div>';
    }
    
    $('#liveActivityChart').html(html);
  });
}

function loadProtocolDistribution() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    let html = '';
    
    if (data && data.status === 'ok' && data.data && data.data.top_protocols) {
      const protocols = data.data.top_protocols;
      const total = data.data.total_events || 1;
      
      Object.entries(protocols).slice(0, 5).forEach(([protocol, count]) => {
        const percentage = Math.round((count / total) * 100) || 0;
        html += `
          <div class="mb-2">
            <div class="clearfix">
              <span class="pull-left">${protocol.toUpperCase()}</span>
              <span class="pull-right">${count} (${percentage}%)</span>
            </div>
            <div class="progress progress-xs">
              <div class="progress-bar progress-bar-primary" style="width: ${percentage}%"></div>
            </div>
          </div>
        `;
      });
    } else {
      html = '<div class="text-muted text-center"><i class="fa fa-pie-chart"></i><br>{{ lang._("No data") }}</div>';
    }
    
    $('#protocolDistribution').html(html || '<div class="text-muted">{{ lang._("No data") }}</div>');
  });
}

function loadTopBlockedSources() {
  ajaxCall('/api/netzones/dashboard/logs_list', {}, function(data) {
    let html = '';
    
    if (data && data.status === 'ok' && data.data) {
      const blocked = data.data.filter(entry => entry.decision.toLowerCase() === 'block');
      const sources = {};
      
      blocked.forEach(entry => {
        sources[entry.src] = (sources[entry.src] || 0) + 1;
      });
      
      const sorted = Object.entries(sources).sort((a, b) => b[1] - a[1]).slice(0, 5);
      
      if (sorted.length > 0) {
        sorted.forEach(([ip, count]) => {
          html += `<div class="mb-1"><code>${ip}</code> <span class="badge badge-danger pull-right">${count}</span></div>`;
        });
      } else {
        html = '<div class="text-muted">{{ lang._("No blocked sources") }}</div>';
      }
    } else {
      html = '<div class="text-muted">{{ lang._("No data available") }}</div>';
    }
    
    $('#topBlockedSources').html(html);
  });
}

// Initialize dashboard
$(function() {
  loadDashboard();
  
  // Auto-refresh every 30 seconds
  setInterval(function() {
    loadDashboard();
  }, 30000);
});

// Global refresh function
window.reloadDashboard = loadDashboard;
</script>

<style>
/* Reset completo */
* {
  box-sizing: border-box;
}

html, body {
  margin: 0;
  padding: 0;
  width: 100%;
  height: 100%;
}

/* Container principale - FULL SCREEN */
.dashboard-container {
  width: 100vw !important;
  max-width: 100vw !important;
  margin: 0 !important;
  padding: 0 !important;
  overflow-x: hidden;
}

.content-box {
  background: #fff;
  padding: 20px;
  margin: 0 0 20px 0;
  border-radius: 10px;
  box-shadow: 0 2px 5px rgba(0,0,0,0.1);
  width: 100% !important;
  max-width: 100% !important;
}

/* Grid System */
.row {
  display: flex;
  flex-wrap: wrap;
  margin: 0 -10px;
  width: calc(100% + 20px);
}

/* 4 PANNELLI SULLA STESSA RIGA */
.dashboard-main {
  display: flex;
  flex-wrap: nowrap !important;
  gap: 15px;
  margin: 0 !important;
  padding: 0 !important;
  width: 100% !important;
}

.dashboard-main .col-md-3 {
  flex: 1 1 25%;
  max-width: 25%;
  min-width: 200px;
  padding: 0 5px;
}

.col-md-4 {
  flex: 0 0 33.3333%;
  max-width: 33.3333%;
  padding: 0 10px;
}

.col-md-6 {
  flex: 0 0 50%;
  max-width: 50%;
  padding: 0 10px;
}

.col-md-8 {
  flex: 0 0 66.6667%;
  max-width: 66.6667%;
  padding: 0 10px;
}

.col-xs-4 {
  flex: 0 0 33.3333%;
  max-width: 33.3333%;
}

.col-xs-6 {
  flex: 0 0 50%;
  max-width: 50%;
}

/* Panel Styles */
.panel {
  background-color: #f8f9fa;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #dee2e6;
  margin-bottom: 15px;
  height: 100%;
  width: 100%;
  min-height: 150px;
}

.panel-heading {
  background-color: #e9ecef;
  padding: 10px 15px;
  font-weight: bold;
  border-bottom: 1px solid #dee2e6;
  font-size: 13px;
}

.panel-body {
  padding: 15px;
  min-height: 100px;
}

/* Live Activity Chart - COMPATTO */
.activity-chart-compact {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  padding: 8px 5px;
  background-color: #f9f9f9;
  border-radius: 5px;
  height: 100px;
  overflow: hidden;
}

.chart-bar-compact {
  display: flex;
  flex-direction: column;
  align-items: center;
  flex: 1;
  max-width: 14%;
  margin: 0 1px;
}

.chart-bar-container {
  height: 60px;
  width: 100%;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  margin-bottom: 3px;
}

.chart-bar-fill {
  width: 80%;
  background-color: #337ab7;
  min-height: 2px;
  border-radius: 2px 2px 0 0;
}

.chart-bar-label {
  font-size: 9px;
  color: #666;
  text-align: center;
  white-space: nowrap;
}

/* Activity Monitor Section */
.activity-monitor-section {
  margin-bottom: 20px;
}

.activity-monitor-section h6 {
  margin-bottom: 8px;
  font-size: 12px;
}

/* Protocol Distribution */
.protocol-distribution-section h6 {
  margin-bottom: 8px;
  font-size: 12px;
}

.protocol-distribution-section .mb-2 {
  margin-bottom: 8px;
}

.protocol-distribution-section .progress {
  height: 8px;
  margin-bottom: 3px;
}

.protocol-distribution-section .clearfix span {
  font-size: 10px;
}

/* Traffic Gauge */
.traffic-gauge {
  padding: 15px;
  background: linear-gradient(135deg, #f5f5f5 0%, #e8e8e8 100%);
  border-radius: 8px;
  margin-bottom: 15px;
}

/* Zone connection styling */
.zone-connection {
  padding: 5px;
  border-left: 3px solid #337ab7;
  margin-bottom: 5px;
  background-color: #f9f9f9;
}

/* Table styling */
.table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 0;
}

.table th, .table td {
  padding: 8px;
  border: 1px solid #dee2e6;
  text-align: left;
}

.table-container {
  overflow-x: auto;
  width: 100%;
}

/* Badge styling */
.badge {
  font-size: 11px;
  padding: 3px 6px;
  border-radius: 3px;
}

.badge-success {
  background-color: #5cb85c;
  color: white;
}

.badge-danger {
  background-color: #d9534f;
  color: white;
}

.badge-warning {
  background-color: #f0ad4e;
  color: white;
}

.badge-info {
  background-color: #5bc0de;
  color: white;
}

/* Label styling */
.label {
  display: inline-block;
  padding: 2px 6px;
  font-size: 10px;
  font-weight: bold;
  line-height: 1;
  color: #fff;
  text-align: center;
  white-space: nowrap;
  vertical-align: baseline;
  border-radius: 2px;
}

.label-success {
  background-color: #5cb85c;
}

.label-danger {
  background-color: #d9534f;
}

.label-warning {
  background-color: #f0ad4e;
}

.label-info {
  background-color: #5bc0de;
}

/* Progress bar styling */
.progress {
  height: 20px;
  margin-bottom: 5px;
  overflow: hidden;
  background-color: #f5f5f5;
  border-radius: 4px;
}

.progress-xs {
  height: 10px;
}

.progress-bar {
  float: left;
  width: 0%;
  height: 100%;
  font-size: 12px;
  line-height: 20px;
  color: #fff;
  text-align: center;
  background-color: #337ab7;
  transition: width 0.6s ease;
}

.progress-bar-primary {
  background-color: #337ab7;
}

/* Text utilities */
.text-center {
  text-align: center;
}

.text-left {
  text-align: left;
}

.text-right {
  text-align: right;
}

.text-muted {
  color: #777;
}

.text-primary {
  color: #337ab7;
}

.text-success {
  color: #5cb85c;
}

.text-danger {
  color: #d9534f;
}

.text-warning {
  color: #f0ad4e;
}

.text-info {
  color: #5bc0de;
}

/* Spacing utilities */
.mb-0 {
  margin-bottom: 0;
}

.mb-1 {
  margin-bottom: 5px;
}

.mb-2 {
  margin-bottom: 10px;
}

.mb-3 {
  margin-bottom: 15px;
}

.mt-2 {
  margin-top: 10px;
}

.mt-3 {
  margin-top: 15px;
}

.mt-4 {
  margin-top: 20px;
}

.mx-1 {
  margin-left: 5px;
  margin-right: 5px;
}

/* Pull utilities */
.pull-left {
  float: left;
}

.pull-right {
  float: right;
}

.clearfix::after {
  content: "";
  display: table;
  clear: both;
}

/* Alert styling */
.alert {
  padding: 15px;
  margin-bottom: 20px;
  border: 1px solid transparent;
  border-radius: 4px;
}

.alert-info {
  color: #31708f;
  background-color: #d9edf7;
  border-color: #bce8f1;
}

.alert-warning {
  color: #8a6d3b;
  background-color: #fcf8e3;
  border-color: #faebcc;
}

/* Modal styling */
.modal {
  display: none;
  position: fixed;
  z-index: 1050;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  overflow: hidden;
  background-color: rgba(0,0,0,0.5);
}

.modal-dialog {
  position: relative;
  width: auto;
  margin: 10px;
  max-width: 600px;
  margin: 30px auto;
}

.modal-content {
  background-color: #fff;
  border: 1px solid #999;
  border-radius: 6px;
  box-shadow: 0 3px 9px rgba(0,0,0,0.5);
}

.modal-header {
  padding: 15px;
  border-bottom: 1px solid #e5e5e5;
}

.modal-body {
  padding: 15px;
}

.modal-footer {
  padding: 15px;
  text-align: right;
  border-top: 1px solid #e5e5e5;
}

/* Form styling */
.form-group {
  margin-bottom: 15px;
}

.form-control {
  display: block;
  width: 100%;
  padding: 6px 12px;
  font-size: 14px;
  line-height: 1.42857143;
  color: #555;
  background-color: #fff;
  border: 1px solid #ccc;
  border-radius: 4px;
}

/* Button styling */
.btn {
  display: inline-block;
  padding: 6px 12px;
  margin-bottom: 0;
  font-size: 14px;
  font-weight: normal;
  line-height: 1.42857143;
  text-align: center;
  white-space: nowrap;
  vertical-align: middle;
  cursor: pointer;
  border: 1px solid transparent;
  border-radius: 4px;
  text-decoration: none;
}

.btn-primary {
  color: #fff;
  background-color: #337ab7;
  border-color: #2e6da4;
}

.btn-secondary {
  color: #333;
  background-color: #fff;
  border-color: #ccc;
}

/* Icon spacing */
.fa {
  margin-right: 5px;
}

.fa:last-child {
  margin-right: 0;
}

/* Section spacing */
.traffic-section {
  margin-bottom: 20px;
}

.blocked-sources-section {
  margin-bottom: 10px;
}

/* Mobile responsiveness */
@media (max-width: 768px) {
  .dashboard-main {
    flex-wrap: wrap !important;
    gap: 10px;
  }
  
  .dashboard-main .col-md-3 {
    flex: 0 0 calc(50% - 5px);
    max-width: calc(50% - 5px);
    min-width: calc(50% - 5px);
  }
  
  .col-md-4, .col-md-6, .col-md-8 {
    flex: 0 0 100%;
    max-width: 100%;
  }
  
  .content-box {
    padding: 15px;
  }
  
  .panel {
    min-height: 120px;
  }
  
  .panel-body {
    min-height: 80px;
  }
}

@media (max-width: 480px) {
  .dashboard-main .col-md-3 {
    flex: 0 0 100%;
    max-width: 100%;
  }
  
  .content-box {
    padding: 10px;
  }
  
  .row {
    margin: 0 -5px;
  }
  
  [class*="col-"] {
    padding: 0 5px;
  }
  
  .table th, .table td {
    padding: 4px;
    font-size: 12px;
  }
  
  .activity-chart-compact {
    height: 80px;
  }
  
  .chart-bar-container {
    height: 40px;
  }
  
  .chart-bar-label {
    font-size: 8px;
  }
}

/* Responsive improvements */
@media (max-width: 992px) {
  .content-box {
    padding: 15px;
  }
}

@media (max-width: 576px) {
  .content-box {
    padding: 10px;
  }
}
</style>