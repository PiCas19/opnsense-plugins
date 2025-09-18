<style>
/* OPNsense Alert Dashboard Styling */
:root {
  --opnsense-orange: #d94f00;
  --opnsense-orange-light: #ff6600;
  --opnsense-orange-dark: #b8440a;
  --bg-primary: #ffffff;
  --bg-secondary: #f8fafc;
  --bg-tertiary: #f1f5f9;
  --text-primary: #1e293b;
  --text-secondary: #64748b;
  --border-color: #e2e8f0;
  --success-color: #10b981;
  --warning-color: #f59e0b;
  --danger-color: #ef4444;
  --info-color: #3b82f6;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
}

/* Modern Alert Dashboard Container */
.alert-dashboard {
  background: var(--bg-primary);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
  border: 2px solid var(--border-color);
  overflow: hidden;
  margin: 1.5rem 0;
  min-height: 600px;
  position: relative;
}

/* Dashboard Header */
.alert-dashboard-header {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  color: white;
  padding: 2rem;
  border-bottom: 3px solid var(--opnsense-orange-dark);
  position: relative;
  overflow: hidden;
}

.alert-dashboard-header::before {
  content: '';
  position: absolute;
  top: -50%;
  right: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
  transform: rotate(30deg);
  pointer-events: none;
}

.alert-dashboard-title {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  position: relative;
  z-index: 1;
}

.alert-dashboard-title i {
  font-size: 28px;
  text-shadow: 0 2px 4px rgba(0,0,0,0.3);
}

.alert-dashboard-subtitle {
  margin: 0.5rem 0 0 0;
  font-size: 14px;
  opacity: 0.9;
  position: relative;
  z-index: 1;
}

/* Stats Cards Row */
.stats-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
  padding: 2rem;
  background: var(--bg-secondary);
}

.stat-card {
  background: var(--bg-primary);
  border-radius: var(--radius-lg);
  padding: 1.5rem;
  text-align: center;
  box-shadow: var(--shadow-md);
  border: 2px solid var(--border-color);
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.stat-card:hover {
  transform: translateY(-4px);
  box-shadow: var(--shadow-lg);
  border-color: var(--opnsense-orange);
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: var(--opnsense-orange);
  transform: scaleX(0);
  transition: transform 0.3s ease;
}

.stat-card:hover::before {
  transform: scaleX(1);
}

.stat-icon {
  font-size: 32px;
  margin-bottom: 0.75rem;
  color: var(--opnsense-orange);
}

.stat-number {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  margin: 0;
}

.stat-label {
  font-size: 12px;
  color: var(--text-secondary);
  margin: 0.5rem 0 0 0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Controls Section */
.controls-section {
  padding: 1.5rem 2rem;
  background: var(--bg-primary);
  border-bottom: 2px solid var(--border-color);
}

.controls-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  align-items: end;
}

.control-group {
  display: flex;
  flex-direction: column;
}

.control-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.modern-select {
  appearance: none;
  background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 0.75rem 2.5rem 0.75rem 1rem;
  font-size: 12px;
  color: var(--text-primary);
  cursor: pointer;
  transition: all 0.3s ease;
  background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><path fill="%23334155" d="M4 6l4 4 4-4z"/></svg>');
  background-repeat: no-repeat;
  background-position: right 0.75rem center;
  background-size: 16px;
}

.modern-select:hover {
  border-color: var(--opnsense-orange);
  box-shadow: var(--shadow-md);
}

.modern-select:focus {
  outline: none;
  border-color: var(--opnsense-orange);
  box-shadow: 0 0 0 3px rgba(217, 79, 0, 0.15);
}

.modern-btn {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  border: 2px solid var(--opnsense-orange);
  border-radius: var(--radius-md);
  color: white;
  padding: 0.75rem 1.5rem;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.modern-btn:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  background: linear-gradient(135deg, var(--opnsense-orange-light) 0%, #ff7722 100%);
}

.modern-btn:active {
  transform: translateY(0);
}

.modern-btn.loading {
  pointer-events: none;
  opacity: 0.8;
}

.modern-btn.loading::after {
  content: '';
  width: 16px;
  height: 16px;
  border: 2px solid transparent;
  border-top-color: white;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Modern Table Styling */
.modern-table-container {
  padding: 2rem;
  background: var(--bg-primary);
  min-height: 400px;
}

.modern-table {
  width: 100%;
  border-collapse: collapse;
  border-radius: var(--radius-lg);
  overflow: hidden;
  box-shadow: var(--shadow-md);
  border: 2px solid var(--border-color);
  background: var(--bg-primary);
}

.modern-table thead {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
}

.modern-table thead th {
  padding: 1.25rem 1rem;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 3px solid var(--border-color);
  position: relative;
}

.modern-table thead th::after {
  content: '';
  position: absolute;
  bottom: -3px;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--opnsense-orange);
  transform: scaleX(0);
  transition: transform 0.3s ease;
}

.modern-table thead th:hover::after {
  transform: scaleX(1);
}

.modern-table tbody tr {
  transition: all 0.2s ease;
}

.modern-table tbody tr:hover {
  background: var(--bg-secondary);
  transform: scale(1.001);
}

.modern-table tbody td {
  padding: 1rem;
  font-size: 12px;
  color: var(--text-primary);
  border-bottom: 1px solid var(--border-color);
  vertical-align: middle;
}

/* Alert Severity Badges */
.severity-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.severity-critical {
  background: linear-gradient(135deg, var(--danger-color) 0%, #dc2626 100%);
  color: white;
  box-shadow: var(--shadow-sm);
}

.severity-high {
  background: linear-gradient(135deg, var(--warning-color) 0%, #d97706 100%);
  color: white;
  box-shadow: var(--shadow-sm);
}

.severity-medium {
  background: linear-gradient(135deg, var(--info-color) 0%, #2563eb 100%);
  color: white;
  box-shadow: var(--shadow-sm);
}

.severity-low {
  background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
  color: white;
  box-shadow: var(--shadow-sm);
}

/* Protocol Tags */
.protocol-tag {
  background: var(--bg-tertiary);
  color: var(--text-primary);
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  border: 1px solid var(--border-color);
}

/* IP Address Styling */
.ip-address {
  font-family: 'Monaco', 'Menlo', monospace;
  background: var(--bg-secondary);
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  border: 1px solid var(--border-color);
}

/* Timestamp Styling */
.timestamp {
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 11px;
  color: var(--text-secondary);
}

/* Empty State */
.empty-state {
  text-align: center;
  padding: 4rem 2rem;
  color: var(--text-secondary);
}

.empty-state-icon {
  font-size: 64px;
  color: var(--border-color);
  margin-bottom: 1rem;
}

.empty-state-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 0.5rem;
}

.empty-state-text {
  font-size: 14px;
  max-width: 400px;
  margin: 0 auto;
}

/* Responsive Design */
@media (max-width: 768px) {
  .alert-dashboard-header {
    padding: 1.5rem;
  }
  
  .alert-dashboard-title {
    font-size: 20px;
  }
  
  .stats-row {
    padding: 1.5rem;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
  }
  
  .stat-card {
    padding: 1rem;
  }
  
  .stat-icon {
    font-size: 24px;
  }
  
  .stat-number {
    font-size: 20px;
  }
  
  .controls-section {
    padding: 1rem 1.5rem;
  }
  
  .controls-row {
    grid-template-columns: 1fr;
    gap: 1rem;
  }
  
  .modern-table-container {
    padding: 1rem;
    overflow-x: auto;
  }
  
  .modern-table {
    min-width: 600px;
  }
  
  .modern-table thead th,
  .modern-table tbody td {
    padding: 0.75rem 0.5rem;
    font-size: 11px;
  }
}

/* Loading Animation */
.loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(255, 255, 255, 0.9);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10;
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid var(--border-color);
  border-top-color: var(--opnsense-orange);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}
</style>

<div class="alert-dashboard">
  <!-- Dashboard Header -->
  <div class="alert-dashboard-header">
    <h2 class="alert-dashboard-title">
      <i class="fa fa-shield"></i>
      {{ lang._('Security Alerts Dashboard') }}
    </h2>
    <p class="alert-dashboard-subtitle">
      {{ lang._('Real-time security alerts from Advanced Packet Inspector') }}
    </p>
  </div>

  <!-- Statistics Row -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-icon">
        <i class="fa fa-exclamation-triangle"></i>
      </div>
      <h3 class="stat-number" id="criticalCount">0</h3>
      <p class="stat-label">{{ lang._('Critical') }}</p>
    </div>
    
    <div class="stat-card">
      <div class="stat-icon">
        <i class="fa fa-warning"></i>
      </div>
      <h3 class="stat-number" id="highCount">0</h3>
      <p class="stat-label">{{ lang._('High') }}</p>
    </div>
    
    <div class="stat-card">
      <div class="stat-icon">
        <i class="fa fa-info-circle"></i>
      </div>
      <h3 class="stat-number" id="mediumCount">0</h3>
      <p class="stat-label">{{ lang._('Medium') }}</p>
    </div>
    
    <div class="stat-card">
      <div class="stat-icon">
        <i class="fa fa-check-circle"></i>
      </div>
      <h3 class="stat-number" id="lowCount">0</h3>
      <p class="stat-label">{{ lang._('Low') }}</p>
    </div>
    
    <div class="stat-card">
      <div class="stat-icon">
        <i class="fa fa-list"></i>
      </div>
      <h3 class="stat-number" id="totalCount">0</h3>
      <p class="stat-label">{{ lang._('Total Alerts') }}</p>
    </div>
  </div>

  <!-- Controls Section -->
  <div class="controls-section">
    <div class="controls-row">
      <div class="control-group">
        <label class="control-label">{{ lang._('Severity Filter') }}</label>
        <select id="severityFilter" class="modern-select">
          <option value="">{{ lang._('All Severities') }}</option>
          <option value="critical">{{ lang._('Critical') }}</option>
          <option value="high">{{ lang._('High') }}</option>
          <option value="medium">{{ lang._('Medium') }}</option>
          <option value="low">{{ lang._('Low') }}</option>
        </select>
      </div>
      
      <div class="control-group">
        <label class="control-label">{{ lang._('Protocol Filter') }}</label>
        <select id="protocolFilter" class="modern-select">
          <option value="">{{ lang._('All Protocols') }}</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
          <option value="modbus_tcp">Modbus TCP</option>
          <option value="opcua">OPC UA</option>
          <option value="mqtt">MQTT</option>
          <option value="dnp3">DNP3</option>
          <option value="s7comm">S7comm</option>
        </select>
      </div>
      
      <div class="control-group">
        <label class="control-label">{{ lang._('Time Range') }}</label>
        <select id="timeFilter" class="modern-select">
          <option value="1h">{{ lang._('Last Hour') }}</option>
          <option value="6h">{{ lang._('Last 6 Hours') }}</option>
          <option value="24h" selected>{{ lang._('Last 24 Hours') }}</option>
          <option value="7d">{{ lang._('Last 7 Days') }}</option>
          <option value="30d">{{ lang._('Last 30 Days') }}</option>
        </select>
      </div>
      
      <div class="control-group">
        <label class="control-label">&nbsp;</label>
        <button id="refreshAlertsBtn" class="modern-btn">
          <i class="fa fa-refresh"></i>
          {{ lang._('Refresh') }}
        </button>
      </div>
    </div>
  </div>

  <!-- Alerts Table -->
  <div class="modern-table-container">
    <table id="grid-alerts" class="modern-table" style="display: none;">
      <thead>
        <tr>
          <th data-column-id="timestamp" data-order="desc">{{ lang._('Timestamp') }}</th>
          <th data-column-id="severity" data-formatter="severity">{{ lang._('Severity') }}</th>
          <th data-column-id="src" data-formatter="ip">{{ lang._('Source IP') }}</th>
          <th data-column-id="dst" data-formatter="ip">{{ lang._('Destination IP') }}</th>
          <th data-column-id="port">{{ lang._('Port') }}</th>
          <th data-column-id="protocol" data-formatter="protocol">{{ lang._('Protocol') }}</th>
          <th data-column-id="reason">{{ lang._('Reason') }}</th>
          <th data-column-id="actions" data-formatter="actions" data-sortable="false">{{ lang._('Actions') }}</th>
        </tr>
      </thead>
      <tbody id="alertsTableBody">
        <!-- Dynamic content will be loaded here -->
      </tbody>
    </table>
    
    <!-- Empty State -->
    <div id="emptyState" class="empty-state" style="display: none;">
      <div class="empty-state-icon">
        <i class="fa fa-shield"></i>
      </div>
      <h3 class="empty-state-title">{{ lang._('No Security Alerts') }}</h3>
      <p class="empty-state-text">
        {{ lang._('Great! No security alerts have been detected in the selected time range. Your network appears to be secure.') }}
      </p>
    </div>
    
    <!-- Loading Overlay -->
    <div id="loadingOverlay" class="loading-overlay" style="display: none;">
      <div class="loading-spinner"></div>
    </div>
  </div>
</div>

<script>
let alertsData = [];

// Severity color mapping
const severityConfig = {
  critical: { class: 'severity-critical', icon: 'fa-times-circle' },
  high: { class: 'severity-high', icon: 'fa-exclamation-triangle' },
  medium: { class: 'severity-medium', icon: 'fa-info-circle' },
  low: { class: 'severity-low', icon: 'fa-check-circle' }
};

// Data formatters
const formatters = {
  severity: function(value, row) {
    const config = severityConfig[value] || severityConfig.medium;
    return `<span class="severity-badge ${config.class}">
              <i class="fa ${config.icon}"></i>
              ${value.toUpperCase()}
            </span>`;
  },
  
  ip: function(value, row) {
    return `<span class="ip-address">${value}</span>`;
  },
  
  protocol: function(value, row) {
    return `<span class="protocol-tag">${value.toUpperCase()}</span>`;
  },
  
  timestamp: function(value, row) {
    const date = new Date(value);
    return `<span class="timestamp">${date.toLocaleString()}</span>`;
  },
  
  actions: function(value, row) {
    return `<div class="btn-group btn-group-sm">
              <button class="btn btn-outline-primary btn-sm" onclick="viewAlertDetails('${row.id}')" title="View Details">
                <i class="fa fa-eye"></i>
              </button>
              <button class="btn btn-outline-success btn-sm" onclick="acknowledgeAlert('${row.id}')" title="Acknowledge">
                <i class="fa fa-check"></i>
              </button>
              <button class="btn btn-outline-danger btn-sm" onclick="blockSource('${row.src}')" title="Block Source">
                <i class="fa fa-ban"></i>
              </button>
            </div>`;
  }
};

function updateStatistics() {
  const stats = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0
  };
  
  alertsData.forEach(alert => {
    const severity = alert.severity || 'medium';
    stats[severity] = (stats[severity] || 0) + 1;
    stats.total++;
  });
  
  $('#criticalCount').text(stats.critical);
  $('#highCount').text(stats.high);
  $('#mediumCount').text(stats.medium);
  $('#lowCount').text(stats.low);
  $('#totalCount').text(stats.total);
}

function filterAlerts() {
  const severityFilter = $('#severityFilter').val();
  const protocolFilter = $('#protocolFilter').val();
  const timeFilter = $('#timeFilter').val();
  
  let filteredData = alertsData;
  
  // Apply severity filter
  if (severityFilter) {
    filteredData = filteredData.filter(alert => alert.severity === severityFilter);
  }
  
  // Apply protocol filter
  if (protocolFilter) {
    filteredData = filteredData.filter(alert => alert.protocol === protocolFilter);
  }
  
  // Apply time filter
  if (timeFilter) {
    const now = new Date();
    const timeThreshold = new Date();
    
    switch(timeFilter) {
      case '1h':
        timeThreshold.setHours(now.getHours() - 1);
        break;
      case '6h':
        timeThreshold.setHours(now.getHours() - 6);
        break;
      case '24h':
        timeThreshold.setDate(now.getDate() - 1);
        break;
      case '7d':
        timeThreshold.setDate(now.getDate() - 7);
        break;
      case '30d':
        timeThreshold.setDate(now.getDate() - 30);
        break;
    }
    
    filteredData = filteredData.filter(alert => new Date(alert.timestamp) >= timeThreshold);
  }
  
  renderTable(filteredData);
}

function renderTable(data) {
  const $tbody = $('#alertsTableBody');
  const $table = $('#grid-alerts');
  const $emptyState = $('#emptyState');
  
  if (data.length === 0) {
    $table.hide();
    $emptyState.show();
    return;
  }
  
  $emptyState.hide();
  $table.show();
  
  $tbody.empty();
  
  data.forEach(alert => {
    const $row = $('<tr>');
    
    $row.append(`<td>${formatters.timestamp(alert.timestamp, alert)}</td>`);
    $row.append(`<td>${formatters.severity(alert.severity, alert)}</td>`);
    $row.append(`<td>${formatters.ip(alert.src, alert)}</td>`);
    $row.append(`<td>${formatters.ip(alert.dst, alert)}</td>`);
    $row.append(`<td>${alert.port}</td>`);
    $row.append(`<td>${formatters.protocol(alert.protocol, alert)}</td>`);
    $row.append(`<td>${alert.reason}</td>`);
    $row.append(`<td>${formatters.actions('', alert)}</td>`);
    
    $tbody.append($row);
  });
}

function loadAlerts() {
  const $loading = $('#loadingOverlay');
  const $btn = $('#refreshAlertsBtn');
  
  $loading.show();
  $btn.addClass('loading').prop('disabled', true);
  
  ajaxCall('/api/advinspector/alerts/list', {}, function(data) {
    $loading.hide();
    $btn.removeClass('loading').prop('disabled', false);
    
    if (data.status === 'ok' && Array.isArray(data.data) && data.data.length > 0) {
      alertsData = data.data.filter(alert => 
        alert.id && alert.timestamp && alert.severity && alert.src && alert.dst && alert.protocol && alert.reason
      );
      
      updateStatistics();
      filterAlerts();
    } else {
      alertsData = [];
      updateStatistics();
      renderTable([]);
    }
  }).fail(function() {
    $loading.hide();
    $btn.removeClass('loading').prop('disabled', false);
    
    // Show error state
    alertsData = [];
    updateStatistics();
    renderTable([]);
  });
}

// Alert action functions
function viewAlertDetails(alertId) {
  // Implementation for viewing alert details
  console.log('View alert details:', alertId);
}

function acknowledgeAlert(alertId) {
  // Implementation for acknowledging alert
  console.log('Acknowledge alert:', alertId);
}

function blockSource(sourceIp) {
  // Implementation for blocking source IP
  console.log('Block source IP:', sourceIp);
}

// Initialize on document ready
$(document).ready(function() {
  // Event listeners
  $('#refreshAlertsBtn').click(loadAlerts);
  $('#severityFilter, #protocolFilter, #timeFilter').change(filterAlerts);
  
  // Initial load
  loadAlerts();
  
  // Auto-refresh every 30 seconds
  setInterval(loadAlerts, 30000);
});
</script>