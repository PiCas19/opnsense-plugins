<style>
/* NetZones Modern Dashboard - OPNsense Professional Style */
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
  --danger-color: #ef4444;
  --warning-color: #f59e0b;
  --info-color: #3b82f6;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
}

/* Modern Dashboard Container */
.modern-dashboard-container {
  background: var(--bg-secondary);
  min-height: 100vh;
  padding: 1.5rem;
  margin: 0;
}

/* Dashboard Header */
.dashboard-header {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  color: white;
  padding: 2rem;
  border-radius: var(--radius-xl);
  margin-bottom: 2rem;
  position: relative;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
}

.dashboard-header::before {
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

.dashboard-title {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin: 0;
  font-size: 28px;
  font-weight: 700;
  position: relative;
  z-index: 1;
}

.dashboard-title i {
  font-size: 32px;
  text-shadow: 0 2px 4px rgba(0,0,0,0.3);
}

.dashboard-subtitle {
  margin: 0.5rem 0 0 0;
  font-size: 16px;
  opacity: 0.9;
  position: relative;
  z-index: 1;
}

/* Stats Grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

/* Modern Stat Card */
.stat-card {
  background: var(--bg-primary);
  border-radius: var(--radius-lg);
  padding: 1.5rem;
  border: 2px solid var(--border-color);
  box-shadow: var(--shadow-md);
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  border-color: var(--opnsense-orange);
}

.stat-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.stat-card-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.stat-card-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  color: white;
}

.stat-card-icon.service { background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%); }
.stat-card-icon.zones { background: linear-gradient(135deg, var(--info-color) 0%, #2563eb 100%); }
.stat-card-icon.policies { background: linear-gradient(135deg, var(--warning-color) 0%, #d97706 100%); }
.stat-card-icon.security { background: linear-gradient(135deg, var(--danger-color) 0%, #dc2626 100%); }

.stat-card-value {
  font-size: 32px;
  font-weight: 700;
  color: var(--text-primary);
  margin: 0.5rem 0;
  line-height: 1;
}

.stat-card-label {
  font-size: 14px;
  color: var(--text-secondary);
  margin-bottom: 0.75rem;
}

.stat-card-details {
  display: flex;
  justify-content: space-between;
  padding-top: 0.75rem;
  border-top: 1px solid var(--border-color);
  font-size: 12px;
}

.stat-card-detail {
  text-align: center;
}

.stat-card-detail-value {
  display: block;
  font-weight: 600;
  color: var(--text-primary);
}

.stat-card-detail-label {
  color: var(--text-secondary);
  margin-top: 0.25rem;
}

/* Main Content Grid */
.main-content-grid {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 2rem;
  margin-bottom: 2rem;
}

/* Modern Content Box */
.modern-content-box {
  background: var(--bg-primary);
  border-radius: var(--radius-lg);
  border: 2px solid var(--border-color);
  box-shadow: var(--shadow-md);
  overflow: hidden;
}

.content-box-header {
  background: var(--bg-tertiary);
  padding: 1.25rem 1.5rem;
  border-bottom: 2px solid var(--border-color);
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.content-box-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.content-box-title i {
  color: var(--opnsense-orange);
  font-size: 18px;
}

.content-box-body {
  padding: 1.5rem;
}

/* Zone Cards Grid */
.zones-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
}

.zone-card {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 1.25rem;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.zone-card:hover {
  transform: translateY(-1px);
  border-color: var(--opnsense-orange);
  box-shadow: var(--shadow-md);
}

.zone-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
}

.zone-card-name {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.zone-card-name i {
  color: var(--opnsense-orange);
}

.zone-status-badge {
  padding: 0.25rem 0.75rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.zone-status-badge.active {
  background: var(--success-color);
  color: white;
}

.zone-status-badge.inactive {
  background: var(--text-secondary);
  color: white;
}

.zone-card-subnets {
  font-size: 12px;
  color: var(--text-secondary);
  font-family: 'Courier New', monospace;
  background: var(--bg-primary);
  padding: 0.5rem;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
}

/* Relationships Sidebar */
.relationships-container {
  max-height: 400px;
  overflow-y: auto;
}

.relationship-item {
  display: flex;
  align-items: center;
  padding: 0.75rem;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  margin-bottom: 0.75rem;
  background: var(--bg-secondary);
  transition: all 0.3s ease;
}

.relationship-item:hover {
  border-color: var(--opnsense-orange);
  transform: translateX(2px);
}

.relationship-zones {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex: 1;
}

.relationship-zone {
  padding: 0.25rem 0.75rem;
  background: var(--info-color);
  color: white;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
}

.relationship-arrow {
  color: var(--text-secondary);
  margin: 0 0.5rem;
}

.relationship-action {
  padding: 0.25rem 0.75rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.relationship-action.pass {
  background: var(--success-color);
  color: white;
}

.relationship-action.block {
  background: var(--danger-color);
  color: white;
}

.relationship-action.reject {
  background: var(--warning-color);
  color: white;
}

/* Activity Table */
.activity-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}

.activity-table th,
.activity-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
}

.activity-table th {
  background: var(--bg-tertiary);
  font-weight: 600;
  font-size: 12px;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.activity-table tbody tr:hover {
  background: var(--bg-secondary);
}

.activity-badge {
  padding: 0.25rem 0.75rem;
  border-radius: var(--radius-sm);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
}

.activity-badge.allow { background: var(--success-color); color: white; }
.activity-badge.block { background: var(--danger-color); color: white; }
.activity-badge.reject { background: var(--warning-color); color: white; }

.protocol-badge {
  background: var(--info-color);
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  font-size: 10px;
  font-weight: 600;
  font-family: monospace;
}

.ip-code {
  font-family: 'Courier New', monospace;
  font-size: 11px;
  background: var(--bg-tertiary);
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  color: var(--text-primary);
}

/* Metrics Section */
.metrics-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
}

.metric-card {
  background: var(--bg-primary);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 1.25rem;
  text-align: center;
}

.metric-icon {
  font-size: 32px;
  margin-bottom: 0.75rem;
}

.metric-icon.traffic { color: var(--info-color); }
.metric-icon.blocked { color: var(--danger-color); }

.metric-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.5rem;
}

.metric-label {
  font-size: 12px;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.metric-trend {
  font-size: 11px;
  margin-top: 0.5rem;
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
}

.metric-trend.up {
  background: rgba(239, 68, 68, 0.1);
  color: var(--danger-color);
}

.metric-trend.down {
  background: rgba(16, 185, 129, 0.1);
  color: var(--success-color);
}

/* Loading States */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  text-align: center;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color);
  border-top: 3px solid var(--opnsense-orange);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 1rem;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.loading-text {
  color: var(--text-secondary);
  font-size: 14px;
}

/* Empty States */
.empty-state {
  text-align: center;
  padding: 3rem 2rem;
  color: var(--text-secondary);
}

.empty-state i {
  font-size: 48px;
  margin-bottom: 1rem;
  opacity: 0.5;
}

.empty-state-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 0.5rem;
  color: var(--text-primary);
}

.empty-state-text {
  font-size: 14px;
}

/* Responsive Design */
@media (max-width: 1200px) {
  .main-content-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .modern-dashboard-container {
    padding: 1rem;
  }
  
  .dashboard-header {
    padding: 1.5rem;
  }
  
  .dashboard-title {
    font-size: 24px;
  }
  
  .stats-grid {
    grid-template-columns: 1fr;
  }
  
  .zones-grid {
    grid-template-columns: 1fr;
  }
  
  .metrics-grid {
    grid-template-columns: 1fr;
  }
}

/* Scrollbar Styling */
.relationships-container::-webkit-scrollbar {
  width: 6px;
}

.relationships-container::-webkit-scrollbar-track {
  background: var(--bg-secondary);
  border-radius: var(--radius-sm);
}

.relationships-container::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: var(--radius-sm);
}

.relationships-container::-webkit-scrollbar-thumb:hover {
  background: var(--text-secondary);
}

/* Animation Classes */
.fade-in {
  animation: fadeIn 0.5s ease-in;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>

<div class="modern-dashboard-container">
  <!-- Dashboard Header -->
  <div class="dashboard-header">
    <h1 class="dashboard-title">
      <i class="fa fa-shield-alt"></i>
      {{ lang._('NetZones Dashboard') }}
    </h1>
    <p class="dashboard-subtitle">
      {{ lang._('Zero-Trust Network Segmentation & Policy Management') }}
    </p>
  </div>

  <!-- Stats Overview -->
  <div class="stats-grid">
    <!-- Service Status Card -->
    <div class="stat-card">
      <div class="stat-card-header">
        <div class="stat-card-title">
          <i class="fa fa-server"></i>
          {{ lang._('Service Status') }}
        </div>
        <div class="stat-card-icon service">
          <i class="fa fa-heartbeat"></i>
        </div>
      </div>
      <div id="serviceStatus">
        <div class="loading-container">
          <div class="loading-spinner"></div>
          <div class="loading-text">{{ lang._('Checking service status...') }}</div>
        </div>
      </div>
    </div>

    <!-- Zones Card -->
    <div class="stat-card">
      <div class="stat-card-header">
        <div class="stat-card-title">
          <i class="fa fa-layer-group"></i>
          {{ lang._('Network Zones') }}
        </div>
        <div class="stat-card-icon zones">
          <i class="fa fa-sitemap"></i>
        </div>
      </div>
      <div id="zonesStatus">
        <div class="loading-container">
          <div class="loading-spinner"></div>
          <div class="loading-text">{{ lang._('Loading zones...') }}</div>
        </div>
      </div>
    </div>

    <!-- Policies Card -->
    <div class="stat-card">
      <div class="stat-card-header">
        <div class="stat-card-title">
          <i class="fa fa-exchange-alt"></i>
          {{ lang._('Policy Activity') }}
        </div>
        <div class="stat-card-icon policies">
          <i class="fa fa-filter"></i>
        </div>
      </div>
      <div id="policyActivity">
        <div class="loading-container">
          <div class="loading-spinner"></div>
          <div class="loading-text">{{ lang._('Loading activity...') }}</div>
        </div>
      </div>
    </div>

    <!-- Security Summary Card -->
    <div class="stat-card">
      <div class="stat-card-header">
        <div class="stat-card-title">
          <i class="fa fa-shield-alt"></i>
          {{ lang._('Security Summary') }}
        </div>
        <div class="stat-card-icon security">
          <i class="fa fa-lock"></i>
        </div>
      </div>
      <div id="securitySummary">
        <div class="loading-container">
          <div class="loading-spinner"></div>
          <div class="loading-text">{{ lang._('Analyzing security...') }}</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Main Content Grid -->
  <div class="main-content-grid">
    <!-- Zones Overview -->
    <div class="modern-content-box">
      <div class="content-box-header">
        <h3 class="content-box-title">
          <i class="fa fa-layer-group"></i>
          {{ lang._('Active Network Zones') }}
        </h3>
      </div>
      <div class="content-box-body">
        <div id="zonesOverview">
          <div class="loading-container">
            <div class="loading-spinner"></div>
            <div class="loading-text">{{ lang._('Loading zone configurations...') }}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Sidebar -->
    <div class="modern-content-box">
      <div class="content-box-header">
        <h3 class="content-box-title">
          <i class="fa fa-project-diagram"></i>
          {{ lang._('Zone Relationships') }}
        </h3>
      </div>
      <div class="content-box-body">
        <div id="zoneRelationships" class="relationships-container">
          <div class="loading-container">
            <div class="loading-spinner"></div>
            <div class="loading-text">{{ lang._('Loading relationships...') }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Activity & Metrics -->
  <div class="main-content-grid">
    <!-- Recent Activity -->
    <div class="modern-content-box">
      <div class="content-box-header">
        <h3 class="content-box-title">
          <i class="fa fa-history"></i>
          {{ lang._('Recent Policy Decisions') }}
        </h3>
      </div>
      <div class="content-box-body">
        <div style="max-height: 400px; overflow-y: auto;">
          <table class="activity-table" id="recentDecisions">
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
                <td colspan="6">
                  <div class="loading-container">
                    <div class="loading-spinner"></div>
                    <div class="loading-text">{{ lang._('Loading recent activity...') }}</div>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Traffic Metrics -->
    <div class="modern-content-box">
      <div class="content-box-header">
        <h3 class="content-box-title">
          <i class="fa fa-chart-line"></i>
          {{ lang._('Traffic Metrics') }}
        </h3>
      </div>
      <div class="content-box-body">
        <div class="metrics-grid">
          <div class="metric-card" id="trafficMetric">
            <div class="metric-icon traffic">
              <i class="fa fa-exchange-alt"></i>
            </div>
            <div class="metric-value">--</div>
            <div class="metric-label">{{ lang._('Packets/Hour') }}</div>
            <div class="metric-trend">
              <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
            </div>
          </div>
          
          <div class="metric-card" id="blockedMetric">
            <div class="metric-icon blocked">
              <i class="fa fa-ban"></i>
            </div>
            <div class="metric-value">--</div>
            <div class="metric-label">{{ lang._('Blocked Sources') }}</div>
            <div class="metric-trend">
              <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading...') }}
            </div>
          </div>
        </div>
        
        <div style="margin-top: 1.5rem;" id="protocolDistribution">
          <h4 style="font-size: 14px; font-weight: 600; color: var(--text-secondary); margin-bottom: 1rem; text-transform: uppercase;">
            <i class="fa fa-pie-chart"></i> {{ lang._('Protocol Distribution') }}
          </h4>
          <div class="loading-container">
            <div class="loading-spinner"></div>
            <div class="loading-text">{{ lang._('Loading protocol data...') }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
// Modern Dashboard Implementation
$(document).ready(function () {
  loadModernDashboard();
  
  // Auto-refresh every 30 seconds
  setInterval(loadModernDashboard, 30000);
});

function loadModernDashboard() {
  loadServiceStatus();
  loadZonesStatus();
  loadPolicyActivity();
  loadSecuritySummary();
  loadZonesOverview();
  loadZoneRelationships();
  loadRecentDecisions();
  loadTrafficMetrics();
  loadProtocolDistribution();
}

function loadServiceStatus() {
  ajaxCall('/api/netzones/service/status', {}, function(data) {
    const isRunning = data && data.running;
    const html = `
      <div class="stat-card-value">${isRunning ? 'ONLINE' : 'OFFLINE'}</div>
      <div class="stat-card-label">${isRunning ? '{{ lang._('Service Running') }}' : '{{ lang._('Service Stopped') }}'}</div>
      <div class="stat-card-details">
        <div class="stat-card-detail">
          <span class="stat-card-detail-value" style="color: ${isRunning ? 'var(--success-color)' : 'var(--danger-color)'};">
            <i class="fa fa-${isRunning ? 'check-circle' : 'times-circle'}"></i>
          </span>
          <div class="stat-card-detail-label">Status</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${data.pid || '--'}</span>
          <div class="stat-card-detail-label">PID</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${isRunning ? 'Active' : 'Inactive'}</span>
          <div class="stat-card-detail-label">State</div>
        </div>
      </div>
    `;
    $('#serviceStatus').html(html).addClass('fade-in');
  }).fail(function() {
    $('#serviceStatus').html(`
      <div class="stat-card-value">ERROR</div>
      <div class="stat-card-label">{{ lang._('Status Check Failed') }}</div>
      <div class="stat-card-details">
        <div class="stat-card-detail">
          <span class="stat-card-detail-value" style="color: var(--warning-color);">
            <i class="fa fa-exclamation-triangle"></i>
          </span>
          <div class="stat-card-detail-label">Connection</div>
        </div>
      </div>
    `);
  });
}

function loadZonesStatus() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    const stats = (data && data.data) || {};
    const zones = stats.zones || { active: 0, total: 0 };
    const policies = stats.policies || { active: 0, total: 0 };
    
    const html = `
      <div class="stat-card-value">${zones.active}</div>
      <div class="stat-card-label">{{ lang._('Active Zones') }}</div>
      <div class="stat-card-details">
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${zones.total}</span>
          <div class="stat-card-detail-label">Total</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${policies.active}</span>
          <div class="stat-card-detail-label">Policies</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${Math.round((zones.active / Math.max(zones.total, 1)) * 100)}%</span>
          <div class="stat-card-detail-label">Coverage</div>
        </div>
      </div>
    `;
    $('#zonesStatus').html(html).addClass('fade-in');
  }).fail(function() {
    $('#zonesStatus').html(`
      <div class="stat-card-value">--</div>
      <div class="stat-card-label">{{ lang._('Data Unavailable') }}</div>
    `);
  });
}

function loadPolicyActivity() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    const stats = (data && data.data) || {};
    const totalEvents = stats.total_events || 0;
    const allowEvents = stats.allow_events || 0;
    const blockEvents = stats.block_events || 0;
    const lastHour = stats.last_hour_count || 0;
    
    const html = `
      <div class="stat-card-value">${totalEvents}</div>
      <div class="stat-card-label">{{ lang._('Total Events') }}</div>
      <div class="stat-card-details">
        <div class="stat-card-detail">
          <span class="stat-card-detail-value" style="color: var(--success-color);">${allowEvents}</span>
          <div class="stat-card-detail-label">Allowed</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value" style="color: var(--danger-color);">${blockEvents}</span>
          <div class="stat-card-detail-label">Blocked</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${lastHour}</span>
          <div class="stat-card-detail-label">Last Hour</div>
        </div>
      </div>
    `;
    $('#policyActivity').html(html).addClass('fade-in');
  }).fail(function() {
    $('#policyActivity').html(`
      <div class="stat-card-value">--</div>
      <div class="stat-card-label">{{ lang._('Activity Unavailable') }}</div>
    `);
  });
}

function loadSecuritySummary() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    const stats = (data && data.data) || {};
    const blocked = stats.block_events || 0;
    const total = Math.max(stats.total_events || 1, 1);
    const blockRate = Math.round((blocked / total) * 100);
    
    let securityLevel = 'High';
    let securityColor = 'var(--success-color)';
    let securityIcon = 'shield-alt';
    
    if (blockRate > 20) {
      securityLevel = 'Medium';
      securityColor = 'var(--warning-color)';
      securityIcon = 'shield-alt';
    }
    if (blockRate > 50) {
      securityLevel = 'Alert';
      securityColor = 'var(--danger-color)';
      securityIcon = 'exclamation-shield';
    }
    
    const html = `
      <div class="stat-card-value" style="color: ${securityColor};">${blockRate}%</div>
      <div class="stat-card-label">{{ lang._('Block Rate') }}</div>
      <div class="stat-card-details">
        <div class="stat-card-detail">
          <span class="stat-card-detail-value" style="color: ${securityColor};">
            <i class="fa fa-${securityIcon}"></i>
          </span>
          <div class="stat-card-detail-label">${securityLevel}</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${blocked}</span>
          <div class="stat-card-detail-label">Blocked</div>
        </div>
        <div class="stat-card-detail">
          <span class="stat-card-detail-value">${total}</span>
          <div class="stat-card-detail-label">Total</div>
        </div>
      </div>
    `;
    $('#securitySummary').html(html).addClass('fade-in');
  }).fail(function() {
    $('#securitySummary').html(`
      <div class="stat-card-value">--</div>
      <div class="stat-card-label">{{ lang._('Security Data Unavailable') }}</div>
    `);
  });
}

function loadZonesOverview() {
  ajaxCall('/api/netzones/management/getZoneList', {}, function(data) {
    if (data && data.zones && data.zones.length > 0) {
      let html = '<div class="zones-grid">';
      data.zones.forEach(zone => {
        html += `
          <div class="zone-card">
            <div class="zone-card-header">
              <h4 class="zone-card-name">
                <i class="fa fa-layer-group"></i>
                ${zone.text || 'Unknown Zone'}
              </h4>
              <span class="zone-status-badge active">Active</span>
            </div>
            <div class="zone-card-subnets">
              ${zone.description || 'No description available'}
            </div>
          </div>
        `;
      });
      html += '</div>';
      $('#zonesOverview').html(html).addClass('fade-in');
    } else {
      $('#zonesOverview').html(`
        <div class="empty-state">
          <i class="fa fa-layer-group"></i>
          <div class="empty-state-title">{{ lang._('No Active Zones') }}</div>
          <div class="empty-state-text">{{ lang._('Configure network zones to enable zero-trust segmentation') }}</div>
        </div>
      `);
    }
  }).fail(function() {
    $('#zonesOverview').html(`
      <div class="empty-state">
        <i class="fa fa-exclamation-triangle"></i>
        <div class="empty-state-title">{{ lang._('Failed to Load Zones') }}</div>
        <div class="empty-state-text">{{ lang._('Unable to retrieve zone configuration') }}</div>
      </div>
    `);
  });
}

function loadZoneRelationships() {
  ajaxCall('/api/netzones/dashboard/zoneRelationships', {}, function(data) {
    if (data && data.relationships && data.relationships.length > 0) {
      let html = '';
      data.relationships.forEach(rel => {
        html += `
          <div class="relationship-item">
            <div class="relationship-zones">
              <span class="relationship-zone">${rel.source_zone}</span>
              <i class="fa fa-arrow-right relationship-arrow"></i>
              <span class="relationship-zone">${rel.destination_zone}</span>
            </div>
            <span class="relationship-action ${rel.action.toLowerCase()}">${rel.action}</span>
          </div>
        `;
      });
      $('#zoneRelationships').html(html).addClass('fade-in');
    } else {
      $('#zoneRelationships').html(`
        <div class="empty-state">
          <i class="fa fa-project-diagram"></i>
          <div class="empty-state-title">{{ lang._('No Policies Configured') }}</div>
          <div class="empty-state-text">{{ lang._('Create inter-zone policies to control traffic flow') }}</div>
        </div>
      `);
    }
  }).fail(function() {
    $('#zoneRelationships').html(`
      <div class="empty-state">
        <i class="fa fa-exclamation-triangle"></i>
        <div class="empty-state-title">{{ lang._('Failed to Load Relationships') }}</div>
      </div>
    `);
  });
}

function loadRecentDecisions() {
  ajaxCall('/api/netzones/dashboard/logs_list', {}, function(data) {
    if (data && data.data && data.data.length > 0) {
      let html = '';
      data.data.slice(0, 10).forEach(entry => {
        const decision = (entry.decision || 'unknown').toLowerCase();
        html += `
          <tr>
            <td style="font-size: 11px;">${entry.timestamp || '--'}</td>
            <td><span class="ip-code">${entry.src || 'unknown'}</span></td>
            <td><span class="ip-code">${entry.dst || 'unknown'}</span></td>
            <td><span class="protocol-badge">${entry.protocol || 'unknown'}</span></td>
            <td><span class="activity-badge ${decision}">${entry.decision || 'unknown'}</span></td>
            <td style="font-size: 11px;">${entry.source_zone || 'UNKNOWN'} → ${entry.destination_zone || 'UNKNOWN'}</td>
          </tr>
        `;
      });
      $('#recentDecisions tbody').html(html);
    } else {
      $('#recentDecisions tbody').html(`
        <tr>
          <td colspan="6">
            <div class="empty-state">
              <i class="fa fa-history"></i>
              <div class="empty-state-title">{{ lang._('No Recent Activity') }}</div>
              <div class="empty-state-text">{{ lang._('Policy decisions will appear here') }}</div>
            </div>
          </td>
        </tr>
      `);
    }
  }).fail(function() {
    $('#recentDecisions tbody').html(`
      <tr>
        <td colspan="6">
          <div class="empty-state">
            <i class="fa fa-exclamation-triangle"></i>
            <div class="empty-state-title">{{ lang._('Failed to Load Activity') }}</div>
          </div>
        </td>
      </tr>
    `);
  });
}

function loadTrafficMetrics() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    const stats = (data && data.data) || {};
    const lastHour = stats.last_hour_count || 0;
    const pps = Math.round(lastHour / 3600) || 0;
    
    // Traffic Metric
    $('#trafficMetric .metric-value').text(pps);
    let trendClass = 'down';
    let trendIcon = 'arrow-down';
    let trendText = '{{ lang._('Low Traffic') }}';
    
    if (pps > 10) {
      trendClass = 'up';
      trendIcon = 'arrow-up';
      trendText = '{{ lang._('Moderate Traffic') }}';
    }
    if (pps > 50) {
      trendText = '{{ lang._('High Traffic') }}';
    }
    
    $('#trafficMetric .metric-trend').removeClass('up down').addClass(trendClass)
      .html(`<i class="fa fa-${trendIcon}"></i> ${trendText}`);
    
    // Blocked Sources Metric
    const blockedSources = stats.unique_blocked_sources || 0;
    $('#blockedMetric .metric-value').text(blockedSources);
    
    let blockedTrendClass = blockedSources > 5 ? 'up' : 'down';
    let blockedTrendIcon = blockedSources > 5 ? 'arrow-up' : 'arrow-down';
    let blockedTrendText = blockedSources > 5 ? '{{ lang._('High Blocks') }}' : '{{ lang._('Low Blocks') }}';
    
    $('#blockedMetric .metric-trend').removeClass('up down').addClass(blockedTrendClass)
      .html(`<i class="fa fa-${blockedTrendIcon}"></i> ${blockedTrendText}`);
  });
}

function loadProtocolDistribution() {
  ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
    const stats = (data && data.data) || {};
    const protocols = stats.top_protocols || {};
    const total = Math.max(stats.total_events || 1, 1);
    
    if (Object.keys(protocols).length > 0) {
      let html = '';
      Object.entries(protocols).slice(0, 5).forEach(([protocol, count]) => {
        const percentage = Math.round((count / total) * 100) || 0;
        html += `
          <div style="margin-bottom: 0.75rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
              <span style="font-size: 12px; font-weight: 600; color: var(--text-primary);">${protocol.toUpperCase()}</span>
              <span style="font-size: 11px; color: var(--text-secondary);">${count} (${percentage}%)</span>
            </div>
            <div style="height: 6px; background: var(--bg-tertiary); border-radius: var(--radius-sm); overflow: hidden;">
              <div style="width: ${percentage}%; height: 100%; background: linear-gradient(90deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%); transition: width 0.3s ease;"></div>
            </div>
          </div>
        `;
      });
      $('#protocolDistribution > div').html(html);
    } else {
      $('#protocolDistribution > div').html(`
        <div class="empty-state">
          <i class="fa fa-pie-chart"></i>
          <div class="empty-state-title">{{ lang._('No Protocol Data') }}</div>
        </div>
      `);
    }
  });
}

// Global refresh function
window.reloadDashboard = loadModernDashboard;
</script>