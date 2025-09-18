<style>
/* Modern Tab Navigation */
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
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
}

/* Modern Tab Container */
.modern-tabs-container {
  background: var(--bg-primary);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
  border: 2px solid var(--border-color);
  overflow: hidden;
  margin: 1.5rem 0;
  min-height: 700px;
}

/* Enhanced Navigation Tabs */
.nav-tabs {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
  border-bottom: 3px solid var(--border-color);
  padding: 0 2rem;
  margin: 0;
  display: flex;
  gap: 0;
}

.nav-tabs li {
  margin: 0;
  position: relative;
}

.nav-tabs li a {
  background: transparent;
  border: none;
  border-radius: 0;
  color: var(--text-secondary);
  font-size: 14px;
  font-weight: 600;
  padding: 1.5rem 2rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  transition: all 0.3s ease;
  position: relative;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
}

.nav-tabs li a:hover {
  background: rgba(217, 79, 0, 0.05);
  color: var(--opnsense-orange);
  border: none;
}

.nav-tabs li.active a {
  background: var(--bg-primary);
  color: var(--opnsense-orange);
  border: none;
  box-shadow: var(--shadow-md);
}

.nav-tabs li.active a::after {
  content: '';
  position: absolute;
  bottom: -3px;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--opnsense-orange);
}

/* Tab Icons */
.nav-tabs li a::before {
  font-family: 'FontAwesome';
  font-size: 16px;
  margin-right: 0.5rem;
}

.nav-tabs li:nth-child(1) a::before {
  content: '\f013'; /* fa-cog */
}

.nav-tabs li:nth-child(2) a::before {
  content: '\f0ca'; /* fa-list-alt */
}

.nav-tabs li:nth-child(3) a::before {
  content: '\f071'; /* fa-exclamation-triangle */
}

.nav-tabs li:nth-child(4) a::before {
  content: '\f0f6'; /* fa-file-text-o */
}

/* Tab Content */
.tab-content {
  background: var(--bg-primary);
  padding: 0;
  border: none;
  min-height: 600px;
}

.tab-content .content-box {
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  padding: 0 !important;
  margin: 0 !important;
}

.tab-pane {
  padding: 0;
  border: none;
}

/* Welcome Panel for Default State */
.welcome-panel {
  padding: 4rem 2rem;
  text-align: center;
  background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
  border-radius: var(--radius-lg);
  margin: 2rem;
  border: 2px solid var(--border-color);
}

.welcome-icon {
  font-size: 64px;
  color: var(--opnsense-orange);
  margin-bottom: 1.5rem;
  text-shadow: var(--shadow-sm);
}

.welcome-title {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 1rem;
}

.welcome-subtitle {
  font-size: 16px;
  color: var(--text-secondary);
  margin-bottom: 2rem;
  max-width: 600px;
  margin-left: auto;
  margin-right: auto;
  line-height: 1.6;
}

.welcome-features {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-top: 3rem;
  max-width: 800px;
  margin-left: auto;
  margin-right: auto;
}

.feature-card {
  background: var(--bg-primary);
  padding: 1.5rem;
  border-radius: var(--radius-md);
  border: 2px solid var(--border-color);
  box-shadow: var(--shadow-sm);
  transition: all 0.3s ease;
}

.feature-card:hover {
  transform: translateY(-4px);
  box-shadow: var(--shadow-lg);
  border-color: var(--opnsense-orange);
}

.feature-icon {
  font-size: 32px;
  color: var(--opnsense-orange);
  margin-bottom: 1rem;
}

.feature-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 0.5rem;
}

.feature-description {
  font-size: 14px;
  color: var(--text-secondary);
  line-height: 1.5;
}

/* Quick Actions */
.quick-actions {
  display: flex;
  justify-content: center;
  gap: 1rem;
  margin-top: 2rem;
  flex-wrap: wrap;
}

.quick-action-btn {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  border: 2px solid var(--opnsense-orange);
  border-radius: var(--radius-md);
  color: white;
  padding: 0.875rem 1.5rem;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.quick-action-btn:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  background: linear-gradient(135deg, var(--opnsense-orange-light) 0%, #ff7722 100%);
  color: white;
  text-decoration: none;
}

.quick-action-btn:active {
  transform: translateY(0);
}

.quick-action-btn.secondary {
  background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
  border-color: var(--border-color);
  color: var(--text-primary);
}

.quick-action-btn.secondary:hover {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
  border-color: var(--opnsense-orange);
  color: var(--text-primary);
}

/* Status Indicators */
.status-indicators {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin: 2rem;
  margin-bottom: 0;
}

.status-card {
  background: var(--bg-primary);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: 1.5rem;
  box-shadow: var(--shadow-md);
  transition: all 0.3s ease;
}

.status-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  border-color: var(--opnsense-orange);
}

.status-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.status-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.status-badge.active {
  background: linear-gradient(135deg, #10b981 0%, #059669 100%);
  color: white;
}

.status-badge.inactive {
  background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
  color: white;
}

.status-badge.pending {
  background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
  color: white;
}

.status-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  margin: 0;
}

.status-label {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 0.25rem;
}

/* Responsive Design */
@media (max-width: 768px) {
  .nav-tabs {
    padding: 0 1rem;
    flex-wrap: wrap;
  }
  
  .nav-tabs li a {
    padding: 1rem 1.5rem;
    font-size: 12px;
  }
  
  .welcome-panel {
    padding: 2rem 1rem;
    margin: 1rem;
  }
  
  .welcome-title {
    font-size: 24px;
  }
  
  .welcome-subtitle {
    font-size: 14px;
  }
  
  .welcome-features {
    grid-template-columns: 1fr;
    gap: 1rem;
  }
  
  .quick-actions {
    flex-direction: column;
    align-items: center;
  }
  
  .quick-action-btn {
    width: 100%;
    max-width: 300px;
    justify-content: center;
  }
  
  .status-indicators {
    grid-template-columns: 1fr;
    margin: 1rem;
  }
}

/* Loading State */
.tab-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 400px;
  color: var(--text-secondary);
  font-size: 16px;
}

.tab-loading i {
  margin-right: 0.5rem;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>

<div class="modern-tabs-container">
  <!-- Status Indicators -->
  <div class="status-indicators">
    <div class="status-card">
      <div class="status-header">
        <span class="status-title">Service Status</span>
        <span class="status-badge inactive" id="serviceStatusBadge">
          <i class="fa fa-circle"></i>
          Offline
        </span>
      </div>
      <div class="status-value" id="serviceUptime">--</div>
      <div class="status-label">Uptime</div>
    </div>
    
    <div class="status-card">
      <div class="status-header">
        <span class="status-title">Active Rules</span>
        <span class="status-badge pending" id="rulesStatusBadge">
          <i class="fa fa-clock-o"></i>
          Loading
        </span>
      </div>
      <div class="status-value" id="activeRulesCount">0</div>
      <div class="status-label">Rules configured</div>
    </div>
    
    <div class="status-card">
      <div class="status-header">
        <span class="status-title">Recent Alerts</span>
        <span class="status-badge pending" id="alertsStatusBadge">
          <i class="fa fa-clock-o"></i>
          Loading
        </span>
      </div>
      <div class="status-value" id="recentAlertsCount">0</div>
      <div class="status-label">Last 24 hours</div>
    </div>
    
    <div class="status-card">
      <div class="status-header">
        <span class="status-title">Inspected Packets</span>
        <span class="status-badge pending" id="packetsStatusBadge">
          <i class="fa fa-clock-o"></i>
          Loading
        </span>
      </div>
      <div class="status-value" id="inspectedPacketsCount">0</div>
      <div class="status-label">Today</div>
    </div>
  </div>

  <!-- Navigation Tabs -->
  <ul class="nav nav-tabs" data-tabs="tabs" id="advInspectorTabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#rules">{{ lang._('Rules') }}</a></li>
    <li><a data-toggle="tab" href="#alerts">{{ lang._('Alerts') }}</a></li>
    <li><a data-toggle="tab" href="#logs">{{ lang._('Logs') }}</a></li>
  </ul>

  <!-- Tab Content -->
  <div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
      {{ partial("OPNsense/AdvInspector/settings.volt") }}
    </div>
    <div id="rules" class="tab-pane fade in">
      {{ partial("OPNsense/AdvInspector/rules.volt") }}
    </div>
    <div id="alerts" class="tab-pane fade in">
      {{ partial("OPNsense/AdvInspector/alerts.volt") }}
    </div>
    <div id="logs" class="tab-pane fade in">
      {{ partial("OPNsense/AdvInspector/logs.volt") }}
    </div>
  </div>
</div>

<script>
$(document).ready(function () {
  // Enhanced tab navigation with URL hash support
  if (window.location.hash !== "") {
    $('a[href="' + window.location.hash + '"]').click();
  }
  
  $('.nav-tabs a').on('shown.bs.tab', function (e) {
    history.pushState(null, null, e.target.hash);
    updateStatusForActiveTab(e.target.hash);
  });

  // Initialize status monitoring
  initializeStatusMonitoring();
  
  function initializeStatusMonitoring() {
    // Update status indicators immediately
    updateServiceStatus();
    updateRulesStatus();
    updateAlertsStatus();
    updatePacketsStatus();
    
    // Set up periodic updates
    setInterval(updateServiceStatus, 30000); // Every 30 seconds
    setInterval(updateRulesStatus, 60000);   // Every minute
    setInterval(updateAlertsStatus, 60000);  // Every minute
    setInterval(updatePacketsStatus, 60000); // Every minute
  }

  function updateServiceStatus() {
    ajaxGet('/api/advinspector/service/status', {}, function(data) {
      const $badge = $('#serviceStatusBadge');
      const $uptime = $('#serviceUptime');
      
      if (data && data.status === 'running' && data.uptime) {
        $badge.removeClass('inactive').addClass('active');
        $badge.html('<i class="fa fa-circle"></i> Online');
        $uptime.text(data.uptime);
      } else {
        $badge.removeClass('active').addClass('inactive');
        $badge.html('<i class="fa fa-circle"></i> Offline');
        $uptime.text('--');
      }
    }).fail(function() {
      $('#serviceStatusBadge').removeClass('active').addClass('inactive');
      $('#serviceStatusBadge').html('<i class="fa fa-circle"></i> Error');
      $('#serviceUptime').text('--');
    });
  }

  function updateRulesStatus() {
    ajaxGet('/api/advinspector/rules/search_rule', {}, function(data) {
      const $badge = $('#rulesStatusBadge');
      const $count = $('#activeRulesCount');
      
      if (data && data.rows && data.rows.length > 0) {
        const activeRules = data.rows.filter(rule => 
          (rule.enabled === "1" || rule.enabled === true) && 
          rule.description && rule.source && rule.destination
        );
        $count.text(activeRules.length);
        
        if (activeRules.length > 0) {
          $badge.removeClass('pending inactive').addClass('active');
          $badge.html('<i class="fa fa-check"></i> Active');
        } else {
          $badge.removeClass('pending active').addClass('inactive');
          $badge.html('<i class="fa fa-times"></i> None');
        }
      } else {
        $badge.removeClass('pending active').addClass('inactive');
        $badge.html('<i class="fa fa-times"></i> None');
        $count.text('0');
      }
    }).fail(function() {
      $('#rulesStatusBadge').removeClass('pending active').addClass('inactive');
      $('#rulesStatusBadge').html('<i class="fa fa-times"></i> Error');
      $('#activeRulesCount').text('0');
    });
  }

  function updateAlertsStatus() {
    ajaxGet('/api/advinspector/alerts/list', {}, function(data) {
      const $badge = $('#alertsStatusBadge');
      const $count = $('#recentAlertsCount');
      
      if (data && data.data && data.data.length > 0) {
        // Filter valid alerts from last 24 hours
        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const recentAlerts = data.data.filter(alert => 
          alert.timestamp && alert.severity && alert.src && alert.dst &&
          new Date(alert.timestamp) >= yesterday
        );
        
        $count.text(recentAlerts.length);
        
        if (recentAlerts.length > 0) {
          const criticalAlerts = recentAlerts.filter(alert => alert.severity === 'critical');
          if (criticalAlerts.length > 0) {
            $badge.removeClass('pending inactive').addClass('inactive');
            $badge.html('<i class="fa fa-exclamation-triangle"></i> Critical');
          } else {
            $badge.removeClass('pending inactive').addClass('active');
            $badge.html('<i class="fa fa-shield"></i> Active');
          }
        } else {
          $badge.removeClass('pending inactive').addClass('active');
          $badge.html('<i class="fa fa-check"></i> Clear');
        }
      } else {
        $badge.removeClass('pending active').addClass('inactive');
        $badge.html('<i class="fa fa-check"></i> Clear');
        $count.text('0');
      }
    }).fail(function() {
      $('#alertsStatusBadge').removeClass('pending active').addClass('inactive');
      $('#alertsStatusBadge').html('<i class="fa fa-times"></i> Error');
      $('#recentAlertsCount').text('0');
    });
  }

  function updatePacketsStatus() {
    ajaxGet('/api/advinspector/logs/read?type=packets', {}, function(data) {
      const $badge = $('#packetsStatusBadge');
      const $count = $('#inspectedPacketsCount');
      
      if (data && data.logs && data.logs.length > 0) {
        // Filter valid packets from today
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayPackets = data.logs.filter(log => 
          log.timestamp && log.protocol && log.src && log.dst &&
          new Date(log.timestamp) >= today
        );
        
        $count.text(todayPackets.length);
        
        if (todayPackets.length > 0) {
          $badge.removeClass('pending inactive').addClass('active');
          $badge.html('<i class="fa fa-check"></i> Active');
        } else {
          $badge.removeClass('pending active').addClass('inactive');
          $badge.html('<i class="fa fa-minus"></i> Idle');
        }
      } else {
        $badge.removeClass('pending active').addClass('inactive');
        $badge.html('<i class="fa fa-minus"></i> Idle');
        $count.text('0');
      }
    }).fail(function() {
      $('#packetsStatusBadge').removeClass('pending active').addClass('inactive');
      $('#packetsStatusBadge').html('<i class="fa fa-times"></i> Error');
      $('#inspectedPacketsCount').text('0');
    });
  }

  function updateStatusForActiveTab(hash) {
    // Update specific status based on active tab
    switch(hash) {
      case '#settings':
        updateServiceStatus();
        break;
      case '#rules':
        updateRulesStatus();
        break;
      case '#alerts':
        updateAlertsStatus();
        break;
      case '#logs':
        updatePacketsStatus();
        break;
    }
  }

  // Enhanced status card click handlers
  $('.status-card').click(function() {
    const title = $(this).find('.status-title').text().toLowerCase();
    
    if (title.includes('service')) {
      $('a[href="#settings"]').click();
    } else if (title.includes('rules')) {
      $('a[href="#rules"]').click();
    } else if (title.includes('alerts')) {
      $('a[href="#alerts"]').click();
    } else if (title.includes('packets')) {
      $('a[href="#logs"]').click();
    }
  });

  // Add hover effects to status cards
  $('.status-card').hover(
    function() {
      $(this).css('cursor', 'pointer');
    },
    function() {
      $(this).css('cursor', 'default');
    }
  );
});
</script>