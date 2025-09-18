<style>
/* OPNsense Colors */
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
}

/* Normal 12px Font Dropdown Improvements */
.form-select, 
#logTypeSelect, 
#logViewMode {
  appearance: none;
  -webkit-appearance: none;
  -moz-appearance: none;
  width: 100%;
  padding: 0.875rem 3rem 0.875rem 1.25rem;
  font-size: 12px !important;
  font-weight: normal;
  color: var(--text-primary);
  background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  cursor: pointer;
  position: relative;
  background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20"><path fill="%23334155" d="M5 8l5 5 5-5z"/></svg>');
  background-repeat: no-repeat;
  background-position: right 1rem center;
  background-size: 20px;
  min-height: 50px;
}

.form-select:hover,
#logTypeSelect:hover,
#logViewMode:hover {
  border-color: var(--opnsense-orange);
  box-shadow: var(--shadow-md);
  transform: translateY(-1px);
  background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20"><path fill="%23d94f00" d="M5 8l5 5 5-5z"/></svg>');
}

.form-select:focus,
#logTypeSelect:focus,
#logViewMode:focus {
  outline: none;
  border-color: var(--opnsense-orange);
  box-shadow: 0 0 0 3px rgba(217, 79, 0, 0.15), var(--shadow-md);
  transform: translateY(-1px);
  background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20"><path fill="%23d94f00" d="M5 8l5 5 5-5z"/></svg>');
}

.form-select:disabled,
#logTypeSelect:disabled,
#logViewMode:disabled {
  background-color: #f1f5f9 !important;
  opacity: 0.5 !important;
  cursor: not-allowed !important;
  transform: none !important;
  pointer-events: none !important;
  color: #94a3b8 !important;
  background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20"><path fill="%23cbd5e1" d="M5 8l5 5 5-5z"/></svg>') !important;
}

.form-select option,
#logTypeSelect option,
#logViewMode option {
  padding: 0.75rem;
  font-weight: normal;
  background: var(--bg-primary);
  color: var(--text-primary);
  font-size: 12px !important;
}

/* Normal 12px Form Labels */
.form-label {
  font-weight: normal;
  color: var(--text-primary);
  font-size: 12px !important;
  margin-bottom: 0.75rem;
  display: block;
}

/* OPNsense Orange Button - 12px font */
.btn-primary,
#refreshLogsBtn {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.875rem 1.25rem;
  font-size: 12px !important;
  font-weight: normal;
  color: white;
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  border: 2px solid var(--opnsense-orange);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  overflow: hidden;
  min-height: 50px;
}

.btn-primary:hover,
#refreshLogsBtn:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  background: linear-gradient(135deg, var(--opnsense-orange-light) 0%, #ff7722 100%);
  border-color: var(--opnsense-orange-light);
}

.btn-primary:active,
#refreshLogsBtn:active {
  transform: translateY(0);
  box-shadow: var(--shadow-md);
}

.btn-primary:disabled,
#refreshLogsBtn:disabled {
  cursor: not-allowed;
  opacity: 0.6;
  transform: none;
  background: linear-gradient(135deg, #94a3b8 0%, #64748b 100%);
  border-color: #94a3b8;
}

/* Normal 12px Console Text */
#logContent {
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%) !important;
  color: #10b981 !important;
  padding: 2rem !important;
  height: 500px !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Courier New', monospace !important;
  border-radius: var(--radius-lg) !important;
  border: 3px solid #334155 !important;
  font-size: 12px !important;
  white-space: pre-wrap !important;
  box-shadow: var(--shadow-lg) !important;
  position: relative !important;
  margin: 1.5rem 0 !important;
  line-height: 1.8 !important;
  font-weight: normal !important;
}

#logContent::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2.5rem;
  background: linear-gradient(90deg, #ef4444 0%, var(--opnsense-orange) 33%, #10b981 66%);
  border-radius: var(--radius-lg) var(--radius-lg) 0 0;
  opacity: 0.9;
  z-index: 1;
}

#logContent::after {
  content: '●●●';
  position: absolute;
  top: 0.75rem;
  left: 1.5rem;
  color: #1e293b;
  font-size: 1rem;
  z-index: 2;
  font-family: inherit;
  font-weight: bold;
}

/* Console Scrollbar */
#logContent::-webkit-scrollbar {
  width: 12px;
}

#logContent::-webkit-scrollbar-track {
  background: #2d2d2d;
  border-radius: 6px;
}

#logContent::-webkit-scrollbar-thumb {
  background: #555;
  border-radius: 6px;
  border: 2px solid #2d2d2d;
}

#logContent::-webkit-scrollbar-thumb:hover {
  background: #777;
}

/* Content Box Styling */
.content-box {
  background: var(--bg-primary);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-md);
  padding: 2rem;
  border: 2px solid var(--border-color);
}

/* Row Improvements */
.row.align-items-center {
  align-items: end !important;
}

.g-3.mb-3 {
  gap: 1.5rem !important;
  margin-bottom: 2rem !important;
}

/* Column responsive improvements */
.col-md-3, .col-sm-6 {
  margin-bottom: 1rem;
}

/* Table styling with 12px normal fonts */
.table-condensed {
  margin-top: 1.5rem;
  border-radius: var(--radius-md);
  overflow: hidden;
  box-shadow: var(--shadow-md);
  border: 2px solid var(--border-color);
}

.table-condensed thead th {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
  border-bottom: 3px solid var(--border-color);
  padding: 1rem;
  font-weight: normal;
  color: var(--text-primary);
  font-size: 12px !important;
}

.table-condensed tbody tr:hover {
  background-color: var(--bg-secondary);
  transition: background-color 0.2s ease;
}

.table-condensed tbody td {
  padding: 1rem;
  border-bottom: 1px solid var(--border-color);
  font-size: 12px !important;
  font-weight: normal;
}

/* Responsive Design - 12px fonts */
@media (max-width: 768px) {
  .content-box {
    padding: 1.5rem;
  }
  
  .form-select, 
  #logTypeSelect, 
  #logViewMode,
  .btn-primary,
  #refreshLogsBtn {
    font-size: 11px !important;
    padding: 0.75rem 2.5rem 0.75rem 1rem;
    min-height: 45px;
  }
  
  #logContent {
    height: 400px !important;
    padding: 1.5rem !important;
    font-size: 11px !important;
  }
  
  .form-label {
    font-size: 11px !important;
  }
  
  .col-md-3 {
    margin-bottom: 1.25rem;
  }
  
  .table-condensed thead th,
  .table-condensed tbody td {
    font-size: 11px !important;
  }
}

/* Loading state for button */
#refreshLogsBtn.loading {
  pointer-events: none;
}

#refreshLogsBtn.loading::after {
  content: '';
  position: absolute;
  width: 20px;
  height: 20px;
  margin: auto;
  border: 3px solid transparent;
  border-top-color: #ffffff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Alert mode styling - hide table option completely */
body[data-log-type="alerts"] #logViewMode option[value="table"] {
  display: none !important;
}

body[data-log-type="alerts"] #logViewMode {
  opacity: 0.7;
  pointer-events: none;
}

/* Make disabled state more obvious */
.form-select.mode-locked,
#logViewMode.mode-locked {
  background: #f8fafc !important;
  border-color: #e2e8f0 !important;
  color: #94a3b8 !important;
  cursor: not-allowed !important;
}
</style>

<div class="content-box">
  <div class="row align-items-center g-3 mb-3">
    <div class="col-md-3 col-sm-6">
      <label class="form-label fw-semibold mb-1">{{ lang._('Log Type') }}</label>
      <select id="logTypeSelect" class="form-select form-select-sm">
        <option value="alerts">{{ lang._('Alerts') }}</option>
        <option value="packets">{{ lang._('Packets') }}</option>
      </select>
    </div>

    <div class="col-md-3 col-sm-6">
      <label class="form-label fw-semibold mb-1">{{ lang._('View Mode') }}</label>
      <select id="logViewMode" class="form-select form-select-sm">
        <option value="console">{{ lang._('Console') }}</option>
        <option value="table">{{ lang._('Table') }}</option>
      </select>
    </div>

    <div class="col-md-3 col-sm-6">
      <label class="form-label d-block mb-1">&nbsp;</label>
      <button class="btn btn-sm btn-primary w-100" id="refreshLogsBtn">
        <i class="fa fa-refresh"></i> {{ lang._('Refresh Logs') }}
      </button>
    </div>
  </div>

  <!-- Console View -->
  <pre id="logContent" style="display: none;">{{ lang._('Loading logs...') }}</pre>

  <!-- Table View -->
  <table id="logTable" class="table table-condensed table-hover table-striped" data-toggle="bootgrid" style="display: none;">
    <thead>
      <tr>
        <th data-column-id="timestamp">Timestamp</th>
        <th data-column-id="src">Source IP</th>
        <th data-column-id="dst">Destination IP</th>
        <th data-column-id="port">Port</th>
        <th data-column-id="protocol">Protocol</th>
        <th data-column-id="interface">Interface</th>
        <th data-column-id="reason">Reason</th>
        <th data-column-id="raw" data-formatter="raw" data-sortable="false">Raw</th>
      </tr>
    </thead>
  </table>
</div>

<script>
function updateViewModeAvailability() {
  const type = $('#logTypeSelect').val();
  const $view = $('#logViewMode');
  const $body = $('body');
  
  // Update body attribute for CSS targeting
  $body.attr('data-log-type', type);
  
  if (type === 'alerts') {
    // In alert mode, force console view and lock the dropdown
    $view.val('console');
    $view.addClass('mode-locked');
    $view.prop('disabled', true);
    
    // Hide table option completely
    $view.find('option[value="table"]').hide();
  } else {
    // In packet mode, enable both options
    $view.removeClass('mode-locked');
    $view.prop('disabled', false);
    
    // Show table option
    $view.find('option[value="table"]').show();
  }
}

function loadLogs() {
  const $spinner = $("#refreshSpinner");
  const $button = $("#refreshLogsBtn");

  // Add loading state
  $button.addClass('loading').prop("disabled", true);

  const type = $('#logTypeSelect').val();
  const mode = $('#logViewMode').val();
  const $console = $('#logContent');
  const $table = $('#logTable');

  $console.hide();
  $table.hide();

  ajaxCall(`/api/advinspector/logs/read?type=${type}`, {}, function(data) {
    // Remove loading state
    $button.removeClass('loading').prop("disabled", false);

    if (mode === 'console') {
      $console.show();

      if (data.status === 'ok' && Array.isArray(data.logs) && data.logs.length > 0) {
        const validLogs = data.logs.filter(log => 
          log.timestamp && log.protocol && log.src && log.dst && log.reason
        );
        
        if (validLogs.length > 0) {
          const lines = validLogs.map(log => {
            return `[${log.timestamp}] ${log.protocol.toUpperCase()} ${log.src} → ${log.dst} : ${log.reason}`;
          });
          $console.text(lines.join('\n'));
          
          // Auto-scroll to bottom
          $console.scrollTop($console[0].scrollHeight);
        } else {
          $console.text("{{ lang._('No valid logs found.') }}");
        }
      } else {
        $console.text("{{ lang._('No logs available.') }}");
      }

    } else if (mode === 'table') {
      $table.show();
      const validLogs = Array.isArray(data.logs) ? 
        data.logs.filter(log => 
          log.timestamp && log.src && log.dst && log.protocol && log.reason
        ) : [];

      $table.bootgrid('destroy').bootgrid({
        caseSensitive: false,
        rowCount: [10, 25, 50, -1],
        formatters: {
          raw: function(column, row) {
            if (!row.timestamp || !row.raw) return '';
            const ts = encodeURIComponent(row.timestamp);
            const logType = $('#logTypeSelect').val();
            const basePath = logType === 'alerts'
              ? '/api/advinspector/alerts/downloadRaw'
              : '/api/advinspector/logs/download';

            return `<a href="${basePath}/${ts}?type=${logType}"
                      class="btn btn-sm btn-outline-secondary"
                      target="_blank" title="Download .bin">
                      <i class="fa fa-download"></i> .bin
                    </a>`;
          }
        }
      }).bootgrid('append', validLogs);
    }
  }).fail(function() {
    // Remove loading state on error
    $button.removeClass('loading').prop("disabled", false);
    
    if (mode === 'console') {
      $console.show().text("{{ lang._('Error loading logs. Please try again.') }}");
    }
  });
}

$(function () {
  // Event handlers
  $('#refreshLogsBtn').click(loadLogs);
  
  $('#logTypeSelect').change(function() {
    updateViewModeAvailability();
    // If switching to alerts, automatically go to console mode
    if ($(this).val() === 'alerts') {
      $('#logViewMode').val('console');
    }
    loadLogs();
  });
  
  $('#logViewMode').change(loadLogs);
  
  // Initialize
  updateViewModeAvailability();
  loadLogs(); // Initial load
});
</script>