<style>
#logContent {
    background: #1e293b;
    color: #10b981;
    padding: 1rem;
    height: 500px;
    overflow-y: auto;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    border-radius: 4px;
    border: 1px solid #334155;
    margin: 1rem 0;
}

#logContent::-webkit-scrollbar { width: 8px; }
#logContent::-webkit-scrollbar-track { background: #2d2d2d; border-radius: 4px; }
#logContent::-webkit-scrollbar-thumb { background: #555; border-radius: 4px; }
#logContent::-webkit-scrollbar-thumb:hover { background: #777; }
</style>

<div class="content-box">
  <div class="row" style="margin-bottom:1rem;">
    <div class="col-md-3">
      <label>{{ lang._('Log Type') }}</label>
      <select id="logTypeSelect" class="form-control">
        <option value="alerts">{{ lang._('Alerts') }}</option>
        <option value="packets">{{ lang._('Packets') }}</option>
      </select>
    </div>

    <div class="col-md-3">
      <label>{{ lang._('View Mode') }}</label>
      <select id="logViewMode" class="form-control">
        <option value="console">{{ lang._('Console') }}</option>
        <option value="table">{{ lang._('Table') }}</option>
      </select>
    </div>

    <div class="col-md-3">
      <label>&nbsp;</label>
      <button class="btn btn-primary btn-block" id="refreshLogsBtn">
        <i class="fa fa-refresh"></i> {{ lang._('Refresh Logs') }}
      </button>
    </div>
  </div>

  <!-- Console View -->
  <pre id="logContent" style="display:none;"></pre>

  <!-- Table View -->
  <table id="logTable" class="table table-condensed table-hover table-striped" data-toggle="bootgrid" style="display:none;">
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

  if (type === 'alerts') {
    $view.val('console');
    $view.prop('disabled', true);
    $view.find('option[value="table"]').hide();
  } else {
    $view.prop('disabled', false);
    $view.find('option[value="table"]').show();
  }
}

function loadLogs() {
  const $button = $("#refreshLogsBtn");
  $button.prop("disabled", true);

  const type = $('#logTypeSelect').val();
  const mode = $('#logViewMode').val();
  const $console = $('#logContent');
  const $table = $('#logTable');

  $console.hide();
  $table.hide();

  ajaxCall(`/api/advinspector/logs/read?type=${type}`, {}, function(data) {
    $button.prop("disabled", false);

    if (mode === 'console') {
      $console.show();

      if (data.status === 'ok' && Array.isArray(data.logs) && data.logs.length > 0) {
        const lines = data.logs.map(log => {
          return `[${log.timestamp || '-'}] ${log.protocol?.toUpperCase() || ''} ${log.src || '-'} → ${log.dst || '-'} : ${log.reason || ''}`;
        });
        $console.text(lines.join('\n'));
        $console.scrollTop($console[0].scrollHeight);
      } else {
        $console.text("");
      }

    } else if (mode === 'table') {
      $table.show();
      const logs = Array.isArray(data.logs) ? data.logs : [];

      $table.bootgrid('destroy').bootgrid({
        caseSensitive: false,
        rowCount: [10, 25, 50, -1],
        formatters: {
          raw: function(column, row) {
            if (!row.timestamp || !row.raw) return '-';
            const ts = encodeURIComponent(row.timestamp);
            const logType = $('#logTypeSelect').val();
            const basePath = logType === 'alerts'
              ? '/api/advinspector/alerts/downloadRaw'
              : '/api/advinspector/logs/download';
            return `<a href="${basePath}/${ts}?type=${logType}" class="btn btn-xs btn-default" target="_blank" title="Download .bin"><i class="fa fa-download"></i> .bin</a>`;
          }
        }
      }).bootgrid('append', logs);
    }
  }).fail(function() {
    $button.prop("disabled", false);
    if (mode === 'console') {
      $console.show().text("");
    }
  });
}

$(function () {
  $('#refreshLogsBtn').click(loadLogs);

  $('#logTypeSelect').change(function() {
    updateViewModeAvailability();
    if ($(this).val() === 'alerts') {
      $('#logViewMode').val('console');
    }
    loadLogs();
  });

  $('#logViewMode').change(loadLogs);

  updateViewModeAvailability();
  loadLogs();
});
</script>
