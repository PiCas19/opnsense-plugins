<div class="content-box">
  <div class="row" style="margin-bottom:1rem;">
    <div class="col-md-8">
      <h4 style="margin-top:0;">{{ lang._('Alerts') }}</h4>
      <p class="text-muted" style="font-size:.875rem;margin:0;">
        {{ lang._('Traffic alerts detected by the Advanced Inspector engine.') }}
      </p>
    </div>
    <div class="col-md-4 text-right">
      <button class="btn btn-default btn-sm" id="refreshAlertsBtn">
        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
      </button>
    </div>
  </div>

  <div class="table-responsive">
    <table id="grid-alerts"
           data-toggle="bootgrid"
           data-ajax="true"
           class="table table-condensed table-hover table-striped">
      <thead>
        <tr>
          <th data-column-id="timestamp" data-order="desc">{{ lang._('Timestamp') }}</th>
          <th data-column-id="src">{{ lang._('Source IP') }}</th>
          <th data-column-id="dst">{{ lang._('Destination IP') }}</th>
          <th data-column-id="protocol">{{ lang._('Protocol') }}</th>
          <th data-column-id="reason">{{ lang._('Reason') }}</th>
        </tr>
      </thead>
    </table>
  </div>
</div>

<script>
$('#grid-alerts').bootgrid({
    ajax: true,
    url: '/api/advinspector/alerts/list',
    ajaxSettings: {
        method: 'GET',
        contentType: 'application/json'
    },
    responseHandler: function(response) {
        if (response && response.status === 'ok' && Array.isArray(response.data)) {
            return {
                current: 1,
                rowCount: response.data.length,
                rows: response.data,
                total: response.data.length
            };
        }
        return { current: 1, rowCount: 0, rows: [], total: 0 };
    },
    rowCount: [10, 25, 50, -1],
    searchSettings: { delay: 250, characters: 1 }
}).on('loaded.rs.jquery.bootgrid', function() {
    $('[data-toggle="tooltip"]').tooltip();
});

$('#refreshAlertsBtn').click(function() {
    $('#grid-alerts').bootgrid('reload');
});
</script>
