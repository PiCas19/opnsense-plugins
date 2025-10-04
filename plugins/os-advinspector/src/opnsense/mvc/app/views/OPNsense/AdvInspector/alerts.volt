<div class="content-box">
  <table id="grid-alerts" 
         data-toggle="bootgrid" 
         data-ajax="true" 
         class="table table-condensed table-hover table-striped">
    <thead>
      <tr>
        <th data-column-id="timestamp" data-order="desc">Timestamp</th>
        <th data-column-id="src">Source IP</th>
        <th data-column-id="dst">Destination IP</th>
        <th data-column-id="protocol">Protocol</th>
        <th data-column-id="reason">Reason</th>
      </tr>
    </thead>
  </table>
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

        return {
            current: 1,
            rowCount: 0,
            rows: [],
            total: 0
        };
    },
    rowCount: [10, 25, 50, -1],
    searchSettings: {
        delay: 250,
        characters: 1
    }
}).on('loaded.rs.jquery.bootgrid', function() {
    $('[data-toggle="tooltip"]').tooltip();
});
</script>