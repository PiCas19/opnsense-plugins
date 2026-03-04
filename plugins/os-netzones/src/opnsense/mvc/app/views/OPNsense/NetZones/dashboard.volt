<div id="nz-notifications" style="position:fixed;bottom:24px;right:24px;z-index:9999;min-width:280px;max-width:380px;pointer-events:none;"></div>

<!-- Stats panels -->
<div class="content-box" style="padding:1.25rem;margin-bottom:1rem;">
  <div class="row">
    <div class="col-md-3">
      <div class="panel panel-default">
        <div class="panel-heading"><h6 style="margin:0;"><i class="fa fa-server"></i> {{ lang._('Service Status') }}</h6></div>
        <div class="panel-body text-center" id="serviceStatus">
          <i class="fa fa-spinner fa-spin"></i>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="panel panel-default">
        <div class="panel-heading"><h6 style="margin:0;"><i class="fa fa-shield"></i> {{ lang._('Zones') }}</h6></div>
        <div class="panel-body text-center" id="zonesStatus">
          <i class="fa fa-spinner fa-spin"></i>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="panel panel-default">
        <div class="panel-heading"><h6 style="margin:0;"><i class="fa fa-exchange"></i> {{ lang._('Policy Activity') }}</h6></div>
        <div class="panel-body text-center" id="policyActivity">
          <i class="fa fa-spinner fa-spin"></i>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="panel panel-default">
        <div class="panel-heading"><h6 style="margin:0;"><i class="fa fa-exclamation-triangle"></i> {{ lang._('Security') }}</h6></div>
        <div class="panel-body text-center" id="securitySummary">
          <i class="fa fa-spinner fa-spin"></i>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Zone details + relationships -->
<div class="content-box" style="padding:1.25rem;margin-bottom:1rem;">
  <div class="row">
    <div class="col-md-8">
      <h5><i class="fa fa-list"></i> {{ lang._('Active Zones Overview') }}</h5>
      <div id="zonesOverview">
        <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading zones...') }}
      </div>
    </div>
    <div class="col-md-4">
      <h5><i class="fa fa-sitemap"></i> {{ lang._('Zone Relationships') }}</h5>
      <div id="zoneRelationships" style="min-height:100px;margin-bottom:1.25rem;">
        <i class="fa fa-spinner fa-spin"></i>
      </div>

      <h6><i class="fa fa-tachometer text-info"></i> {{ lang._('Traffic Flow') }}</h6>
      <div id="trafficFlow" style="margin-bottom:1.25rem;">
        <i class="fa fa-spinner fa-spin"></i>
      </div>

      <h6><i class="fa fa-ban text-danger"></i> {{ lang._('Top Blocked Sources') }}</h6>
      <div id="topBlockedSources" class="small">
        <i class="fa fa-spinner fa-spin"></i>
      </div>
    </div>
  </div>
</div>

<!-- Recent activity -->
<div class="content-box" style="padding:1.25rem;margin-bottom:1rem;">
  <div class="row">
    <div class="col-md-8">
      <h5><i class="fa fa-history"></i> {{ lang._('Recent Policy Decisions') }}</h5>
      <div class="table-responsive" style="max-height:400px;overflow-y:auto;">
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
            <tr><td colspan="6" class="text-center"><i class="fa fa-spinner fa-spin"></i></td></tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="col-md-4">
      <h6><i class="fa fa-bar-chart"></i> {{ lang._('Live Activity Monitor') }}</h6>
      <div id="liveActivityChart" style="height:120px;margin-bottom:1.25rem;">
        <i class="fa fa-spinner fa-spin"></i>
      </div>

      <h6><i class="fa fa-pie-chart"></i> {{ lang._('Protocol Distribution') }}</h6>
      <div id="protocolDistribution">
        <i class="fa fa-spinner fa-spin"></i>
      </div>
    </div>
  </div>
</div>

<!-- Test Zone Policy Modal -->
<div class="modal fade" id="testModal" tabindex="-1" role="dialog">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
        <h4 class="modal-title">{{ lang._('Test Zone Policy') }}</h4>
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
        <div id="testResult" style="margin-top:1rem;"></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
        <button type="button" class="btn btn-primary" onclick="runTest()">{{ lang._('Run Test') }}</button>
      </div>
    </div>
  </div>
</div>

<style>
/* Bar chart only — no Bootstrap overrides */
.activity-chart-compact {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  padding: 8px 5px;
  background: #f9f9f9;
  border-radius: 4px;
  height: 90px;
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
  background: #337ab7;
  min-height: 2px;
  border-radius: 2px 2px 0 0;
}
.chart-bar-label {
  font-size: 9px;
  color: #666;
  text-align: center;
}
.zone-connection {
  padding: 5px 8px;
  border-left: 3px solid #337ab7;
  margin-bottom: 5px;
  background: #f9f9f9;
}
</style>

<script>
function nzNotify(message, type) {
    var isSuccess = (type === 'success');
    var cls  = isSuccess ? 'alert-success' : 'alert-danger';
    var icon = isSuccess ? 'fa-check' : 'fa-exclamation-circle';
    var $n = $('<div role="alert" style="pointer-events:all;margin-top:.4rem;border-radius:3px;box-shadow:0 2px 10px rgba(0,0,0,.28);">' +
               '<div class="alert ' + cls + ' alert-dismissible" style="margin:0;padding:.6rem .9rem;">' +
               '<button type="button" class="close" data-dismiss="alert" style="top:0;right:4px;"><span>&times;</span></button>' +
               '<i class="fa ' + icon + '" style="margin-right:.45rem;"></i>' + message + '</div></div>');
    $('#nz-notifications').append($n);
    setTimeout(function() { $n.find('.alert').alert('close'); $n.remove(); }, 4000);
}

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
        if (data && data.running) {
            $('#serviceStatus').html(
                '<div class="text-success">' +
                '<i class="fa fa-check-circle fa-2x"></i><br>' +
                '<strong>{{ lang._("RUNNING") }}</strong><br>' +
                '<small>PID: ' + (data.pid || 'N/A') + '</small>' +
                '</div>'
            );
        } else {
            $('#serviceStatus').html(
                '<div class="text-danger">' +
                '<i class="fa fa-times-circle fa-2x"></i><br>' +
                '<strong>{{ lang._("STOPPED") }}</strong>' +
                '</div>'
            );
        }
    }).fail(function() {
        $('#serviceStatus').html(
            '<div class="text-warning">' +
            '<i class="fa fa-exclamation-triangle fa-2x"></i><br>' +
            '<strong>{{ lang._("UNKNOWN") }}</strong>' +
            '</div>'
        );
    });
}

function loadZonesStatus() {
    ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
        if (data && data.status === 'ok' && data.data && typeof data.data === 'object') {
            var stats = data.data;
            var zonesActive = (stats.zones && stats.zones.active) || 0;
            var zonesTotal  = (stats.zones && stats.zones.total)  || 0;
            var polActive   = (stats.policies && stats.policies.active) || 0;
            var polTotal    = (stats.policies && stats.policies.total)  || 0;
            $('#zonesStatus').html(
                '<div class="row">' +
                '<div class="col-xs-6"><h3 class="text-primary" style="margin:0;">' + zonesActive + '</h3><small>{{ lang._("Active") }}</small></div>' +
                '<div class="col-xs-6"><h3 class="text-muted" style="margin:0;">' + zonesTotal + '</h3><small>{{ lang._("Total") }}</small></div>' +
                '</div><hr style="margin:.5rem 0;"><small class="text-muted">{{ lang._("Policies:") }} ' + polActive + '/' + polTotal + '</small>'
            );
        } else {
            $('#zonesStatus').html('<span class="text-muted">{{ lang._("No data") }}</span>');
        }
    }).fail(function() {
        $('#zonesStatus').html('<span class="text-muted">{{ lang._("Unavailable") }}</span>');
    });
}

function loadPolicyActivity() {
    ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
        if (data && data.status === 'ok' && data.data) {
            var stats = data.data;
            $('#policyActivity').html(
                '<h3 class="text-info" style="margin:0 0 .25rem;">' + (stats.total_events || 0) + '</h3>' +
                '<small>{{ lang._("Total Events") }}</small><hr style="margin:.5rem 0;">' +
                '<div class="row text-center">' +
                '<div class="col-xs-4"><span class="label label-success">' + (stats.allow_events || 0) + '</span><br><small>{{ lang._("Allow") }}</small></div>' +
                '<div class="col-xs-4"><span class="label label-danger">' + (stats.block_events || 0) + '</span><br><small>{{ lang._("Block") }}</small></div>' +
                '<div class="col-xs-4"><span class="label label-warning">' + (stats.last_hour_count || 0) + '</span><br><small>{{ lang._("Last Hour") }}</small></div>' +
                '</div>'
            );
        } else {
            $('#policyActivity').html('<span class="text-muted">{{ lang._("No data") }}</span>');
        }
    });
}

function loadSecuritySummary() {
    ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
        if (data && data.status === 'ok' && data.data) {
            var stats    = data.data;
            var blocked  = stats.block_events || 0;
            var total    = stats.total_events || 1;
            var rate     = Math.round((blocked / total) * 100);
            var cls      = rate > 50 ? 'danger' : rate > 20 ? 'warning' : 'success';
            $('#securitySummary').html(
                '<div class="text-' + cls + '">' +
                '<i class="fa fa-shield fa-2x"></i><br>' +
                '<strong>' + rate + '%</strong><br>' +
                '<small>{{ lang._("Block Rate") }}</small><br>' +
                '<small class="text-muted">' + blocked + ' {{ lang._("blocked") }}</small>' +
                '</div>'
            );
        } else {
            $('#securitySummary').html('<span class="text-muted">{{ lang._("No data") }}</span>');
        }
    });
}

function loadZonesOverview() {
    ajaxCall('/api/netzones/management/getZoneList', {}, function(data) {
        if (data && data.status === 'ok' && data.zones && data.zones.length > 0) {
            var html = '<div class="row">';
            data.zones.forEach(function(zone, index) {
                if (index % 2 === 0 && index > 0) html += '</div><div class="row">';
                html += '<div class="col-md-6" style="margin-bottom:.75rem;">' +
                        '<div class="panel panel-default" style="margin-bottom:0;">' +
                        '<div class="panel-body" style="padding:.75rem;">' +
                        '<h6 style="margin:0;"><i class="fa fa-shield text-primary"></i> ' + nzEsc(zone.text || 'Unknown') + '</h6>' +
                        '<small class="text-muted">' + (zone.value ? zone.value.substr(0,8) + '...' : 'N/A') + '</small>' +
                        '</div></div></div>';
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
        if (data && data.status === 'ok' && data.relationships && data.relationships.length > 0) {
            var html = '';
            data.relationships.forEach(function(rel) {
                var action = rel.action.toLowerCase();
                var cls = action === 'pass' || action === 'allow' ? 'success' : action === 'block' ? 'danger' : 'warning';
                html += '<div class="zone-connection">' +
                        '<span class="label label-info">' + nzEsc(rel.source_zone) + '</span>' +
                        ' <i class="fa fa-arrow-right text-muted"></i> ' +
                        '<span class="label label-info">' + nzEsc(rel.destination_zone) + '</span>' +
                        '<span class="label label-' + cls + ' pull-right">' + nzEsc(rel.action) + '</span>' +
                        '</div>';
            });
            $('#zoneRelationships').html(html);
        } else {
            $('#zoneRelationships').html('<div class="text-muted text-center"><i class="fa fa-info-circle"></i> {{ lang._("No policies configured") }}</div>');
        }
    });
}

function loadTrafficFlow() {
    ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
        if (data && data.status === 'ok' && data.data) {
            var lastHour = data.data.last_hour_count || 0;
            var pps = Math.round(lastHour / 3600) || 0;
            var cls = pps > 50 ? 'danger' : pps > 10 ? 'warning' : 'success';
            $('#trafficFlow').html(
                '<div class="text-center">' +
                '<i class="fa fa-tachometer fa-2x text-' + cls + '"></i><br>' +
                '<strong>' + pps + '</strong> <small>pps</small><br>' +
                '<small class="text-muted">' + lastHour + ' {{ lang._("events/hour") }}</small>' +
                '</div>'
            );
        } else {
            $('#trafficFlow').html('<span class="text-muted">{{ lang._("No data") }}</span>');
        }
    });
}

function loadRecentDecisions() {
    ajaxCall('/api/netzones/dashboard/logs_list', {}, function(data) {
        if (data && data.status === 'ok' && data.data && data.data.length > 0) {
            var html = '';
            data.data.slice(0, 10).forEach(function(entry) {
                var dec = (entry.decision || 'unknown').toLowerCase();
                var cls = dec === 'allow' || dec === 'pass' ? 'success' : dec === 'block' ? 'danger' : 'warning';
                html += '<tr>' +
                        '<td><small>' + nzEsc(entry.timestamp || 'N/A') + '</small></td>' +
                        '<td><code>' + nzEsc(entry.src || 'unknown') + '</code></td>' +
                        '<td><code>' + nzEsc(entry.dst || 'unknown') + '</code></td>' +
                        '<td><span class="label label-info">' + nzEsc(entry.protocol || 'unknown') + '</span></td>' +
                        '<td><span class="label label-' + cls + '">' + nzEsc(entry.decision || 'unknown') + '</span></td>' +
                        '<td><small>' + nzEsc(entry.source_zone || 'UNKNOWN') + ' → ' + nzEsc(entry.destination_zone || 'UNKNOWN') + '</small></td>' +
                        '</tr>';
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
        if (data && data.status === 'ok' && data.data && data.data.hourly) {
            var values = Object.values(data.data.hourly);
            var maxVal = Math.max.apply(null, values.concat([1]));
            var html = '<div class="activity-chart-compact">';
            values.slice(-6).forEach(function(val, i) {
                var h   = (new Date(Date.now() - (5-i)*3600000)).getHours();
                var pct = Math.max((val / maxVal) * 100, 2);
                html += '<div class="chart-bar-compact">' +
                        '<div class="chart-bar-container">' +
                        '<div class="chart-bar-fill" style="height:' + pct + '%;" title="' + val + ' @ ' + h + ':00"></div>' +
                        '</div><div class="chart-bar-label">' + h + 'h</div></div>';
            });
            html += '</div>';
            $('#liveActivityChart').html(html);
        } else {
            $('#liveActivityChart').html('<div class="text-muted text-center"><i class="fa fa-line-chart"></i><br><small>{{ lang._("No data") }}</small></div>');
        }
    });
}

function loadProtocolDistribution() {
    ajaxCall('/api/netzones/dashboard/stats', {}, function(data) {
        if (data && data.status === 'ok' && data.data && data.data.top_protocols) {
            var protocols = data.data.top_protocols;
            var total     = data.data.total_events || 1;
            var html      = '';
            Object.entries(protocols).slice(0, 5).forEach(function(kv) {
                var pct = Math.round((kv[1] / total) * 100) || 0;
                html += '<div style="margin-bottom:.5rem;">' +
                        '<div class="clearfix"><span class="pull-left">' + nzEsc(kv[0].toUpperCase()) + '</span>' +
                        '<span class="pull-right">' + kv[1] + ' (' + pct + '%)</span></div>' +
                        '<div class="progress progress-xs" style="margin-bottom:0;">' +
                        '<div class="progress-bar" style="width:' + pct + '%;"></div>' +
                        '</div></div>';
            });
            $('#protocolDistribution').html(html || '<div class="text-muted">{{ lang._("No data") }}</div>');
        } else {
            $('#protocolDistribution').html('<div class="text-muted text-center"><i class="fa fa-pie-chart"></i><br>{{ lang._("No data") }}</div>');
        }
    });
}

function loadTopBlockedSources() {
    ajaxCall('/api/netzones/dashboard/logs_list', {}, function(data) {
        if (data && data.status === 'ok' && data.data) {
            var sources = {};
            data.data.filter(function(e) {
                return (e.decision || '').toLowerCase() === 'block';
            }).forEach(function(e) {
                sources[e.src] = (sources[e.src] || 0) + 1;
            });
            var sorted = Object.entries(sources).sort(function(a,b){ return b[1]-a[1]; }).slice(0,5);
            if (sorted.length > 0) {
                var html = '';
                sorted.forEach(function(kv) {
                    html += '<div style="margin-bottom:.25rem;"><code>' + nzEsc(kv[0]) + '</code>' +
                            '<span class="label label-danger pull-right">' + kv[1] + '</span></div>';
                });
                $('#topBlockedSources').html(html);
            } else {
                $('#topBlockedSources').html('<span class="text-muted">{{ lang._("No blocked sources") }}</span>');
            }
        } else {
            $('#topBlockedSources').html('<span class="text-muted">{{ lang._("No data") }}</span>');
        }
    });
}

function nzEsc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

$(function() {
    loadDashboard();
    setInterval(loadDashboard, 30000);
});

window.reloadDashboard = loadDashboard;
</script>
