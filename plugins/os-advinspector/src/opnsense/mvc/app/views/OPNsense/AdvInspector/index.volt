<ul class="nav nav-tabs" data-tabs="tabs" id="advInspectorTabs">
  <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
  <li><a data-toggle="tab" href="#rules">{{ lang._('Rules') }}</a></li>
  <li><a data-toggle="tab" href="#alerts">{{ lang._('Alerts') }}</a></li>
  <li><a data-toggle="tab" href="#logs">{{ lang._('Logs') }}</a></li>
</ul>

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

<script>
$(document).ready(function () {
  if (window.location.hash !== "") {
    $('a[href="' + window.location.hash + '"]').click();
  }
  $('.nav-tabs a').on('shown.bs.tab', function (e) {
    history.pushState(null, null, e.target.hash);
  });
});
</script>
