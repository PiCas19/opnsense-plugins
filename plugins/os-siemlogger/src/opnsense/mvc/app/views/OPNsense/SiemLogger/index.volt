{% extends "/ui/layouts/standard.volt" %}

{% block content %}
<div class="content-box">
    <div class="content-box-main">
        <h3>{{ gettext("SIEM Logger Settings") }}</h3>
        <ul class="nav nav-tabs">
            <li class="active"><a data-toggle="tab" href="#general">{{ gettext("General") }}</a></li>
            <li><a data-toggle="tab" href="#siem_export">{{ gettext("SIEM Export") }}</a></li>
            <li><a data-toggle="tab" href="#logging_rules">{{ gettext("Logging Rules") }}</a></li>
            <li><a data-toggle="tab" href="#audit_settings">{{ gettext("Audit Settings") }}</a></li>
            <li><a data-toggle="tab" href="#notifications">{{ gettext("Notifications") }}</a></li>
            <li><a data-toggle="tab" href="#monitoring">{{ gettext("Monitoring") }}</a></li>
        </ul>
        <div class="tab-content">
            <div id="general" class="tab-pane fade in active">
                {{ formGeneralSettings.render() }}
            </div>
            <div id="siem_export" class="tab-pane fade">
                {{ formSiemExportSettings.render() }}
            </div>
            <div id="logging_rules" class="tab-pane fade">
                {{ formLoggingRulesSettings.render() }}
            </div>
            <div id="audit_settings" class="tab-pane fade">
                {{ formAuditSettings.render() }}
            </div>
            <div id="notifications" class="tab-pane fade">
                {{ formNotificationsSettings.render() }}
            </div>
            <div id="monitoring" class="tab-pane fade">
                {{ formMonitoringSettings.render() }}
            </div>
        </div>
        <div class="col-md-12">
            <button class="btn btn-primary" onclick="saveSettings()">{{ gettext("Save & Apply") }}</button>
        </div>
    </div>
</div>

<script>
function saveSettings() {
    var forms = [
        '#formGeneralSettings',
        '#formSiemExportSettings',
        '#formLoggingRulesSettings',
        '#formAuditSettings',
        '#formNotificationsSettings',
        '#formMonitoringSettings'
    ];

    var data = {};
    $.each(forms, function(i, formId) {
        $(formId).serializeArray().forEach(function(item) {
            data[item.name] = item.value;
        });
    });

    $.ajax({
        url: '/api/siemlogger/settings/set',
        type: 'POST',
        data: { siemlogger: data },
        success: function(response) {
            if (response.result === 'saved') {
                alert('Settings saved successfully');
            } else {
                alert('Failed to save settings: ' + JSON.stringify(response.validations));
            }
        },
        error: function() {
            alert('Error saving settings');
        }
    });
}
</script>
{% endblock %}