{#
# Copyright (C) 2025 OPNsense SIEM Logger Plugin
# All rights reserved.
#}

<script>
$(document).ready(function() {
    // Update service status
    updateServiceStatus();
    
    // Map form data for actions
    mapDataToFormUI({'frm_GeneralSettings': '/api/siemlogger/settings/get'}).done(function() {
        // data is loaded, format result
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
    });

    // Initialize forms
    ajaxCall('/api/siemlogger/service/status', {}, function(data, status) {
        updateServiceControlUI('siemlogger');
    });
});

function saveAct() {
    // Save all forms
    var savePromises = [];
    
    // Save each form section
    savePromises.push(saveFormToEndpoint('/api/siemlogger/settings/set', 'frm_GeneralSettings', null, null, 'general'));
    savePromises.push(saveFormToEndpoint('/api/siemlogger/settings/set', 'frm_SiemExportSettings', null, null, 'siem_export'));
    savePromises.push(saveFormToEndpoint('/api/siemlogger/settings/set', 'frm_LoggingRulesSettings', null, null, 'logging_rules'));
    savePromises.push(saveFormToEndpoint('/api/siemlogger/settings/set', 'frm_AuditSettings', null, null, 'audit_settings'));
    savePromises.push(saveFormToEndpoint('/api/siemlogger/settings/set', 'frm_NotificationsSettings', null, null, 'notifications'));
    savePromises.push(saveFormToEndpoint('/api/siemlogger/settings/set', 'frm_MonitoringSettings', null, null, 'monitoring'));
    
    $.when.apply($, savePromises).done(function() {
        // Reconfigure service
        ajaxCall('/api/siemlogger/service/reconfigure', {}, function(data, status) {
            if (status === "success") {
                updateServiceControlUI('siemlogger');
            }
        });
    });
}

function updateServiceStatus() {
    ajaxCall('/api/siemlogger/service/status', {}, function(data, status) {
        if (status === "success" && data) {
            var statusText = data.running ? "{{ lang._('Running') }}" : "{{ lang._('Stopped') }}";
            var statusClass = data.running ? "label-success" : "label-danger";
            $("#service_status_text").html('<span class="label ' + statusClass + '">' + statusText + '</span>');
        }
    });
}
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="table-responsive">
        <div class="col-xs-12">
            <div class="pull-right">
                <small>{{ lang._('full help') }} </small>
                <a href="#"><i class="fa fa-toggle-off text-danger" style="cursor: pointer;" id="show_all_help_page"></i></a>
                &nbsp;
            </div>
        </div>
        <div class="col-xs-12">
            <div class="content-box" style="padding-bottom: 1.5em;">
                <!-- Service Status -->
                <div class="row">
                    <div class="col-md-12">
                        <div class="pull-right">
                            <span style="padding-right: 10px;">
                                <strong>{{ lang._('Service Status') }}:</strong>
                                <span id="service_status_text">
                                    <span class="label label-default">{{ lang._('Unknown') }}</span>
                                </span>
                            </span>
                            <span id="siemlogger_progress" class="page_content_progress"></span>
                        </div>
                    </div>
                </div>
                <hr/>

                <!-- Navigation tabs -->
                <ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
                    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
                    <li><a data-toggle="tab" href="#siem_export">{{ lang._('SIEM Export') }}</a></li>
                    <li><a data-toggle="tab" href="#logging_rules">{{ lang._('Logging Rules') }}</a></li>
                    <li><a data-toggle="tab" href="#audit_settings">{{ lang._('Audit Settings') }}</a></li>
                    <li><a data-toggle="tab" href="#notifications">{{ lang._('Notifications') }}</a></li>
                    <li><a data-toggle="tab" href="#monitoring">{{ lang._('Monitoring') }}</a></li>
                </ul>

                <div class="tab-content content-box col-xs-12 col-lg-6">
                    <!-- General Tab -->
                    <div id="general" class="tab-pane fade in active">
                        {{ partial("layout_partials/base_form", ['fields': formGeneralSettings, 'id': 'frm_GeneralSettings']) }}
                    </div>

                    <!-- SIEM Export Tab -->
                    <div id="siem_export" class="tab-pane fade">
                        {{ partial("layout_partials/base_form", ['fields': formSiemExportSettings, 'id': 'frm_SiemExportSettings']) }}
                    </div>

                    <!-- Logging Rules Tab -->
                    <div id="logging_rules" class="tab-pane fade">
                        {{ partial("layout_partials/base_form", ['fields': formLoggingRulesSettings, 'id': 'frm_LoggingRulesSettings']) }}
                    </div>

                    <!-- Audit Settings Tab -->
                    <div id="audit_settings" class="tab-pane fade">
                        {{ partial("layout_partials/base_form", ['fields': formAuditSettings, 'id': 'frm_AuditSettings']) }}
                    </div>

                    <!-- Notifications Tab -->
                    <div id="notifications" class="tab-pane fade">
                        {{ partial("layout_partials/base_form", ['fields': formNotificationsSettings, 'id': 'frm_NotificationsSettings']) }}
                    </div>

                    <!-- Monitoring Tab -->
                    <div id="monitoring" class="tab-pane fade">
                        {{ partial("layout_partials/base_form", ['fields': formMonitoringSettings, 'id': 'frm_MonitoringSettings']) }}
                    </div>

                    <div class="col-xs-12">
                        <hr/>
                        <button class="btn btn-primary" id="saveAct" type="button">
                            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog",['fields':formDialogEditSiemLogger,'id':'DialogEditSiemLogger','label':lang._('Edit SIEM Logger')]) }}