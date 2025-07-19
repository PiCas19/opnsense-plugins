{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="content-box-main">
        <div class="table-responsive">
            <div class="col-sm-12">
                <div class="pull-right">
                    <small>{{ lang._('full help') }}&nbsp;</small>
                    <a href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
                </div>
            </div>
            
            <!-- Navigation Tabs -->
            <ul class="nav nav-tabs" role="tablist">
                <li role="presentation" class="active">
                    <a href="#general" aria-controls="general" role="tab" data-toggle="tab">
                        <i class="fa fa-cog"></i> {{ lang._('General') }}
                    </a>
                </li>
                <li role="presentation">
                    <a href="#waf" aria-controls="waf" role="tab" data-toggle="tab">
                        <i class="fa fa-shield"></i> {{ lang._('WAF Protection') }}
                    </a>
                </li>
                <li role="presentation">
                    <a href="#behavioral" aria-controls="behavioral" role="tab" data-toggle="tab">
                        <i class="fa fa-brain"></i> {{ lang._('Behavioral Analysis') }}
                    </a>
                </li>
                <li role="presentation">
                    <a href="#covert" aria-controls="covert" role="tab" data-toggle="tab">
                        <i class="fa fa-eye-slash"></i> {{ lang._('Covert Channels') }}
                    </a>
                </li>
                <li role="presentation">
                    <a href="#response" aria-controls="response" role="tab" data-toggle="tab">
                        <i class="fa fa-bolt"></i> {{ lang._('Response') }}
                    </a>
                </li>
                <li role="presentation">
                    <a href="#whitelist" aria-controls="whitelist" role="tab" data-toggle="tab">
                        <i class="fa fa-check-circle"></i> {{ lang._('Whitelist') }}
                    </a>
                </li>
            </ul>

            <!-- Tab Content -->
            <div class="tab-content">
                <!-- General Settings Tab -->
                <div role="tabpanel" class="tab-pane active" id="general">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-cog"></i> {{ lang._('General Settings') }}
                            </h3>
                        </div>
                        <div class="panel-body">
                            {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_general_settings']) }}
                        </div>
                    </div>
                </div>

                <!-- WAF Settings Tab -->
                <div role="tabpanel" class="tab-pane" id="waf">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-shield"></i> {{ lang._('Web Application Firewall Protection') }}
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="alert alert-info">
                                <i class="fa fa-info-circle"></i>
                                {{ lang._('Configure WAF protection rules to defend against common web attacks. These rules inspect HTTP requests and responses for malicious patterns.') }}
                            </div>
                            {{ partial("layout_partials/base_form",['fields':wafForm,'id':'frm_waf_settings']) }}
                        </div>
                    </div>
                </div>

                <!-- Behavioral Analysis Tab -->
                <div role="tabpanel" class="tab-pane" id="behavioral">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-brain"></i> {{ lang._('Behavioral Analysis Settings') }}
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="alert alert-info">
                                <i class="fa fa-info-circle"></i>
                                {{ lang._('Behavioral analysis uses machine learning to detect anomalous patterns that may indicate advanced threats or insider attacks.') }}
                            </div>
                            {{ partial("layout_partials/base_form",['fields':behavioralForm,'id':'frm_behavioral_settings']) }}
                        </div>
                    </div>
                </div>

                <!-- Covert Channels Tab -->
                <div role="tabpanel" class="tab-pane" id="covert">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-eye-slash"></i> {{ lang._('Covert Channels Detection') }}
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="alert alert-warning">
                                <i class="fa fa-warning"></i>
                                {{ lang._('Covert channel detection identifies hidden communication methods used by advanced persistent threats to evade traditional security measures.') }}
                            </div>
                            {{ partial("layout_partials/base_form",['fields':covertChannelsForm,'id':'frm_covert_settings']) }}
                        </div>
                    </div>
                </div>

                <!-- Response Settings Tab -->
                <div role="tabpanel" class="tab-pane" id="response">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-bolt"></i> {{ lang._('Automated Response Settings') }}
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="alert alert-warning">
                                <i class="fa fa-warning"></i>
                                {{ lang._('Configure automated response actions when threats are detected. Use caution with aggressive settings to avoid blocking legitimate traffic.') }}
                            </div>
                            {{ partial("layout_partials/base_form",['fields':responseForm,'id':'frm_response_settings']) }}
                        </div>
                    </div>
                </div>

                <!-- Whitelist Settings Tab -->
                <div role="tabpanel" class="tab-pane" id="whitelist">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">
                                <i class="fa fa-check-circle"></i> {{ lang._('Whitelist Settings') }}
                            </h3>
                        </div>
                        <div class="panel-body">
                            <div class="alert alert-info">
                                <i class="fa fa-info-circle"></i>
                                {{ lang._('Configure trusted sources and bypass rules. Whitelisted entries will bypass some security checks.') }}
                            </div>
                            {{ partial("layout_partials/base_form",['fields':whitelistForm,'id':'frm_whitelist_settings']) }}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="row">
                <div class="col-md-12">
                    <hr/>
                    <button class="btn btn-primary" id="saveAct" type="button">
                        <i class="fa fa-save"></i> {{ lang._('Save') }}
                    </button>
                    <button class="btn btn-info" id="testRulesAct" type="button">
                        <i class="fa fa-flask"></i> {{ lang._('Test Rules') }}
                    </button>
                    <button class="btn btn-warning" id="updateRulesAct" type="button">
                        <i class="fa fa-download"></i> {{ lang._('Update Rules') }}
                    </button>
                    <button class="btn btn-default" id="exportConfigAct" type="button">
                        <i class="fa fa-upload"></i> {{ lang._('Export Config') }}
                    </button>
                    <button class="btn btn-default" id="importConfigAct" type="button">
                        <i class="fa fa-download"></i> {{ lang._('Import Config') }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Test Rules Modal -->
<div class="modal fade" id="testRulesModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Test WAF Rules') }}</h4>
            </div>
            <div class="modal-body">
                <form id="testRulesForm">
                    <div class="form-group">
                        <label for="testUrl">{{ lang._('Test URL') }}</label>
                        <input type="text" class="form-control" id="testUrl" placeholder="http://example.com/test">
                    </div>
                    <div class="form-group">
                        <label for="testPayload">{{ lang._('Test Payload') }}</label>
                        <textarea class="form-control" id="testPayload" rows="4" placeholder="Enter test payload (e.g., SQL injection, XSS)"></textarea>
                    </div>
                </form>
                <div id="testResults" style="display: none;">
                    <h5>{{ lang._('Test Results') }}</h5>
                    <div id="testResultsContent"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
                <button type="button" class="btn btn-primary" id="runTestBtn">{{ lang._('Run Test') }}</button>
            </div>
        </div>
    </div>
</div>

<!-- Import Config Modal -->
<div class="modal fade" id="importConfigModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
                <h4 class="modal-title">{{ lang._('Import Configuration') }}</h4>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="configData">{{ lang._('Configuration Data (JSON)') }}</label>
                    <textarea class="form-control" id="configData" rows="10" placeholder="Paste configuration JSON here..."></textarea>
                </div>
                <div class="alert alert-warning">
                    <i class="fa fa-warning"></i>
                    {{ lang._('Importing configuration will overwrite current settings. Make sure to export your current configuration first.') }}
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-primary" id="importBtn">{{ lang._('Import') }}</button>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    let mapDataToFormUI = {
        'frm_general_settings': "/api/webguard/settings/get",
        'frm_waf_settings': "/api/webguard/settings/get",
        'frm_behavioral_settings': "/api/webguard/settings/get",
        'frm_covert_settings': "/api/webguard/settings/get",
        'frm_response_settings': "/api/webguard/settings/get",
        'frm_whitelist_settings': "/api/webguard/settings/get"
    };

    // Load all form data
    $.each(mapDataToFormUI, function(formId, endpoint) {
        ajaxGet(endpoint, {}, function(data) {
            mapDataToFormUI(data, formId);
        });
    });

    // Save configuration
    $("#saveAct").click(function() {
        saveFormToEndpoint(url="/api/webguard/settings/set", formid='frm_general_settings,frm_waf_settings,frm_behavioral_settings,frm_covert_settings,frm_response_settings,frm_whitelist_settings', callback_ok=function() {
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_SUCCESS,
                title: '{{ lang._("Configuration saved") }}',
                message: '{{ lang._("WebGuard configuration has been saved successfully.") }}',
                buttons: [{
                    label: '{{ lang._("Close") }}',
                    action: function(dialogRef) {
                        dialogRef.close();
                    }
                }]
            });
        });
    });

    // Test Rules
    $("#testRulesAct").click(function() {
        $("#testRulesModal").modal('show');
    });

    $("#runTestBtn").click(function() {
        let url = $("#testUrl").val();
        let payload = $("#testPayload").val();
        
        if (!url || !payload) {
            BootstrapDialog.alert('{{ lang._("Please provide both URL and payload for testing.") }}');
            return;
        }

        $("#runTestBtn").prop('disabled', true).text('{{ lang._("Testing...") }}');

        ajaxCall('/api/webguard/settings/testRules', {
            url: url,
            payload: payload
        }, function(data) {
            if (data.result === 'ok') {
                let results = data.test_result;
                let html = '<div class="alert alert-' + (results.blocked ? 'danger' : 'success') + '">';
                html += '<strong>' + (results.blocked ? '{{ lang._("Blocked") }}' : '{{ lang._("Allowed") }}') + '</strong><br>';
                html += '{{ lang._("Rule matched") }}: ' + (results.rule_matched || '{{ lang._("None") }}') + '<br>';
                html += '{{ lang._("Score") }}: ' + (results.score || 0) + '<br>';
                html += '{{ lang._("Message") }}: ' + (results.message || '{{ lang._("No message") }}');
                html += '</div>';
                
                $("#testResultsContent").html(html);
                $("#testResults").show();
            } else {
                BootstrapDialog.alert('{{ lang._("Test failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
            }
            
            $("#runTestBtn").prop('disabled', false).text('{{ lang._("Run Test") }}');
        });
    });

    // Update Rules
    $("#updateRulesAct").click(function() {
        BootstrapDialog.confirm({
            title: '{{ lang._("Update WAF Rules") }}',
            message: '{{ lang._("This will download the latest WAF rules from external sources. Continue?") }}',
            type: BootstrapDialog.TYPE_WARNING,
            btnCancelLabel: '{{ lang._("Cancel") }}',
            btnOKLabel: '{{ lang._("Update") }}',
            callback: function(result) {
                if (result) {
                    $("#updateRulesAct").prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Updating...") }}');
                    
                    ajaxCall('/api/webguard/settings/updateRules', {}, function(data) {
                        if (data.result === 'ok') {
                            BootstrapDialog.show({
                                type: BootstrapDialog.TYPE_SUCCESS,
                                title: '{{ lang._("Rules Updated") }}',
                                message: data.message || '{{ lang._("WAF rules updated successfully.") }}',
                                buttons: [{
                                    label: '{{ lang._("Close") }}',
                                    action: function(dialogRef) {
                                        dialogRef.close();
                                    }
                                }]
                            });
                        } else {
                            BootstrapDialog.alert('{{ lang._("Update failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                        }
                        
                        $("#updateRulesAct").prop('disabled', false).html('<i class="fa fa-download"></i> {{ lang._("Update Rules") }}');
                    });
                }
            }
        });
    });

    // Export Configuration
    $("#exportConfigAct").click(function() {
        ajaxGet('/api/webguard/settings/exportConfig', {}, function(data) {
            if (data.result === 'ok') {
                let blob = new Blob([JSON.stringify(data.config, null, 2)], {type: 'application/json'});
                let url = window.URL.createObjectURL(blob);
                let a = document.createElement('a');
                a.href = url;
                a.download = 'webguard-config-' + data.timestamp.replace(/[: ]/g, '-') + '.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            } else {
                BootstrapDialog.alert('{{ lang._("Export failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
            }
        });
    });

    // Import Configuration
    $("#importConfigAct").click(function() {
        $("#importConfigModal").modal('show');
    });

    $("#importBtn").click(function() {
        let configData = $("#configData").val();
        
        if (!configData) {
            BootstrapDialog.alert('{{ lang._("Please provide configuration data.") }}');
            return;
        }

        try {
            JSON.parse(configData); // Validate JSON
        } catch (e) {
            BootstrapDialog.alert('{{ lang._("Invalid JSON format.") }}');
            return;
        }

        $("#importBtn").prop('disabled', true).text('{{ lang._("Importing...") }}');

        ajaxCall('/api/webguard/settings/importConfig', {
            config: configData
        }, function(data) {
            if (data.result === 'ok') {
                $("#importConfigModal").modal('hide');
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("Configuration Imported") }}',
                    message: '{{ lang._("Configuration imported successfully. Please refresh the page to see changes.") }}',
                    buttons: [{
                        label: '{{ lang._("Refresh Page") }}',
                        action: function(dialogRef) {
                            location.reload();
                        }
                    }]
                });
            } else {
                BootstrapDialog.alert('{{ lang._("Import failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                if (data.validations) {
                    let validationMsg = data.validations.join('<br>');
                    BootstrapDialog.alert('{{ lang._("Validation errors") }}:<br>' + validationMsg);
                }
            }
            
            $("#importBtn").prop('disabled', false).text('{{ lang._("Import") }}');
        });
    });

    // Tab change handler
    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        // Handle any tab-specific logic here
    });
});
</script>

<style>
.nav-tabs {
    margin-bottom: 20px;
}

.tab-content {
    background: #fff;
    padding: 0;
}

.panel {
    border: none;
    box-shadow: none;
}

.panel-body {
    padding: 20px;
}

.alert {
    margin-bottom: 20px;
}

.modal-dialog {
    width: 600px;
}

#testResultsContent .alert {
    margin-top: 15px;
}
</style>