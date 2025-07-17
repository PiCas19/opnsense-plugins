{#
 # Copyright (C) 2025 OPNsense Project
 # All rights reserved.
 #}

<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
    {{ lang._('The Deep Packet Inspector configuration has been changed') }}<br/>
    {{ lang._('You must apply the changes in order for them to take effect.') }}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#protocols">{{ lang._('Protocols') }}</a></li>
    <li><a data-toggle="tab" href="#detection">{{ lang._('Detection') }}</a></li>
    <li><a data-toggle="tab" href="#advanced">{{ lang._('Advanced') }}</a></li>
</ul>

<div class="tab-content content-box">
    <!-- GENERAL TAB -->
    <div id="general" class="tab-pane fade in active">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('General Settings') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formGeneral,
                    'id':     'frm_DeepInspectorGeneral'
                }) }}
                <div class="text-right" style="margin-top: 15px;">
                    <button id="btnApplyGeneral" type="button" class="btn btn-primary"
                            data-endpoint='/api/deepinspector/service/reconfigure'
                            data-label="{{ lang._('Apply') }}"
                            data-error-title="{{ lang._('Error reconfiguring Deep Packet Inspector') }}">
                        <i class="fa fa-check"></i> {{ lang._('Apply') }}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- PROTOCOLS TAB -->
    <div id="protocols" class="tab-pane fade in">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Protocol Inspection') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formProtocols,
                    'id':     'frm_DeepInspectorProtocols'
                }) }}
                <div class="text-right" style="margin-top: 15px;">
                    <button id="btnApplyProtocols" type="button" class="btn btn-primary"
                            data-endpoint='/api/deepinspector/service/reconfigure'
                            data-label="{{ lang._('Apply') }}"
                            data-error-title="{{ lang._('Error reconfiguring Deep Packet Inspector') }}">
                        <i class="fa fa-check"></i> {{ lang._('Apply') }}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- DETECTION TAB -->
    <div id="detection" class="tab-pane fade in">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Detection Engines') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formDetection,
                    'id':     'frm_DeepInspectorDetection'
                }) }}
                <div class="text-right" style="margin-top: 15px;">
                    <button id="btnApplyDetection" type="button" class="btn btn-primary"
                            data-endpoint='/api/deepinspector/service/reconfigure'
                            data-label="{{ lang._('Apply') }}"
                            data-error-title="{{ lang._('Error reconfiguring Deep Packet Inspector') }}">
                        <i class="fa fa-check"></i> {{ lang._('Apply') }}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- ADVANCED TAB -->
    <div id="advanced" class="tab-pane fade in">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Advanced Settings') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formAdvanced,
                    'id':     'frm_DeepInspectorAdvanced'
                }) }}
                <div class="text-right" style="margin-top: 15px;">
                    <button id="btnApplyAdvanced" type="button" class="btn btn-primary"
                            data-endpoint='/api/deepinspector/service/reconfigure'
                            data-label="{{ lang._('Apply') }}"
                            data-error-title="{{ lang._('Error reconfiguring Deep Packet Inspector') }}">
                        <i class="fa fa-check"></i> {{ lang._('Apply') }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.panel-body { padding: 15px; }
</style>

<script>
$(function() {
    // Controlla se bisogna mostrare il banner "config changed"
    function isSubsystemDirty() {
        ajaxGet("/api/deepinspector/settings/dirty", {}, function(data) {
            $("#configChangedMsg").toggleClass("hidden", !(data.deepinspector && data.deepinspector.dirty));
        });
    }

    // Funzione per gestire i pulsanti Apply con spinner e snackbar
    function bindApplyButton(buttonId, formId) {
        $(buttonId).click(function() {
            var $btn = $(this);
            var originalText = $btn.html();
            
            // Mostra spinner
            $btn.html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Applying...") }}');
            $btn.prop('disabled', true);
            
            // Salva i dati del form prima di applicare
            var formData = { deepinspector: {} };
            var $form = $('#' + formId);
            
            // Serializza tutti i campi del form
            $form.find('input, select, textarea').each(function() {
                var $field = $(this);
                var name = $field.attr('name');
                
                if (name && name.indexOf('deepinspector.') === 0) {
                    // Rimuovi il prefisso deepinspector.
                    var cleanName = name.substring(13);
                    
                    if ($field.is(':checkbox')) {
                        formData.deepinspector[cleanName] = $field.is(':checked') ? '1' : '0';
                    } else if ($field.is('select[multiple]')) {
                        formData.deepinspector[cleanName] = $field.val() ? $field.val().join(',') : '';
                    } else {
                        formData.deepinspector[cleanName] = $field.val() || '';
                    }
                }
            });
            
            console.log("Saving data for " + formId + ":", formData);
            
            // Salva i dati prima di applicare
            ajaxCall("/api/deepinspector/settings/set", formData,
                function(resp) {
                    if (resp.result !== 'saved') {
                        var msg = "{{ lang._('Failed to save settings') }}:<br/>";
                        if (resp.validations) {
                            for (var f in resp.validations) {
                                msg += '<strong>'+f+'</strong>: '+resp.validations[f]+'<br/>';
                            }
                        }
                        
                        // Ripristina il pulsante
                        $btn.html(originalText);
                        $btn.prop('disabled', false);
                        
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_DANGER,
                            title: "{{ lang._('Error') }}",
                            message: msg,
                            buttons: [{ label:'OK', action:function(d){d.close(); }}]
                        });
                        return;
                    }
                    
                    console.log("Settings saved successfully for " + formId);
                    
                    // Applica la configurazione
                    ajaxCall("/api/deepinspector/service/reconfigure", {},
                        function(applyResp) {
                            // Ripristina il pulsante
                            $btn.html(originalText);
                            $btn.prop('disabled', false);
                            
                            if (applyResp.status === 'ok') {
                                // Controlla lo stato dirty
                                isSubsystemDirty();
                                
                                // Mostra snackbar di successo
                                BootstrapDialog.show({
                                    type: BootstrapDialog.TYPE_SUCCESS,
                                    title: "{{ lang._('Success') }}",
                                    message: "{{ lang._('Configuration applied successfully') }}",
                                    size: BootstrapDialog.SIZE_SMALL,
                                    buttons: [{ label:'OK', action:function(d){ d.close(); }}]
                                });
                            } else {
                                BootstrapDialog.show({
                                    type: BootstrapDialog.TYPE_DANGER,
                                    title: "{{ lang._('Error') }}",
                                    message: "{{ lang._('Failed to apply configuration') }}",
                                    buttons: [{ label:'OK', action:function(d){d.close(); }}]
                                });
                            }
                        }
                    );
                }
            );
        });
    }

    // Bind di tutti i pulsanti Apply
    bindApplyButton('#btnApplyGeneral', 'frm_DeepInspectorGeneral');
    bindApplyButton('#btnApplyProtocols', 'frm_DeepInspectorProtocols');
    bindApplyButton('#btnApplyDetection', 'frm_DeepInspectorDetection');
    bindApplyButton('#btnApplyAdvanced', 'frm_DeepInspectorAdvanced');

    // Carica i dati iniziali
    var initialFormMap = {
        'frm_DeepInspectorGeneral': "/api/deepinspector/settings/get",
        'frm_DeepInspectorProtocols': "/api/deepinspector/settings/get",
        'frm_DeepInspectorDetection': "/api/deepinspector/settings/get",
        'frm_DeepInspectorAdvanced': "/api/deepinspector/settings/get"
    };
    
    mapDataToFormUI(initialFormMap).done(function(data) {
        console.log("Initial data loaded:", data);
        $('.selectpicker').selectpicker('refresh');
        formatTokenizersUI();
    }).fail(function(error) {
        console.error("Failed to load initial data:", error);
    });

    // Listener per rilevare cambiamenti nei form e mostrare il banner
    $('.tab-content').on('change', 'input, select, textarea', function() {
        isSubsystemDirty();
    });

    isSubsystemDirty();
});
</script>