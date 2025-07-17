{#
 # Copyright (C) 2025 OPNsense Project
 # All rights reserved.
 #}

<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
    <button class="btn btn-primary pull-right" id="btnApplyConfig"
            data-endpoint='/api/deepinspector/service/reconfigure'
            data-label="{{ lang._('Apply') }}"
            data-error-title="{{ lang._('Error reconfiguring Deep Packet Inspector') }}"
            type="button">
    </button>
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
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnEditGeneral" type="button" class="btn btn-default">
                <i class="fa fa-edit"></i> {{ lang._('Edit') }}
            </button>
        </div>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('General Settings') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formGeneral,
                    'id':     'frm_DeepInspectorGeneral'
                }) }}
            </div>
        </div>
    </div>

    <!-- PROTOCOLS TAB -->
    <div id="protocols" class="tab-pane fade in">
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnEditProtocols" type="button" class="btn btn-default">
                <i class="fa fa-edit"></i> {{ lang._('Edit') }}
            </button>
        </div>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Protocol Inspection') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formProtocols,
                    'id':     'frm_DeepInspectorProtocols'
                }) }}
            </div>
        </div>
    </div>

    <!-- DETECTION TAB -->
    <div id="detection" class="tab-pane fade in">
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnEditDetection" type="button" class="btn btn-default">
                <i class="fa fa-edit"></i> {{ lang._('Edit') }}
            </button>
        </div>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Detection Engines') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formDetection,
                    'id':     'frm_DeepInspectorDetection'
                }) }}
            </div>
        </div>
    </div>

    <!-- ADVANCED TAB -->
    <div id="advanced" class="tab-pane fade in">
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnEditAdvanced" type="button" class="btn btn-default">
                <i class="fa fa-edit"></i> {{ lang._('Edit') }}
            </button>
        </div>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Advanced Settings') }}</h3>
            </div>
            <div class="panel-body">
                {{ partial("layout_partials/base_form", {
                    'fields': formAdvanced,
                    'id':     'frm_DeepInspectorAdvanced'
                }) }}
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

    // Pulsante globale "Apply"
    $('#btnApplyConfig').SimpleActionButton({
        onAction: function() {
            isSubsystemDirty();
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_SUCCESS,
                title: "{{ lang._('Success') }}",
                message: "{{ lang._('Configuration applied successfully') }}",
                buttons: [{ label:'OK', action:function(d){ d.close(); }}]
            });
        }
    });

    // Funzione che apre un dialog con gestione corretta dei dati
    function bindDialog(btnId, dialogId, title, formId) {
        $(btnId).click(function() {
            var dialogRef = BootstrapDialog.show({
                title: title,
                message: $('#' + dialogId).html(),
                size: BootstrapDialog.SIZE_LARGE,
                buttons: [
                    {
                        label: "{{ lang._('Save') }}",
                        cssClass: 'btn-primary',
                        action: function(dlg) {
                            // Raccoglie i dati dal form nel dialog
                            var formData = {};
                            var $form = dlg.getModalBody().find('#' + formId);
                            
                            // Serializza tutti i campi del form
                            $form.find('input, select, textarea').each(function() {
                                var $field = $(this);
                                var name = $field.attr('name');
                                
                                if (name) {
                                    if ($field.is(':checkbox')) {
                                        formData[name] = $field.is(':checked') ? '1' : '0';
                                    } else if ($field.is('select[multiple]')) {
                                        formData[name] = $field.val() ? $field.val().join(',') : '';
                                    } else {
                                        formData[name] = $field.val() || '';
                                    }
                                }
                            });
                            
                            console.log("Saving data:", formData);
                            
                            ajaxCall("/api/deepinspector/settings/set", formData,
                                function(resp) {
                                    if (resp.result === 'saved') {
                                        isSubsystemDirty();
                                        dlg.close();
                                        BootstrapDialog.show({
                                            type: BootstrapDialog.TYPE_SUCCESS,
                                            title: "{{ lang._('Success') }}",
                                            message: "{{ lang._('Settings saved successfully') }}",
                                            buttons: [{ label:'OK', action:function(d){d.close(); }}]
                                        });
                                    } else {
                                        var msg = "{{ lang._('Failed to save settings') }}:<br/>";
                                        if (resp.validations) {
                                            for (var f in resp.validations) {
                                                msg += '<strong>'+f+'</strong>: '+resp.validations[f]+'<br/>';
                                            }
                                        }
                                        dlg.getModalBody().find('.alert').remove();
                                        dlg.getModalBody().prepend('<div class="alert alert-danger">'+msg+'</div>');
                                    }
                                }
                            );
                        }
                    },
                    {
                        label: "{{ lang._('Cancel') }}",
                        action: function(dlg){ dlg.close(); }
                    }
                ],
                onshown: function(dlg) {
                    // Carica i dati nel form
                    var formMap = {};
                    formMap[formId] = "/api/deepinspector/settings/get";
                    
                    mapDataToFormUI(formMap).done(function() {
                        // Inizializza i componenti UI
                        dlg.getModalBody().find('select.selectpicker').selectpicker('refresh');
                        formatTokenizersUI(dlg.getModalBody());
                    }).fail(function(error) {
                        console.error("Failed to load form data:", error);
                    });
                }
            });
        });
    }

    // Bind di tutti i bottoni Edit con i form ID corretti
    bindDialog('#btnEditGeneral',   'DialogGeneral',   '{{ lang._("Edit General Settings") }}', 'frm_DeepInspectorGeneral');
    bindDialog('#btnEditProtocols', 'DialogProtocols', '{{ lang._("Edit Protocol Inspection") }}', 'frm_DeepInspectorProtocols');
    bindDialog('#btnEditDetection', 'DialogDetection', '{{ lang._("Edit Detection Engines") }}', 'frm_DeepInspectorDetection');
    bindDialog('#btnEditAdvanced',  'DialogAdvanced',  '{{ lang._("Edit Advanced Settings") }}', 'frm_DeepInspectorAdvanced');

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

    isSubsystemDirty();
});
</script>

{# Include di tutti i dialog templates #}
{{ partial("layout_partials/base_dialog", {
    'fields': formGeneral,
    'id':     'DialogGeneral',
    'label':  lang._('General Settings')
}) }}

{{ partial("layout_partials/base_dialog", {
    'fields': formProtocols,
    'id':     'DialogProtocols',
    'label':  lang._('Protocol Inspection')
}) }}

{{ partial("layout_partials/base_dialog", {
    'fields': formDetection,
    'id':     'DialogDetection',
    'label':  lang._('Detection Engines')
}) }}

{{ partial("layout_partials/base_dialog", {
    'fields': formAdvanced,
    'id':     'DialogAdvanced',
    'label':  lang._('Advanced Settings')
}) }}