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
            
            console.log("Form found:", $form.length, "Form ID:", formId);
            console.log("Form fields found:", $form.find('input, select, textarea').length);
            
            // Serializza tutti i campi del form
            $form.find('input, select, textarea').each(function() {
                var $field = $(this);
                var id = $field.attr('id');
                var name = $field.attr('name');
                var fieldValue = $field.val();
                
                console.log("Processing field - ID:", id, "Name:", name, "Type:", $field.prop('type'), "Value:", fieldValue);
                
                // Usa l'ID se il name non è presente o usa il name direttamente
                var fieldName = name || id;
                
                // Skip se né ID né name sono presenti
                if (!fieldName) {
                    console.log("Skipping field - no ID or name");
                    return;
                }
                
                // Se il nome/id inizia con deepinspector., rimuovi il prefisso
                var cleanName = fieldName.indexOf('deepinspector.') === 0 ? 
                    fieldName.substring(13) : fieldName;
                
                console.log("Clean name:", cleanName);
                
                if ($field.is(':checkbox')) {
                    formData.deepinspector[cleanName] = $field.is(':checked') ? '1' : '0';
                } else if ($field.is('select[multiple]') || $field.attr('multiple') === 'multiple' || $field.hasClass('selectpicker')) {
                    // Gestione select multipli (inclusi selectpicker)
                    var selectedValues = $field.val();
                    console.log("Multi-select values:", selectedValues);
                    if (selectedValues && selectedValues.length > 0) {
                        formData.deepinspector[cleanName] = Array.isArray(selectedValues) ? selectedValues.join(',') : selectedValues;
                    } else {
                        formData.deepinspector[cleanName] = '';
                    }
                } else {
                    formData.deepinspector[cleanName] = fieldValue || '';
                }
            });
            
            // Fallback: se non abbiamo trovato campi, prova con la serializzazione standard
            if (Object.keys(formData.deepinspector).length === 0) {
                console.log("No fields found, trying standard serialization");
                var serializedArray = $form.serializeArray();
                console.log("Serialized array:", serializedArray);
                
                $.each(serializedArray, function(i, field) {
                    if (field.name) {
                        var cleanName = field.name.indexOf('deepinspector.') === 0 ? 
                            field.name.substring(13) : field.name;
                        formData.deepinspector[cleanName] = field.value;
                    }
                });
                
                // Se ancora non abbiamo dati, prova a raccogliere manualmente tutti i campi visibili
                if (Object.keys(formData.deepinspector).length === 0) {
                    console.log("Standard serialization failed, trying manual collection");
                    $form.find('input:visible, select:visible, textarea:visible').each(function() {
                        var $field = $(this);
                        var fieldId = $field.attr('id');
                        
                        if (fieldId && fieldId.indexOf('deepinspector.') === 0) {
                            var cleanName = fieldId.substring(13);
                            
                            if ($field.is(':checkbox')) {
                                formData.deepinspector[cleanName] = $field.is(':checked') ? '1' : '0';
                            } else if ($field.is('select')) {
                                var val = $field.val();
                                if (Array.isArray(val)) {
                                    formData.deepinspector[cleanName] = val.join(',');
                                } else {
                                    formData.deepinspector[cleanName] = val || '';
                                }
                            } else {
                                formData.deepinspector[cleanName] = $field.val() || '';
                            }
                        }
                    });
                }
            }
            
            console.log("Final form data:", formData);
            
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
                                
                                // Ricarica i dati nel form dopo l'apply
                                setTimeout(function() {
                                    reloadFormData();
                                }, 500);
                                
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

    // Carica i dati iniziali con gestione errori migliorata
    var initialFormMap = {
        'frm_DeepInspectorGeneral': "/api/deepinspector/settings/get",
        'frm_DeepInspectorProtocols': "/api/deepinspector/settings/get",
        'frm_DeepInspectorDetection': "/api/deepinspector/settings/get",
        'frm_DeepInspectorAdvanced': "/api/deepinspector/settings/get"
    };
    
    // Funzione per ricaricare i dati nei form
    function reloadFormData() {
        console.log("Reloading form data...");
        
        mapDataToFormUI(initialFormMap).done(function(data) {
            console.log("Form data reloaded successfully:", data);
            
            // Forza il refresh di tutti i componenti UI
            $('.selectpicker').selectpicker('refresh');
            formatTokenizersUI();
            
            // Assicura che i multi-select siano correttamente inizializzati
            $('select[multiple]').each(function() {
                $(this).selectpicker('refresh');
            });
            
            // Forza il refresh dei selectpicker dopo un breve delay
            setTimeout(function() {
                $('.selectpicker').selectpicker('refresh');
            }, 100);
            
        }).fail(function(error) {
            console.error("Failed to reload form data:", error);
            
            // Mostra errore all'utente
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_WARNING,
                title: "{{ lang._('Warning') }}",
                message: "{{ lang._('Failed to load configuration data. Please refresh the page.') }}",
                buttons: [{ 
                    label: 'OK', 
                    action: function(d) { d.close(); } 
                }]
            });
        });
    }
    
    // Caricamento iniziale
    reloadFormData();

    // Listener per rilevare cambiamenti nei form e mostrare il banner
    $('.tab-content').on('change', 'input, select, textarea', function() {
        console.log("Form field changed:", $(this).attr('id') || $(this).attr('name'));
        isSubsystemDirty();
    });
    
    // Listener per i tab changes per ricaricare i dati
    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        console.log("Tab changed to:", e.target.getAttribute('href'));
        // Forza il refresh dei selectpicker nel tab attivo
        setTimeout(function() {
            $('.tab-pane.active .selectpicker').selectpicker('refresh');
        }, 100);
    });

    isSubsystemDirty();
});
</script>