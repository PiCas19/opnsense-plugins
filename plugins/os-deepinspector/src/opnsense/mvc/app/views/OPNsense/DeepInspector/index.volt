{#
 # Copyright (C) 2025 OPNsense Project
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
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
            <div class="panel-heading"><h3 class="panel-title">{{ lang._('General Settings') }}</h3></div>
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
            <div class="panel-heading"><h3 class="panel-title">{{ lang._('Protocol Inspection') }}</h3></div>
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
            <div class="panel-heading"><h3 class="panel-title">{{ lang._('Detection Engines') }}</h3></div>
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
            <div class="panel-heading"><h3 class="panel-title">{{ lang._('Advanced Settings') }}</h3></div>
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
    // Mostra banner se config dirty
    function isSubsystemDirty() {
        ajaxGet("/api/deepinspector/settings/dirty", {}, function(data) {
            $("#configChangedMsg").toggleClass("hidden", !(data.deepinspector && data.deepinspector.dirty));
        });
    }

    // Apply global config
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

    // Apri dialog per edit
    function bindDialog(btnId, dialogId) {
        $(btnId).click(function() {
            BootstrapDialog.show({
                title: $(this).text(),
                message: $('#' + dialogId).html(),
                buttons: [
                    {
                        label: "{{ lang._('Save') }}",
                        cssClass: 'btn-primary',
                        action: function(dlg) {
                            var form = dlg.getModalBody().find('form');
                            ajaxCall("/api/deepinspector/settings/set",
                                mapDataToFormObject(form.attr('id')),
                                function(resp) {
                                    if (resp.result === 'saved') {
                                        isSubsystemDirty();
                                        dlg.close();
                                        BootstrapDialog.show({
                                            type: BootstrapDialog.TYPE_SUCCESS,
                                            title: "{{ lang._('Success') }}",
                                            message: "{{ lang._('Settings saved successfully') }}",
                                            buttons:[{label:'OK', action:function(d){d.close();}}]
                                        });
                                    } else {
                                        var msg = "{{ lang._('Failed to save settings') }}:<br/>";
                                        for (var f in resp.validations) {
                                            msg += '<strong>'+f+'</strong>: '+resp.validations[f]+'<br/>';
                                        }
                                        dlg.enableButtons(false);
                                        dlg.setClosable(true);
                                        dlg.getModalBody().prepend('<div class="alert alert-danger">'+msg+'</div>');
                                    }
                                }
                            );
                        }
                    },
                    {
                        label: "{{ lang._('Cancel') }}",
                        action: function(dlg) { dlg.close(); }
                    }
                ]
            });
        });
    }

    bindDialog('#btnEditGeneral',   'DialogGeneral');
    bindDialog('#btnEditProtocols', 'DialogProtocols');
    bindDialog('#btnEditDetection', 'DialogDetection');
    bindDialog('#btnEditAdvanced',  'DialogAdvanced');

    isSubsystemDirty();
});
</script>

{# -- DIALOG PARTIALS -- #}
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
