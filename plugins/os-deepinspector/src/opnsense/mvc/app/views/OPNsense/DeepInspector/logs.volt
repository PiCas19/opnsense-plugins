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
    <div id="general" class="tab-pane fade in active">
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnSaveGeneral" type="button" class="btn btn-primary">
                <i class="fa fa-save"></i> {{ lang._('Save Settings') }}
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

    <div id="protocols" class="tab-pane fade in">
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnSaveProtocols" type="button" class="btn btn-primary">
                <i class="fa fa-save"></i> {{ lang._('Save Settings') }}
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

    <div id="detection" class="tab-pane fade in">
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnSaveDetection" type="button" class="btn btn-primary">
                <i class="fa fa-save"></i> {{ lang._('Save Settings') }}
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

    <div id="advanced" class="tab-pane fade in">
        <div class="pull-right" style="margin-bottom: 10px;">
            <button id="btnSaveAdvanced" type="button" class="btn btn-primary">
                <i class="fa fa-save"></i> {{ lang._('Save Settings') }}
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
.panel-body {
   padding: 15px;
}
</style>

<script>
$(document).ready(function() {
    // funzione per mostrare banner di configurazione cambiata
    function isSubsystemDirty() {
        ajaxGet("/api/deepinspector/settings/dirty", {}, function(data) {
            $("#configChangedMsg").toggleClass("hidden", !(data.deepinspector && data.deepinspector.dirty));
        });
    }

    // SimpleActionButton per Apply Config
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

    // helper per salvataggi inline
    function bindSave(btnId, formId) {
        $(btnId).click(function() {
            ajaxCall("/api/deepinspector/settings/set", 
                mapDataToFormObject(formId), 
                function(resp) {
                    if (resp.result === 'saved') {
                        isSubsystemDirty();
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_SUCCESS,
                            title: "{{ lang._('Success') }}",
                            message: "{{ lang._('Settings saved successfully') }}",
                            buttons:[{label:'OK', action:function(d){d.close();}}]
                        });
                    } else {
                        // mostra validazioni
                        let msg = "{{ lang._('Failed to save settings') }}";
                        if (resp.validations) {
                            msg += ":<br>";
                            for (let f in resp.validations) {
                                msg += "<strong>"+f+"</strong>: "+resp.validations[f]+"<br>";
                            }
                        }
                        BootstrapDialog.show({type:BootstrapDialog.TYPE_DANGER,title:"{{ lang._('Error') }}",message:msg});
                    }
                }
            );
        });
    }

    bindSave('#btnSaveGeneral',   '#frm_DeepInspectorGeneral');
    bindSave('#btnSaveProtocols', '#frm_DeepInspectorProtocols');
    bindSave('#btnSaveDetection', '#frm_DeepInspectorDetection');
    bindSave('#btnSaveAdvanced',  '#frm_DeepInspectorAdvanced');

    isSubsystemDirty();
});
</script>
