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

<div id="nz-notifications" style="position:fixed;bottom:24px;right:24px;z-index:9999;min-width:280px;max-width:380px;pointer-events:none;"></div>

<script>
function nzNotify(message, type) {
    var isSuccess = (type === 'success');
    var cls  = isSuccess ? 'alert-success' : (type === 'warning' ? 'alert-warning' : 'alert-danger');
    var icon = isSuccess ? 'fa-check' : (type === 'warning' ? 'fa-exclamation-triangle' : 'fa-exclamation-circle');
    var $n = $('<div role="alert" style="pointer-events:all;margin-top:.4rem;border-radius:3px;box-shadow:0 2px 10px rgba(0,0,0,.28);">' +
               '<div class="alert ' + cls + ' alert-dismissible" style="margin:0;padding:.6rem .9rem;">' +
               '<button type="button" class="close" data-dismiss="alert" style="top:0;right:4px;"><span>&times;</span></button>' +
               '<i class="fa ' + icon + '" style="margin-right:.45rem;"></i>' + message + '</div></div>');
    $('#nz-notifications').append($n);
    setTimeout(function() { $n.find('.alert').alert('close'); $n.remove(); }, 4000);
}

$(document).ready(function() {
    function isSubsystemDirty() {
        ajaxGet("/api/netzones/settings/dirty", {}, function(data, status) {
            if (status === "success") {
                if (data.netzones && data.netzones.dirty === true) {
                    $("#configChangedMsg").removeClass("hidden");
                } else {
                    $("#configChangedMsg").addClass("hidden");
                }
            }
        });
    }

    var opn_std_bootgrid_reload = std_bootgrid_reload;
    std_bootgrid_reload = function(gridId) {
        opn_std_bootgrid_reload(gridId);
        isSubsystemDirty();
    };

    $('#btnApplyConfig').SimpleActionButton({
        onAction: function(data, status) {
            isSubsystemDirty();
            if (status === "success") {
                nzNotify('{{ lang._("Configuration applied successfully") }}', 'success');
            } else {
                nzNotify('{{ lang._("Failed to apply configuration") }}', 'error');
            }
        }
    });

    $("#grid-zones").UIBootgrid({
        'search':  '/api/netzones/settings/search_zone/',
        'get':     '/api/netzones/settings/get_zone/',
        'set':     '/api/netzones/settings/set_zone/',
        'add':     '/api/netzones/settings/add_zone/',
        'del':     '/api/netzones/settings/del_zone/',
        'toggle':  '/api/netzones/settings/toggleZone/'
    });

    $("#grid-policies").UIBootgrid({
        'search':  '/api/netzones/settings/search_policy/',
        'get':     '/api/netzones/settings/get_policy/',
        'set':     '/api/netzones/settings/set_policy/',
        'add':     '/api/netzones/settings/add_policy/',
        'del':     '/api/netzones/settings/del_policy/',
        'toggle':  '/api/netzones/settings/toggle_policy/'
    });

    function showCreateZoneFromTemplate() {
        ajaxGet("/api/netzones/settings/get_zone_templates", {}, function(data, status) {
            if (status !== "success" || !data.templates) {
                nzNotify('{{ lang._("Failed to load zone templates") }}', 'error');
                return;
            }

            var templateOptions = '<option value="">{{ lang._("Choose a template") }}</option>';
            $.each(data.templates, function(id, template) {
                templateOptions += '<option value="' + id + '">' + template.name + ' — ' + template.description + '</option>';
            });

            var interfaceOptions = '';
            if (data.available_interfaces && data.available_interfaces.length > 0) {
                $.each(data.available_interfaces, function(i, iface) {
                    interfaceOptions += '<option value="' + iface.key + '">' + iface.display + '</option>';
                });
            } else {
                interfaceOptions = '<option value="">{{ lang._("No interfaces available") }}</option>';
            }

            BootstrapDialog.show({
                title: "{{ lang._('Create Zone from Template') }}",
                message: '<form id="createZoneFromTemplateForm">' +
                    '<div class="form-group">' +
                    '<label>{{ lang._("Select Template") }}</label>' +
                    '<select class="form-control" id="templateSelect" required>' + templateOptions + '</select>' +
                    '</div>' +
                    '<div id="templateDetails" style="display:none;">' +
                    '<div class="alert alert-info" id="templateDescription"></div>' +
                    '<div class="form-group">' +
                    '<label>{{ lang._("Zone Name") }}</label>' +
                    '<input type="text" class="form-control" id="zoneName" required maxlength="32" pattern="[a-zA-Z0-9_-]+">' +
                    '<small class="help-block">{{ lang._("1-32 chars, alphanumeric, underscore or dash") }}</small>' +
                    '</div>' +
                    '<div class="form-group">' +
                    '<label>{{ lang._("Description") }}</label>' +
                    '<input type="text" class="form-control" id="zoneDescription">' +
                    '</div>' +
                    '<div class="form-group">' +
                    '<label>{{ lang._("Subnets") }}</label>' +
                    '<input type="text" class="form-control" id="zoneSubnets" required placeholder="192.168.1.0/24">' +
                    '<small class="help-block">{{ lang._("CIDR format, comma-separated if multiple") }}</small>' +
                    '</div>' +
                    '<div class="form-group">' +
                    '<label>{{ lang._("Interface") }}</label>' +
                    '<select class="form-control" id="zoneInterfaces" required>' + interfaceOptions + '</select>' +
                    '</div>' +
                    '</div>' +
                    '</form>',
                buttons: [{
                    label: "{{ lang._('Create Zone') }}",
                    cssClass: "btn-success",
                    action: function(dialog) {
                        var templateId   = $('#templateSelect').val();
                        var zoneName     = $('#zoneName').val().trim();
                        var zoneSubnets  = $('#zoneSubnets').val().trim();
                        var zoneIface    = $('#zoneInterfaces').val();

                        if (!templateId) {
                            nzNotify('{{ lang._("Please select a template") }}', 'warning');
                            return false;
                        }
                        if (!zoneName || !zoneName.match(/^[a-zA-Z0-9_-]{1,32}$/)) {
                            nzNotify('{{ lang._("Zone name must be 1-32 alphanumeric/underscore/dash characters") }}', 'warning');
                            return false;
                        }
                        if (!zoneSubnets) {
                            nzNotify('{{ lang._("Subnets are required") }}', 'warning');
                            return false;
                        }
                        if (!zoneIface) {
                            nzNotify('{{ lang._("Interface is required") }}', 'warning');
                            return false;
                        }

                        var $btn = dialog.getButton('{{ lang._("Create Zone") }}');
                        if ($btn) { $btn.disable(); $btn.setText('{{ lang._("Creating...") }}'); }

                        ajaxCall("/api/netzones/settings/create_zone_from_template/" + templateId, {
                            name: zoneName,
                            description: $('#zoneDescription').val().trim(),
                            subnets: zoneSubnets,
                            interface: zoneIface
                        }, function(res, st) {
                            if (st === "success" && res.result === "saved") {
                                dialog.close();
                                nzNotify(res.message || '{{ lang._("Zone created successfully from template") }}', 'success');
                                $('#grid-zones').bootgrid('reload');
                                isSubsystemDirty();
                            } else {
                                if ($btn) { $btn.enable(); $btn.setText('{{ lang._("Create Zone") }}'); }
                                var msg = '{{ lang._("Failed to create zone from template") }}';
                                if (res.validations && res.validations.length > 0) {
                                    msg += ': ' + res.validations.join(', ');
                                } else if (res.message) {
                                    msg += ': ' + res.message;
                                }
                                nzNotify(msg, 'error');
                            }
                        });
                        return false;
                    }
                }, {
                    label: "{{ lang._('Cancel') }}",
                    cssClass: "btn-default",
                    action: function(dialog) { dialog.close(); }
                }],
                onshown: function(dialog) {
                    $('#templateSelect').on('change', function() {
                        var tid = $(this).val();
                        if (tid && data.templates[tid]) {
                            var t = data.templates[tid];
                            $('#zoneName').val(t.name);
                            $('#zoneDescription').val(t.description);
                            $('#zoneSubnets').val(t.suggested_subnets);
                            if (t.suggested_interface) {
                                $('#zoneInterfaces').val(t.suggested_interface);
                            }
                            $('#templateDescription').html(
                                '<strong>{{ lang._("Template Details") }}:</strong><br>' +
                                '{{ lang._("Default Action") }}: ' + t.default_action + '<br>' +
                                '{{ lang._("Priority") }}: ' + t.priority + '<br>' +
                                '{{ lang._("Logging") }}: ' + (t.log_traffic ? '{{ lang._("Enabled") }}' : '{{ lang._("Disabled") }}') +
                                (t.suggested_interface ? '<br>{{ lang._("Suggested Interface") }}: ' + t.suggested_interface : '')
                            );
                            $('#templateDetails').show();
                        } else {
                            $('#templateDetails').hide();
                        }
                    });
                }
            });
        });
    }

    $('#btnCreateFromTemplate').on('click', function() {
        showCreateZoneFromTemplate();
    });

    isSubsystemDirty();
});
</script>

<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
    <button class="btn btn-primary pull-right" id="btnApplyConfig"
            data-endpoint='/api/netzones/service/reconfigure'
            data-label="{{ lang._('Apply') }}"
            data-error-title="{{ lang._('Error reconfiguring NetZones') }}"
            type="button">
    </button>
    {{ lang._('The NetZones configuration has been changed') }} <br />
    {{ lang._('You must apply the changes in order for them to take effect.') }}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#zones">{{ lang._('Zones') }}</a></li>
    <li><a data-toggle="tab" href="#policies">{{ lang._('Inter-Zone Policies') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="zones" class="tab-pane fade in active">
        <div class="row" style="margin-bottom:.75rem;">
            <div class="col-md-12">
                <div class="pull-right">
                    <button id="btnCreateFromTemplate" type="button" class="btn btn-success btn-sm">
                        <i class="fa fa-magic"></i> {{ lang._('Create from Template') }}
                    </button>
                </div>
                <div class="clearfix"></div>
            </div>
        </div>
        <table id="grid-zones"
               class="table table-condensed table-hover table-striped table-responsive"
               data-editDialog="DialogEditZone">
            <thead>
                <tr>
                    <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="default_action" data-width="8em" data-type="string">{{ lang._('Default Action') }}</th>
                    <th data-column-id="priority" data-width="6em" data-type="string">{{ lang._('Priority') }}</th>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Edit') }} | {{ lang._('Delete') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-plus fa-fw"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o fa-fw"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
    </div>

    <div id="policies" class="tab-pane fade in">
        <table id="grid-policies"
               class="table table-condensed table-hover table-striped table-responsive"
               data-editDialog="DialogEditPolicy">
            <thead>
                <tr>
                    <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="source_zone" data-width="8em" data-type="string">{{ lang._('Source Zone') }}</th>
                    <th data-column-id="destination_zone" data-width="8em" data-type="string">{{ lang._('Destination Zone') }}</th>
                    <th data-column-id="action" data-width="6em" data-type="string">{{ lang._('Action') }}</th>
                    <th data-column-id="priority" data-width="6em" data-type="string">{{ lang._('Priority') }}</th>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Edit') }} | {{ lang._('Delete') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-plus fa-fw"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o fa-fw"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
    </div>
</div>

{{ partial("layout_partials/base_dialog",['fields':formDialogEditZone,'id':'DialogEditZone','label':'Edit Zone'])}}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditPolicy,'id':'DialogEditPolicy','label':'Edit Inter-Zone Policy'])}}
