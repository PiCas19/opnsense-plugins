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

<script>
   $( document ).ready(function() {
      /**
       * get the isSubsystemDirty value and print a notice
       */
      function isSubsystemDirty() {
         ajaxGet("/api/netzones/settings/dirty", {}, function(data,status) {
            if (status == "success") {
               if (data.netzones.dirty === true) {
                  $("#configChangedMsg").removeClass("hidden");
               } else {
                  $("#configChangedMsg").addClass("hidden");
               }
            }
         });
      }

      /**
       * chain std_bootgrid_reload from opnsense_bootgrid_plugin.js
       * to get the isSubsystemDirty state on "UIBootgrid" changes
       */
      var opn_std_bootgrid_reload = std_bootgrid_reload;
      std_bootgrid_reload = function(gridId) {
         opn_std_bootgrid_reload(gridId);
         isSubsystemDirty();
      };

      /**
       * apply changes and reload netzones
       */
      $('#btnApplyConfig').SimpleActionButton({
         onAction: function(data, status) {
            isSubsystemDirty();
            if (status === "success") {
               BootstrapDialog.show({
                  type: BootstrapDialog.TYPE_SUCCESS,
                  title: "{{ lang._('Success') }}",
                  message: "{{ lang._('Configuration applied successfully') }}",
                  buttons: [{
                     label: 'OK',
                     action: function(dialog) {
                        dialog.close();
                     }
                  }]
               });
            }
         }
      });

      /**
       * zone settings
       */
      $("#grid-zones").UIBootgrid({
         'search':'/api/netzones/settings/search_zone/',
         'get':'/api/netzones/settings/get_zone/',
         'set':'/api/netzones/settings/set_zone/',
         'add':'/api/netzones/settings/add_zone/',
         'del':'/api/netzones/settings/del_zone/',
         'toggle':'/api/netzones/settings/toggleZone/'
      });

      /**
       * inter-zone policy settings
       */
      $("#grid-policies").UIBootgrid({
         'search':'/api/netzones/settings/search_policy/',
         'get':'/api/netzones/settings/get_policy/',
         'set':'/api/netzones/settings/set_policy/',
         'add':'/api/netzones/settings/add_policy/',
         'del':'/api/netzones/settings/del_policy/',
         'toggle':'/api/netzones/settings/toggle_policy/'
      });

      // I dropdown source_zone e destination_zone ora si popolano automaticamente 
      // tramite ModelRelationField nel modello XML - non serve JavaScript manuale

      /**
       * Funzione per creare una zona da template predefiniti (con gestione errori migliorata)
       */
      function showCreateZoneFromTemplate() {
         // Prima ottieni i template disponibili
         ajaxGet("/api/netzones/settings/get_zone_templates", {}, function(data, status) {
            if (status === "success" && data.templates) {
               let templateOptions = '<option value="">{{ lang._('Choose a template') }}</option>';
               $.each(data.templates, function(id, template) {
                  templateOptions += '<option value="' + id + '">' + template.name + ' - ' + template.description + '</option>';
               });
               
               // Crea dropdown per le interfacce disponibili
               let interfaceOptions = '';
               if (data.available_interfaces && data.available_interfaces.length > 0) {
                  $.each(data.available_interfaces, function(index, iface) {
                     interfaceOptions += '<option value="' + iface.key + '">' + iface.display + '</option>';
                  });
               } else {
                  interfaceOptions = '<option value="">{{ lang._('No interfaces available') }}</option>';
               }
               
               BootstrapDialog.show({
                  title: "{{ lang._('Create Zone from Template') }}",
                  message: '<form id="createZoneFromTemplateForm">' +
                           '<div class="form-group">' +
                           '<label for="templateSelect">{{ lang._('Select Template') }}</label>' +
                           '<select class="form-control" id="templateSelect" name="template" required>' +
                           templateOptions +
                           '</select>' +
                           '</div>' +
                           '<div id="templateDetails" style="display:none;">' +
                           '<div class="alert alert-info" id="templateDescription"></div>' +
                           '<div class="form-group">' +
                           '<label for="zoneName">{{ lang._('Zone Name') }}</label>' +
                           '<input type="text" class="form-control" id="zoneName" name="name" required maxlength="32" pattern="[a-zA-Z0-9_-]+">' +
                           '<small class="help-block">{{ lang._('1-32 characters, alphanumeric, underscore or dash only') }}</small>' +
                           '</div>' +
                           '<div class="form-group">' +
                           '<label for="zoneDescription">{{ lang._('Description') }}</label>' +
                           '<input type="text" class="form-control" id="zoneDescription" name="description">' +
                           '</div>' +
                           '<div class="form-group">' +
                           '<label for="zoneSubnets">{{ lang._('Subnets') }}</label>' +
                           '<input type="text" class="form-control" id="zoneSubnets" name="subnets" required placeholder="192.168.1.0/24">' +
                           '<small class="help-block">{{ lang._('CIDR format, comma-separated if multiple') }}</small>' +
                           '</div>' +
                           '<div class="form-group">' +
                           '<label for="zoneInterfaces">{{ lang._('Interface') }}</label>' +
                           '<select class="form-control" id="zoneInterfaces" name="interface" required>' +
                           interfaceOptions +
                           '</select>' +
                           '<small class="help-block">{{ lang._('Network interface for this zone') }}</small>' +
                           '</div>' +
                           '</div>' +
                           '</form>',
                  buttons: [{
                     label: "{{ lang._('Create Zone') }}",
                     cssClass: "btn-success",
                     action: function(dialog) {
                        var templateId = $('#templateSelect').val();
                        if (!templateId) {
                           BootstrapDialog.show({
                              type: BootstrapDialog.TYPE_WARNING,
                              title: "{{ lang._('Warning') }}",
                              message: "{{ lang._('Please select a template') }}"
                           });
                           return false;
                        }
                        
                        // Validazione client-side
                        var zoneName = $('#zoneName').val().trim();
                        var zoneSubnets = $('#zoneSubnets').val().trim();
                        var zoneInterface = $('#zoneInterfaces').val();
                        
                        if (!zoneName) {
                           BootstrapDialog.show({
                              type: BootstrapDialog.TYPE_WARNING,
                              title: "{{ lang._('Warning') }}",
                              message: "{{ lang._('Zone name is required') }}"
                           });
                           return false;
                        }
                        
                        if (!zoneName.match(/^[a-zA-Z0-9_-]{1,32}$/)) {
                           BootstrapDialog.show({
                              type: BootstrapDialog.TYPE_WARNING,
                              title: "{{ lang._('Warning') }}",
                              message: "{{ lang._('Zone name must be 1-32 characters, alphanumeric, underscore or dash only') }}"
                           });
                           return false;
                        }
                        
                        if (!zoneSubnets) {
                           BootstrapDialog.show({
                              type: BootstrapDialog.TYPE_WARNING,
                              title: "{{ lang._('Warning') }}",
                              message: "{{ lang._('Subnets are required') }}"
                           });
                           return false;
                        }
                        
                        if (!zoneInterface) {
                           BootstrapDialog.show({
                              type: BootstrapDialog.TYPE_WARNING,
                              title: "{{ lang._('Warning') }}",
                              message: "{{ lang._('Interface is required') }}"
                           });
                           return false;
                        }
                        
                        var formData = {
                           name: zoneName,
                           description: $('#zoneDescription').val().trim(),
                           subnets: zoneSubnets,
                           interface: zoneInterface
                        };
                        
                        // Disabilita il pulsante per evitare doppi click
                        var createButton = $(this);
                        createButton.prop('disabled', true).text('{{ lang._('Creating...') }}');
                        
                        ajaxCall("/api/netzones/settings/create_zone_from_template/" + templateId, formData, function(data, status) {
                           if (status === "success" && data.result === "saved") {
                              dialog.close();
                              BootstrapDialog.show({
                                 type: BootstrapDialog.TYPE_SUCCESS,
                                 title: "{{ lang._('Success') }}",
                                 message: data.message || "{{ lang._('Zone created successfully from template') }}",
                                 buttons: [{
                                    label: 'OK',
                                    action: function(successDialog) {
                                       successDialog.close();
                                       $('#grid-zones').bootgrid('reload');
                                       isSubsystemDirty();
                                    }
                                 }]
                              });
                           } else {
                              // Re-abilita il pulsante in caso di errore
                              createButton.prop('disabled', false).text('{{ lang._('Create Zone') }}');
                              
                              let errorMsg = "{{ lang._('Failed to create zone from template') }}";
                              if (data.validations && data.validations.length > 0) {
                                 errorMsg += ":\n\n" + data.validations.join("\n");
                              } else if (data.message) {
                                 errorMsg += ": " + data.message;
                              }
                              
                              BootstrapDialog.show({
                                 type: BootstrapDialog.TYPE_DANGER,
                                 title: "{{ lang._('Error') }}",
                                 message: errorMsg.replace(/\n/g, '<br>')
                              });
                           }
                        });
                        return false; // Mantieni il dialog aperto per gestire errori
                     }
                  }, {
                     label: "{{ lang._('Cancel') }}",
                     cssClass: "btn-default",
                     action: function(dialog) {
                        dialog.close();
                     }
                  }],
                  onshown: function(dialog) {
                     // Gestisci il cambio di template
                     $('#templateSelect').on('change', function() {
                        var templateId = $(this).val();
                        if (templateId && data.templates[templateId]) {
                           var template = data.templates[templateId];
                           $('#zoneName').val(template.name);
                           $('#zoneDescription').val(template.description);
                           $('#zoneSubnets').val(template.suggested_subnets);
                           
                           // Imposta l'interfaccia suggerita se disponibile
                           if (template.suggested_interface) {
                              $('#zoneInterfaces').val(template.suggested_interface);
                           }
                           
                           $('#templateDescription').html('<strong>Template Details:</strong><br>' + 
                                                          'Default Action: ' + template.default_action + '<br>' + 
                                                          'Priority: ' + template.priority + '<br>' + 
                                                          'Logging: ' + (template.log_traffic ? 'Enabled' : 'Disabled') + '<br>' +
                                                          'Suggested Interface: ' + (template.suggested_interface || 'None'));
                           $('#templateDetails').show();
                        } else {
                           $('#templateDetails').hide();
                        }
                     });
                  }
               });
            } else {
               BootstrapDialog.show({
                  type: BootstrapDialog.TYPE_DANGER,
                  title: "{{ lang._('Error') }}",
                  message: "{{ lang._('Failed to load zone templates') }}"
               });
            }
         });
      }

      // Aggiungi pulsante per creare da template
      $('#btnCreateFromTemplate').on('click', function() {
         showCreateZoneFromTemplate();
      });

      // Inizializzazione della pagina
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
   {{ lang._('The NetZones configuration has been changed') }} <br /> {{ lang._('You must apply the changes in order for them to take effect.')}}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
   <li class="active"><a data-toggle="tab" href="#zones">{{ lang._('Zones') }}</a></li>
   <li><a data-toggle="tab" href="#policies">{{ lang._('Inter-Zone Policies') }}</a></li>
</ul>

<div class="tab-content content-box">
   <div id="zones" class="tab-pane fade in active">
      <div class="row">
         <div class="col-md-12">
            <div class="pull-right" style="margin-bottom: 10px;">
               <button id="btnCreateFromTemplate" type="button" class="btn btn-success">
                  <i class="fa fa-magic"></i> {{ lang._('Create from Template') }}
               </button>
            </div>
            <div class="clearfix"></div>
         </div>
      </div>
      <table id="grid-zones" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogEditZone">
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
         <tbody>
         </tbody>
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
      <table id="grid-policies" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogEditPolicy">
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
         <tbody>
         </tbody>
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

{# include dialogs #}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditZone,'id':'DialogEditZone','label':'Edit Zone'])}}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditPolicy,'id':'DialogEditPolicy','label':'Edit Inter-Zone Policy'])}}