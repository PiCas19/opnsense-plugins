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

<style>
/* NetZones Modern Configuration Page - OPNsense Professional Style */
:root {
  --opnsense-orange: #d94f00;
  --opnsense-orange-light: #ff6600;
  --opnsense-orange-dark: #b8440a;
  --bg-primary: #ffffff;
  --bg-secondary: #f8fafc;
  --bg-tertiary: #f1f5f9;
  --text-primary: #1e293b;
  --text-secondary: #64748b;
  --border-color: #e2e8f0;
  --success-color: #10b981;
  --danger-color: #ef4444;
  --warning-color: #f59e0b;
  --info-color: #3b82f6;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
}

/* Modern Tabs */
.modern-nav-tabs {
  border: none;
  background: var(--bg-primary);
  border-radius: var(--radius-lg) var(--radius-lg) 0 0;
  box-shadow: var(--shadow-md);
  margin-bottom: 0;
  overflow: hidden;
}

.modern-nav-tabs .nav-item {
  margin-bottom: 0;
}

.modern-nav-tabs .nav-link {
  border: none;
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  padding: 1rem 2rem;
  font-weight: 600;
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  transition: all 0.3s ease;
  position: relative;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.modern-nav-tabs .nav-link:hover {
  background: var(--bg-secondary);
  color: var(--text-primary);
  transform: translateY(-1px);
}

.modern-nav-tabs .nav-link.active {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  color: white;
  box-shadow: var(--shadow-md);
}

.modern-nav-tabs .nav-link.active::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--opnsense-orange-dark);
}

/* Modern Content Box */
.modern-tab-content {
  background: var(--bg-primary);
  border: 2px solid var(--border-color);
  border-radius: 0 0 var(--radius-lg) var(--radius-lg);
  box-shadow: var(--shadow-lg);
  overflow: hidden;
}

.modern-tab-pane {
  padding: 2rem;
}

/* Action Bar */
.action-bar {
  background: var(--bg-tertiary);
  padding: 1.25rem 2rem;
  border-bottom: 2px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.action-bar-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.action-bar-title i {
  color: var(--opnsense-orange);
  font-size: 20px;
}

.action-bar-buttons {
  display: flex;
  gap: 0.75rem;
}

/* Modern Buttons */
.modern-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  border: 2px solid transparent;
  border-radius: var(--radius-md);
  font-weight: 600;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  transition: all 0.3s ease;
  cursor: pointer;
  text-decoration: none;
}

.modern-btn:hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.modern-btn-primary {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  color: white;
  border-color: var(--opnsense-orange);
}

.modern-btn-primary:hover {
  background: linear-gradient(135deg, var(--opnsense-orange-light) 0%, #ff7722 100%);
  color: white;
}

.modern-btn-success {
  background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
  color: white;
  border-color: var(--success-color);
}

.modern-btn-success:hover {
  background: linear-gradient(135deg, #059669 0%, #047857 100%);
  color: white;
}

.modern-btn-secondary {
  background: var(--bg-primary);
  color: var(--text-secondary);
  border-color: var(--border-color);
}

.modern-btn-secondary:hover {
  background: var(--bg-secondary);
  color: var(--text-primary);
  border-color: var(--opnsense-orange);
}

/* Modern Tables */
.modern-table-container {
  background: var(--bg-primary);
  border-radius: var(--radius-md);
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}

.modern-table {
  width: 100%;
  border-collapse: collapse;
  margin: 0;
}

.modern-table th {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 1rem 1.5rem;
  border-bottom: 2px solid var(--border-color);
  text-align: left;
}

.modern-table td {
  padding: 1rem 1.5rem;
  border-bottom: 1px solid var(--border-color);
  vertical-align: middle;
}

.modern-table tbody tr {
  transition: all 0.2s ease;
}

.modern-table tbody tr:hover {
  background: var(--bg-secondary);
}

.modern-table tbody tr:last-child td {
  border-bottom: none;
}

/* Status Badges */
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.status-badge.enabled {
  background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
  color: white;
}

.status-badge.disabled {
  background: var(--text-secondary);
  color: white;
}

.priority-badge {
  background: var(--info-color);
  color: white;
  padding: 0.25rem 0.75rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
}

.action-badge {
  padding: 0.25rem 0.75rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.action-badge.pass {
  background: var(--success-color);
  color: white;
}

.action-badge.block {
  background: var(--danger-color);
  color: white;
}

.action-badge.reject {
  background: var(--warning-color);
  color: white;
}

/* Action Buttons */
.table-actions {
  display: flex;
  gap: 0.5rem;
}

.action-btn {
  padding: 0.5rem;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  background: var(--bg-primary);
  color: var(--text-secondary);
  transition: all 0.2s ease;
  cursor: pointer;
  font-size: 12px;
}

.action-btn:hover {
  border-color: var(--opnsense-orange);
  color: var(--opnsense-orange);
  background: var(--bg-secondary);
}

.action-btn.edit:hover {
  border-color: var(--info-color);
  color: var(--info-color);
}

.action-btn.delete:hover {
  border-color: var(--danger-color);
  color: var(--danger-color);
}

/* Table Footer */
.table-footer {
  background: var(--bg-tertiary);
  padding: 1rem 1.5rem;
  border-top: 2px solid var(--border-color);
  display: flex;
  gap: 0.75rem;
}

/* Responsive Design */
@media (max-width: 768px) {
  .modern-nav-tabs .nav-link {
    padding: 0.75rem 1rem;
    font-size: 12px;
  }
  
  .modern-tab-pane {
    padding: 1rem;
  }
  
  .action-bar {
    flex-direction: column;
    gap: 1rem;
    text-align: center;
  }
  
  .action-bar-buttons {
    flex-wrap: wrap;
    justify-content: center;
  }
  
  .modern-table th,
  .modern-table td {
    padding: 0.75rem;
    font-size: 12px;
  }
}
</style>

<ul class="nav nav-tabs modern-nav-tabs" role="tablist" id="maintabs">
   <li class="nav-item">
      <a class="nav-link active" data-toggle="tab" href="#zones">
         <i class="fa fa-layer-group"></i>
         {{ lang._('Network Zones') }}
      </a>
   </li>
   <li class="nav-item">
      <a class="nav-link" data-toggle="tab" href="#policies">
         <i class="fa fa-exchange-alt"></i>
         {{ lang._('Inter-Zone Policies') }}
      </a>
   </li>
</ul>

<div class="tab-content modern-tab-content">
   <div id="zones" class="tab-pane fade in active">
      <div class="action-bar">
         <h3 class="action-bar-title">
            <i class="fa fa-layer-group"></i>
            {{ lang._('Network Zone Configuration') }}
         </h3>
         <div class="action-bar-buttons">
            <button id="btnCreateFromTemplate" type="button" class="modern-btn modern-btn-success">
               <i class="fa fa-magic"></i>
               {{ lang._('Create from Template') }}
            </button>
         </div>
      </div>
      
      <div class="modern-tab-pane">
         <div class="modern-table-container">
            <table id="grid-zones" class="modern-table table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogEditZone">
               <thead>
                  <tr>
                      <th data-column-id="enabled" data-width="8em" data-type="string" data-formatter="rowtoggle">{{ lang._('Status') }}</th>
                      <th data-column-id="name" data-type="string">{{ lang._('Zone Name') }}</th>
                      <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                      <th data-column-id="default_action" data-width="10em" data-type="string">{{ lang._('Default Action') }}</th>
                      <th data-column-id="priority" data-width="8em" data-type="string">{{ lang._('Priority') }}</th>
                      <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                      <th data-column-id="commands" data-width="10em" data-formatter="commands" data-sortable="false">{{ lang._('Actions') }}</th>
                  </tr>
               </thead>
               <tbody>
               </tbody>
            </table>
            <div class="table-footer">
               <button data-action="add" type="button" class="modern-btn modern-btn-primary">
                  <i class="fa fa-plus"></i>
                  {{ lang._('Add Zone') }}
               </button>
               <button data-action="deleteSelected" type="button" class="modern-btn modern-btn-secondary">
                  <i class="fa fa-trash-o"></i>
                  {{ lang._('Delete Selected') }}
               </button>
            </div>
         </div>
      </div>
   </div>

   <div id="policies" class="tab-pane fade in">
      <div class="action-bar">
         <h3 class="action-bar-title">
            <i class="fa fa-exchange-alt"></i>
            {{ lang._('Inter-Zone Policy Management') }}
         </h3>
         <div class="action-bar-buttons">
            <button type="button" class="modern-btn modern-btn-success" onclick="showPolicyWizard()">
               <i class="fa fa-magic"></i>
               {{ lang._('Policy Wizard') }}
            </button>
         </div>
      </div>
      
      <div class="modern-tab-pane">
         <div class="modern-table-container">
            <table id="grid-policies" class="modern-table table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogEditPolicy">
               <thead>
                  <tr>
                      <th data-column-id="enabled" data-width="8em" data-type="string" data-formatter="rowtoggle">{{ lang._('Status') }}</th>
                      <th data-column-id="name" data-type="string">{{ lang._('Policy Name') }}</th>
                      <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                      <th data-column-id="source_zone" data-width="10em" data-type="string">{{ lang._('Source Zone') }}</th>
                      <th data-column-id="destination_zone" data-width="10em" data-type="string">{{ lang._('Destination Zone') }}</th>
                      <th data-column-id="action" data-width="8em" data-type="string">{{ lang._('Action') }}</th>
                      <th data-column-id="priority" data-width="8em" data-type="string">{{ lang._('Priority') }}</th>
                      <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                      <th data-column-id="commands" data-width="10em" data-formatter="commands" data-sortable="false">{{ lang._('Actions') }}</th>
                  </tr>
               </thead>
               <tbody>
               </tbody>
            </table>
            <div class="table-footer">
               <button data-action="add" type="button" class="modern-btn modern-btn-primary">
                  <i class="fa fa-plus"></i>
                  {{ lang._('Add Policy') }}
               </button>
               <button data-action="deleteSelected" type="button" class="modern-btn modern-btn-secondary">
                  <i class="fa fa-trash-o"></i>
                  {{ lang._('Delete Selected') }}
               </button>
            </div>
         </div>
      </div>
   </div>
</div>

{# include dialogs #}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditZone,'id':'DialogEditZone','label':'Edit Zone'])}}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditPolicy,'id':'DialogEditPolicy','label':'Edit Inter-Zone Policy'])}}