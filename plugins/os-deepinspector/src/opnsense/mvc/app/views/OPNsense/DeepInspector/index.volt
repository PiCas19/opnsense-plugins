{#
 # Copyright (C) 2025 OPNsense Project
 # All rights reserved.
 #}
<script>
   $( document ).ready(function() {
      /**
       * get the isSubsystemDirty value and print a notice
       */
      function isSubsystemDirty() {
         ajaxGet("/api/deepinspector/settings/dirty", {}, function(data,status) {
            if (status == "success") {
               if (data.deepinspector.dirty === true) {
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
       * apply changes and reload deepinspector
       */
      $('#btnApplyConfig').SimpleActionButton({onAction: function(data, status){
          isSubsystemDirty();
      }});

      /**
       * Load all settings using single endpoint
       * Fixed: Use individual endpoints per form and proper data extraction
       */
      ajaxGet("/api/deepinspector/settings/get", {}, function(data, status) {
         if (status == "success" && data.deepinspector) {
            console.log("Raw API data:", data);
            
            // Transform complex structure to simple values for UI
            var transformedData = {
               deepinspector: {}
            };
            
            // Process each section
            ['general', 'protocols', 'detection', 'advanced'].forEach(function(section) {
               if (data.deepinspector[section]) {
                  transformedData.deepinspector[section] = {};
                  
                  $.each(data.deepinspector[section], function(key, value) {
                     console.log(value);
                     if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                        // Check if it's an OptionField structure with 'selected'
                        var selectedValues = [];
                        var hasSelected = false;
                        
                        $.each(value, function(optKey, optValue) {
                           if (optValue && optValue.selected == 1) {
                              selectedValues.push(optKey);
                              hasSelected = true;
                           }
                        });
                        
                        if (hasSelected) {
                           // Multi-select or single select
                           transformedData.deepinspector[section][key] = selectedValues.join(',');
                        } else {
                           // Not an option field, keep as is
                           transformedData.deepinspector[section][key] = value;
                        }
                     } else {
                        // Simple value
                        transformedData.deepinspector[section][key] = value;
                     }
                  });
               }
            });
            
            console.log("Transformed data:", transformedData);
            
            // Apply to forms
            setFormData('frm_GeneralSettings', transformedData.deepinspector);
            setFormData('frm_ProtocolsSettings', transformedData.deepinspector);
            setFormData('frm_DetectionSettings', transformedData.deepinspector);
            setFormData('frm_AdvancedSettings', transformedData.deepinspector);
            
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            isSubsystemDirty();
            updateServiceControlUI('deepinspector');
         }
      });

      /**
       * Save general settings
       */
      $('#btnSaveGeneral').unbind('click').click(function(){
         $("#btnSaveGeneralProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_GeneralSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set", frm_id, function(){
            updateServiceControlUI('deepinspector');
            isSubsystemDirty();
         }, true);
         $("#btnSaveGeneralProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveGeneral").blur();
      });

      /**
       * Save protocol settings
       */
      $('#btnSaveProtocols').unbind('click').click(function(){
         $("#btnSaveProtocolsProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_ProtocolsSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set", frm_id, function(){
            isSubsystemDirty();
         }, true);
         $("#btnSaveProtocolsProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveProtocols").blur();
      });

      /**
       * Save detection settings
       */
      $('#btnSaveDetection').unbind('click').click(function(){
         $("#btnSaveDetectionProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_DetectionSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set", frm_id, function(){
            isSubsystemDirty();
         }, true);
         $("#btnSaveDetectionProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveDetection").blur();
      });

      /**
       * Save advanced settings
       */
      $('#btnSaveAdvanced').unbind('click').click(function(){
         $("#btnSaveAdvancedProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_AdvancedSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set", frm_id, function(){
            isSubsystemDirty();
         }, true);
         $("#btnSaveAdvancedProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveAdvanced").blur();
      });

   });
</script>

<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
   <button class="btn btn-primary pull-right" id="btnApplyConfig"
           data-endpoint='/api/deepinspector/service/reconfigure'
           data-label="{{ lang._('Apply') }}"
           data-service-widget="deepinspector"
           data-error-title="{{ lang._('Error reconfiguring Deep Packet Inspector') }}"
           type="button">
   </button>
   {{ lang._('The Deep Packet Inspector configuration has been changed') }} <br /> {{ lang._('You must apply the changes in order for them to take effect.')}}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
   <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General Settings') }}</a></li>
   <li><a data-toggle="tab" href="#protocols">{{ lang._('Protocol Inspection') }}</a></li>
   <li><a data-toggle="tab" href="#detection">{{ lang._('Detection Engines') }}</a></li>
   <li><a data-toggle="tab" href="#advanced">{{ lang._('Advanced Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
   <div id="general" class="tab-pane fade in active">
      {{ partial("layout_partials/base_form",['fields':formGeneralSettings,'id':'frm_GeneralSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveGeneral" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveGeneralProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="protocols" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formProtocolsSettings,'id':'frm_ProtocolsSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveProtocols" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveProtocolsProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="detection" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formDetectionSettings,'id':'frm_DetectionSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveDetection" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveDetectionProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="advanced" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formAdvancedSettings,'id':'frm_AdvancedSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveAdvanced" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveAdvancedProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>
</div>