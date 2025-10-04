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
       * general settings
       */
      mapDataToFormUI({'frm_GeneralSettings':"/api/deepinspector/settings/getGeneral/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
         isSubsystemDirty();
         updateServiceControlUI('deepinspector');
      });

      $('#btnSaveGeneral').unbind('click').click(function(){
         $("#btnSaveGeneralProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_GeneralSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
            updateServiceControlUI('deepinspector');
         }, true);
         $("#btnSaveGeneralProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveGeneral").blur();
      });

      /**
       * protocols settings - FIX: Use correct endpoint
       */
      mapDataToFormUI({'frm_ProtocolsSettings':"/api/deepinspector/settings/getProtocols/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveProtocols').unbind('click').click(function(){
         $("#btnSaveProtocolsProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_ProtocolsSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveProtocolsProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveProtocols").blur();
      });

      /**
       * detection settings - FIX: Use correct endpoint
       */
      mapDataToFormUI({'frm_DetectionSettings':"/api/deepinspector/settings/getDetection/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveDetection').unbind('click').click(function(){
         $("#btnSaveDetectionProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_DetectionSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveDetectionProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveDetection").blur();
      });

      /**
       * advanced settings - FIX: Use correct endpoint
       */
      mapDataToFormUI({'frm_AdvancedSettings':"/api/deepinspector/settings/getAdvanced/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveAdvanced').unbind('click').click(function(){
         $("#btnSaveAdvancedProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_AdvancedSettings';
         saveFormToEndpoint("/api/deepinspector/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
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