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
       * general settings - COPIA ESATTA DI MONIT
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
         // COPIA ESATTA DI MONIT - USA L'ENDPOINT /set/ NON /setGeneral/
         saveFormToEndpoint("/api/deepinspector/settings/set/", frm_id, function(){
            isSubsystemDirty();
            updateServiceControlUI('deepinspector');
         }, true);
         $("#btnSaveGeneralProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveGeneral").blur();
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
</div>