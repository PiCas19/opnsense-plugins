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