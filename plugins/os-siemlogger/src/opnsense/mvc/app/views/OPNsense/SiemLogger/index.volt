{#
 # Copyright (C) 2025 OPNsense SIEM Logger Plugin
 # All rights reserved.
 #}

<script>
   $( document ).ready(function() {
      /**
       * get the isSubsystemDirty value and print a notice
       */
      function isSubsystemDirty() {
         ajaxGet("/api/siemlogger/settings/dirty", {}, function(data,status) {
            if (status == "success") {
               if (data.siemlogger.dirty === true) {
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
       * apply changes and reload siemlogger
       */
      $('#btnApplyConfig').SimpleActionButton({onAction: function(data, status){
          isSubsystemDirty();
      }});

      /**
       * general settings
       */
      mapDataToFormUI({'frm_GeneralSettings':"/api/siemlogger/settings/getGeneral/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
         isSubsystemDirty();
         updateServiceControlUI('siemlogger');
      });

      $('#btnSaveGeneral').unbind('click').click(function(){
         $("#btnSaveGeneralProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_GeneralSettings';
         saveFormToEndpoint("/api/siemlogger/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
            updateServiceControlUI('siemlogger');
         }, true);
         $("#btnSaveGeneralProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveGeneral").blur();
      });

      /**
       * siem export settings
       */
      mapDataToFormUI({'frm_SiemExportSettings':"/api/siemlogger/settings/getSiemExport/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveSiemExport').unbind('click').click(function(){
         $("#btnSaveSiemExportProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_SiemExportSettings';
         saveFormToEndpoint("/api/siemlogger/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveSiemExportProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveSiemExport").blur();
      });

      /**
       * logging rules settings
       */
      mapDataToFormUI({'frm_LoggingRulesSettings':"/api/siemlogger/settings/getLoggingRules/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveLoggingRules').unbind('click').click(function(){
         $("#btnSaveLoggingRulesProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_LoggingRulesSettings';
         saveFormToEndpoint("/api/siemlogger/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveLoggingRulesProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveLoggingRules").blur();
      });

      /**
       * audit settings
       */
      mapDataToFormUI({'frm_AuditSettingsSettings':"/api/siemlogger/settings/getAuditSettings/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveAuditSettings').unbind('click').click(function(){
         $("#btnSaveAuditSettingsProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_AuditSettingsSettings';
         saveFormToEndpoint("/api/siemlogger/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveAuditSettingsProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveAuditSettings").blur();
      });

      /**
       * notifications settings
       */
      mapDataToFormUI({'frm_NotificationsSettings':"/api/siemlogger/settings/getNotifications/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveNotifications').unbind('click').click(function(){
         $("#btnSaveNotificationsProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_NotificationsSettings';
         saveFormToEndpoint("/api/siemlogger/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveNotificationsProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveNotifications").blur();
      });

      /**
       * monitoring settings
       */
      mapDataToFormUI({'frm_MonitoringSettings':"/api/siemlogger/settings/getMonitoring/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveMonitoring').unbind('click').click(function(){
         $("#btnSaveMonitoringProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_MonitoringSettings';
         saveFormToEndpoint("/api/siemlogger/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveMonitoringProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveMonitoring").blur();
      });

   });
</script>

<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
   <button class="btn btn-primary pull-right" id="btnApplyConfig"
           data-endpoint='/api/siemlogger/service/reconfigure'
           data-label="{{ lang._('Apply') }}"
           data-service-widget="siemlogger"
           data-error-title="{{ lang._('Error reconfiguring SIEM Logger') }}"
           type="button">
   </button>
   {{ lang._('The SIEM Logger configuration has been changed') }} <br /> {{ lang._('You must apply the changes in order for them to take effect.')}}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
   <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General Settings') }}</a></li>
   <li><a data-toggle="tab" href="#siem_export">{{ lang._('SIEM Export') }}</a></li>
   <li><a data-toggle="tab" href="#logging_rules">{{ lang._('Logging Rules') }}</a></li>
   <li><a data-toggle="tab" href="#audit_settings">{{ lang._('Audit Settings') }}</a></li>
   <li><a data-toggle="tab" href="#notifications">{{ lang._('Notifications') }}</a></li>
   <li><a data-toggle="tab" href="#monitoring">{{ lang._('Monitoring') }}</a></li>
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

   <div id="siem_export" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formSiemExportSettings,'id':'frm_SiemExportSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveSiemExport" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveSiemExportProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="logging_rules" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formLoggingRulesSettings,'id':'frm_LoggingRulesSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveLoggingRules" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveLoggingRulesProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="audit_settings" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formAuditSettingsSettings,'id':'frm_AuditSettingsSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveAuditSettings" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveAuditSettingsProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="notifications" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formNotificationsSettings,'id':'frm_NotificationsSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveNotifications" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveNotificationsProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="monitoring" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formMonitoringSettings,'id':'frm_MonitoringSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveMonitoring" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveMonitoringProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>
</div>