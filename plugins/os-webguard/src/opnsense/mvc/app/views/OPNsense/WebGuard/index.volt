{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<script>
   $( document ).ready(function() {
      /**
       * get the isSubsystemDirty value and print a notice
       */
      function isSubsystemDirty() {
         ajaxGet("/api/webguard/settings/dirty", {}, function(data,status) {
            if (status == "success") {
               if (data.webguard.dirty === true) {
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
       * apply changes and reload webguard
       */
      $('#btnApplyConfig').SimpleActionButton({onAction: function(data, status){
          isSubsystemDirty();
      }});

      /**
       * general settings
       */
      mapDataToFormUI({'frm_GeneralSettings':"/api/webguard/settings/getGeneral/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
         isSubsystemDirty();
         updateServiceControlUI('webguard');
      });

      $('#btnSaveGeneral').unbind('click').click(function(){
         $("#btnSaveGeneralProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_GeneralSettings';
         saveFormToEndpoint("/api/webguard/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
            updateServiceControlUI('webguard');
         }, true);
         $("#btnSaveGeneralProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveGeneral").blur();
      });

      /**
       * waf settings
       */
      mapDataToFormUI({'frm_WafSettings':"/api/webguard/settings/getWaf/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveWaf').unbind('click').click(function(){
         $("#btnSaveWafProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_WafSettings';
         saveFormToEndpoint("/api/webguard/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveWafProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveWaf").blur();
      });

      /**
       * behavioral settings
       */
      mapDataToFormUI({'frm_BehavioralSettings':"/api/webguard/settings/getBehavioral/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveBehavioral').unbind('click').click(function(){
         $("#btnSaveBehavioralProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_BehavioralSettings';
         saveFormToEndpoint("/api/webguard/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveBehavioralProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveBehavioral").blur();
      });

      /**
       * covert channels settings
       */
      mapDataToFormUI({'frm_CovertChannelsSettings':"/api/webguard/settings/getCovertChannels/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveCovertChannels').unbind('click').click(function(){
         $("#btnSaveCovertChannelsProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_CovertChannelsSettings';
         saveFormToEndpoint("/api/webguard/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveCovertChannelsProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveCovertChannels").blur();
      });

      /**
       * response settings
       */
      mapDataToFormUI({'frm_ResponseSettings':"/api/webguard/settings/getResponse/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveResponse').unbind('click').click(function(){
         $("#btnSaveResponseProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_ResponseSettings';
         saveFormToEndpoint("/api/webguard/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveResponseProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveResponse").blur();
      });

      /**
       * whitelist settings
       */
      mapDataToFormUI({'frm_WhitelistSettings':"/api/webguard/settings/getWhitelist/"}).done(function(){
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
      });

      $('#btnSaveWhitelist').unbind('click').click(function(){
         $("#btnSaveWhitelistProgress").addClass("fa fa-spinner fa-pulse");
         var frm_id = 'frm_WhitelistSettings';
         saveFormToEndpoint("/api/webguard/settings/set/", frm_id, function(){
            // Don't call isSubsystemDirty() here since we auto-apply
         }, true);
         $("#btnSaveWhitelistProgress").removeClass("fa fa-spinner fa-pulse");
         $("#btnSaveWhitelist").blur();
      });

   });
</script>

<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
   <button class="btn btn-primary pull-right" id="btnApplyConfig"
           data-endpoint='/api/webguard/service/reconfigure'
           data-label="{{ lang._('Apply') }}"
           data-service-widget="webguard"
           data-error-title="{{ lang._('Error reconfiguring WebGuard') }}"
           type="button">
   </button>
   {{ lang._('The WebGuard configuration has been changed') }} <br /> {{ lang._('You must apply the changes in order for them to take effect.')}}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
   <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General Settings') }}</a></li>
   <li><a data-toggle="tab" href="#waf">{{ lang._('WAF Protection') }}</a></li>
   <li><a data-toggle="tab" href="#behavioral">{{ lang._('Behavioral Analysis') }}</a></li>
   <li><a data-toggle="tab" href="#covert_channels">{{ lang._('Covert Channels') }}</a></li>
   <li><a data-toggle="tab" href="#response">{{ lang._('Response Settings') }}</a></li>
   <li><a data-toggle="tab" href="#whitelist">{{ lang._('Whitelist Settings') }}</a></li>
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

   <div id="waf" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formWafSettings,'id':'frm_WafSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveWaf" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveWafProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="behavioral" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formBehavioralSettings,'id':'frm_BehavioralSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveBehavioral" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveBehavioralProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="covert_channels" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formCovertChannelsSettings,'id':'frm_CovertChannelsSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveCovertChannels" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveCovertChannelsProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="response" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formResponseSettings,'id':'frm_ResponseSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveResponse" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveResponseProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>

   <div id="whitelist" class="tab-pane fade in">
      {{ partial("layout_partials/base_form",['fields':formWhitelistSettings,'id':'frm_WhitelistSettings'])}}
      <div class="table-responsive">
         <table class="table table-striped table-condensed table-responsive">
            <tr>
               <td>
                  <button class="btn btn-primary" id="btnSaveWhitelist" type="button">
                     <b>{{ lang._('Save') }}</b> <i id="btnSaveWhitelistProgress"></i>
                  </button>
               </td>
            </tr>
         </table>
      </div>
   </div>
</div>