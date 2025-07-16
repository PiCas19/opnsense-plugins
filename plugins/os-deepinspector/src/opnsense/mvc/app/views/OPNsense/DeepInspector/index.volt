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
         ajaxGet("/api/deepinspector/settings/dirty", {}, function(data,status) {
            if (status == "success") {
               if (data.deepinspector && data.deepinspector.dirty === true) {
                  $("#configChangedMsg").removeClass("hidden");
               } else {
                  $("#configChangedMsg").addClass("hidden");
               }
            }
         });
      }

      /**
       * apply changes and reload deep inspector
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
       * Standard OPNsense form handling
       */
      const formMap = {
         'frm_DeepInspectorGeneral': "/api/deepinspector/settings/get",
         'frm_DeepInspectorProtocols': "/api/deepinspector/settings/get", 
         'frm_DeepInspectorDetection': "/api/deepinspector/settings/get",
         'frm_DeepInspectorAdvanced': "/api/deepinspector/settings/get"
      };

      // Load form data using standard OPNsense method
      mapDataToFormUI(formMap).done(function(data) {
         console.log("DeepInspector forms loaded successfully", data);
         formatTokenizersUI();
         $('.selectpicker').selectpicker('refresh');
         handleIndustrialModeToggle();
      }).fail(function(error) {
         console.error("Failed to load DeepInspector forms", error);
      });

      // Save button handler
      $('#btnSaveSettings').click(function() {
         // Collect form data
         const formData = {
            deepinspector: {}
         };

         // Get data from all forms
         $('form input, form select, form textarea').each(function() {
            const $field = $(this);
            const name = $field.attr('name');
            
            if (name && name.startsWith('deepinspector.')) {
               let value;
               
               if ($field.is(':checkbox')) {
                  value = $field.is(':checked') ? '1' : '0';
               } else if ($field.is('select[multiple]')) {
                  value = $field.val() ? $field.val().join(',') : '';
               } else {
                  value = $field.val() || '';
               }
               
               formData.deepinspector[name] = value;
            }
         });

         console.log("Saving form data:", formData);

         // Save using standard OPNsense method
         saveFormToEndpoint("/api/deepinspector/settings/set", formData, function(response) {
            console.log("Save response:", response);
            
            if (response.result === "saved") {
               BootstrapDialog.show({
                  type: BootstrapDialog.TYPE_SUCCESS,
                  title: "{{ lang._('Success') }}",
                  message: "{{ lang._('Settings saved successfully') }}",
                  buttons: [{
                     label: 'OK',
                     action: function(dialog) {
                        dialog.close();
                        isSubsystemDirty();
                     }
                  }]
               });
            } else {
               let errorMsg = "{{ lang._('Failed to save settings') }}";
               if (response.validations) {
                  errorMsg += ":\n\n";
                  Object.keys(response.validations).forEach(function(field) {
                     errorMsg += response.validations[field] + "\n";
                  });
               }
               
               BootstrapDialog.show({
                  type: BootstrapDialog.TYPE_DANGER,
                  title: "{{ lang._('Error') }}",
                  message: errorMsg.replace(/\n/g, '<br>')
               });
            }
         });
      });

      // Handle performance profile changes
      $(document).on('change', '[name="deepinspector.general.performance_profile"]', function() {
         const profile = $(this).val();
         handlePerformanceProfileChange(profile);
      });

      // Handle industrial mode toggle
      $(document).on('change', '[name="deepinspector.general.industrial_mode"]', function() {
         const enabled = $(this).is(':checked');
         handleIndustrialModeToggle(enabled);
      });

      // Industrial optimization button
      $('#btnApplyIndustrialOptimization').click(function() {
         const $btn = $(this);
         const originalText = $btn.text();
         
         $btn.prop('disabled', true).text('{{ lang._("Applying...") }}');
         
         ajaxCall("/api/deepinspector/settings/applyIndustrialOptimization", {}, function(data, status) {
            $btn.prop('disabled', false).text(originalText);
            
            if (status === "success" && data.status === 'ok') {
               BootstrapDialog.show({
                  type: BootstrapDialog.TYPE_SUCCESS,
                  title: "{{ lang._('Success') }}",
                  message: "{{ lang._('Industrial optimization applied successfully') }}",
                  buttons: [{
                     label: 'OK',
                     action: function(dialog) {
                        dialog.close();
                        // Reload forms
                        mapDataToFormUI(formMap).done(function(data) {
                           formatTokenizersUI();
                           $('.selectpicker').selectpicker('refresh');
                           handleIndustrialModeToggle();
                        });
                     }
                  }]
               });
            } else {
               BootstrapDialog.show({
                  type: BootstrapDialog.TYPE_DANGER,
                  title: "{{ lang._('Error') }}",
                  message: "{{ lang._('Failed to apply industrial optimization') }}"
               });
            }
         });
      });

      // Zero Trust compliance check
      $('#btnCheckZeroTrust').click(function() {
         const $btn = $(this);
         const originalText = $btn.text();
         
         $btn.prop('disabled', true).text('{{ lang._("Checking...") }}');
         
         ajaxCall("/api/deepinspector/settings/zeroTrustStatus", {}, function(data, status) {
            $btn.prop('disabled', false).text(originalText);
            
            if (status === "success" && data.status === 'ok') {
               showZeroTrustReport(data.data);
            } else {
               BootstrapDialog.show({
                  type: BootstrapDialog.TYPE_DANGER,
                  title: "{{ lang._('Error') }}",
                  message: "{{ lang._('Failed to check Zero Trust compliance') }}"
               });
            }
         });
      });

      // Initialize
      isSubsystemDirty();

      // Auto-refresh industrial metrics
      setInterval(function() {
         loadIndustrialMetrics();
      }, 30000);
   });
   });

   function handlePerformanceProfileChange(profile) {
      const $customFields = $('.custom-profile-field');
      const $industrialFields = $('.industrial-profile-field');
      
      if (profile === 'custom') {
         $customFields.show();
         $industrialFields.hide();
      } else if (profile === 'industrial' || profile === 'high_performance') {
         $customFields.hide();
         $industrialFields.show();
      } else {
         $customFields.hide();
         $industrialFields.hide();
      }
   }

   function handleIndustrialModeToggle(enabled) {
      const $industrialTab = $('a[href="#industrial"]').parent();
      
      if (enabled === undefined) {
         enabled = $('[name="deepinspector.general.industrial_mode"]').is(':checked');
      }
      
      if (enabled) {
         $industrialTab.removeClass('hidden');
      } else {
         $industrialTab.addClass('hidden');
      }
   }

   function loadIndustrialMetrics() {
      ajaxGet("/api/deepinspector/settings/industrialStats", {}, function(data, status) {
         if (status === "success" && data.status === 'ok') {
            const stats = data.data;
            $('#avgLatency').text(stats.avg_latency + ' μs');
            $('#industrialPackets').text(formatNumber(stats.modbus_packets + stats.dnp3_packets + stats.opcua_packets));
            $('#scadaAlerts').text(formatNumber(stats.scada_alerts));
         }
      });
   }

   function showZeroTrustReport(compliance) {
      const scoreColor = compliance.overall_score >= 80 ? 'success' : 
                        compliance.overall_score >= 60 ? 'warning' : 'danger';
      
      let html = '<div class="zero-trust-report">';
      html += '<div class="compliance-score">';
      html += '<h4>{{ lang._("Overall Compliance Score") }}</h4>';
      html += '<div class="score-circle text-' + scoreColor + '">';
      html += '<span class="score-value">' + compliance.overall_score + '%</span>';
      html += '</div></div>';
      
      html += '<div class="compliance-checks">';
      html += '<h5>{{ lang._("Compliance Checks") }}</h5>';
      html += '<ul class="list-group">';
      
      Object.entries(compliance.checks).forEach(([check, passed]) => {
         const icon = passed ? 'check text-success' : 'times text-danger';
         const status = passed ? '{{ lang._("Passed") }}' : '{{ lang._("Failed") }}';
         const checkName = check.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
         
         html += '<li class="list-group-item">';
         html += '<span class="pull-left">' + checkName + '</span>';
         html += '<span class="pull-right"><i class="fa fa-' + icon + '"></i> ' + status + '</span>';
         html += '<div class="clearfix"></div>';
         html += '</li>';
      });
      
      html += '</ul></div>';
      
      if (compliance.recommendations && compliance.recommendations.length > 0) {
         html += '<div class="recommendations">';
         html += '<h5>{{ lang._("Recommendations") }}</h5>';
         html += '<ul class="list-group">';
         
         compliance.recommendations.forEach(rec => {
            html += '<li class="list-group-item">' + rec + '</li>';
         });
         
         html += '</ul></div>';
      }
      
      html += '</div>';
      
      BootstrapDialog.show({
         type: BootstrapDialog.TYPE_INFO,
         title: "{{ lang._('Zero Trust Compliance Report') }}",
         message: html,
         size: BootstrapDialog.SIZE_LARGE,
         buttons: [{
            label: 'OK',
            action: function(dialog) {
               dialog.close();
            }
         }]
      });
   }

   function formatNumber(num) {
      return new Intl.NumberFormat().format(num || 0);
   }
</script>

<div class="alert alert-info hidden" role="alert" id="configChangedMsg">
   <button class="btn btn-primary pull-right" id="btnApplyConfig"
           data-endpoint='/api/deepinspector/service/reconfigure'
           data-label="{{ lang._('Apply') }}"
           data-error-title="{{ lang._('Error reconfiguring Deep Packet Inspector') }}"
           type="button">
   </button>
   {{ lang._('The Deep Packet Inspector configuration has been changed') }} <br /> {{ lang._('You must apply the changes in order for them to take effect.')}}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
   <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
   <li><a data-toggle="tab" href="#protocols">{{ lang._('Protocols') }}</a></li>
   <li><a data-toggle="tab" href="#detection">{{ lang._('Detection') }}</a></li>
   <li><a data-toggle="tab" href="#advanced">{{ lang._('Advanced') }}</a></li>
   <li class="hidden"><a data-toggle="tab" href="#industrial">{{ lang._('Industrial') }}</a></li>
</ul>

<div class="tab-content content-box">
   <div id="general" class="tab-pane fade in active">
      <div class="row">
         <div class="col-md-12">
            <div class="pull-right" style="margin-bottom: 10px;">
               <button id="btnSaveSettings" type="button" class="btn btn-primary">
                  <i class="fa fa-save"></i> {{ lang._('Save Settings') }}
               </button>
            </div>
            <div class="clearfix"></div>
         </div>
      </div>
      
      <div class="panel panel-default">
         <div class="panel-heading">
            <h3 class="panel-title">{{ lang._('General Settings') }}</h3>
         </div>
         <div class="panel-body">
            {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_DeepInspectorGeneral']) }}
         </div>
      </div>
   </div>

   <div id="protocols" class="tab-pane fade in">
      <div class="panel panel-default">
         <div class="panel-heading">
            <h3 class="panel-title">{{ lang._('Protocol Inspection') }}</h3>
         </div>
         <div class="panel-body">
            {{ partial("layout_partials/base_form", ['fields': protocolsForm, 'id': 'frm_DeepInspectorProtocols']) }}
         </div>
      </div>
   </div>

   <div id="detection" class="tab-pane fade in">
      <div class="panel panel-default">
         <div class="panel-heading">
            <h3 class="panel-title">{{ lang._('Detection Engines') }}</h3>
         </div>
         <div class="panel-body">
            {{ partial("layout_partials/base_form", ['fields': detectionForm, 'id': 'frm_DeepInspectorDetection']) }}
         </div>
      </div>
   </div>

   <div id="advanced" class="tab-pane fade in">
      <div class="panel panel-default">
         <div class="panel-heading">
            <h3 class="panel-title">{{ lang._('Advanced Settings') }}</h3>
         </div>
         <div class="panel-body">
            {{ partial("layout_partials/base_form", ['fields': advancedForm, 'id': 'frm_DeepInspectorAdvanced']) }}
         </div>
      </div>
   </div>

   <div id="industrial" class="tab-pane fade in">
      <div class="panel panel-default">
         <div class="panel-heading">
            <h3 class="panel-title">{{ lang._('Industrial Environment Settings') }}</h3>
         </div>
         <div class="panel-body">
            <div class="alert alert-info">
               <i class="fa fa-info-circle"></i>
               {{ lang._('These settings optimize the Deep Packet Inspector for industrial environments (SCADA, PLC, OT networks) with low latency requirements.') }}
            </div>
            
            <div class="row">
               <div class="col-md-4">
                  <div class="panel panel-default">
                     <div class="panel-body text-center">
                        <i class="fa fa-tachometer-alt fa-2x text-primary"></i>
                        <h4 id="avgLatency">-- μs</h4>
                        <p class="text-muted">{{ lang._('Average Latency') }}</p>
                     </div>
                  </div>
               </div>
               <div class="col-md-4">
                  <div class="panel panel-default">
                     <div class="panel-body text-center">
                        <i class="fa fa-industry fa-2x text-primary"></i>
                        <h4 id="industrialPackets">--</h4>
                        <p class="text-muted">{{ lang._('Industrial Packets') }}</p>
                     </div>
                  </div>
               </div>
               <div class="col-md-4">
                  <div class="panel panel-default">
                     <div class="panel-body text-center">
                        <i class="fa fa-exclamation-triangle fa-2x text-warning"></i>
                        <h4 id="scadaAlerts">--</h4>
                        <p class="text-muted">{{ lang._('SCADA Alerts') }}</p>
                     </div>
                  </div>
               </div>
            </div>

            <div class="row">
               <div class="col-md-6">
                  <button class="btn btn-success btn-block" id="btnApplyIndustrialOptimization">
                     <i class="fa fa-magic"></i> {{ lang._('Apply Industrial Optimization') }}
                  </button>
               </div>
               <div class="col-md-6">
                  <button class="btn btn-info btn-block" id="btnCheckZeroTrust">
                     <i class="fa fa-shield-alt"></i> {{ lang._('Check Zero Trust Compliance') }}
                  </button>
               </div>
            </div>
         </div>
      </div>
   </div>
</div>

<style>
.zero-trust-report {
   text-align: center;
}

.compliance-score {
   margin-bottom: 30px;
}

.score-circle {
   width: 120px;
   height: 120px;
   border-radius: 50%;
   border: 6px solid #e5e7eb;
   display: flex;
   align-items: center;
   justify-content: center;
   margin: 20px auto;
   font-size: 24px;
   font-weight: bold;
}

.score-value {
   font-size: 2rem;
   font-weight: bold;
}

.compliance-checks {
   text-align: left;
   margin-bottom: 20px;
}

.recommendations {
   text-align: left;
}

.panel-body {
   padding: 15px;
}
</style>