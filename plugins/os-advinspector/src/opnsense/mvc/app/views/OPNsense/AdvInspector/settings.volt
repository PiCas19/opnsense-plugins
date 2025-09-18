<style>
/* OPNsense Settings Modern Styling */
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
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
}

/* Modern Settings Container */
.modern-settings-container {
  background: var(--bg-primary);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
  border: 2px solid var(--border-color);
  overflow: hidden;
  margin: 1.5rem 0;
  min-height: 500px;
}

/* Settings Header */
.settings-header {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  color: white;
  padding: 2rem;
  border-bottom: 3px solid var(--opnsense-orange-dark);
  position: relative;
  overflow: hidden;
}

.settings-header::before {
  content: '';
  position: absolute;
  top: -50%;
  right: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
  transform: rotate(30deg);
  pointer-events: none;
}

.settings-title {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  position: relative;
  z-index: 1;
}

.settings-title i {
  font-size: 28px;
  text-shadow: 0 2px 4px rgba(0,0,0,0.3);
}

.settings-subtitle {
  margin: 0.5rem 0 0 0;
  font-size: 14px;
  opacity: 0.9;
  position: relative;
  z-index: 1;
}

/* Form Content */
.settings-content {
  padding: 2rem;
  background: var(--bg-primary);
}

/* Enhanced Form Groups */
.form-group {
  margin-bottom: 2rem;
  position: relative;
}

.form-group label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 0.75rem;
  display: block;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Modern Form Controls */
.form-control,
.selectpicker,
select {
  appearance: none;
  background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 0.875rem 1rem;
  font-size: 12px;
  color: var(--text-primary);
  transition: all 0.3s ease;
  box-shadow: var(--shadow-sm);
  width: 100%;
}

.form-control:focus,
.selectpicker:focus,
select:focus {
  outline: none;
  border-color: var(--opnsense-orange);
  box-shadow: 0 0 0 3px rgba(217, 79, 0, 0.15), var(--shadow-md);
  transform: translateY(-1px);
}

.form-control:hover,
.selectpicker:hover,
select:hover {
  border-color: var(--opnsense-orange);
  box-shadow: var(--shadow-md);
}

/* Enhanced Checkboxes */
.form-check {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 1rem 0;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  border: 2px solid var(--border-color);
  transition: all 0.3s ease;
}

.form-check:hover {
  border-color: var(--opnsense-orange);
  box-shadow: var(--shadow-md);
}

.form-check-input {
  width: 20px;
  height: 20px;
  margin: 0;
  accent-color: var(--opnsense-orange);
  transform: scale(1.2);
}

.form-check-label {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-primary);
  margin: 0;
}

/* Help Text */
.help-block {
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 0.5rem;
  padding: 0.5rem;
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  border-left: 3px solid var(--opnsense-orange);
}

/* Enhanced Apply Button */
.modern-apply-btn {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  border: 2px solid var(--opnsense-orange);
  border-radius: var(--radius-md);
  color: white;
  padding: 1rem 2rem;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  min-width: 150px;
  position: relative;
  overflow: hidden;
}

.modern-apply-btn:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  background: linear-gradient(135deg, var(--opnsense-orange-light) 0%, #ff7722 100%);
}

.modern-apply-btn:active {
  transform: translateY(0);
}

.modern-apply-btn:disabled {
  opacity: 0.6;
  transform: none;
  cursor: not-allowed;
  background: linear-gradient(135deg, #94a3b8 0%, #64748b 100%);
  border-color: #94a3b8;
}

.modern-apply-btn .spinner-border-sm {
  width: 16px;
  height: 16px;
  border-width: 2px;
}

/* Success Notice */
.success-notice {
  background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
  color: white;
  padding: 1rem 1.5rem;
  border-radius: var(--radius-md);
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  box-shadow: var(--shadow-md);
  border: 2px solid var(--success-color);
}

.success-notice i {
  font-size: 18px;
}

.success-notice-content {
  flex: 1;
}

.success-notice-title {
  font-weight: 600;
  margin: 0 0 0.25rem 0;
  font-size: 14px;
}

.success-notice-text {
  margin: 0;
  font-size: 12px;
  opacity: 0.9;
}

/* Form Section Headers */
.form-section {
  border-bottom: 1px solid var(--border-color);
  margin-bottom: 2rem;
  padding-bottom: 1rem;
}

.form-section-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.form-section-title i {
  color: var(--opnsense-orange);
  font-size: 18px;
}

/* Service Status Badge */
.service-status {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  box-shadow: var(--shadow-sm);
}

.service-status.running {
  background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
  color: white;
}

.service-status.stopped {
  background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
  color: white;
}

.service-status i {
  font-size: 12px;
}

/* Button Actions Container */
.settings-actions {
  background: var(--bg-secondary);
  padding: 1.5rem 2rem;
  border-top: 2px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}

.settings-actions-left {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.settings-actions-right {
  display: flex;
  align-items: center;
  gap: 1rem;
}

/* Responsive Design */
@media (max-width: 768px) {
  .settings-header {
    padding: 1.5rem;
  }
  
  .settings-title {
    font-size: 20px;
  }
  
  .settings-content {
    padding: 1.5rem;
  }
  
  .settings-actions {
    padding: 1rem 1.5rem;
    flex-direction: column;
    gap: 1rem;
  }
  
  .settings-actions-left,
  .settings-actions-right {
    width: 100%;
    justify-content: center;
  }
  
  .modern-apply-btn {
    width: 100%;
  }
}

/* Override default content-box styling */
.content-box.__mb {
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  padding: 0 !important;
  margin: 0 !important;
}
</style>

<div class="modern-settings-container">
  <!-- Settings Header -->
  <div class="settings-header">
    <h2 class="settings-title">
      <i class="fa fa-cogs"></i>
      {{ lang._('Advanced Packet Inspector Settings') }}
    </h2>
    <p class="settings-subtitle">
      {{ lang._('Configure the Advanced Packet Inspector for industrial protocol monitoring and security analysis') }}
    </p>
  </div>

  <!-- Settings Content -->
  <div class="settings-content">
    <div class="content-box __mb">
      {{ partial("layout_partials/base_form", ['fields': settingsForm, 'id': 'frm_AdvInspectorSettings']) }}
    </div>
  </div>

  <!-- Settings Actions -->
  <div class="settings-actions">
    <div class="settings-actions-left">
      <div class="service-status" id="serviceStatus">
        <i class="fa fa-circle"></i>
        <span id="serviceStatusText">{{ lang._('Checking...') }}</span>
      </div>
    </div>
    
    <div class="settings-actions-right">
      <button class="modern-apply-btn d-none" id="saveAct" type="button">
        <span class="spinner-border spinner-border-sm me-2 d-none" id="applySpinner" role="status" aria-hidden="true"></span>
        <i class="fa fa-check" id="applyIcon"></i>
        <span id="applyLabel">{{ lang._('Apply Changes') }}</span>
      </button>
    </div>
  </div>
</div>

<script>
$(document).ready(function () {
  const formId = 'frm_AdvInspectorSettings';
  const getEndpoint = "/api/advinspector/settings/get";
  const setEndpoint = "/api/advinspector/settings/set";
  const reconfigureEndpoint = "/api/advinspector/service/reconfigure";
  const $applyButton = $("#saveAct");
  const $spinner = $("#applySpinner");
  const $icon = $("#applyIcon");
  const $label = $("#applyLabel");

  // Enhanced form loading with better styling
  const data_get_map = {};
  data_get_map[formId] = getEndpoint;
  mapDataToFormUI(data_get_map).done(function () {
    formatTokenizersUI();
    $('.selectpicker').selectpicker('refresh');
    
    // Apply modern styling to form elements
    enhanceFormElements();
    checkServiceStatus();
  });

  function enhanceFormElements() {
    // Add section headers for better organization
    const $form = $(`#${formId}`);
    
    // Group related fields with section headers
    const sections = [
      {
        title: 'General Settings',
        icon: 'fa-sliders',
        fields: ['enabled', 'ips', 'promisc']
      },
      {
        title: 'Network Configuration', 
        icon: 'fa-network-wired',
        fields: ['interfaces', 'homenet']
      },
      {
        title: 'Inspection Mode',
        icon: 'fa-search',
        fields: ['inspection_mode', 'verbosity']
      }
    ];

    sections.forEach(section => {
      const firstField = $form.find(`[name*="${section.fields[0]}"]`).closest('.form-group');
      if (firstField.length) {
        firstField.before(`
          <div class="form-section">
            <h3 class="form-section-title">
              <i class="fa ${section.icon}"></i>
              ${section.title}
            </h3>
          </div>
        `);
      }
    });
  }

  function checkServiceStatus() {
    ajaxGet('/api/advinspector/service/status', {}, function(data) {
      const $status = $('#serviceStatus');
      const $text = $('#serviceStatusText');
      
      if (data && data.status === 'running') {
        $status.removeClass('stopped').addClass('running');
        $text.text('{{ lang._("Service Running") }}');
      } else {
        $status.removeClass('running').addClass('stopped');
        $text.text('{{ lang._("Service Stopped") }}');
      }
    });
  }

  function showSuccessNotice() {
    const $notice = $(`
      <div class="success-notice" id="successNotice" style="display: none;">
        <i class="fa fa-check-circle"></i>
        <div class="success-notice-content">
          <div class="success-notice-title">{{ lang._("Configuration Applied") }}</div>
          <div class="success-notice-text">{{ lang._("The Advanced Packet Inspector configuration has been successfully applied.") }}</div>
        </div>
      </div>
    `);
    
    $('.settings-content').prepend($notice);
    $notice.slideDown(300);
    
    setTimeout(() => {
      $notice.slideUp(300, function() {
        $(this).remove();
      });
    }, 5000);
  }

  // Show apply button when form changes
  $(`#${formId}`).on("input change", "input, select, textarea", function () {
    $applyButton.removeClass("d-none");
  });

  // Enhanced apply button functionality
  $applyButton.click(function () {
    // Start loading state
    $spinner.removeClass("d-none");
    $icon.addClass("d-none");
    $label.text("{{ lang._('Applying Changes...') }}");
    $applyButton.prop("disabled", true);

    saveFormToEndpoint(setEndpoint, formId, function () {
      ajaxCall(reconfigureEndpoint, {}, function (response) {
        // Reset loading state
        $spinner.addClass("d-none");
        $icon.removeClass("d-none");
        $label.text("{{ lang._('Apply Changes') }}");
        $applyButton.prop("disabled", false).addClass("d-none");

        // Show success notice
        showSuccessNotice();
        
        // Update service status
        setTimeout(checkServiceStatus, 1000);
      }).fail(function() {
        // Reset on error
        $spinner.addClass("d-none");
        $icon.removeClass("d-none");
        $label.text("{{ lang._('Apply Changes') }}");
        $applyButton.prop("disabled", false);
      });
    });
  });

  // Initialize service control UI
  updateServiceControlUI('advinspector');
  
  // Refresh service status every 30 seconds
  setInterval(checkServiceStatus, 30000);
});
</script>