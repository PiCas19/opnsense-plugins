<style>
/* OPNsense Rules Modern Styling */
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
  --warning-color: #f59e0b;
  --danger-color: #ef4444;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
}

/* Modern Rules Container */
.modern-rules-container {
  background: var(--bg-primary);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
  border: 2px solid var(--border-color);
  overflow: hidden;
  margin: 1.5rem 0;
  min-height: 600px;
}

/* Rules Header */
.rules-header {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  color: white;
  padding: 2rem;
  border-bottom: 3px solid var(--opnsense-orange-dark);
  position: relative;
  overflow: hidden;
}

.rules-header::before {
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

.rules-title {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  position: relative;
  z-index: 1;
}

.rules-title i {
  font-size: 28px;
  text-shadow: 0 2px 4px rgba(0,0,0,0.3);
}

.rules-subtitle {
  margin: 0.5rem 0 0 0;
  font-size: 14px;
  opacity: 0.9;
  position: relative;
  z-index: 1;
}

/* Rules Content */
.rules-content {
  padding: 2rem;
  background: var(--bg-primary);
}

/* Modern Table Styling */
.modern-rules-table {
  width: 100%;
  border-collapse: collapse;
  border-radius: var(--radius-lg);
  overflow: hidden;
  box-shadow: var(--shadow-md);
  border: 2px solid var(--border-color);
  background: var(--bg-primary);
  margin-bottom: 1rem;
}

.modern-rules-table thead {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
}

.modern-rules-table thead th {
  padding: 1.25rem 1rem;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 3px solid var(--border-color);
  position: relative;
}

.modern-rules-table thead th::after {
  content: '';
  position: absolute;
  bottom: -3px;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--opnsense-orange);
  transform: scaleX(0);
  transition: transform 0.3s ease;
}

.modern-rules-table thead th:hover::after {
  transform: scaleX(1);
}

.modern-rules-table tbody tr {
  transition: all 0.2s ease;
}

.modern-rules-table tbody tr:hover {
  background: var(--bg-secondary);
  transform: scale(1.001);
}

.modern-rules-table tbody td {
  padding: 1rem;
  font-size: 12px;
  color: var(--text-primary);
  border-bottom: 1px solid var(--border-color);
  vertical-align: middle;
}

/* Modern Action Buttons */
.modern-action-btn {
  background: linear-gradient(135deg, var(--opnsense-orange) 0%, var(--opnsense-orange-light) 100%);
  border: 2px solid var(--opnsense-orange);
  border-radius: var(--radius-md);
  color: white;
  padding: 0.75rem 1.5rem;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-right: 0.5rem;
  margin-bottom: 0.5rem;
}

.modern-action-btn:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  background: linear-gradient(135deg, var(--opnsense-orange-light) 0%, #ff7722 100%);
}

.modern-action-btn:active {
  transform: translateY(0);
}

.modern-action-btn.danger {
  background: linear-gradient(135deg, var(--danger-color) 0%, #dc2626 100%);
  border-color: var(--danger-color);
}

.modern-action-btn.danger:hover {
  background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
}

.modern-action-btn:disabled {
  opacity: 0.5;
  transform: none;
  cursor: not-allowed;
  background: linear-gradient(135deg, #94a3b8 0%, #64748b 100%);
  border-color: #94a3b8;
}

/* Form Error Styling */
.has-error-border {
  border: 2px solid var(--danger-color) !important;
  box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.15) !important;
  background: #fef2f2 !important;
}

.help-block {
  color: var(--danger-color) !important;
  font-size: 11px !important;
  margin-top: 0.5rem !important;
  font-weight: 600 !important;
  padding: 0.5rem;
  background: #fef2f2;
  border-radius: var(--radius-sm);
  border-left: 3px solid var(--danger-color);
}

/* Enhanced Table Actions */
.table-actions {
  background: var(--bg-secondary);
  padding: 1.5rem;
  border-top: 2px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.table-actions-left {
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.table-actions-right {
  display: flex;
  align-items: center;
  gap: 1rem;
}

/* Rule Status Indicators */
.rule-status {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  border: 2px solid;
  font-size: 12px;
  font-weight: 600;
}

.rule-status.enabled {
  background: var(--success-color);
  border-color: var(--success-color);
  color: white;
}

.rule-status.disabled {
  background: #94a3b8;
  border-color: #94a3b8;
  color: white;
}

/* Protocol Tags */
.protocol-tag {
  background: var(--bg-tertiary);
  color: var(--text-primary);
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  border: 1px solid var(--border-color);
}

/* Action Badges */
.action-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
}

.action-badge.allow {
  background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
  color: white;
}

.action-badge.block {
  background: linear-gradient(135deg, var(--danger-color) 0%, #dc2626 100%);
  color: white;
}

.action-badge.alert {
  background: linear-gradient(135deg, var(--warning-color) 0%, #d97706 100%);
  color: white;
}

/* Apply Changes Notice */
.apply-notice {
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  color: white;
  padding: 1rem 1.5rem;
  border-radius: var(--radius-md);
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  box-shadow: var(--shadow-md);
  border: 2px solid #3b82f6;
  cursor: pointer;
  transition: all 0.3s ease;
}

.apply-notice:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.apply-notice-content {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.apply-notice i {
  font-size: 18px;
}

.apply-notice-text {
  font-size: 14px;
  font-weight: 500;
}

.apply-notice-btn {
  background: rgba(255, 255, 255, 0.2);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: var(--radius-sm);
  color: white;
  padding: 0.5rem 1rem;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  transition: all 0.3s ease;
}

.apply-notice-btn:hover {
  background: rgba(255, 255, 255, 0.3);
  border-color: rgba(255, 255, 255, 0.5);
}

/* Responsive Design */
@media (max-width: 768px) {
  .rules-header {
    padding: 1.5rem;
  }
  
  .rules-title {
    font-size: 20px;
  }
  
  .rules-content {
    padding: 1rem;
  }
  
  .table-actions {
    padding: 1rem;
    flex-direction: column;
    align-items: stretch;
  }
  
  .table-actions-left,
  .table-actions-right {
    width: 100%;
    justify-content: center;
  }
  
  .modern-action-btn {
    flex: 1;
    margin-right: 0;
    margin-bottom: 0.5rem;
  }
  
  .modern-rules-table {
    font-size: 11px;
  }
  
  .modern-rules-table th,
  .modern-rules-table td {
    padding: 0.75rem 0.5rem;
  }
}

/* Hide specific columns */
#grid-rules td:nth-child(10),
#grid-rules th:nth-child(10) {
  display: none !important;
}

/* Override default table styling */
.table-condensed {
  border: none !important;
  box-shadow: none !important;
  background: transparent !important;
}

.content-box {
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  padding: 0 !important;
}
</style>

<div class="modern-rules-container">
  <!-- Rules Header -->
  <div class="rules-header">
    <h2 class="rules-title">
      <i class="fa fa-list-alt"></i>
      {{ lang._('Inspection Rules Management') }}
    </h2>
    <p class="rules-subtitle">
      {{ lang._('Create and manage packet inspection rules for industrial protocols and network security') }}
    </p>
  </div>

  <!-- Rules Content -->
  <div class="rules-content">
    <div class="content-box">
      <div class="col-md-12" id="applyWrapper"></div>
      <div class="col-md-12">
        <table id="grid-rules" class="modern-rules-table table-condensed table-hover table-striped table-responsive"
               data-editAlert="changeMessage"
               data-editDialog="dialogRule">
          <thead>
            <tr>
              <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Status') }}</th>
              <th data-column-id="description">{{ lang._('Description') }}</th>
              <th data-column-id="source">{{ lang._('Source') }}</th>
              <th data-column-id="destination">{{ lang._('Destination') }}</th>
              <th data-column-id="port">{{ lang._('Port') }}</th>
              <th data-column-id="protocol">{{ lang._('Protocol') }}</th>
              <th data-column-id="action">{{ lang._('Action') }}</th>
              <th data-column-id="log" data-width="6em" data-formatter="readonlytoggle">{{ lang._('Log') }}</th>
              <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
              <th data-column-id="uuid" data-identifier="true" data-selectable="true">{{ lang._('ID') }}</th>
            </tr>
          </thead>
          <tbody>
            <!-- Dynamic content will be loaded here -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Table Actions -->
  <div class="table-actions">
    <div class="table-actions-left">
      <button data-action="add" type="button" class="modern-action-btn">
        <i class="fa fa-plus"></i>
        {{ lang._('Add Rule') }}
      </button>
      <button data-action="deleteSelected" type="button" class="modern-action-btn danger" disabled>
        <i class="fa fa-trash-o"></i>
        <span class="del-count-label">{{ lang._('Delete Selected') }}</span>
      </button>
    </div>
    <div class="table-actions-right">
      <div class="rules-count">
        <span id="rulesCount">0</span> {{ lang._('rules configured') }}
      </div>
    </div>
  </div>
</div>

{{ partial("layout_partials/base_dialog", {
    'fields': formDialogRuleFields,
    'id': dialogRuleID,
    'label': dialogRuleLabel
}) }}

<script>
$(document).ready(function () {
    // Enhanced grid initialization
    const grid_rules = $("#grid-rules").UIBootgrid({
        search: '/api/advinspector/rules/search_rule',
        get: '/api/advinspector/rules/get_rule/',
        set: '/api/advinspector/rules/set_rule/',
        add: '/api/advinspector/rules/add_rule/',
        del: '/api/advinspector/rules/del_rule/',
        toggle: '/api/advinspector/rules/toggle_rule/',
        options: {
            selection: true,
            multiSelect: true,
            rowSelect: true,
            keepSelection: true,
            formatters: {
                "commands": function (column, row) {
                    return `<div class="btn-group btn-group-sm">
                              <button type="button" class="btn btn-xs btn-outline-primary command-edit bootgrid-tooltip" 
                                      title="{{ lang._("Edit") }}" data-row-id="${row.uuid}">
                                <i class="fa fa-pencil"></i>
                              </button>
                              <button type="button" class="btn btn-xs btn-outline-danger command-delete bootgrid-tooltip" 
                                      title="{{ lang._("Delete") }}" data-row-id="${row.uuid}">
                                <i class="fa fa-trash-o"></i>
                              </button>
                            </div>`;
                },
                "rowtoggle": function (column, row) {
                    const isEnabled = row.enabled === "1" || row.enabled === true;
                    return `<div class="rule-status ${isEnabled ? 'enabled' : 'disabled'}" title="${isEnabled ? 'Enabled' : 'Disabled'}">
                              <i class="fa ${isEnabled ? 'fa-check' : 'fa-times'}"></i>
                            </div>`;
                },
                "readonlytoggle": function (column, row) {
                    const isChecked = row.log === "1" || row.log === true;
                    return `<div class="form-check form-switch m-0">
                              <input class="form-check-input" type="checkbox" ${isChecked ? "checked" : ""} disabled>
                            </div>`;
                },
                "protocol": function (column, row) {
                    return row.protocol ? `<span class="protocol-tag">${row.protocol.toUpperCase()}</span>` : '';
                },
                "action": function (column, row) {
                    if (!row.action) return '';
                    const action = row.action.toLowerCase();
                    return `<span class="action-badge ${action}">
                              <i class="fa ${action === 'allow' ? 'fa-check' : action === 'block' ? 'fa-ban' : 'fa-exclamation-triangle'}"></i>
                              ${action.toUpperCase()}
                            </span>`;
                }
            }
        }
    });

    function showApplyNotice(message) {
        // Remove existing notice
        $("#applyBtnWrapper").remove();
        
        const $applyNotice = $(`
          <div id="applyBtnWrapper" class="apply-notice" style="display: none;">
            <div class="apply-notice-content">
              <i class="fa fa-info-circle"></i>
              <span class="apply-notice-text">${message}</span>
            </div>
            <button class="apply-notice-btn" id="reconfigureAct" type="button"
                    data-endpoint="/api/advinspector/service/reconfigure"
                    data-label="{{ 'Apply Changes' | escape_js }}"
                    data-error-title="{{ 'Error applying rules' | escape_js }}">
              {{ lang._('Apply Now') }}
            </button>
          </div>
        `);
        
        $(".rules-content").prepend($applyNotice);
        $applyNotice.slideDown(300);
        
        // Initialize apply button
        $("#reconfigureAct").SimpleActionButton();
        
        // Auto-hide notice when apply button is clicked
        $("#reconfigureAct").on('click', function() {
          setTimeout(() => {
            $applyNotice.slideUp(300, function() {
              $(this).remove();
            });
          }, 1000);
        });
        
        // Click to dismiss
        $applyNotice.on('click', function(e) {
          if (e.target === this) {
            $applyNotice.slideUp(300, function() {
              $(this).remove();
            });
          }
        });
    }

    function updateDeleteSelectedButton() {
        const selected = $("#grid-rules").bootgrid("getSelectedRows");
        const $btn = $('[data-action="deleteSelected"]');
        const $label = $btn.find(".del-count-label");

        if (selected.length > 0) {
            $btn.show().prop("disabled", false);
            $label.text(`{{ lang._('Delete Selected') }} (${selected.length})`);
        } else {
            $btn.hide().prop("disabled", true);
            $label.text(`{{ lang._('Delete Selected') }}`);
        }
    }

    function updateRulesCount() {
        const totalRows = $("#grid-rules").bootgrid("getTotalRowCount") || 0;
        $("#rulesCount").text(totalRows);
    }

    // Initialize button states
    updateDeleteSelectedButton();

    // Update button state when selection changes
    $("#grid-rules").on("selected.rs.jquery.bootgrid deselected.rs.jquery.bootgrid", updateDeleteSelectedButton);

    // Delete selected rules
    $('[data-action="deleteSelected"]').click(function () {
        const selectedUUIDs = $("#grid-rules").bootgrid("getSelectedRows");
        if (selectedUUIDs.length === 0) return;

        stdDialogConfirm(
            '{{ lang._("Confirm multiple removal") }}',
            '{{ lang._("Do you really want to delete the selected rules?") }}',
            '{{ lang._("Yes") }}', '{{ lang._("Cancel") }}',
            function () {
                ajaxCall("/api/advinspector/rules/del_rule_bulk", { uuids: selectedUUIDs }, function (response) {
                    if (response.result === "deleted") { 
                        $("#grid-rules").bootgrid("reload");
                        showApplyNotice("{{ 'Selected rules have been removed. Apply changes to activate.' | escape_js }}");
                    }
                });
            }
        );
    });

    // Grid loaded event
    grid_rules.on("loaded.rs.jquery.bootgrid", function () {
        updateDeleteSelectedButton();
        updateRulesCount();
        
        // Enhanced edit button functionality
        grid_rules.find(".command-edit").on("click", function () {
            const uuid = $(this).data("row-id");
            ajaxGet("/api/advinspector/rules/get_rule/" + uuid, {}, function () {
                $("#dialogRule").data("uuid", uuid);
                $("#dialogRule").find("input[id], select[id], textarea[id]").each(function () {
                    const id = $(this).attr("id");
                    if (id && !$(this).attr("name")) {
                        $(this).attr("name", "advinspector.rules.rule." + id);
                    }
                });
                $("#dialogRule").modal({ backdrop: 'static', keyboard: false });
            });
        });

        // Enhanced delete button functionality
        grid_rules.off("click", ".command-delete").on("click", ".command-delete", function () {
            const uuid = $(this).data("row-id");
            stdDialogConfirm('{{ lang._("Confirm removal") }}',
                '{{ lang._("Do you want to remove the selected rule?") }}',
                '{{ lang._("Yes") }}', '{{ lang._("Cancel") }}',
                function () {
                    ajaxCall("/api/advinspector/rules/del_rule/" + uuid, {}, function (response) {
                        if (response.result === "deleted") {
                            $("#grid-rules").bootgrid("reload");
                            showApplyNotice("{{ 'Rule has been removed. Apply changes to activate.' | escape_js }}");
                        }
                    });
                });
        });
    });

    // Enhanced add rule functionality
    $('[data-action="add"]').click(function () {
        ajaxGet("/api/advinspector/rules/get_rule/", {}, function () {
            setFormDialog("dialogRule", {});
            $("#dialogRule").removeData("uuid");
            $("#dialogRule").find("input[id], select[id], textarea[id]").each(function () {
                const id = $(this).attr("id");
                if (id && !$(this).attr("name")) {
                    $(this).attr("name", "advinspector.rules.rule." + id);
                }
            });
            $("#dialogRule").modal({ backdrop: 'static', keyboard: false });
        });
    });

    // Dialog cleanup
    $("#dialogRule").on("hidden.bs.modal", function () {
        $(this).find(".help-block").remove();
        $(this).find(".has-error-border").removeClass("has-error-border");
    });

    // Enhanced form validation and saving
    $("#dialogRule").on("shown.bs.modal", function () {
        const $dialog = $(this);
        $dialog.find("#btn_dialogRule_save").off("click").on("click", function (e) {
            e.preventDefault();
            let uuid = $dialog.data("uuid");
            const ruleData = {};

            // Clear previous errors
            $dialog.find(".help-block").remove();
            $dialog.find("input, select, textarea").removeClass("has-error-border");

            // Ensure name attributes
            $dialog.find("input[id], select[id], textarea[id]").each(function () {
                const id = $(this).attr("id");
                if (id && !$(this).attr("name")) {
                    $(this).attr("name", "advinspector.rules.rule." + id);
                }
            });

            let hasClientError = false;

            // Client-side validation - only accept non-empty values
            $dialog.find("input[id], select[id], textarea[id]").each(function () {
                const $field = $(this);
                const id = $field.attr("id");
                const val = $field.is(":checkbox") ? ($field.is(":checked") ? "1" : "0") : $field.val().trim();

                if (!val && $field.attr('required')) {
                    $field.addClass("has-error-border");
                    $field.after('<div class="help-block">This field is required</div>');
                    hasClientError = true;
                } else if (val && val !== "" && val !== "0" && val !== "undefined" && val !== "null") {
                    const fieldName = id.split('.').pop();
                    ruleData[fieldName] = val;
                }
            });

            if (hasClientError) {
                setTimeout(() => {
                    $dialog.find(".has-error-border:visible:enabled").first().focus();
                }, 100);
                return;
            }

            // Generate UUID if needed
            if (!uuid && ruleData.uuid) uuid = ruleData.uuid;
            if (!uuid) {
                uuid = self.crypto?.randomUUID?.() || 'uuid-' + Math.random().toString(36).substr(2, 10);
                ruleData.uuid = uuid;
            }

            const endpoint = $dialog.data("uuid")
                ? "/api/advinspector/rules/set_rule/" + $dialog.data("uuid")
                : "/api/advinspector/rules/add_rule";

            const postData = { advinspector: { rules: { rule: ruleData } } };

            // Save rule
            ajaxCall(endpoint, postData, function (response) {
                $dialog.find(".help-block").remove();
                $dialog.find("input, select, textarea").removeClass("has-error-border");

                // Handle validation errors
                if (response.result === "failed" && response.validations) {
                    Object.keys(response.validations).forEach(function (fieldId) {
                        const normalizedFieldId = fieldId.replace(/^(advinspector\.rules\.rule)\.[a-f0-9-]{36}\./, '$1.');
                        const $field = $dialog.find(`[name="${normalizedFieldId}"], [id="${normalizedFieldId}"]`);

                        if ($field.length) {
                            const val = $field.is(":checkbox") ? ($field.is(":checked") ? "1" : "0") : $field.val().trim();

                            if (val !== "") {
                                $field.addClass("has-error-border");
                                $field.next(".help-block").remove();
                                $field.after(`<div class="help-block">${response.validations[fieldId]}</div>`);
                            }
                        }
                    });

                    setTimeout(() => {
                        $dialog.find(".has-error-border:visible:enabled").first().focus();
                    }, 100);
                    return;
                }

                // Success
                $dialog.modal("hide");
                $("#grid-rules").bootgrid("reload");
                showApplyNotice("{{ 'Rule changes have been saved. Apply changes to activate them.' | escape_js }}");
            });
        });
    });
});
</script>