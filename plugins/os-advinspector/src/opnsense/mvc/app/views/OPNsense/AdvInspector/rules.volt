{# layout_partials/base_dialog deve generare campi con BOTH id e name! #}
<style>
.has-error-border {
    border: 1px solid #dc3545 !important;
    box-shadow: 0 0 0 0.2rem rgba(220, 53, 69, 0.25);
    background-color: #fff;
}

.help-block {
    color: #dc3545 !important;
    font-size: 1rem;
    margin-top: 0.25rem;
    font-weight: 500;
}

#grid-rules td:nth-child(10),
#grid-rules th:nth-child(10) {
    display: none !important;
}
</style>

<script>
$(document).ready(function () {
    // REMOVED: $('[data-action="deleteSelected"]').hide();
    // This line was preventing the bulk delete button from showing

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
                    return '<button type="button" class="btn btn-xs btn-default command-edit bootgrid-tooltip" title="{{ lang._("Edit") }}" data-row-id="' + row.uuid + '"><span class="fa fa-pencil fa-fw"></span></button> '
                         + '<button type="button" class="btn btn-xs btn-default command-delete bootgrid-tooltip" title="{{ lang._("Delete") }}" data-row-id="' + row.uuid + '"><span class="fa fa-trash-o fa-fw"></span></button>';
                },
                "readonlytoggle": function (column, row) {
                    const isChecked = row.log === "1" || row.log === true;
                    return `<div class="form-check form-switch m-0">
                        <input class="form-check-input" type="checkbox" ${isChecked ? "checked" : ""} disabled>
                    </div>`;
                }
            }
        }
    });

    function showApplyNotice(message) {
        if ($("#applyBtnWrapper").length === 0) {
            const $applyBox = $('<div id="applyBtnWrapper">').append(
                $('<div class="alert alert-info" role="alert" style="cursor:pointer;">')
                    .html('<strong>{{ "Notice" | escape_js }}:</strong> ' + message)
                    .click(function () { $("#applyBtnWrapper").fadeOut(300, function () { $(this).remove(); }); }),
                $('<button class="btn btn-primary mt-2" id="reconfigureAct" type="button">')
                    .attr("data-endpoint", "/api/advinspector/service/reconfigure")
                    .attr("data-label", "{{ 'Apply changes' | escape_js }}")
                    .attr("data-error-title", "{{ 'Error applying rules' | escape_js }}")
                    .click(function () { $("#applyBtnWrapper").fadeOut(300, function () { $(this).remove(); }); }),
                $("<hr>")
            );
            $("#applyWrapper").prepend($applyBox);
            $("#reconfigureAct").SimpleActionButton();
        }
    }

    function updateDeleteSelectedButton() {
        const selected = $("#grid-rules").bootgrid("getSelectedRows");
        const $btn = $('[data-action="deleteSelected"]');
        const $label = $btn.find(".del-count-label");

        if (selected.length > 0) {
            $btn.show().prop("disabled", false); // Show and enable when rows are selected
            $label.text(`{{ lang._('Delete Selected') }} (${selected.length})`);
        } else {
            $btn.hide().prop("disabled", true); // Hide and disable when no rows are selected
            $label.text(`{{ lang._('Delete Selected') }}`);
        }
    }

    // Initialize the button state
    updateDeleteSelectedButton();

    // Update button state when selection changes
    $("#grid-rules").on("selected.rs.jquery.bootgrid deselected.rs.jquery.bootgrid", updateDeleteSelectedButton);

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
                        showApplyNotice("{{ 'Selected rules have been removed. Click Apply to activate the changes.' | escape_js }}");
                    }
                });
            }
        );
    });

    grid_rules.on("loaded.rs.jquery.bootgrid", function () {
        // Update delete button state after grid loads
        updateDeleteSelectedButton();
        
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

        grid_rules.off("click", ".command-delete").on("click", ".command-delete", function () {
            const uuid = $(this).data("row-id");
            stdDialogConfirm('{{ lang._("Confirm removal") }}',
                '{{ lang._("Do you want to remove the selected rule?") }}',
                '{{ lang._("Yes") }}', '{{ lang._("Cancel") }}',
                function () {
                    ajaxCall("/api/advinspector/rules/del_rule/" + uuid, {}, function (response) {
                        if (response.result === "deleted") {
                            $("#grid-rules").bootgrid("reload");
                            showApplyNotice("{{ 'A rule has been removed, but changes are not yet active. Click Apply to activate them.' | escape_js }}");
                        }
                    });
                });
        });
    });

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

    // Pulizia quando si chiude il dialog
    $("#dialogRule").on("hidden.bs.modal", function () {
        $(this).find(".help-block").remove();
        $(this).find(".has-error-border").removeClass("has-error-border");
    });

    // Validazione e salvataggio
    $("#dialogRule").on("shown.bs.modal", function () {
        const $dialog = $(this);
        $dialog.find("#btn_dialogRule_save").off("click").on("click", function (e) {
            e.preventDefault();
            let uuid = $dialog.data("uuid");
            const ruleData = {};

            $dialog.find(".help-block").remove();
            $dialog.find("input, select, textarea").removeClass("has-error-border");

            $dialog.find("input[id], select[id], textarea[id]").each(function () {
                const id = $(this).attr("id");
                if (id && !$(this).attr("name")) {
                    $(this).attr("name", "advinspector.rules.rule." + id);
                }
            });

            let hasClientError = false;

            $dialog.find("input[id], select[id], textarea[id]").each(function () {
                const $field = $(this);
                const id = $field.attr("id");
                const val = $field.is(":checkbox") ? ($field.is(":checked") ? "1" : "0") : $field.val().trim();

                if (!val) {
                    $field.addClass("has-error-border");
                    $field.after('<div class="help-block">Field is required</div>');
                    hasClientError = true;
                } else {
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

            if (!uuid && ruleData.uuid) uuid = ruleData.uuid;
            if (!uuid) {
                uuid = self.crypto?.randomUUID?.() || 'uuid-' + Math.random().toString(36).substr(2, 10);
                ruleData.uuid = uuid;
            }

            const endpoint = $dialog.data("uuid")
                ? "/api/advinspector/rules/set_rule/" + $dialog.data("uuid")
                : "/api/advinspector/rules/add_rule";

            const postData = { advinspector: { rules: { rule: ruleData } } };

            ajaxCall(endpoint, postData, function (response) {
                $dialog.find(".help-block").remove();
                $dialog.find("input, select, textarea").removeClass("has-error-border");

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

                $dialog.modal("hide");
                $("#grid-rules").bootgrid("reload");
                showApplyNotice("{{ 'Changes to the rules have been saved, but are not yet active. Click Apply to apply them.' | escape_js }}");
            });
        });
    });
});
</script>
<div class="content-box">
    <div class="col-md-12" id="applyWrapper"></div>
    <div class="col-md-12">
        <table id="grid-rules" class="table table-condensed table-hover table-striped table-responsive"
               data-editAlert="changeMessage"
               data-editDialog="dialogRule">
            <thead>
                <tr>
                    <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
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
            <tfoot>
                <tr>
                    <td colspan="10">
                        <button data-action="add" type="button" class="btn btn-xs btn-primary">
                            <span class="fa fa-fw fa-plus"></span>
                        </button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-danger" disabled>
                            <span class="fa fa-fw fa-trash-o"></span>
                            <span class="del-count-label">{{ lang._('Delete Selected') }}</span>
                        </button>
                    </td>
                </tr>
            </tfoot>
        </table>
    </div>
</div>

{{ partial("layout_partials/base_dialog", {
    'fields': formDialogRuleFields,
    'id': dialogRuleID,
    'label': dialogRuleLabel
}) }}