<div class="content-box __mb">
  {{ partial("layout_partials/base_form", ['fields': settingsForm, 'id': 'frm_AdvInspectorSettings']) }}
</div>

<p>
  <button class="btn btn-primary d-none d-flex align-items-center" id="saveAct" type="button">
    <span class="spinner-border spinner-border-sm me-2 d-none" id="applySpinner" role="status" aria-hidden="true"></span>
    <span id="applyLabel">{{ lang._('Apply') }}</span>
  </button>
</p>

<script>
$(document).ready(function () {
  const formId = 'frm_AdvInspectorSettings';
  const getEndpoint = "/api/advinspector/settings/get";
  const setEndpoint = "/api/advinspector/settings/set";
  const reconfigureEndpoint = "/api/advinspector/service/reconfigure";
  const $applyButton = $("#saveAct");
  const $spinner = $("#applySpinner");
  const $label = $("#applyLabel");

  // Load the data into the form
  const data_get_map = {};
  data_get_map[formId] = getEndpoint;
  mapDataToFormUI(data_get_map).done(function () {
    formatTokenizersUI();
    $('.selectpicker').selectpicker('refresh');
  });

  // Show the Apply button when something is changed
  $(`#${formId}`).on("input change", "input, select, textarea", function () {
    $applyButton.removeClass("d-none");
  });

  // Apply button
  $applyButton.click(function () {
    $spinner.removeClass("d-none");
    $label.text("{{ lang._('Applying...') }}");
    $applyButton.prop("disabled", true);

    saveFormToEndpoint(setEndpoint, formId, function () {
      ajaxCall(reconfigureEndpoint, {}, function (response) {
        $spinner.addClass("d-none");
        $label.text("{{ lang._('Apply') }}");
        $applyButton.prop("disabled", false).addClass("d-none");

        // “Apply Changes” message in rules style, without button
        if ($("#applyBtnWrapper").length === 0) {
          const $applyBox = $('<div id="applyBtnWrapper" class="mt-3">').append(
            $('<div class="alert alert-info" role="alert">')
              .html('<strong>{{ lang._("Notice") }}:</strong> {{ lang._("The configuration has been applied successfully.") }}')
          );

          $(".content-box.__mb").prepend($applyBox);
          setTimeout(() => {
            $("#applyBtnWrapper").fadeOut(300, function () {
              $(this).remove();
            });
          }, 4000);
        }
      });
    });
  });

  updateServiceControlUI('advinspector');
});
</script>