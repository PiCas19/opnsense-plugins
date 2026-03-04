<div class="content-box __mb">
  {{ partial("layout_partials/base_form", ['fields': settingsForm, 'id': 'frm_AdvInspectorSettings']) }}
</div>

<p>
  <button class="btn btn-primary hidden" id="saveAct" type="button">
    <i class="fa fa-spinner fa-pulse hidden" id="applySpinner"></i>
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

  const data_get_map = {};
  data_get_map[formId] = getEndpoint;
  mapDataToFormUI(data_get_map).done(function () {
    formatTokenizersUI();
    $('.selectpicker').selectpicker('refresh');
  });

  $(`#${formId}`).on("input change", "input, select, textarea", function () {
    $applyButton.removeClass("hidden");
  });

  $applyButton.click(function () {
    $spinner.removeClass("hidden");
    $label.text("{{ lang._('Applying...') }}");
    $applyButton.prop("disabled", true);

    saveFormToEndpoint(setEndpoint, formId, function () {
      ajaxCall(reconfigureEndpoint, {}, function (response) {
        $spinner.addClass("hidden");
        $label.text("{{ lang._('Apply') }}");
        $applyButton.prop("disabled", false).addClass("hidden");

        if ($("#applyBtnWrapper").length === 0) {
          const $applyBox = $('<div id="applyBtnWrapper" style="margin-top:1rem;">').append(
            $('<div class="alert alert-info" role="alert">')
              .html('<strong>{{ lang._("Notice") }}:</strong> {{ lang._("The configuration has been applied successfully.") }}')
          );
          $(".content-box.__mb").prepend($applyBox);
          setTimeout(function () {
            $("#applyBtnWrapper").fadeOut(300, function () { $(this).remove(); });
          }, 4000);
        }
      });
    });
  });

  updateServiceControlUI('advinspector');
});
</script>
