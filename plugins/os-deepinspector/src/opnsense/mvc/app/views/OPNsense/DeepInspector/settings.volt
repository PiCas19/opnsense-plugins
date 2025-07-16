{# settings.volt - Deep Packet Inspector Settings #}

<div class="tab-content content-box">
    <div id="subtabs">
        <ul class="nav nav-tabs" role="tablist">
            <li class="nav-item">
                <a class="nav-link active" data-toggle="tab" href="#general" role="tab">
                    <i class="fa fa-cog"></i> {{ lang._('General') }}
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#protocols" role="tab">
                    <i class="fa fa-network-wired"></i> {{ lang._('Protocols') }}
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#detection" role="tab">
                    <i class="fa fa-shield-alt"></i> {{ lang._('Detection') }}
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#advanced" role="tab">
                    <i class="fa fa-cogs"></i> {{ lang._('Advanced') }}
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#industrial" role="tab">
                    <i class="fa fa-industry"></i> {{ lang._('Industrial') }}
                </a>
            </li>
        </ul>
    </div>

    <div class="tab-content">
        <!-- General Settings Tab -->
        <div class="tab-pane fade show active" id="general" role="tabpanel">
            <div class="content-box __mb">
                <h2>{{ lang._('General Settings') }}</h2>
                {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_DeepInspectorGeneral']) }}
            </div>
        </div>

        <!-- Protocols Tab -->
        <div class="tab-pane fade" id="protocols" role="tabpanel">
            <div class="content-box __mb">
                <h2>{{ lang._('Protocol Inspection') }}</h2>
                {{ partial("layout_partials/base_form", ['fields': protocolsForm, 'id': 'frm_DeepInspectorProtocols']) }}
            </div>
        </div>

        <!-- Detection Tab -->
        <div class="tab-pane fade" id="detection" role="tabpanel">
            <div class="content-box __mb">
                <h2>{{ lang._('Detection Engines') }}</h2>
                {{ partial("layout_partials/base_form", ['fields': detectionForm, 'id': 'frm_DeepInspectorDetection']) }}
            </div>
        </div>

        <!-- Advanced Tab -->
        <div class="tab-pane fade" id="advanced" role="tabpanel">
            <div class="content-box __mb">
                <h2>{{ lang._('Advanced Settings') }}</h2>
                {{ partial("layout_partials/base_form", ['fields': advancedForm, 'id': 'frm_DeepInspectorAdvanced']) }}
            </div>
        </div>

        <!-- Industrial Tab -->
        <div class="tab-pane fade" id="industrial" role="tabpanel">
            <div class="content-box __mb">
                <h2>{{ lang._('Industrial Environment Settings') }}</h2>
                <div class="alert alert-info">
                    <i class="fa fa-info-circle"></i>
                    {{ lang._('These settings optimize the Deep Packet Inspector for industrial environments (SCADA, PLC, OT networks) with low latency requirements.') }}
                </div>
                
                <div class="industrial-metrics">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="metric-card">
                                <div class="metric-icon">
                                    <i class="fa fa-tachometer-alt"></i>
                                </div>
                                <div class="metric-content">
                                    <div class="metric-value" id="avgLatency">-- μs</div>
                                    <div class="metric-label">{{ lang._('Average Latency') }}</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="metric-card">
                                <div class="metric-icon">
                                    <i class="fa fa-industry"></i>
                                </div>
                                <div class="metric-content">
                                    <div class="metric-value" id="industrialPackets">--</div>
                                    <div class="metric-label">{{ lang._('Industrial Packets') }}</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="metric-card">
                                <div class="metric-icon">
                                    <i class="fa fa-exclamation-triangle"></i>
                                </div>
                                <div class="metric-content">
                                    <div class="metric-value" id="scadaAlerts">--</div>
                                    <div class="metric-label">{{ lang._('SCADA Alerts') }}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="industrial-controls">
                    <div class="row">
                        <div class="col-md-6">
                            <button class="btn btn-primary btn-block" id="applyIndustrialOptimization">
                                <i class="fa fa-magic"></i> {{ lang._('Apply Industrial Optimization') }}
                            </button>
                        </div>
                        <div class="col-md-6">
                            <button class="btn btn-info btn-block" id="checkZeroTrustCompliance">
                                <i class="fa fa-shield-alt"></i> {{ lang._('Check Zero Trust Compliance') }}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Zero Trust Compliance Modal -->
<div class="modal fade" id="zeroTrustModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">{{ lang._('Zero Trust Compliance Report') }}</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <div class="modal-body" id="zeroTrustBody">
                <!-- Zero Trust report will be loaded here -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">
                    {{ lang._('Close') }}
                </button>
            </div>
        </div>
    </div>
</div>

<p>
    <button class="btn btn-primary d-none d-flex align-items-center" id="saveAct" type="button">
        <span class="spinner-border spinner-border-sm me-2 d-none" id="applySpinner" role="status"></span>
        <span id="applyLabel">{{ lang._('Apply') }}</span>
    </button>
</p>

<script>
$(document).ready(function() {
    const formIds = [
        'frm_DeepInspectorGeneral',
        'frm_DeepInspectorProtocols', 
        'frm_DeepInspectorDetection',
        'frm_DeepInspectorAdvanced'
    ];
    const getEndpoint = "/api/deepinspector/settings/get";
    const setEndpoint = "/api/deepinspector/settings/set";
    const reconfigureEndpoint = "/api/deepinspector/service/reconfigure";
    
    const $applyButton = $("#saveAct");
    const $spinner = $("#applySpinner");
    const $label = $("#applyLabel");

    // Load settings data
    const data_get_map = {};
    formIds.forEach(function(formId) {
        data_get_map[formId] = getEndpoint;
    });

    mapDataToFormUI(data_get_map).done(function() {
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
        loadIndustrialMetrics();
    });

    // Show Apply button when form changes
    formIds.forEach(function(formId) {
        $(`#${formId}`).on("input change", "input, select, textarea", function() {
            $applyButton.removeClass("d-none");
        });
    });

    // Handle performance profile changes
    $('#deepinspector\\.general\\.performance_profile').change(function() {
        const profile = $(this).val();
        handlePerformanceProfileChange(profile);
    });

    // Handle industrial mode toggle
    $('#deepinspector\\.general\\.industrial_mode').change(function() {
        const enabled = $(this).is(':checked');
        handleIndustrialModeToggle(enabled);
    });

    // Apply button click
    $applyButton.click(function() {
        $spinner.removeClass("d-none");
        $label.text("{{ lang._('Applying...') }}");
        $applyButton.prop("disabled", true);

        const formData = {};
        formData['deepinspector'] = getFormData(formIds);

        saveFormToEndpoint(setEndpoint, formData, function() {
            ajaxCall(reconfigureEndpoint, {}, function(response) {
                $spinner.addClass("d-none");
                $label.text("{{ lang._('Apply') }}");
                $applyButton.prop("disabled", false).addClass("d-none");
                
                showApplyNotification();
                loadIndustrialMetrics();
            });
        });
    });

    // Industrial optimization button
    $('#applyIndustrialOptimization').click(function() {
        const $btn = $(this);
        const originalText = $btn.text();
        
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Applying...") }}');
        
        ajaxCall("/api/deepinspector/settings/applyIndustrialOptimization", {}, function(data) {
            $btn.prop('disabled', false).html(originalText);
            
            if (data.status === 'ok') {
                showNotification('{{ lang._("Industrial optimization applied successfully") }}', 'success');
                // Reload the form data
                mapDataToFormUI(data_get_map).done(function() {
                    formatTokenizersUI();
                    $('.selectpicker').selectpicker('refresh');
                    loadIndustrialMetrics();
                });
            } else {
                showNotification('{{ lang._("Failed to apply industrial optimization") }}', 'error');
            }
        });
    });

    // Zero Trust compliance check
    $('#checkZeroTrustCompliance').click(function() {
        const $btn = $(this);
        const originalText = $btn.text();
        
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Checking...") }}');
        
        ajaxCall("/api/deepinspector/settings/zeroTrustStatus", {}, function(data) {
            $btn.prop('disabled', false).html(originalText);
            
            if (data.status === 'ok') {
                showZeroTrustReport(data.data);
            } else {
                showNotification('{{ lang._("Failed to check Zero Trust compliance") }}', 'error');
            }
        });
    });

    // Auto-refresh industrial metrics
    setInterval(loadIndustrialMetrics, 30000);

    updateServiceControlUI('deepinspector');
});

function getFormData(formIds) {
    const data = {};
    formIds.forEach(function(formId) {
        const formData = new FormData(document.getElementById(formId));
        for (let [key, value] of formData.entries()) {
            data[key] = value;
        }
    });
    return data;
}

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
    const $industrialTab = $('.nav-link[href="#industrial"]');
    const $industrialSettings = $('.industrial-settings');
    
    if (enabled) {
        $industrialTab.removeClass('d-none');
        $industrialSettings.show();
    } else {
        $industrialTab.addClass('d-none');
        $industrialSettings.hide();
    }
}

function loadIndustrialMetrics() {
    ajaxCall("/api/deepinspector/settings/industrialStats", {}, function(data) {
        if (data.status === 'ok') {
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
    
    let html = `
        <div class="zero-trust-report">
            <div class="compliance-score">
                <h4>{{ lang._('Overall Compliance Score') }}</h4>
                <div class="score-circle">
                    <span class="score-value text-${scoreColor}">${compliance.overall_score}%</span>
                </div>
            </div>
            
            <div class="compliance-checks">
                <h5>{{ lang._('Compliance Checks') }}</h5>
                <ul class="list-group">
    `;
    
    Object.entries(compliance.checks).forEach(([check, passed]) => {
        const icon = passed ? 'check text-success' : 'times text-danger';
        const status = passed ? '{{ lang._("Passed") }}' : '{{ lang._("Failed") }}';
        const checkName = check.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        
        html += `
            <li class="list-group-item d-flex justify-content-between">
                <span>${checkName}</span>
                <span><i class="fa fa-${icon}"></i> ${status}</span>
            </li>
        `;
    });
    
    html += `
                </ul>
            </div>
    `;
    
    if (compliance.recommendations.length > 0) {
        html += `
            <div class="recommendations">
                <h5>{{ lang._('Recommendations') }}</h5>
                <ul class="list-group">
        `;
        
        compliance.recommendations.forEach(rec => {
            html += `<li class="list-group-item">${rec}</li>`;
        });
        
        html += `
                </ul>
            </div>
        `;
    }
    
    html += `</div>`;
    
    $('#zeroTrustBody').html(html);
    $('#zeroTrustModal').modal('show');
}

function showApplyNotification() {
    if ($("#applyBtnWrapper").length === 0) {
        const $applyBox = $('<div id="applyBtnWrapper" class="mt-3">').append(
            $('<div class="alert alert-info" role="alert">')
                .html('<strong>{{ lang._("Notice") }}:</strong> {{ lang._("The configuration has been applied successfully.") }}')
        );
        $(".content-box.__mb").first().prepend($applyBox);
        setTimeout(() => {
            $("#applyBtnWrapper").fadeOut(300, function() {
                $(this).remove();
            });
        }, 4000);
    }
}

function showNotification(message, type) {
    const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
    const notification = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $('#notifications').append(notification);
    setTimeout(() => notification.alert('close'), 5000);
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}
</script>

<div id="notifications" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;"></div>

<style>
.industrial-metrics {
    margin: 20px 0;
}

.metric-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
}

.metric-icon {
    font-size: 2rem;
    color: #2563eb;
    margin-right: 1rem;
}

.metric-content {
    flex: 1;
}

.metric-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
}

.metric-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.industrial-controls {
    margin-top: 20px;
}

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
</style>