{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<div class="content-box" data-threat-id="{{ threatId }}">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                <h1>{{ lang._('Threat Details') }} #{{ threatId }}</h1>
                <div>
                    <a href="/ui/webguard/threats" class="btn btn-default">
                        <i class="fa fa-arrow-left"></i> {{ lang._('Back to Threats') }}
                    </a>
                </div>
            </div>
        </div>
    </div>

    {% if error %}
    <div class="row">
        <div class="col-md-12">
            <div class="alert alert-danger">
                <strong>{{ lang._('Error') }}:</strong> {{ error }}
            </div>
        </div>
    </div>
    {% endif %}

    <div class="row">
        <div class="col-md-8">
            <!-- Threat Information -->
            <div class="threat-detail-card">
                <h3>{{ lang._('Threat Information') }}</h3>
                <div id="threatInfo">
                    <div class="info-loading">
                        <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading threat details...') }}
                    </div>
                </div>
            </div>

            <!-- Request Details -->
            <div class="threat-detail-card">
                <h3>{{ lang._('Request Details') }}</h3>
                <div id="requestDetails">
                    <!-- Dynamic content -->
                </div>
            </div>

            <!-- Payload Analysis -->
            <div class="threat-detail-card">
                <h3>{{ lang._('Payload Analysis') }}</h3>
                <div id="payloadAnalysis">
                    <!-- Dynamic content -->
                </div>
            </div>
        </div>

        <div class="col-md-4">
            <!-- Actions Panel -->
            <div class="threat-detail-card">
                <h3>{{ lang._('Actions') }}</h3>
                <div class="btn-group-vertical" style="width: 100%;">
                    <button class="btn btn-warning" id="markFalsePositive">
                        <i class="fa fa-exclamation-triangle"></i> {{ lang._('Mark as False Positive') }}
                    </button>
                    <button class="btn btn-success" id="whitelistIP">
                        <i class="fa fa-check-circle"></i> {{ lang._('Whitelist IP') }}
                    </button>
                    <button class="btn btn-danger" id="blockIP">
                        <i class="fa fa-ban"></i> {{ lang._('Block IP') }}
                    </button>
                    <button class="btn btn-info" id="createRule">
                        <i class="fa fa-shield"></i> {{ lang._('Create Rule') }}
                    </button>
                </div>
            </div>

            <!-- Source Information -->
            <div class="threat-detail-card">
                <h3>{{ lang._('Source Information') }}</h3>
                <div id="sourceInfo">
                    <!-- Dynamic content -->
                </div>
            </div>

            <!-- Related Threats -->
            <div class="threat-detail-card">
                <h3>{{ lang._('Related Threats') }}</h3>
                <div id="relatedThreats">
                    <!-- Dynamic content -->
                </div>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    const currentThreatId = $('.content-box').data('threat-id');
    
    // Load threat details
    loadThreatDetails(currentThreatId);
    
    // Action buttons
    $('#markFalsePositive').click(() => markFalsePositive(currentThreatId));
    $('#whitelistIP').click(() => whitelistIP(currentThreatId));
    $('#blockIP').click(() => blockIP(currentThreatId));
    $('#createRule').click(() => createRule(currentThreatId));
    
    function loadThreatDetails(id) {
        ajaxCall(`/api/webguard/threats/getDetail/${id}`, {}, function(data) {
            if (data.result === 'ok' && data.threat) {
                displayThreatInfo(data.threat);
                displayRequestDetails(data.threat);
                displayPayloadAnalysis(data.threat);
                displaySourceInfo(data.threat);
            } else {
                $('#threatInfo').html('<div class="alert alert-warning">{{ lang._("Threat not found") }}</div>');
            }
        });
    }
    
    function displayThreatInfo(threat) {
        const severityClass = getSeverityClass(threat.severity);
        const html = `
            <div class="threat-info-grid">
                <div class="info-item">
                    <label>{{ lang._('Threat ID') }}:</label>
                    <span>${threat.id}</span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Timestamp') }}:</label>
                    <span>${formatDateTime(threat.timestamp)}</span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Source IP') }}:</label>
                    <span><code>${threat.source_ip}</code></span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Threat Type') }}:</label>
                    <span>${threat.threat_type}</span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Severity') }}:</label>
                    <span><span class="badge ${severityClass}">${threat.severity}</span></span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Status') }}:</label>
                    <span>${threat.status}</span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Score') }}:</label>
                    <span>${threat.score || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Rule Matched') }}:</label>
                    <span>${threat.rule_matched || 'N/A'}</span>
                </div>
            </div>
        `;
        $('#threatInfo').html(html);
    }
    
    function displayRequestDetails(threat) {
        const html = `
            <div class="request-details">
                <div class="info-item">
                    <label>{{ lang._('URL') }}:</label>
                    <span><code>${threat.url || 'N/A'}</code></span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Method') }}:</label>
                    <span><span class="badge badge-secondary">${threat.method || 'GET'}</span></span>
                </div>
                ${threat.request_headers ? `
                <div class="info-item">
                    <label>{{ lang._('Headers') }}:</label>
                    <pre class="headers-display">${JSON.stringify(threat.request_headers, null, 2)}</pre>
                </div>
                ` : ''}
            </div>
        `;
        $('#requestDetails').html(html);
    }
    
    function displayPayloadAnalysis(threat) {
        const html = `
            <div class="payload-analysis">
                <div class="info-item">
                    <label>{{ lang._('Description') }}:</label>
                    <p>${threat.description || 'No description available'}</p>
                </div>
                ${threat.payload ? `
                <div class="info-item">
                    <label>{{ lang._('Payload') }}:</label>
                    <pre class="payload-display">${threat.payload}</pre>
                </div>
                ` : ''}
            </div>
        `;
        $('#payloadAnalysis').html(html);
    }
    
    function displaySourceInfo(threat) {
        const html = `
            <div class="source-info">
                <div class="info-item">
                    <label>{{ lang._('IP Address') }}:</label>
                    <span><code>${threat.source_ip}</code></span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('Country') }}:</label>
                    <span>${threat.geolocation?.country || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <label>{{ lang._('City') }}:</label>
                    <span>${threat.geolocation?.city || 'Unknown'}</span>
                </div>
            </div>
        `;
        $('#sourceInfo').html(html);
    }
    
    function markFalsePositive(id) {
        const comment = prompt('{{ lang._("Optional comment") }}:');
        if (comment !== null) {
            ajaxCall(`/api/webguard/threats/markFalsePositive/${id}`, {comment: comment}, function(data) {
                if (data.result === 'ok') {
                    alert('{{ lang._("Threat marked as false positive") }}');
                    window.location.reload();
                }
            });
        }
    }
    
    function whitelistIP(id) {
        if (confirm('{{ lang._("Add IP to whitelist?") }}')) {
            ajaxCall(`/api/webguard/threats/whitelistIp/${id}`, {}, function(data) {
                if (data.result === 'ok') {
                    alert('{{ lang._("IP added to whitelist") }}');
                }
            });
        }
    }
    
    function blockIP(id) {
        const duration = prompt('{{ lang._("Block duration in seconds") }}:', '3600');
        if (duration !== null) {
            ajaxCall(`/api/webguard/threats/blockIp/${id}`, {duration: duration}, function(data) {
                if (data.result === 'ok') {
                    alert('{{ lang._("IP blocked successfully") }}');
                }
            });
        }
    }
    
    function createRule(id) {
        const ruleName = prompt('{{ lang._("Rule name") }}:');
        if (ruleName) {
            ajaxCall(`/api/webguard/threats/createRule/${id}`, {rule_name: ruleName}, function(data) {
                if (data.result === 'ok') {
                    alert('{{ lang._("Custom rule created") }}');
                }
            });
        }
    }
    
    function getSeverityClass(severity) {
        switch(severity?.toLowerCase()) {
            case 'critical': return 'badge-danger';
            case 'high': return 'badge-warning';
            case 'medium': return 'badge-info';
            case 'low': return 'badge-success';
            default: return 'badge-secondary';
        }
    }
    
    function formatDateTime(timestamp) {
        if (!timestamp) return 'N/A';
        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch (e) {
            return timestamp;
        }
    }
});
</script>

<style>
.threat-detail-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.threat-info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
}

.info-item {
    padding: 0.5rem 0;
}

.info-item label {
    font-weight: 600;
    color: #374151;
    display: block;
    margin-bottom: 0.25rem;
}

.headers-display, .payload-display {
    background: #f8f9fa;
    border: 1px solid #e9ecef;
    border-radius: 4px;
    padding: 1rem;
    max-height: 200px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 0.9rem;
}

.info-loading {
    text-align: center;
    padding: 2rem;
    color: #6b7280;
}

@media (max-width: 768px) {
    .threat-info-grid {
        grid-template-columns: 1fr;
    }
}
</style>