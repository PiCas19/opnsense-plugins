{% extends "/ui/layouts/standard.volt" %}

{% block content %}
<div class="content-box">
    <div class="content-box-main">
        <h3>{{ gettext("SIEM Logger Dashboard") }}</h3>
        {% if error is defined %}
            <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <div class="row">
            <div class="col-md-3">
                <div class="panel panel-default">
                    <div class="panel-heading">Service Status</div>
                    <div class="panel-body">
                        <p><strong>Enabled:</strong> {{ isEnabled ? 'Yes' : 'No' }}</p>
                        <p><strong>Log Level:</strong> {{ logLevel }}</p>
                        <p><strong>Export Enabled:</strong> {{ exportEnabled ? 'Yes' : 'No' }}</p>
                        <p><strong>Audit Enabled:</strong> {{ auditEnabled ? 'Yes' : 'No' }}</p>
                        <button class="btn btn-primary" onclick="refreshStatus()">Refresh</button>
                    </div>
                </div>
            </div>
            <div class="col-md-9">
                <div class="panel panel-default">
                    <div class="panel-heading">Recent Events</div>
                    <div class="panel-body">
                        <table class="table table-striped" id="recentEventsTable">
                            <thead>
                                <tr>
                                    <th>{{ gettext("Timestamp") }}</th>
                                    <th>{{ gettext("Source IP") }}</th>
                                    <th>{{ gettext("Event Type") }}</th>
                                    <th>{{ gettext("Severity") }}</th>
                                    <th>{{ gettext("Message") }}</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function refreshStatus() {
    $.ajax({
        url: '/api/siemlogger/service/status',
        type: 'GET',
        success: function(data) {
            if (data.status === 'ok') {
                $('#serviceStatus').text(data.running ? 'Running' : 'Stopped');
            }
        }
    });
}

function loadRecentEvents() {
    $.ajax({
        url: '/api/siemlogger/settings/stats',
        type: 'GET',
        success: function(data) {
            if (data.status === 'ok' && data.data.recent_events) {
                $('#recentEventsTable tbody').empty();
                $.each(data.data.recent_events, function(i, event) {
                    $('#recentEventsTable tbody').append(
                        '<tr>' +
                        '<td>' + event.timestamp + '</td>' +
                        '<td>' + event.source_ip + '</td>' +
                        '<td>' + event.event_type + '</td>' +
                        '<td>' + event.severity + '</td>' +
                        '<td>' + event.message + '</td>' +
                        '</tr>'
                    );
                });
            }
        }
    });
}

$(document).ready(function() {
    loadRecentEvents();
    setInterval(loadRecentEvents, 60000);
});
</script>
{% endblock %}