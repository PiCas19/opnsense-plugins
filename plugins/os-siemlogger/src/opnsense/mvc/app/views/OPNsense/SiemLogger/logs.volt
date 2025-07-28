{% extends "/ui/layouts/standard.volt" %}

{% block content %}
<div class="content-box">
    <div class="content-box-main">
        <h3>{{ gettext("SIEM Logger Logs") }}</h3>
        {% if error is defined %}
            <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <div class="panel panel-default">
            <div class="panel-heading">
                Log Entries
                <button class="btn btn-default pull-right" onclick="clearLogs()">{{ gettext("Clear Logs") }}</button>
            </div>
            <div class="panel-body">
                <table class="table table-striped" id="logsTable">
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
                <nav>
                    <ul class="pagination" id="pagination"></ul>
                </nav>
            </div>
        </div>
    </div>
</div>

<script>
var currentPage = 1;
var limit = 100;

function loadLogs(page) {
    $.ajax({
        url: '/api/siemlogger/service/getLogs',
        type: 'GET',
        data: { page: page, limit: limit },
        success: function(data) {
            if (data.status === 'ok' && data.data.logs) {
                $('#logsTable tbody').empty();
                $.each(data.data.logs, function(i, log) {
                    $('#logsTable tbody').append(
                        '<tr>' +
                        '<td>' + (log.timestamp_iso || log.timestamp) + '</td>' +
                        '<td>' + (log.source_ip || 'Unknown') + '</td>' +
                        '<td>' + (log.event_type || 'Unknown') + '</td>' +
                        '<td>' + (log.severity || 'info') + '</td>' +
                        '<td>' + log.message + '</td>' +
                        '</tr>'
                    );
                });

                var totalPages = Math.ceil(data.data.total / limit);
                $('#pagination').empty();
                for (var i = 1; i <= totalPages; i++) {
                    $('#pagination').append(
                        '<li class="' + (i === page ? 'active' : '') + '">' +
                        '<a href="#" onclick="loadLogs(' + i + ')">' + i + '</a></li>'
                    );
                }
            }
        }
    });
}

function clearLogs() {
    if (confirm('Are you sure you want to clear all logs?')) {
        $.ajax({
            url: '/api/siemlogger/service/clearLogs',
            type: 'POST',
            success: function(data) {
                if (data.status === 'ok') {
                    alert('Logs cleared successfully');
                    loadLogs(currentPage);
                } else {
                    alert('Failed to clear logs: ' + data.message);
                }
            }
        });
    }
}

$(document).ready(function() {
    loadLogs(currentPage);
});
</script>
{% endblock %}