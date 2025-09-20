<!-- Alert Statistics Cards -->
<div class="row" style="margin-bottom: 20px;">
    <div class="col-md-3">
        <div class="panel panel-danger">
            <div class="panel-body">
                <div class="row">
                    <div class="col-xs-3">
                        <i class="fa fa-exclamation-triangle fa-3x text-danger"></i>
                    </div>
                    <div class="col-xs-9 text-right">
                        <div class="huge" id="critical-count">0</div>
                        <div>Critical Alerts</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="panel panel-warning">
            <div class="panel-body">
                <div class="row">
                    <div class="col-xs-3">
                        <i class="fa fa-warning fa-3x text-warning"></i>
                    </div>
                    <div class="col-xs-9 text-right">
                        <div class="huge" id="high-count">0</div>
                        <div>High Priority</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="panel panel-info">
            <div class="panel-body">
                <div class="row">
                    <div class="col-xs-3">
                        <i class="fa fa-info-circle fa-3x text-info"></i>
                    </div>
                    <div class="col-xs-9 text-right">
                        <div class="huge" id="medium-count">0</div>
                        <div>Medium Priority</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="panel panel-success">
            <div class="panel-body">
                <div class="row">
                    <div class="col-xs-3">
                        <i class="fa fa-check-circle fa-3x text-success"></i>
                    </div>
                    <div class="col-xs-9 text-right">
                        <div class="huge" id="low-count">0</div>
                        <div>Low Priority</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Alerts Table Container -->
<div class="content-box">
    <!-- Empty State Message -->
    <div id="no-alerts-message" class="alert alert-info text-center" style="display: none; margin: 20px;">
        <i class="fa fa-info-circle fa-2x" style="margin-bottom: 10px;"></i>
        <h4>Nessun Alert Disponibile</h4>
        <p>Non sono stati rilevati alert nel sistema. Il monitoraggio è attivo e funzionante.</p>
    </div>
    
    <!-- Alerts Table -->
    <table id="grid-alerts"
           data-toggle="bootgrid"
           data-ajax="true"
           class="table table-condensed table-hover table-striped">
        <thead>
            <tr>
                <th data-column-id="timestamp" data-order="desc" data-formatter="datetime">Timestamp</th>
                <th data-column-id="severity" data-formatter="severity">Severity</th>
                <th data-column-id="src" data-formatter="ip">Source IP</th>
                <th data-column-id="dst" data-formatter="ip">Destination IP</th>
                <th data-column-id="protocol">Protocol</th>
                <th data-column-id="reason">Reason</th>
                <th data-column-id="actions" data-formatter="actions" data-sortable="false">Actions</th>
            </tr>
        </thead>
    </table>
</div>

<style>
.huge {
    font-size: 40px;
    font-weight: bold;
}

.panel-body {
    padding: 15px;
}

#no-alerts-message {
    border-radius: 8px;
    border: 2px dashed #5bc0de;
    background-color: #f0f8ff;
}

.severity-badge {
    padding: 4px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
}

.severity-critical {
    background-color: #d9534f;
    color: white;
}

.severity-high {
    background-color: #f0ad4e;
    color: white;
}

.severity-medium {
    background-color: #5bc0de;
    color: white;
}

.severity-low {
    background-color: #5cb85c;
    color: white;
}

.ip-address {
    font-family: 'Courier New', monospace;
    background-color: #f5f5f5;
    padding: 2px 4px;
    border-radius: 3px;
    font-size: 12px;
}
</style>

<script>
// Function to update alert statistics
function updateAlertStatistics(data) {
    let counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };
    
    // Count alerts by severity
    if (Array.isArray(data)) {
        data.forEach(function(alert) {
            const severity = (alert.severity || '').toLowerCase();
            if (counts.hasOwnProperty(severity)) {
                counts[severity]++;
            }
        });
    }
    
    // Update card counters with animation
    $('#critical-count').countTo({ from: 0, to: counts.critical, speed: 1000 });
    $('#high-count').countTo({ from: 0, to: counts.high, speed: 1000 });
    $('#medium-count').countTo({ from: 0, to: counts.medium, speed: 1000 });
    $('#low-count').countTo({ from: 0, to: counts.low, speed: 1000 });
}

// Simple countTo implementation if not available
if (!$.fn.countTo) {
    $.fn.countTo = function(options) {
        return this.each(function() {
            const $this = $(this);
            const from = options.from || 0;
            const to = options.to || 0;
            const speed = options.speed || 1000;
            const steps = Math.abs(to - from);
            const stepTime = speed / steps;
            
            let current = from;
            const increment = to > from ? 1 : -1;
            
            const timer = setInterval(function() {
                current += increment;
                $this.text(current);
                
                if (current === to) {
                    clearInterval(timer);
                }
            }, stepTime);
        });
    };
}

// Initialize bootgrid
$('#grid-alerts').bootgrid({
    ajax: true,
    url: '/api/advinspector/alerts/list',
    ajaxSettings: {
        method: 'GET',
        contentType: 'application/json'
    },
    responseHandler: function(response) {
        if (response && response.status === 'ok' && Array.isArray(response.data)) {
            const hasData = response.data.length > 0;
            
            // Show/hide empty state message
            if (hasData) {
                $('#no-alerts-message').hide();
                $('#grid-alerts').show();
                updateAlertStatistics(response.data);
            } else {
                $('#no-alerts-message').show();
                $('#grid-alerts').hide();
                updateAlertStatistics([]);
            }
            
            return {
                current: 1,
                rowCount: response.data.length,
                rows: response.data,
                total: response.data.length
            };
        }
        
        // Handle error or empty response
        $('#no-alerts-message').show();
        $('#grid-alerts').hide();
        updateAlertStatistics([]);
        
        return {
            current: 1,
            rowCount: 0,
            rows: [],
            total: 0
        };
    },
    rowCount: [10, 25, 50, -1],
    searchSettings: {
        delay: 250,
        characters: 1
    },
    formatters: {
        "datetime": function(column, row) {
            if (row.timestamp) {
                const date = new Date(row.timestamp * 1000);
                return date.toLocaleString('it-IT');
            }
            return '-';
        },
        "severity": function(column, row) {
            const severity = (row.severity || 'low').toLowerCase();
            return '<span class="severity-badge severity-' + severity + '">' + 
                   severity.charAt(0).toUpperCase() + severity.slice(1) + '</span>';
        },
        "ip": function(column, row) {
            const ip = row[column.id] || '-';
            if (ip !== '-') {
                return '<span class="ip-address">' + ip + '</span>';
            }
            return ip;
        },
        "actions": function(column, row) {
            return '<button class="btn btn-xs btn-default" onclick="viewAlertDetails(\'' + 
                   (row.id || '') + '\')" title="View Details">' +
                   '<i class="fa fa-eye"></i></button> ' +
                   '<button class="btn btn-xs btn-danger" onclick="dismissAlert(\'' + 
                   (row.id || '') + '\')" title="Dismiss">' +
                   '<i class="fa fa-times"></i></button>';
        }
    }
}).on('loaded.rs.jquery.bootgrid', function() {
    $('[data-toggle="tooltip"]').tooltip();
});

// Alert action functions
function viewAlertDetails(alertId) {
    if (!alertId) return;
    
    // Implementation for viewing alert details
    console.log('Viewing alert details for ID:', alertId);
    // You can open a modal or navigate to a detail page
}

function dismissAlert(alertId) {
    if (!alertId) return;
    
    if (confirm('Sei sicuro di voler dismissare questo alert?')) {
        $.ajax({
            url: '/api/advinspector/alerts/dismiss',
            method: 'POST',
            data: JSON.stringify({ id: alertId }),
            contentType: 'application/json',
            success: function(response) {
                if (response.status === 'ok') {
                    $('#grid-alerts').bootgrid('reload');
                } else {
                    alert('Errore nel dismissal dell\'alert');
                }
            },
            error: function() {
                alert('Errore di comunicazione con il server');
            }
        });
    }
}

// Auto-refresh every 30 seconds
setInterval(function() {
    $('#grid-alerts').bootgrid('reload');
}, 30000);
</script>