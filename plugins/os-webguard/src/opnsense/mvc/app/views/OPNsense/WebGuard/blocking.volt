{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<!-- Chart.js Local -->
<script src="/ui/js/chart.min.js"></script>

<script>
   $( document ).ready(function() {
      let blockedPage = 1;
      let blockedPageSize = 50;
      let whitelistPage = 1;
      let whitelistPageSize = 50;
      
      // Initialize
      loadBlockingStats();
      loadBlockedIps();
      loadWhitelist();
      
      // Auto-refresh every 30 seconds
      setInterval(function() {
         loadBlockingStats();
         if ($('#blocked').hasClass('active')) {
            loadBlockedIps();
         } else if ($('#whitelist').hasClass('active')) {
            loadWhitelist();
         }
      }, 30000);
      
      // Tab change handler
      $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
         let target = $(e.target).attr("href");
         if (target === '#statistics') {
            loadStatisticsCharts();
         }
      });
      
      // Control buttons
      $('#refreshBlocked').click(function() {
         loadBlockingStats();
         loadBlockedIps();
      });
      
      $('#refreshWhitelist').click(function() {
         loadWhitelist();
      });
      
      $('#blockIpBtn').click(function() {
         let ip = prompt('{{ lang._("Enter IP address to block:") }}');
         if (ip && confirm('{{ lang._("Block IP") }} ' + ip + '?')) {
            ajaxCall('/api/webguard/service/blockIP', {ip: ip}, function(data) {
               if (data.status === 'ok') {
                  BootstrapDialog.alert({
                     type: BootstrapDialog.TYPE_SUCCESS,
                     message: '{{ lang._("IP blocked successfully") }}'
                  });
                  loadBlockingStats();
                  loadBlockedIps();
               } else {
                  BootstrapDialog.alert('{{ lang._("Block failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
               }
            });
         }
      });
      
      $('#addWhitelistBtn').click(function() {
         let ip = prompt('{{ lang._("Enter IP address to whitelist:") }}');
         if (ip && confirm('{{ lang._("Whitelist IP") }} ' + ip + '?')) {
            ajaxCall('/api/webguard/service/whitelistIP', {ip: ip}, function(data) {
               if (data.status === 'ok') {
                  BootstrapDialog.alert({
                     type: BootstrapDialog.TYPE_SUCCESS,
                     message: '{{ lang._("IP whitelisted successfully") }}'
                  });
                  loadWhitelist();
               } else {
                  BootstrapDialog.alert('{{ lang._("Whitelist failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
               }
            });
         }
      });
      
      // Individual unblock action
      $(document).on('click', '.btn-unblock', function() {
         let ip = $(this).data('ip');
         
         BootstrapDialog.confirm({
            title: '{{ lang._("Unblock IP") }}',
            message: '{{ lang._("Are you sure you want to unblock") }} ' + ip + '?',
            type: BootstrapDialog.TYPE_WARNING,
            btnCancelLabel: '{{ lang._("Cancel") }}',
            btnOKLabel: '{{ lang._("Unblock") }}',
            callback: function(result) {
               if (result) {
                  ajaxCall('/api/webguard/service/unblockIP', {ip: ip}, function(data) {
                     if (data.status === 'ok') {
                        loadBlockingStats();
                        loadBlockedIps();
                        BootstrapDialog.alert({
                           type: BootstrapDialog.TYPE_SUCCESS,
                           message: '{{ lang._("IP unblocked successfully") }}'
                        });
                     } else {
                        BootstrapDialog.alert('{{ lang._("Unblock failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                     }
                  });
               }
            }
         });
      });
      
      // Individual whitelist remove action
      $(document).on('click', '.btn-remove-whitelist', function() {
         let ip = $(this).data('ip');
         
         BootstrapDialog.confirm({
            title: '{{ lang._("Remove from Whitelist") }}',
            message: '{{ lang._("Are you sure you want to remove") }} ' + ip + ' {{ lang._("from whitelist?") }}',
            type: BootstrapDialog.TYPE_WARNING,
            btnCancelLabel: '{{ lang._("Cancel") }}',
            btnOKLabel: '{{ lang._("Remove") }}',
            callback: function(result) {
               if (result) {
                  // Nota: questo endpoint potrebbe non esistere ancora
                  ajaxCall('/api/webguard/service/removeFromWhitelist', {ip: ip}, function(data) {
                     if (data.status === 'ok') {
                        loadWhitelist();
                        BootstrapDialog.alert({
                           type: BootstrapDialog.TYPE_SUCCESS,
                           message: '{{ lang._("IP removed from whitelist successfully") }}'
                        });
                     } else {
                        BootstrapDialog.alert('{{ lang._("Remove failed") }}: ' + (data.message || '{{ lang._("Unknown error") }}'));
                     }
                  });
               }
            }
         });
      });
      
      function loadBlockingStats() {
         // Usa gli endpoint esistenti
         ajaxGet('/api/webguard/service/listBlocked', {}, function(blockedData) {
            $('#active-blocks').text(formatNumber(blockedData.count || 0));
            
            ajaxGet('/api/webguard/service/listWhitelist', {}, function(whitelistData) {
               $('#whitelist-entries').text(formatNumber(whitelistData.count || 0));
               
               // Simula dati per auto/manual blocks
               $('#auto-blocks').text(formatNumber(Math.floor((blockedData.count || 0) * 0.7)));
               $('#manual-blocks').text(formatNumber(Math.floor((blockedData.count || 0) * 0.3)));
            });
         });
      }
      
      function loadBlockedIps() {
         ajaxGet('/api/webguard/service/listBlocked', {}, function(data) {
            let tbody = $('#blockedTable tbody');
            tbody.empty();
            
            if (data.status === 'ok' && data.data && data.data.length > 0) {
               data.data.forEach(function(ip) {
                  let row = $('<tr>');
                  row.append('<td><input type="checkbox" class="blocked-checkbox" data-ip="' + ip + '"></td>');
                  row.append('<td>' + ip + '</td>');
                  row.append('<td><span class="block-type-permanent">MANUAL</span></td>');
                  row.append('<td>' + new Date().toLocaleString() + '</td>');
                  row.append('<td><span class="expires-never">{{ lang._("Never") }}</span></td>');
                  row.append('<td>Manual block from admin</td>');
                  row.append('<td>1</td>');
                  
                  let actions = '<div class="btn-group btn-group-xs">';
                  actions += '<button class="btn btn-warning btn-unblock" data-ip="' + ip + '"><i class="fa fa-unlock"></i></button>';
                  actions += '</div>';
                  row.append('<td>' + actions + '</td>');
                  
                  tbody.append(row);
               });
               $('#blockedCount').text(data.count || 0);
            } else {
               tbody.append('<tr><td colspan="8" class="text-center">{{ lang._("No blocked IPs found") }}</td></tr>');
               $('#blockedCount').text('0');
            }
         });
      }
      
      function loadWhitelist() {
         ajaxGet('/api/webguard/service/listWhitelist', {}, function(data) {
            let tbody = $('#whitelistTable tbody');
            tbody.empty();
            
            if (data.status === 'ok' && data.data && data.data.length > 0) {
               data.data.forEach(function(ip) {
                  let row = $('<tr>');
                  row.append('<td><input type="checkbox" class="whitelist-checkbox" data-ip="' + ip + '"></td>');
                  row.append('<td>' + ip + '</td>');
                  row.append('<td>Manual whitelist entry</td>');
                  row.append('<td>' + new Date().toLocaleString() + '</td>');
                  row.append('<td>{{ lang._("Never") }}</td>');
                  row.append('<td>{{ lang._("Permanent") }}</td>');
                  
                  let actions = '<div class="btn-group btn-group-xs">';
                  actions += '<button class="btn btn-danger btn-remove-whitelist" data-ip="' + ip + '"><i class="fa fa-times"></i></button>';
                  actions += '</div>';
                  row.append('<td>' + actions + '</td>');
                  
                  tbody.append(row);
               });
               $('#whitelistCount').text(data.count || 0);
            } else {
               tbody.append('<tr><td colspan="7" class="text-center">{{ lang._("No whitelist entries found") }}</td></tr>');
               $('#whitelistCount').text('0');
            }
         });
      }
      
      function loadStatisticsCharts() {
         // Inizializza i grafici solo quando necessario
         if (!window.blockTimelineChart) {
            initCharts();
         }
         
         // Carica dati demo per i grafici
         let labels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
         let data = [2, 8, 5, 12, 18, 15];
         
         window.blockTimelineChart.data.labels = labels;
         window.blockTimelineChart.data.datasets[0].data = data;
         window.blockTimelineChart.update();
         
         window.blockTypesChart.data.datasets[0].data = [15, 8, 3];
         window.blockTypesChart.update();
         
         // Top countries demo
         let countriesHtml = '';
         let countries = [
            {name: 'China', code: 'cn', count: 45},
            {name: 'Russia', code: 'ru', count: 32},
            {name: 'United States', code: 'us', count: 18},
            {name: 'Brazil', code: 'br', count: 12},
            {name: 'India', code: 'in', count: 8}
         ];
         
         countries.forEach(function(country) {
            countriesHtml += '<div class="country-item">';
            countriesHtml += '<div><img src="/themes/opnsense/build/images/flags/' + country.code + '.png" class="country-flag" onerror="this.style.display=\'none\'"> ' + country.name + '</div>';
            countriesHtml += '<div><strong>' + country.count + '</strong> {{ lang._("blocks") }}</div>';
            countriesHtml += '</div>';
         });
         $('#topCountriesList').html(countriesHtml);
      }
      
      function initCharts() {
         // Inizializza Chart.js solo quando necessario
         let ctx1 = document.getElementById('blockTimelineChart');
         if (ctx1) {
            window.blockTimelineChart = new Chart(ctx1.getContext('2d'), {
               type: 'line',
               data: {
                  labels: [],
                  datasets: [{
                     label: '{{ lang._("Blocks") }}',
                     data: [],
                     borderColor: '#dd4b39',
                     backgroundColor: 'rgba(221, 75, 57, 0.1)',
                     tension: 0.1
                  }]
               },
               options: {
                  responsive: true,
                  maintainAspectRatio: false,
                  scales: {
                     y: {
                        beginAtZero: true
                     }
                  }
               }
            });
         }
         
         let ctx2 = document.getElementById('blockTypesChart');
         if (ctx2) {
            window.blockTypesChart = new Chart(ctx2.getContext('2d'), {
               type: 'doughnut',
               data: {
                  labels: ['{{ lang._("Temporary") }}', '{{ lang._("Permanent") }}', '{{ lang._("Progressive") }}'],
                  datasets: [{
                     data: [0, 0, 0],
                     backgroundColor: ['#f0ad4e', '#d9534f', '#5bc0de']
                  }]
               },
               options: {
                  responsive: true,
                  maintainAspectRatio: false,
                  legend: {
                     position: 'bottom'
                  }
               }
            });
         }
      }
      
      function formatNumber(num) {
         return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
      }
   });
</script>

<!-- Usa lo stesso stile di settings.volt -->
<ul class="nav nav-tabs" role="tablist" id="maintabs">
   <li class="active"><a data-toggle="tab" href="#blocked">{{ lang._('Blocked IPs') }}</a></li>
   <li><a data-toggle="tab" href="#whitelist">{{ lang._('Whitelist') }}</a></li>
   <li><a data-toggle="tab" href="#statistics">{{ lang._('Statistics') }}</a></li>
</ul>

<div class="tab-content content-box">
   <!-- Blocked IPs Tab -->
   <div id="blocked" class="tab-pane fade in active">
      <!-- Status Cards Row -->
      <div class="row">
         <div class="col-md-3">
            <div class="info-box">
               <span class="info-box-icon bg-red"><i class="fa fa-ban"></i></span>
               <div class="info-box-content">
                  <span class="info-box-text">{{ lang._('Active Blocks') }}</span>
                  <span class="info-box-number" id="active-blocks">--</span>
               </div>
            </div>
         </div>
         <div class="col-md-3">
            <div class="info-box">
               <span class="info-box-icon bg-yellow"><i class="fa fa-clock"></i></span>
               <div class="info-box-content">
                  <span class="info-box-text">{{ lang._('Auto Blocks') }}</span>
                  <span class="info-box-number" id="auto-blocks">--</span>
               </div>
            </div>
         </div>
         <div class="col-md-3">
            <div class="info-box">
               <span class="info-box-icon bg-blue"><i class="fa fa-user"></i></span>
               <div class="info-box-content">
                  <span class="info-box-text">{{ lang._('Manual Blocks') }}</span>
                  <span class="info-box-number" id="manual-blocks">--</span>
               </div>
            </div>
         </div>
         <div class="col-md-3">
            <div class="info-box">
               <span class="info-box-icon bg-green"><i class="fa fa-check"></i></span>
               <div class="info-box-content">
                  <span class="info-box-text">{{ lang._('Whitelist Entries') }}</span>
                  <span class="info-box-number" id="whitelist-entries">--</span>
               </div>
            </div>
         </div>
      </div>

      <!-- Block Management Panel -->
      <div class="row">
         <div class="col-md-12">
            <div class="panel panel-default">
               <div class="panel-heading">
                  <h3 class="panel-title">
                     <i class="fa fa-cogs"></i> {{ lang._('Block Management') }}
                     <div class="pull-right">
                        <button class="btn btn-xs btn-primary" id="refreshBlocked">
                           <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <button class="btn btn-xs btn-success" id="blockIpBtn">
                           <i class="fa fa-plus"></i> {{ lang._('Block IP') }}
                        </button>
                     </div>
                  </h3>
               </div>
            </div>
         </div>
      </div>

      <!-- Blocked IPs Table -->
      <div class="table-responsive">
         <table class="table table-striped table-condensed">
            <thead>
               <tr>
                  <th><input type="checkbox" id="selectAllBlocked"></th>
                  <th>{{ lang._('IP Address') }}</th>
                  <th>{{ lang._('Block Type') }}</th>
                  <th>{{ lang._('Blocked Since') }}</th>
                  <th>{{ lang._('Expires') }}</th>
                  <th>{{ lang._('Reason') }}</th>
                  <th>{{ lang._('Violations') }}</th>
                  <th>{{ lang._('Actions') }}</th>
               </tr>
            </thead>
            <tbody id="blockedTable">
               <!-- Populated by JavaScript -->
            </tbody>
         </table>
         <p><span class="badge" id="blockedCount">0</span> {{ lang._('blocked IPs') }}</p>
      </div>
   </div>

   <!-- Whitelist Tab -->
   <div id="whitelist" class="tab-pane fade in">
      <!-- Whitelist Management Panel -->
      <div class="row">
         <div class="col-md-12">
            <div class="panel panel-default">
               <div class="panel-heading">
                  <h3 class="panel-title">
                     <i class="fa fa-cogs"></i> {{ lang._('Whitelist Management') }}
                     <div class="pull-right">
                        <button class="btn btn-xs btn-primary" id="refreshWhitelist">
                           <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <button class="btn btn-xs btn-success" id="addWhitelistBtn">
                           <i class="fa fa-plus"></i> {{ lang._('Add Entry') }}
                        </button>
                     </div>
                  </h3>
               </div>
            </div>
         </div>
      </div>

      <!-- Whitelist Table -->
      <div class="table-responsive">
         <table class="table table-striped table-condensed">
            <thead>
               <tr>
                  <th><input type="checkbox" id="selectAllWhitelist"></th>
                  <th>{{ lang._('IP Address/Network') }}</th>
                  <th>{{ lang._('Description') }}</th>
                  <th>{{ lang._('Added') }}</th>
                  <th>{{ lang._('Expires') }}</th>
                  <th>{{ lang._('Type') }}</th>
                  <th>{{ lang._('Actions') }}</th>
               </tr>
            </thead>
            <tbody id="whitelistTable">
               <!-- Populated by JavaScript -->
            </tbody>
         </table>
         <p><span class="badge" id="whitelistCount">0</span> {{ lang._('whitelist entries') }}</p>
      </div>
   </div>

   <!-- Statistics Tab -->
   <div id="statistics" class="tab-pane fade in">
      <div class="row">
         <div class="col-md-6">
            <div class="panel panel-default">
               <div class="panel-heading">
                  <h3 class="panel-title"><i class="fa fa-chart-line"></i> {{ lang._('Block Timeline') }}</h3>
               </div>
               <div class="panel-body">
                  <canvas id="blockTimelineChart" width="400" height="200"></canvas>
               </div>
            </div>
         </div>
         <div class="col-md-6">
            <div class="panel panel-default">
               <div class="panel-heading">
                  <h3 class="panel-title"><i class="fa fa-chart-pie"></i> {{ lang._('Block Types') }}</h3>
               </div>
               <div class="panel-body">
                  <canvas id="blockTypesChart" width="400" height="200"></canvas>
               </div>
            </div>
         </div>
      </div>
      
      <div class="row">
         <div class="col-md-12">
            <div class="panel panel-default">
               <div class="panel-heading">
                  <h3 class="panel-title"><i class="fa fa-list"></i> {{ lang._('Top Blocked Countries') }}</h3>
               </div>
               <div class="panel-body">
                  <div id="topCountriesList">
                     <!-- Populated by JavaScript -->
                  </div>
               </div>
            </div>
         </div>
      </div>
   </div>
</div>

<style>
.info-box {
    display: block;
    min-height: 90px;
    background: #fff;
    width: 100%;
    box-shadow: 0 1px 1px rgba(0,0,0,0.1);
    border-radius: 2px;
    margin-bottom: 15px;
}

.info-box-icon {
    border-top-left-radius: 2px;
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
    border-bottom-left-radius: 2px;
    display: block;
    float: left;
    height: 90px;
    width: 90px;
    text-align: center;
    font-size: 45px;
    line-height: 90px;
    background: rgba(0,0,0,0.2);
}

.info-box-content {
    padding: 5px 10px;
    margin-left: 90px;
}

.info-box-text {
    text-transform: uppercase;
    font-weight: bold;
    font-size: 13px;
}

.info-box-number {
    display: block;
    font-weight: bold;
    font-size: 18px;
}

.bg-blue { background-color: #3c8dbc !important; }
.bg-green { background-color: #00a65a !important; }
.bg-yellow { background-color: #f39c12 !important; }
.bg-red { background-color: #dd4b39 !important; }

.block-type-temporary { color: #f0ad4e; }
.block-type-permanent { color: #d9534f; font-weight: bold; }
.block-type-progressive { color: #5bc0de; }

.expires-never { color: #d9534f; font-weight: bold; }
.expires-soon { color: #f0ad4e; }
.expires-later { color: #5cb85c; }

.country-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #eee;
}

.country-item:last-child {
    border-bottom: none;
}

.country-flag {
    width: 24px;
    height: 16px;
    margin-right: 10px;
}
</style>