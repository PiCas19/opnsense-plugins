{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}
<link rel="stylesheet" href="/ui/css/leaflet.css"/>
<script src="/ui/js/leaflet.js"></script>
<script src="/ui/js/chart.min.js"></script>

<style>
.geo-stat-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
}

.stat-icon {
    width: 60px;
    height: 60px;
    border-radius: 50%;
    background: #3b82f6;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 1rem;
    font-size: 1.5rem;
}

.stat-content {
    flex: 1;
}

.stat-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
    line-height: 1;
}

.stat-label {
    font-size: 0.875rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.map-container, .country-list-container, .analysis-card, .table-container, .geo-blocking-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.country-item {
    padding: 1rem 0;
    border-bottom: 1px solid #f3f4f6;
    cursor: pointer;
    transition: background-color 0.2s;
}

.country-item:hover {
    background-color: #f8f9fa;
}

.country-item:last-child {
    border-bottom: none;
}

.country-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.country-name {
    font-weight: 600;
    color: #1f2937;
}

.country-flag {
    margin-right: 0.5rem;
    font-size: 1.2rem;
}

.country-stats {
    display: flex;
    gap: 0.5rem;
    font-size: 0.875rem;
    align-items: center;
}

.threats-count {
    color: #ef4444;
    font-weight: 600;
}

.threats-percentage {
    color: #6b7280;
}

.country-bar {
    height: 8px;
    background: #f3f4f6;
    border-radius: 4px;
    overflow: hidden;
}

.bar-fill {
    height: 100%;
    transition: width 0.3s ease;
}

.analysis-card canvas {
    max-height: 300px;
}

.blocking-controls {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.blocked-countries {
    padding-top: 1rem;
    border-top: 1px solid #e5e7eb;
}

.blocked-country-tag {
    display: inline-block;
    background: #fee2e2;
    color: #dc2626;
    padding: 0.25rem 0.5rem;
    border-radius: 1rem;
    margin: 0.25rem;
    font-size: 0.875rem;
}

.blocked-country-tag button {
    margin-left: 0.5rem;
    border: none;
    background: transparent;
    color: #dc2626;
    padding: 0;
}

/* Leaflet popup styles */
.threat-popup h5 {
    margin: 0 0 0.5rem 0;
    color: #1f2937;
    font-size: 1.1rem;
}

.popup-stats {
    margin-bottom: 0.75rem;
}

.stat-row {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.25rem;
    font-size: 0.875rem;
}

.stat-row .stat-label {
    color: #6b7280;
    font-weight: 500;
}

.stat-row .stat-value {
    color: #1f2937;
    font-weight: 600;
}

.popup-actions {
    display: flex;
    gap: 0.5rem;
}

.popup-actions .btn {
    font-size: 0.75rem;
    padding: 0.25rem 0.5rem;
}

/* Map legend styles */
.map-legend {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 8px;
    padding: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    font-size: 0.875rem;
}

.map-legend h6 {
    margin: 0 0 0.5rem 0;
    font-size: 0.875rem;
    font-weight: 600;
    color: #1f2937;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.25rem;
}

.legend-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 1px solid #fff;
}

.legend-note {
    color: #6b7280;
    font-style: italic;
    margin-top: 0.5rem;
    display: block;
}

.loading-message {
    text-align: center;
    padding: 2rem;
    color: #6b7280;
}

/* Responsive design */
@media (max-width: 768px) {
    .country-info {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.25rem;
    }
    
    .country-stats {
        flex-wrap: wrap;
    }
    
    .blocking-controls {
        flex-direction: column;
    }
    
    .form-group {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .input-group {
        max-width: 100% !important;
    }
    
    .popup-actions {
        flex-direction: column;
    }
}
</style>

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <div class="dpi-header">
                {% if not geoDatabase %}
                <div class="alert alert-warning">
                    <i class="fa fa-exclamation-triangle"></i>
                    {{ lang._('GeoIP database not available. Install GeoLite2 for geographic analysis.') }}
                </div>
                {% endif %}
            </div>
        </div>
    </div>

    <!-- Geographic Stats -->
    <div class="row">
        <div class="col-md-3">
            <div class="geo-stat-card">
                <div class="stat-icon">
                    <i class="fa fa-globe"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="totalCountries">0</div>
                    <div class="stat-label">{{ lang._('Countries') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="geo-stat-card">
                <div class="stat-icon">
                    <i class="fa fa-ban"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="blockedCountries">{{ blockedCountries|length }}</div>
                    <div class="stat-label">{{ lang._('Blocked Countries') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="geo-stat-card">
                <div class="stat-icon">
                    <i class="fa fa-shield"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="topThreatCountry">--</div>
                    <div class="stat-label">{{ lang._('Top Threat Source') }}</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="geo-stat-card">
                <div class="stat-icon">
                    <i class="fa fa-exclamation-triangle"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="geoThreats">0</div>
                    <div class="stat-label">{{ lang._('Geographic Threats') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- World Map and Country List -->
    <div class="row">
        <div class="col-md-8">
            <div class="map-container">
                <h3>{{ lang._('Threat Distribution Map') }}</h3>
                <div id="worldMapContainer" style="height: 400px; background: #f8f9fa; border-radius: 8px; position: relative;">
                    <div id="worldMap" style="height: 100%; width: 100%; border-radius: 8px;"></div>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="country-list-container">
                <h3>{{ lang._('Top Threat Countries') }}</h3>
                <div id="countryList">
                    <div class="loading-message">
                        <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading threat data...') }}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Geographic Analysis Charts -->
    <div class="row">
        <div class="col-md-6">
            <div class="analysis-card">
                <h3>{{ lang._('Regional Distribution') }}</h3>
                <canvas id="regionChart" height="300"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="analysis-card">
                <h3>{{ lang._('Threat Timeline by Region') }}</h3>
                <canvas id="timelineChart" height="300"></canvas>
            </div>
        </div>
    </div>

    <!-- Additional Analysis Charts -->
    <div class="row">
        <div class="col-md-6">
            <div class="analysis-card">
                <h3>{{ lang._('Attack Types Distribution') }}</h3>
                <canvas id="attackTypesChart" height="300"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="analysis-card">
                <h3>{{ lang._('Threat Severity Levels') }}</h3>
                <canvas id="severityChart" height="300"></canvas>
            </div>
        </div>
    </div>

    <!-- Hourly Activity Chart -->
    <div class="row">
        <div class="col-md-12">
            <div class="analysis-card">
                <h3>{{ lang._('24h Activity Heatmap') }}</h3>
                <canvas id="heatmapChart" height="200"></canvas>
            </div>
        </div>
    </div>

    <!-- Country Details Table -->
    <div class="row">
        <div class="col-md-12">
            <div class="table-container">
                <h3>{{ lang._('Detailed Country Analysis') }}</h3>
                <div class="table-responsive">
                    <table class="table table-striped" id="countryTable">
                        <thead>
                            <tr>
                                <th>{{ lang._('Country') }}</th>
                                <th>{{ lang._('Flag') }}</th>
                                <th>{{ lang._('Total Threats') }}</th>
                                <th>{{ lang._('Percentage') }}</th>
                                <th>{{ lang._('Top Threat Type') }}</th>
                                <th>{{ lang._('Severity') }}</th>
                                <th>{{ lang._('Status') }}</th>
                                <th>{{ lang._('Actions') }}</th>
                            </tr>
                        </thead>
                        <tbody id="countryTableBody">
                            <tr>
                                <td colspan="8" class="text-center">
                                    <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading threat data...') }}
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Geo Blocking Controls -->
    {% if geoBlocking %}
    <div class="row">
        <div class="col-md-12">
            <div class="geo-blocking-card">
                <h3>{{ lang._('Geographic Blocking Controls') }}</h3>
                <div class="blocking-controls">
                    <div class="form-group">
                        <label>{{ lang._('Block Country') }}:</label>
                        <div class="input-group" style="max-width: 400px;">
                            <select id="countrySelect" class="form-control">
                                <option value="">{{ lang._('Select Country') }}</option>
                            </select>
                            <div class="input-group-append">
                                <button class="btn btn-danger" id="blockCountryBtn">
                                    <i class="fa fa-ban"></i> {{ lang._('Block') }}
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="blocked-countries">
                        <h4>{{ lang._('Currently Blocked Countries') }}</h4>
                        <div id="blockedCountriesList">
                            {% for country in blockedCountries %}
                            <span class="blocked-country-tag">
                                {{ country }}
                                <button class="btn btn-xs btn-secondary" onclick="unblockCountry('{{ country }}')">
                                    <i class="fa fa-times"></i>
                                </button>
                            </span>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endif %}
</div>

<script type="text/javascript">
    // Initialize app configuration with JavaScript
    window.appConfig = {
        geoBlocking: false,
        blockedCountries: [],
        translations: {
            pleaseSelectCountry: 'Please select a country',
            blockTrafficFrom: 'Block all traffic from',
            blockedSuccessfully: 'blocked successfully',
            unblockTrafficFrom: 'Unblock traffic from',
            unblockedSuccessfully: 'unblocked successfully',
            detailedAnalysisFor: 'Detailed analysis for',
            wouldOpenHere: 'would open here',
            loadingData: 'Loading threat data...',
            noDataAvailable: 'No data available',
            confirmBlock: 'Are you sure you want to block this country?',
            confirmUnblock: 'Are you sure you want to unblock this country?'
        }
    };
    
    // Load configuration from server
    $(document).ready(function() {
        ajaxCall('/api/webguard/settings/getConfig', {}, function(response) {
            if (response && response.status === 'ok') {
                if (response.data.geoBlocking) {
                    window.appConfig.geoBlocking = response.data.geoBlocking === '1';
                }
                if (response.data.blockedCountries && Array.isArray(response.data.blockedCountries)) {
                    window.appConfig.blockedCountries = response.data.blockedCountries;
                }
            }
        });
    });

    // Country coordinates mapping for map display
    var countryCoordinates = {
        'China': [35.8617, 104.1954],
        'Russia': [61.5240, 105.3188],
        'United States': [37.0902, -95.7129],
        'Brazil': [-14.2350, -51.9253],
        'India': [20.5937, 78.9629],
        'Germany': [51.1657, 10.4515],
        'France': [46.6034, 1.8883],
        'United Kingdom': [55.3781, -3.4360],
        'Japan': [36.2048, 138.2529],
        'South Korea': [35.9078, 127.7669],
        'Turkey': [38.9637, 35.2433],
        'Iran': [32.4279, 53.6880],
        'Ukraine': [48.3794, 31.1656],
        'Poland': [51.9194, 19.1451],
        'Vietnam': [14.0583, 108.2772],
        'Italy': [41.8719, 12.5674],
        'Spain': [40.4637, -3.7492],
        'Netherlands': [52.1326, 5.2913],
        'Canada': [56.1304, -106.3468],
        'Australia': [-25.2744, 133.7751],
        'Mexico': [23.6345, -102.5528],
        'Argentina': [-38.4161, -63.6167],
        'South Africa': [-30.5595, 22.9375],
        'Egypt': [26.0975, 30.0444],
        'Nigeria': [9.0820, 8.6753],
        'Israel': [31.0461, 34.8516],
        'Saudi Arabia': [23.8859, 45.0792],
        'Thailand': [15.8700, 100.9925],
        'Singapore': [1.3521, 103.8198],
        'Indonesia': [-0.7893, 113.9213],
        'North Korea': [40.3399, 127.5101],
        'Pakistan': [30.3753, 69.3451],
        'Belgium': [50.8503, 4.3517],
        'Unknown': [0, 0]
    };

    $(document).ready(function() {
        var regionChart, timelineChart, attackTypesChart, severityChart, heatmapChart, worldMap;
        var currentGeoData = null;
        var mapLegend = null;
        
        // Initialize
        initLeafletMap();
        
        // Load data with delay to ensure map is ready
        setTimeout(function() {
            loadGeoData();
        }, 1000);
        
        initControls();
        
        function loadGeoData() {
            console.log('Loading geographic threat data...');
            
            // Show loading state
            $('#countryList').html('<div class="loading-message"><i class="fa fa-spinner fa-spin"></i> Loading threat data...</div>');
            $('#countryTableBody').html('<tr><td colspan="8" class="text-center"><i class="fa fa-spinner fa-spin"></i> Loading threat data...</td></tr>');
            
            // Load real geographic threat data from OPNsense API with better error handling
            $.ajax({
                url: '/api/webguard/threats/getGeoStats',
                method: 'GET',
                data: { period: '24h' },
                timeout: 10000,
                success: function(response) {
                    console.log('API Response:', response);
                    
                    if (response && response.status === 'ok') {
                        if (response.data && Object.keys(response.data.countries || {}).length > 0) {
                            currentGeoData = response.data;
                            updateGeoStats(currentGeoData);
                            updateCountryList(currentGeoData.countries || {});
                            updateCountryTable(currentGeoData.countries || {});
                            updateMapMarkers(currentGeoData.countries || {});
                            populateCountrySelect(currentGeoData.countries || {});
                            updateBlockedCountriesList();
                            initCharts(currentGeoData);
                        } else {
                            console.log('No geographic data available');
                            showNoDataMessage();
                        }
                    } else {
                        console.log('Invalid API response:', response);
                        showNoDataMessage();
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Failed to load geo data:', {
                        status: status,
                        error: error,
                        response: xhr.responseText
                    });
                    
                    // Try fallback method
                    loadFallbackGeoData();
                }
            });
        }

        function loadFallbackGeoData() {
            console.log('Trying fallback geo data loading...');
            
            $.ajax({
                url: '/api/webguard/threats/get',
                method: 'GET',
                data: { 
                    page: 1, 
                    limit: 100 
                },
                success: function(response) {
                    console.log('Fallback API Response:', response);
                    
                    if (response && response.status === 'ok' && response.threats) {
                        // Process threat data to extract geographic information
                        var geoData = processThreatsToGeoData(response.threats);
                        
                        if (Object.keys(geoData.countries).length > 0) {
                            currentGeoData = geoData;
                            updateGeoStats(currentGeoData);
                            updateCountryList(currentGeoData.countries);
                            updateCountryTable(currentGeoData.countries);
                            updateMapMarkers(currentGeoData.countries);
                            populateCountrySelect(currentGeoData.countries);
                            updateBlockedCountriesList();
                            initCharts(currentGeoData);
                        } else {
                            showNoDataMessage();
                        }
                    } else {
                        showNoDataMessage();
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Fallback also failed:', error);
                    showNoDataMessage();
                }
            });
        }

        function processThreatsToGeoData(threats) {
            var countries = {};
            var totalThreats = 0;
            
            // Country detection based on IP patterns (simplified)
            var ipToCountry = {
                '192.168.': null, // Skip local
                '10.': null,      // Skip local
                '172.16.': null,  // Skip local
                '8.8.': 'United States',
                '1.1.': 'Australia',
                '208.67.': 'United States'
            };
            
            threats.forEach(function(threat) {
                var ip = threat.ip_address || threat.source_ip;
                var country = 'Unknown';
                
                if (ip) {
                    // Simple IP to country mapping
                    for (var prefix in ipToCountry) {
                        if (ip.startsWith(prefix)) {
                            country = ipToCountry[prefix];
                            break;
                        }
                    }
                    
                    // If no specific mapping, use heuristic based on first octet
                    if (country === 'Unknown') {
                        var firstOctet = parseInt(ip.split('.')[0]);
                        if (firstOctet >= 1 && firstOctet <= 50) country = 'United States';
                        else if (firstOctet >= 51 && firstOctet <= 100) country = 'China';
                        else if (firstOctet >= 101 && firstOctet <= 150) country = 'Russia';
                        else if (firstOctet >= 151 && firstOctet <= 200) country = 'Germany';
                        else country = 'Unknown';
                    }
                }
                
                if (country && country !== 'Unknown') {
                    if (!countries[country]) {
                        countries[country] = {
                            count: 0,
                            types: {},
                            severities: {},
                            ips: []
                        };
                    }
                    
                    countries[country].count++;
                    totalThreats++;
                    
                    // Track attack types
                    var type = threat.threat_type || 'Unknown';
                    countries[country].types[type] = (countries[country].types[type] || 0) + 1;
                    
                    // Track severities
                    var severity = threat.severity || 'medium';
                    countries[country].severities[severity] = (countries[country].severities[severity] || 0) + 1;
                    
                    // Track unique IPs
                    if (ip && countries[country].ips.indexOf(ip) === -1) {
                        countries[country].ips.push(ip);
                    }
                }
            });
            
            // Format countries data
            var formattedCountries = {};
            for (var country in countries) {
                var data = countries[country];
                var percentage = totalThreats > 0 ? Math.round((data.count / totalThreats) * 100 * 10) / 10 : 0;
                
                // Get top attack type
                var topType = 'Unknown';
                var maxTypeCount = 0;
                for (var type in data.types) {
                    if (data.types[type] > maxTypeCount) {
                        maxTypeCount = data.types[type];
                        topType = type;
                    }
                }
                
                // Get top severity
                var topSeverity = 'medium';
                var maxSevCount = 0;
                for (var sev in data.severities) {
                    if (data.severities[sev] > maxSevCount) {
                        maxSevCount = data.severities[sev];
                        topSeverity = sev;
                    }
                }
                
                formattedCountries[country] = {
                    count: data.count,
                    percentage: percentage,
                    type: topType,
                    severity: topSeverity,
                    unique_ips: data.ips.length
                };
            }
            
            return {
                countries: formattedCountries,
                total_countries: Object.keys(formattedCountries).length,
                total_threats: totalThreats,
                top_countries: formattedCountries
            };
        }
        
        function showNoDataMessage() {
            var noDataHtml = '<div class="alert alert-info text-center">' +
                            '<i class="fa fa-info-circle"></i> ' +
                            'No geographic threat data available. ' +
                            '<br><small>This may be due to:</small>' +
                            '<ul class="text-left" style="display: inline-block; margin-top: 10px;">' +
                            '<li>No recent threats detected</li>' +
                            '<li>GeoIP database not installed</li>' +
                            '<li>Backend service unavailable</li>' +
                            '</ul>' +
                            '</div>';
            
            $('#countryList').html(noDataHtml);
            $('#countryTableBody').html('<tr><td colspan="8" class="text-center">No geographic data available</td></tr>');
            $('#totalCountries').text('0');
            $('#geoThreats').text('0');
            $('#topThreatCountry').text('--');
            
            // Initialize empty charts
            initEmptyCharts();
        }
        
        function initLeafletMap() {
            worldMap = L.map('worldMap').setView([20, 0], 2);
            
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
                maxZoom: 18,
                minZoom: 1
            }).addTo(worldMap);
            
            worldMap.options.scrollWheelZoom = true;
            worldMap.options.doubleClickZoom = true;
            worldMap.options.touchZoom = true;
            
            var mapContainer = document.getElementById('worldMapContainer');
            var loadingDiv = document.createElement('div');
            loadingDiv.id = 'mapLoading';
            loadingDiv.innerHTML = '<div class="text-center p-3"><i class="fa fa-spinner fa-spin"></i> ' + window.appConfig.translations.loadingData + '</div>';
            loadingDiv.style.position = 'absolute';
            loadingDiv.style.top = '50%';
            loadingDiv.style.left = '50%';
            loadingDiv.style.transform = 'translate(-50%, -50%)';
            loadingDiv.style.zIndex = '1000';
            loadingDiv.style.backgroundColor = 'rgba(255,255,255,0.9)';
            loadingDiv.style.padding = '20px';
            loadingDiv.style.borderRadius = '5px';
            mapContainer.appendChild(loadingDiv);
        }
        
        function updateMapMarkers(countries) {
            if (!worldMap) return;
            
            var loadingDiv = document.getElementById('mapLoading');
            if (loadingDiv) {
                loadingDiv.remove();
            }
            
            worldMap.eachLayer(function(layer) {
                if (layer instanceof L.CircleMarker) {
                    worldMap.removeLayer(layer);
                }
            });
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var data = countries[country];
                    var coords = countryCoordinates[country];
                    
                    if (coords && coords.length === 2) {
                        var lat = coords[0];
                        var lng = coords[1];
                        var severity = data.severity || 'Low';
                        var count = data.count || 0;
                        var color, size;
                        
                        var sev = severity.toLowerCase();
                        if (sev === 'critical') {
                            color = '#8B0000';
                            size = Math.min(Math.sqrt(count) * 2.5, 35);
                        } else if (sev === 'high') {
                            color = '#dc3545';
                            size = Math.min(Math.sqrt(count) * 2, 30);
                        } else if (sev === 'medium') {
                            color = '#ffc107';
                            size = Math.min(Math.sqrt(count) * 1.5, 25);
                        } else {
                            color = '#28a745';
                            size = Math.min(Math.sqrt(count) * 1.2, 20);
                        }
                        
                        var marker = L.circleMarker([lat, lng], {
                            radius: Math.max(size, 8),
                            fillColor: color,
                            color: '#ffffff',
                            weight: 2,
                            opacity: 1,
                            fillOpacity: 0.7
                        }).addTo(worldMap);
                        
                        var isBlocked = window.appConfig.blockedCountries.indexOf(country) !== -1;
                        var statusBadge = isBlocked ? 
                            '<span class="label label-danger">Blocked</span>' : 
                            '<span class="label label-success">Allowed</span>';
                        
                        var popupContent = 
                            '<div class="threat-popup">' +
                                '<h5>' + getCountryFlag(country) + ' ' + country + '</h5>' +
                                '<div class="popup-stats">' +
                                    '<div class="stat-row">' +
                                        '<span class="stat-label">Threats:</span>' +
                                        '<span class="stat-value">' + count.toLocaleString() + '</span>' +
                                    '</div>' +
                                    '<div class="stat-row">' +
                                        '<span class="stat-label">Percentage:</span>' +
                                        '<span class="stat-value">' + (data.percentage || '0') + '%</span>' +
                                    '</div>' +
                                    '<div class="stat-row">' +
                                        '<span class="stat-label">Top Attack:</span>' +
                                        '<span class="stat-value">' + (data.type || 'Unknown') + '</span>' +
                                    '</div>' +
                                    '<div class="stat-row">' +
                                        '<span class="stat-label">Severity:</span>' +
                                        '<span class="label label-' + getSeverityColor(severity) + '">' + severity + '</span>' +
                                    '</div>' +
                                    '<div class="stat-row">' +
                                        '<span class="stat-label">Status:</span>' +
                                        statusBadge +
                                    '</div>' +
                                '</div>' +
                                '<div class="popup-actions">' +
                                    (!isBlocked ? 
                                    '<button class="btn btn-xs btn-danger" onclick="blockCountry(\'' + country + '\')">' +
                                        '<i class="fa fa-ban"></i> Block' +
                                    '</button>' :
                                    '<button class="btn btn-xs btn-success" onclick="unblockCountry(\'' + country + '\')">' +
                                        '<i class="fa fa-check"></i> Unblock' +
                                    '</button>') +
                                    '<button class="btn btn-xs btn-info" onclick="viewCountryDetails(\'' + country + '\')">' +
                                        '<i class="fa fa-eye"></i> Details' +
                                    '</button>' +
                                '</div>' +
                            '</div>';
                        
                        marker.bindPopup(popupContent, {
                            maxWidth: 300,
                            className: 'threat-marker-popup'
                        });
                        
                        marker.on('mouseover', function() {
                            this.setStyle({
                                weight: 3,
                                fillOpacity: 0.9
                            });
                        });
                        
                        marker.on('mouseout', function() {
                            this.setStyle({
                                weight: 2,
                                fillOpacity: 0.7
                            });
                        });
                    }
                }
            }
            
            addMapLegend();
        }
        
        function addMapLegend() {
            if (mapLegend) {
                worldMap.removeControl(mapLegend);
            }
            
            mapLegend = L.control({ position: 'bottomright' });
            
            mapLegend.onAdd = function(map) {
                var div = L.DomUtil.create('div', 'map-legend');
                div.innerHTML = 
                    '<h6>Threat Levels</h6>' +
                    '<div class="legend-item">' +
                        '<span class="legend-dot" style="background-color: #8B0000;"></span>' +
                        '<span>Critical</span>' +
                    '</div>' +
                    '<div class="legend-item">' +
                        '<span class="legend-dot" style="background-color: #dc3545;"></span>' +
                        '<span>High Risk</span>' +
                    '</div>' +
                    '<div class="legend-item">' +
                        '<span class="legend-dot" style="background-color: #ffc107;"></span>' +
                        '<span>Medium Risk</span>' +
                    '</div>' +
                    '<div class="legend-item">' +
                        '<span class="legend-dot" style="background-color: #28a745;"></span>' +
                        '<span>Low Risk</span>' +
                    '</div>' +
                    '<small class="legend-note">Circle size = threat count</small>';
                return div;
            };
            
            mapLegend.addTo(worldMap);
        }
        
        function updateGeoStats(data) {
            console.log('Updating geo stats with data:', data);
            
            $('#totalCountries').text(data.total_countries || 0);
            $('#geoThreats').text((data.total_threats || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","));
            
            var countries = data.countries || {};
            var topCountry = '--';
            var maxCount = 0;
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var count = countries[country].count || 0;
                    if (count > maxCount) {
                        maxCount = count;
                        topCountry = country;
                    }
                }
            }
            
            $('#topThreatCountry').text(topCountry);
        }
        
        function updateCountryList(countries) {
            var list = $('#countryList');
            list.empty();
            
            var countryArray = [];
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    countryArray.push([country, countries[country]]);
                }
            }
            
            if (countryArray.length === 0) {
                list.html('<div class="alert alert-info text-center"><i class="fa fa-info-circle"></i> ' + window.appConfig.translations.noDataAvailable + '</div>');
                return;
            }
            
            countryArray.sort(function(a, b) {
                return (b[1].count || 0) - (a[1].count || 0);
            });
            
            var topCountries = countryArray.slice(0, 10);
            
            for (var i = 0; i < topCountries.length; i++) {
                var country = topCountries[i][0];
                var data = topCountries[i][1];
                var severityColor = getSeverityColor(data.severity || 'Low');
                
                var item = $('<div class="country-item" data-country="' + country + '">' +
                    '<div class="country-info">' +
                        '<div class="country-name">' +
                            '<span class="country-flag">' + getCountryFlag(country) + '</span>' +
                            country +
                        '</div>' +
                        '<div class="country-stats">' +
                            '<span class="threats-count">' + (data.count || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",") + ' threats</span>' +
                            '<span class="threats-percentage">' + (data.percentage || 0) + '%</span>' +
                            '<span class="label label-' + severityColor + '">' + (data.severity || 'Low') + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="country-bar">' +
                        '<div class="bar-fill" style="width: ' + Math.min(data.percentage || 0, 100) + '%; background: ' + getSeverityGradient(data.severity || 'Low') + '"></div>' +
                    '</div>' +
                '</div>');
                
                item.click(function() {
                    var coords = countryCoordinates[$(this).data('country')];
                    if (coords && worldMap) {
                        worldMap.setView(coords, 5);
                    }
                });
                
                list.append(item);
            }
        }
        
        function updateCountryTable(countries) {
            var tbody = $('#countryTableBody');
            tbody.empty();
            
            var countryArray = [];
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    countryArray.push([country, countries[country]]);
                }
            }
            
            if (countryArray.length === 0) {
                tbody.html('<tr><td colspan="8" class="text-center">' + window.appConfig.translations.noDataAvailable + '</td></tr>');
                return;
            }
            
            var blockedCountries = window.appConfig.blockedCountries || [];
            
            for (var i = 0; i < countryArray.length; i++) {
                var country = countryArray[i][0];
                var data = countryArray[i][1];
                var isBlocked = blockedCountries.indexOf(country) !== -1;
                var statusBadge = isBlocked ? 
                    '<span class="label label-danger">Blocked</span>' : 
                    '<span class="label label-success">Allowed</span>';
                
                var severityBadge = '<span class="label label-' + getSeverityColor(data.severity || 'Low') + '">' + (data.severity || 'Low') + '</span>';
                
                var row = $('<tr>' +
                    '<td><strong>' + country + '</strong></td>' +
                    '<td><span class="country-flag">' + getCountryFlag(country) + '</span></td>' +
                    '<td><strong>' + (data.count || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",") + '</strong></td>' +
                    '<td>' +
                        '<div class="progress" style="height: 20px;">' +
                            '<div class="progress-bar progress-bar-danger" role="progressbar" ' +
                                 'style="width: ' + (data.percentage || 0) + '%" ' +
                                 'aria-valuenow="' + (data.percentage || 0) + '" aria-valuemin="0" aria-valuemax="100">' +
                                (data.percentage || 0) + '%' +
                            '</div>' +
                        '</div>' +
                    '</td>' +
                    '<td><span class="label label-default">' + (data.type || 'Unknown') + '</span></td>' +
                    '<td>' + severityBadge + '</td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' +
                        '<div class="btn-group">' +
                            (!isBlocked ? 
                            '<button class="btn btn-xs btn-danger" onclick="blockCountry(\'' + country + '\')">' +
                                '<i class="fa fa-ban"></i> Block' +
                            '</button>' :
                            '<button class="btn btn-xs btn-success" onclick="unblockCountry(\'' + country + '\')">' +
                                '<i class="fa fa-check"></i> Unblock' +
                            '</button>') +
                            '<button class="btn btn-xs btn-info" onclick="viewCountryDetails(\'' + country + '\')">' +
                                '<i class="fa fa-eye"></i> Details' +
                            '</button>' +
                        '</div>' +
                    '</td>' +
                '</tr>');
                tbody.append(row);
            }
        }
        
        function initCharts(data) {
            if (!data || !data.countries) {
                initEmptyCharts();
                return;
            }
            
            var countries = data.countries;
            
            // Regional Distribution Chart
            var regionData = calculateRegionalData(countries);
            var ctx1 = document.getElementById('regionChart').getContext('2d');
            regionChart = new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(regionData),
                    datasets: [{
                        data: Object.values(regionData),
                        backgroundColor: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD'],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { 
                            position: 'bottom',
                            labels: { padding: 20, usePointStyle: true }
                        }
                    }
                }
            });
            
            // Timeline Chart
            initTimelineChart();
            
            // Attack Types Chart
            var attackTypes = calculateAttackTypes(countries);
            var ctx3 = document.getElementById('attackTypesChart').getContext('2d');
            attackTypesChart = new Chart(ctx3, {
                type: 'bar',
                data: {
                    labels: Object.keys(attackTypes),
                    datasets: [{
                        label: 'Number of Attacks',
                        data: Object.values(attackTypes),
                        backgroundColor: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } },
                    plugins: { legend: { display: false } }
                }
            });
            
            // Severity Chart
            var severityData = calculateSeverityData(countries);
            var ctx4 = document.getElementById('severityChart').getContext('2d');
            severityChart = new Chart(ctx4, {
                type: 'pie',
                data: {
                    labels: Object.keys(severityData),
                    datasets: [{
                        data: Object.values(severityData),
                        backgroundColor: ['#8B0000', '#FF6B6B', '#FFEAA7', '#96CEB4'],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true } }
                    }
                }
            });
            
            // 24h Activity Heatmap
            initHeatmapChart();
        }
        
        function initTimelineChart() {
            // Load real timeline data from API
            ajaxCall('/api/webguard/threats/getTimeline', {period: '24h'}, function(response) {
                if (response && response.status === 'ok' && response.timeline) {
                    var ctx2 = document.getElementById('timelineChart').getContext('2d');
                    timelineChart = new Chart(ctx2, {
                        type: 'line',
                        data: {
                            labels: response.timeline.labels || [],
                            datasets: [{
                                label: 'Geographic Threats',
                                data: response.timeline.threats || [],
                                borderColor: '#3b82f6',
                                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                tension: 0.4
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: { beginAtZero: true, title: { display: true, text: 'Threats' } },
                                x: { title: { display: true, text: 'Time (UTC)' } }
                            },
                            plugins: {
                                legend: { position: 'top' }
                            }
                        }
                    });
                } else {
                    initEmptyTimelineChart();
                }
            }, function(error) {
                console.error('Failed to load timeline data:', error);
                initEmptyTimelineChart();
            });
        }
        
        function initHeatmapChart() {
            var ctx5 = document.getElementById('heatmapChart').getContext('2d');
            var hours = [];
            var activity = [];
            
            // Generate 24 hours of sample activity data
            for (var i = 0; i < 24; i++) {
                var hourStr = i < 10 ? '0' + i : i.toString();
                hours.push(hourStr + ':00');
                activity.push(Math.floor(Math.random() * 10));
            }
            
            heatmapChart = new Chart(ctx5, {
                type: 'bar',
                data: {
                    labels: hours,
                    datasets: [{
                        label: 'Threat Activity',
                        data: activity,
                        backgroundColor: activity.map(function(value, index, array) {
                            var max = Math.max.apply(null, array);
                            var intensity = max > 0 ? value / max : 0;
                            return 'rgba(255, ' + (255 - Math.floor(intensity * 200)) + ', ' + (255 - Math.floor(intensity * 200)) + ', 0.8)';
                        }),
                        borderWidth: 1,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { 
                        y: { beginAtZero: true, title: { display: true, text: 'Activity Level' } },
                        x: { title: { display: true, text: 'Hour (UTC)' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }
        
        function initEmptyCharts() {
            initEmptyRegionChart();
            initEmptyTimelineChart();
            initEmptyAttackTypesChart();
            initEmptySeverityChart();
            initEmptyHeatmapChart();
        }
        
        function initEmptyRegionChart() {
            var ctx1 = document.getElementById('regionChart').getContext('2d');
            regionChart = new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: ['No Data'],
                    datasets: [{
                        data: [1],
                        backgroundColor: ['#f8f9fa'],
                        borderWidth: 2,
                        borderColor: '#dee2e6'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } }
                }
            });
        }
        
        function initEmptyTimelineChart() {
            var ctx2 = document.getElementById('timelineChart').getContext('2d');
            timelineChart = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                    datasets: [{
                        label: 'No Data Available',
                        data: [0, 0, 0, 0, 0, 0],
                        borderColor: '#ddd',
                        backgroundColor: 'rgba(221, 221, 221, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, title: { display: true, text: 'Threats' } },
                        x: { title: { display: true, text: 'Time (UTC)' } }
                    }
                }
            });
        }
        
        function initEmptyAttackTypesChart() {
            var ctx3 = document.getElementById('attackTypesChart').getContext('2d');
            attackTypesChart = new Chart(ctx3, {
                type: 'bar',
                data: {
                    labels: ['No Data'],
                    datasets: [{
                        label: 'No Attacks',
                        data: [0],
                        backgroundColor: ['#f8f9fa'],
                        borderWidth: 1,
                        borderColor: '#dee2e6'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } },
                    plugins: { legend: { display: false } }
                }
            });
        }
        
        function initEmptySeverityChart() {
            var ctx4 = document.getElementById('severityChart').getContext('2d');
            severityChart = new Chart(ctx4, {
                type: 'pie',
                data: {
                    labels: ['No Data'],
                    datasets: [{
                        data: [1],
                        backgroundColor: ['#f8f9fa'],
                        borderWidth: 2,
                        borderColor: '#dee2e6'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } }
                }
            });
        }
        
        function initEmptyHeatmapChart() {
            var ctx5 = document.getElementById('heatmapChart').getContext('2d');
            var emptyLabels = [];
            var emptyData = [];
            for (var i = 0; i < 24; i++) {
                var hourStr = i.toString();
                if (hourStr.length < 2) hourStr = '0' + hourStr;
                emptyLabels.push(hourStr + ':00');
                emptyData.push(0);
            }
            heatmapChart = new Chart(ctx5, {
                type: 'bar',
                data: {
                    labels: emptyLabels,
                    datasets: [{
                        label: 'No Activity Data',
                        data: emptyData,
                        backgroundColor: '#f8f9fa',
                        borderWidth: 1,
                        borderColor: '#dee2e6'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { 
                        y: { beginAtZero: true, title: { display: true, text: 'Activity Level' } },
                        x: { title: { display: true, text: 'Hour (UTC)' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }
        
        function calculateRegionalData(countries) {
            var regionMap = {
                'Asia': ['China', 'India', 'Japan', 'South Korea', 'Vietnam', 'Iran', 'Thailand', 'Singapore', 'Indonesia', 'North Korea', 'Pakistan'],
                'Europe': ['Russia', 'Germany', 'France', 'United Kingdom', 'Turkey', 'Ukraine', 'Poland', 'Italy', 'Spain', 'Netherlands', 'Belgium'],
                'North America': ['United States', 'Canada', 'Mexico'],
                'South America': ['Brazil', 'Argentina'],
                'Africa': ['South Africa', 'Egypt', 'Nigeria'],
                'Oceania': ['Australia']
            };
            
            var regionData = {};
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var data = countries[country];
                    var region = 'Other';
                    
                    for (var r in regionMap) {
                        if (regionMap.hasOwnProperty(r) && regionMap[r].indexOf(country) !== -1) {
                            region = r;
                            break;
                        }
                    }
                    
                    regionData[region] = (regionData[region] || 0) + (data.count || 0);
                }
            }
            
            return regionData;
        }
        
        function calculateAttackTypes(countries) {
            var attackTypes = {};
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var data = countries[country];
                    var type = data.type || 'Unknown';
                    attackTypes[type] = (attackTypes[type] || 0) + (data.count || 0);
                }
            }
            return attackTypes;
        }
        
        function calculateSeverityData(countries) {
            var severityData = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var data = countries[country];
                    var severity = data.severity || 'Low';
                    severityData[severity] = (severityData[severity] || 0) + (data.count || 0);
                }
            }
            return severityData;
        }
        
        function populateCountrySelect(countries) {
            var select = $('#countrySelect');
            select.find('option:not(:first)').remove();
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country) && window.appConfig.blockedCountries.indexOf(country) === -1) {
                    select.append('<option value="' + country + '">' + getCountryFlag(country) + ' ' + country + '</option>');
                }
            }
        }
        
        function updateBlockedCountriesList() {
            var container = $('#blockedCountriesList');
            container.empty();
            
            if (!window.appConfig.blockedCountries || window.appConfig.blockedCountries.length === 0) {
                container.html('<p class="text-muted">No countries are currently blocked.</p>');
                return;
            }
            
            for (var i = 0; i < window.appConfig.blockedCountries.length; i++) {
                var country = window.appConfig.blockedCountries[i];
                var tag = $('<span class="blocked-country-tag">' +
                    getCountryFlag(country) + ' ' + country +
                    '<button class="btn btn-xs btn-secondary" onclick="unblockCountry(\'' + country + '\')">' +
                        '<i class="fa fa-times"></i>' +
                    '</button>' +
                '</span>');
                container.append(tag);
            }
        }
        
        function initControls() {
            if (window.appConfig.geoBlocking) {
                $('#blockCountryBtn').click(function() {
                    var country = $('#countrySelect').val();
                    if (!country) {
                        alert(window.appConfig.translations.pleaseSelectCountry);
                        return;
                    }
                    
                    var confirmMessage = window.appConfig.translations.blockTrafficFrom + ' ' + country + '?';
                    if (confirm(confirmMessage)) {
                        // Real API call to block country
                        ajaxCall('/api/webguard/service/blockCountry', {
                            country: country,
                            reason: 'Geographic_block_' + country.replace(/\s+/g, '_'),
                            duration: 86400
                        }, function(response) {
                            if (response.status === 'ok') {
                                window.appConfig.blockedCountries.push(country);
                                alert(country + ' ' + window.appConfig.translations.blockedSuccessfully);
                                $('#countrySelect option[value="' + country + '"]').remove();
                                updateBlockedCountriesList();
                                if (currentGeoData) {
                                    updateCountryTable(currentGeoData.countries || {});
                                    updateMapMarkers(currentGeoData.countries || {});
                                }
                                $('#blockedCountries').text(window.appConfig.blockedCountries.length);
                            } else {
                                alert('Error: ' + (response.message || 'Failed to block country'));
                            }
                        }, function(error) {
                            alert('Error blocking country: ' + error);
                        });
                    }
                });
            }
            
            // Auto-refresh data every 5 minutes
            setInterval(function() {
                if (!document.hidden) {
                    loadGeoData();
                }
            }, 300000);
        }
        
        function getSeverityColor(severity) {
            if (!severity) return 'default';
            var sev = severity.toLowerCase();
            if (sev === 'critical') return 'danger';
            if (sev === 'high') return 'danger'; 
            if (sev === 'medium') return 'warning';
            if (sev === 'low') return 'success';
            return 'default';
        }
        
        function getSeverityGradient(severity) {
            if (!severity) return 'linear-gradient(90deg, #6c757d, #545b62)';
            var sev = severity.toLowerCase();
            if (sev === 'critical') return 'linear-gradient(90deg, #8B0000, #A0000A)';
            if (sev === 'high') return 'linear-gradient(90deg, #dc3545, #c82333)';
            if (sev === 'medium') return 'linear-gradient(90deg, #ffc107, #e0a800)';
            if (sev === 'low') return 'linear-gradient(90deg, #17a2b8, #138496)';
            return 'linear-gradient(90deg, #6c757d, #545b62)';
        }
        
        function getCountryFlag(country) {
            var flags = {
                'China': '🇨🇳', 'Russia': '🇷🇺', 'United States': '🇺🇸', 'Brazil': '🇧🇷',
                'India': '🇮🇳', 'Germany': '🇩🇪', 'France': '🇫🇷', 'United Kingdom': '🇬🇧',
                'Japan': '🇯🇵', 'South Korea': '🇰🇷', 'Turkey': '🇹🇷', 'Iran': '🇮🇷',
                'Ukraine': '🇺🇦', 'Poland': '🇵🇱', 'Vietnam': '🇻🇳', 'Italy': '🇮🇹',
                'Spain': '🇪🇸', 'Netherlands': '🇳🇱', 'Canada': '🇨🇦', 'Australia': '🇦🇺',
                'Mexico': '🇲🇽', 'Argentina': '🇦🇷', 'South Africa': '🇿🇦', 'Egypt': '🇪🇬',
                'Nigeria': '🇳🇬', 'Israel': '🇮🇱', 'Saudi Arabia': '🇸🇦', 'Thailand': '🇹🇭',
                'Singapore': '🇸🇬', 'Indonesia': '🇮🇩', 'North Korea': '🇰🇵', 'Pakistan': '🇵🇰',
                'Belgium': '🇧🇪', 'Unknown': '🏳️'
            };
            return flags[country] || '🏳️';
        }
        
        // Global functions for country actions
        window.blockCountry = function(country) {
            var confirmMessage = window.appConfig.translations.blockTrafficFrom + ' ' + country + '?';
            if (confirm(confirmMessage)) {
                ajaxCall('/api/webguard/service/blockCountry', {
                    country: country,
                    reason: 'Manual_geographic_block',
                    duration: 86400
                }, function(response) {
                    if (response.status === 'ok') {
                        if (window.appConfig.blockedCountries.indexOf(country) === -1) {
                            window.appConfig.blockedCountries.push(country);
                        }
                        alert(country + ' ' + window.appConfig.translations.blockedSuccessfully);
                        location.reload();
                    } else {
                        alert('Error: ' + (response.message || 'Failed to block country'));
                    }
                }, function(error) {
                    alert('Error blocking country: ' + error);
                });
            }
        };
        
        window.unblockCountry = function(country) {
            var confirmMessage = window.appConfig.translations.unblockTrafficFrom + ' ' + country + '?';
            if (confirm(confirmMessage)) {
                ajaxCall('/api/webguard/service/unblockCountry', {
                    country: country
                }, function(response) {
                    if (response.status === 'ok') {
                        var index = window.appConfig.blockedCountries.indexOf(country);
                        if (index > -1) {
                            window.appConfig.blockedCountries.splice(index, 1);
                        }
                        alert(country + ' ' + window.appConfig.translations.unblockedSuccessfully);
                        location.reload();
                    } else {
                        alert('Error: ' + (response.message || 'Failed to unblock country'));
                    }
                }, function(error) {
                    alert('Error unblocking country: ' + error);
                });
            }
        };
        
        window.viewCountryDetails = function(country) {
            if (currentGeoData && currentGeoData.countries && currentGeoData.countries[country]) {
                var data = currentGeoData.countries[country];
                var details = 'Country: ' + country + '\n';
                details += 'Threats: ' + (data.count || 0) + '\n';
                details += 'Percentage: ' + (data.percentage || 0) + '%\n';
                details += 'Top Attack: ' + (data.type || 'Unknown') + '\n';
                details += 'Severity: ' + (data.severity || 'Low') + '\n';
                details += 'Region: ' + (data.region || 'Unknown');
                alert(details);
            } else {
                alert('No detailed information available for ' + country);
            }
        };
        
        // Debug function to test API directly
        window.testGeoAPI = function() {
            console.log('Testing Geo API directly...');
            
            $.ajax({
                url: '/api/webguard/threats/getGeoStats',
                method: 'GET',
                data: { period: '24h' },
                success: function(response) {
                    console.log('Direct API test result:', response);
                },
                error: function(xhr, status, error) {
                    console.error('Direct API test failed:', {
                        status: status,
                        error: error,
                        response: xhr.responseText
                    });
                }
            });
        };
        
        // Auto-refresh every 5 minutes, but only if page is visible
        setInterval(function() {
            if (!document.hidden) {
                console.log('Auto-refreshing geo data...');
                loadGeoData();
            }
        }, 300000);
    });
</script>