{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}

<!-- Include external libraries only -->
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
                <h1>{{ lang._('Geographic Threat Analysis') }}</h1>
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

{% set appConfig = {
    geoBlocking: geoBlocking,
    blockedCountries: blockedCountries,
    translations: {
        pleaseSelectCountry: lang._('Please select a country'),
        blockTrafficFrom:   lang._('Block all traffic from'),
        blockedSuccessfully: lang._('blocked successfully'),
        unblockTrafficFrom: lang._('Unblock traffic from'),
        unblockedSuccessfully: lang._('unblocked successfully'),
        detailedAnalysisFor: lang._('Detailed analysis for'),
        wouldOpenHere:       lang._('would open here'),
        loadingData:        lang._('Loading threat data...'),
        noDataAvailable:    lang._('No data available'),
        confirmBlock:       lang._('Are you sure you want to block this country?'),
        confirmUnblock:     lang._('Are you sure you want to unblock this country?')
    }
} %}

<script type="text/javascript">
    window.appConfig = {{ appConfig|json_encode(constant('JSON_UNESCAPED_UNICODE'))|raw }};

// Country coordinates mapping for map display
const countryCoordinates = {
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
    'Pakistan': [30.3753, 69.3451]
};

// Mock threat data for demonstration
const mockThreatData = {
    total_countries: 15,
    countries: {
        'China': { count: 2847, percentage: 28.5, type: 'Brute Force', severity: 'High', region: 'Asia' },
        'Russia': { count: 1923, percentage: 19.2, type: 'DDoS', severity: 'High', region: 'Europe' },
        'North Korea': { count: 1456, percentage: 14.6, type: 'Advanced Persistent Threat', severity: 'Critical', region: 'Asia' },
        'Iran': { count: 892, percentage: 8.9, type: 'Web Application Attack', severity: 'Medium', region: 'Asia' },
        'Turkey': { count: 654, percentage: 6.5, type: 'Reconnaissance', severity: 'Medium', region: 'Europe' },
        'Brazil': { count: 478, percentage: 4.8, type: 'Malware', severity: 'Medium', region: 'South America' },
        'India': { count: 387, percentage: 3.9, type: 'Phishing', severity: 'Low', region: 'Asia' },
        'Vietnam': { count: 298, percentage: 3.0, type: 'Botnet', severity: 'Medium', region: 'Asia' },
        'Pakistan': { count: 234, percentage: 2.3, type: 'SQL Injection', severity: 'Medium', region: 'Asia' },
        'Ukraine': { count: 189, percentage: 1.9, type: 'Cross-site Scripting', severity: 'Low', region: 'Europe' },
        'United States': { count: 156, percentage: 1.6, type: 'Insider Threat', severity: 'Low', region: 'North America' },
        'Germany': { count: 134, percentage: 1.3, type: 'Social Engineering', severity: 'Low', region: 'Europe' },
        'Thailand': { count: 98, percentage: 1.0, type: 'Ransomware', severity: 'High', region: 'Asia' },
        'Indonesia': { count: 76, percentage: 0.8, type: 'Data Breach', severity: 'Medium', region: 'Asia' },
        'Nigeria': { count: 45, percentage: 0.5, type: 'Email Fraud', severity: 'Low', region: 'Africa' }
    }
};

$(document).ready(function() {
    let regionChart, timelineChart, attackTypesChart, severityChart, heatmapChart, worldMap;
    let currentGeoData = null;
    let mapLegend = null;
    
    // Initialize
    initLeafletMap();
    loadGeoData();
    initControls();
    
    function loadGeoData() {
        // In a real implementation, this would call the actual OPNsense API
        // ajaxCall('/api/webguard/threats/getGeoStats', {period: '24h'}, function(response) {
        
        // Simulate loading delay
        setTimeout(function() {
            // Use mock data for demonstration
            if (mockThreatData) {
                currentGeoData = mockThreatData;
                updateGeoStats(currentGeoData);
                updateCountryList(currentGeoData.countries || {});
                updateCountryTable(currentGeoData.countries || {});
                updateMapMarkers(currentGeoData.countries || {});
                populateCountrySelect(currentGeoData.countries || {});
                updateBlockedCountriesList();
                initCharts(currentGeoData);
            } else {
                showNoDataMessage();
            }
        }, 1500);
        
        // For real implementation, uncomment below:
        /*
        ajaxCall('/api/webguard/threats/getGeoStats', {period: '24h'}, function(response) {
            if (response && response.status === 'ok' && response.data) {
                currentGeoData = response.data;
                updateGeoStats(currentGeoData);
                updateCountryList(currentGeoData.countries || {});
                updateCountryTable(currentGeoData.countries || {});
                updateMapMarkers(currentGeoData.countries || {});
                populateCountrySelect(currentGeoData.countries || {});
                updateBlockedCountriesList();
                initCharts(currentGeoData);
            } else {
                showNoDataMessage();
            }
        }, function(error) {
            console.error('Failed to load geo data:', error);
            showNoDataMessage();
        });
        */
    }
    
    function showNoDataMessage() {
        $('#countryList').html('<div class="alert alert-info"><i class="fa fa-info-circle"></i> ' + window.appConfig.translations.noDataAvailable + '</div>');
        $('#countryTableBody').html('<tr><td colspan="8" class="text-center">' + window.appConfig.translations.noDataAvailable + '</td></tr>');
        $('#totalCountries').text('0');
        $('#geoThreats').text('0');
        $('#topThreatCountry').text('--');
    }
    
    function initLeafletMap() {
        // Initialize Leaflet map
        worldMap = L.map('worldMap').setView([20, 0], 2);
        
        // Add OpenStreetMap tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 18,
            minZoom: 1
        }).addTo(worldMap);
        
        // Set map options
        worldMap.options.scrollWheelZoom = true;
        worldMap.options.doubleClickZoom = true;
        worldMap.options.touchZoom = true;
        
        // Add loading indicator
        const mapContainer = document.getElementById('worldMapContainer');
        const loadingDiv = document.createElement('div');
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
        
        // Remove loading indicator
        const loadingDiv = document.getElementById('mapLoading');
        if (loadingDiv) {
            loadingDiv.remove();
        }
        
        // Clear existing markers
        worldMap.eachLayer(function(layer) {
            if (layer instanceof L.CircleMarker) {
                worldMap.removeLayer(layer);
            }
        });
        
        // Add markers for countries with threat data
        Object.entries(countries).forEach(([country, data]) => {
            const coords = countryCoordinates[country];
            if (coords && coords.length === 2) {
                const [lat, lng] = coords;
                
                // Determine marker color and size based on data
                let color, size;
                const severity = data.severity || 'Low';
                const count = data.count || 0;
                
                switch (severity.toLowerCase()) {
                    case 'critical':
                        color = '#8B0000';
                        size = Math.min(Math.sqrt(count) * 2.5, 35);
                        break;
                    case 'high':
                        color = '#dc3545';
                        size = Math.min(Math.sqrt(count) * 2, 30);
                        break;
                    case 'medium':
                        color = '#ffc107';
                        size = Math.min(Math.sqrt(count) * 1.5, 25);
                        break;
                    case 'low':
                    default:
                        color = '#28a745';
                        size = Math.min(Math.sqrt(count) * 1.2, 20);
                        break;
                }
                
                // Create circle marker
                const marker = L.circleMarker([lat, lng], {
                    radius: Math.max(size, 8),
                    fillColor: color,
                    color: '#ffffff',
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 0.7
                }).addTo(worldMap);
                
                // Create popup content
                const isBlocked = window.appConfig.blockedCountries.includes(country);
                const statusBadge = isBlocked ? 
                    '<span class="label label-danger">Blocked</span>' : 
                    '<span class="label label-success">Allowed</span>';
                
                const popupContent = `
                    <div class="threat-popup">
                        <h5>${getCountryFlag(country)} ${country}</h5>
                        <div class="popup-stats">
                            <div class="stat-row">
                                <span class="stat-label">Threats:</span>
                                <span class="stat-value">${count.toLocaleString()}</span>
                            </div>
                            <div class="stat-row">
                                <span class="stat-label">Percentage:</span>
                                <span class="stat-value">${data.percentage || '0'}%</span>
                            </div>
                            <div class="stat-row">
                                <span class="stat-label">Top Attack:</span>
                                <span class="stat-value">${data.type || 'Unknown'}</span>
                            </div>
                            <div class="stat-row">
                                <span class="stat-label">Severity:</span>
                                <span class="label label-${getSeverityColor(severity)}">${severity}</span>
                            </div>
                            <div class="stat-row">
                                <span class="stat-label">Status:</span>
                                ${statusBadge}
                            </div>
                        </div>
                        <div class="popup-actions">
                            ${!isBlocked ? `
                            <button class="btn btn-xs btn-danger" onclick="blockCountry('${country}')">
                                <i class="fa fa-ban"></i> Block
                            </button>
                            ` : `
                            <button class="btn btn-xs btn-success" onclick="unblockCountry('${country}')">
                                <i class="fa fa-check"></i> Unblock
                            </button>
                            `}
                            <button class="btn btn-xs btn-info" onclick="viewCountryDetails('${country}')">
                                <i class="fa fa-eye"></i> Details
                            </button>
                        </div>
                    </div>
                `;
                
                marker.bindPopup(popupContent, {
                    maxWidth: 300,
                    className: 'threat-marker-popup'
                });
                
                // Add hover effects
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
        });
        
        // Add map legend
        addMapLegend();
    }
    
    function addMapLegend() {
        // Remove existing legend
        if (mapLegend) {
            worldMap.removeControl(mapLegend);
        }
        
        // Create legend control
        mapLegend = L.control({ position: 'bottomright' });
        
        mapLegend.onAdd = function(map) {
            const div = L.DomUtil.create('div', 'map-legend');
            div.innerHTML = `
                <h6>Threat Levels</h6>
                <div class="legend-item">
                    <span class="legend-dot" style="background-color: #8B0000;"></span>
                    <span>Critical</span>
                </div>
                <div class="legend-item">
                    <span class="legend-dot" style="background-color: #dc3545;"></span>
                    <span>High Risk</span>
                </div>
                <div class="legend-item">
                    <span class="legend-dot" style="background-color: #ffc107;"></span>
                    <span>Medium Risk</span>
                </div>
                <div class="legend-item">
                    <span class="legend-dot" style="background-color: #28a745;"></span>
                    <span>Low Risk</span>
                </div>
                <small class="legend-note">Circle size = threat count</small>
            `;
            return div;
        };
        
        mapLegend.addTo(worldMap);
    }
    
    function updateGeoStats(data) {
        $('#totalCountries').text(data.total_countries || 0);
        
        const countries = data.countries || {};
        const totalThreats = Object.values(countries).reduce((sum, country) => sum + (country.count || 0), 0);
        $('#geoThreats').text(totalThreats.toLocaleString());
        
        // Find top threat country
        const topCountry = Object.keys(countries).reduce((a, b) => 
            (countries[a]?.count || 0) > (countries[b]?.count || 0) ? a : b, Object.keys(countries)[0]);
        $('#topThreatCountry').text(topCountry || '--');
    }
    
    function updateCountryList(countries) {
        const list = $('#countryList');
        list.empty();
        
        if (Object.keys(countries).length === 0) {
            list.html('<div class="alert alert-info text-center"><i class="fa fa-info-circle"></i> ' + window.appConfig.translations.noDataAvailable + '</div>');
            return;
        }
        
        const sortedCountries = Object.entries(countries)
            .sort(([,a], [,b]) => (b.count || 0) - (a.count || 0))
            .slice(0, 10);
        
        sortedCountries.forEach(([country, data]) => {
            const severityColor = getSeverityColor(data.severity || 'Low');
            const item = $(`
                <div class="country-item" data-country="${country}">
                    <div class="country-info">
                        <div class="country-name">
                            <span class="country-flag">${getCountryFlag(country)}</span>
                            ${country}
                        </div>
                        <div class="country-stats">
                            <span class="threats-count">${(data.count || 0).toLocaleString()} threats</span>
                            <span class="threats-percentage">${data.percentage || 0}%</span>
                            <span class="label label-${severityColor}">${data.severity || 'Low'}</span>
                        </div>
                    </div>
                    <div class="country-bar">
                        <div class="bar-fill" style="width: ${Math.min(data.percentage || 0, 100)}%; background: ${getSeverityGradient(data.severity || 'Low')}"></div>
                    </div>
                </div>
            `);
            
            // Add click handler to center map on country
            item.click(function() {
                const coords = countryCoordinates[country];
                if (coords && worldMap) {
                    worldMap.setView(coords, 5);
                }
            });
            
            list.append(item);
        });
    }
    
    function updateCountryTable(countries) {
        const tbody = $('#countryTableBody');
        tbody.empty();
        
        if (Object.keys(countries).length === 0) {
            tbody.html('<tr><td colspan="8" class="text-center">' + window.appConfig.translations.noDataAvailable + '</td></tr>');
            return;
        }
        
        const blockedCountries = window.appConfig.blockedCountries || [];
        
        Object.entries(countries).forEach(([country, data]) => {
            const isBlocked = blockedCountries.includes(country);
            const statusBadge = isBlocked ? 
                '<span class="label label-danger">Blocked</span>' : 
                '<span class="label label-success">Allowed</span>';
            
            const severityBadge = `<span class="label label-${getSeverityColor(data.severity || 'Low')}">${data.severity || 'Low'}</span>`;
            
            const row = $(`
                <tr>
                    <td><strong>${country}</strong></td>
                    <td><span class="country-flag">${getCountryFlag(country)}</span></td>
                    <td><strong>${(data.count || 0).toLocaleString()}</strong></td>
                    <td>
                        <div class="progress" style="height: 20px;">
                            <div class="progress-bar progress-bar-danger" role="progressbar" 
                                 style="width: ${data.percentage || 0}%" 
                                 aria-valuenow="${data.percentage || 0}" aria-valuemin="0" aria-valuemax="100">
                                ${data.percentage || 0}%
                            </div>
                        </div>
                    </td>
                    <td><span class="label label-default">${data.type || 'Unknown'}</span></td>
                    <td>${severityBadge}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <div class="btn-group">
                            ${!isBlocked ? `
                            <button class="btn btn-xs btn-danger" onclick="blockCountry('${country}')">
                                <i class="fa fa-ban"></i> Block
                            </button>
                            ` : `
                            <button class="btn btn-xs btn-success" onclick="unblockCountry('${country}')">
                                <i class="fa fa-check"></i> Unblock
                            </button>
                            `}
                            <button class="btn btn-xs btn-info" onclick="viewCountryDetails('${country}')">
                                <i class="fa fa-eye"></i> Details
                            </button>
                        </div>
                    </td>
                </tr>
            `);
            tbody.append(row);
        });
    }
    
    function initCharts(data) {
        if (!data || !data.countries) {
            initEmptyCharts();
            return;
        }
        
        const countries = data.countries;
        
        // Regional Distribution Chart
        const regionData = calculateRegionalData(countries);
        const ctx1 = document.getElementById('regionChart').getContext('2d');
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
        const attackTypes = calculateAttackTypes(countries);
        const ctx3 = document.getElementById('attackTypesChart').getContext('2d');
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
        const severityData = calculateSeverityData(countries);
        const ctx4 = document.getElementById('severityChart').getContext('2d');
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
        // In real implementation, call API for timeline data
        // ajaxCall('/api/webguard/threats/getTimeline', {period: '24h'}, function(response) {
        
        // Mock timeline data
        const mockTimelineData = generateMockTimelineData();
        const ctx2 = document.getElementById('timelineChart').getContext('2d');
        timelineChart = new Chart(ctx2, {
            type: 'line',
            data: mockTimelineData,
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
    }
    
    function initHeatmapChart() {
        // In real implementation, call API for heatmap data
        // ajaxCall('/api/webguard/threats/getStats', {period: '24h'}, function(response) {
        
        // Mock heatmap data
        const mockHeatmapData = generateMockHeatmapData();
        const ctx5 = document.getElementById('heatmapChart').getContext('2d');
        heatmapChart = new Chart(ctx5, {
            type: 'bar',
            data: {
                labels: mockHeatmapData.labels,
                datasets: [{
                    label: 'Threat Activity',
                    data: mockHeatmapData.data,
                    backgroundColor: mockHeatmapData.data.map(value => {
                        const max = Math.max(...mockHeatmapData.data);
                        const intensity = value / max;
                        return `rgba(255, ${255 - Math.floor(intensity * 200)}, ${255 - Math.floor(intensity * 200)}, 0.8)`;
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
        // Empty Regional Distribution Chart
        const ctx1 = document.getElementById('regionChart').getContext('2d');
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
        
        // Empty Timeline Chart
        const ctx2 = document.getElementById('timelineChart').getContext('2d');
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
        
        // Empty Attack Types Chart
        const ctx3 = document.getElementById('attackTypesChart').getContext('2d');
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
        
        // Empty Severity Chart
        const ctx4 = document.getElementById('severityChart').getContext('2d');
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
        
        // Empty Heatmap Chart
        const ctx5 = document.getElementById('heatmapChart').getContext('2d');
        heatmapChart = new Chart(ctx5, {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => i.toString().padStart(2, '0') + ':00'),
                datasets: [{
                    label: 'No Activity Data',
                    data: new Array(24).fill(0),
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
    
    function generateMockTimelineData() {
        const labels = [];
        const asiaData = [];
        const europeData = [];
        const americaData = [];
        
        for (let i = 23; i >= 0; i--) {
            const hour = new Date();
            hour.setHours(hour.getHours() - i);
            labels.push(hour.getHours().toString().padStart(2, '0') + ':00');
            
            asiaData.push(Math.floor(Math.random() * 100) + 50);
            europeData.push(Math.floor(Math.random() * 60) + 30);
            americaData.push(Math.floor(Math.random() * 40) + 20);
        }
        
        return {
            labels: labels,
            datasets: [
                {
                    label: 'Asia',
                    data: asiaData,
                    borderColor: '#FF6B6B',
                    backgroundColor: 'rgba(255, 107, 107, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Europe', 
                    data: europeData,
                    borderColor: '#4ECDC4',
                    backgroundColor: 'rgba(78, 205, 196, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Americas',
                    data: americaData,
                    borderColor: '#45B7D1',
                    backgroundColor: 'rgba(69, 183, 209, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        };
    }
    
    function generateMockHeatmapData() {
        const labels = Array.from({length: 24}, (_, i) => i.toString().padStart(2, '0'));
        const data = labels.map(() => Math.floor(Math.random() * 200) + 50);
        return { labels, data };
    }
    
    function calculateRegionalData(countries) {
        const regionMap = {
            'Asia': ['China', 'India', 'Japan', 'South Korea', 'Vietnam', 'Iran', 'Thailand', 'Singapore', 'Indonesia', 'North Korea', 'Pakistan'],
            'Europe': ['Russia', 'Germany', 'France', 'United Kingdom', 'Turkey', 'Ukraine', 'Poland', 'Italy', 'Spain', 'Netherlands'],
            'North America': ['United States', 'Canada', 'Mexico'],
            'South America': ['Brazil', 'Argentina'],
            'Africa': ['South Africa', 'Egypt', 'Nigeria'],
            'Oceania': ['Australia']
        };
        
        const regionData = {};
        
        Object.entries(countries).forEach(([country, data]) => {
            const region = Object.keys(regionMap).find(r => regionMap[r].includes(country)) || 'Other';
            regionData[region] = (regionData[region] || 0) + (data.count || 0);
        });
        
        return regionData;
    }
    
    function calculateAttackTypes(countries) {
        const attackTypes = {};
        Object.values(countries).forEach(data => {
            const type = data.type || 'Unknown';
            attackTypes[type] = (attackTypes[type] || 0) + (data.count || 0);
        });
        return attackTypes;
    }
    
    function calculateSeverityData(countries) {
        const severityData = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        Object.values(countries).forEach(data => {
            const severity = data.severity || 'Low';
            severityData[severity] = (severityData[severity] || 0) + (data.count || 0);
        });
        return severityData;
    }
    
    function populateCountrySelect(countries) {
        const select = $('#countrySelect');
        select.find('option:not(:first)').remove(); // Keep the default option
        
        Object.keys(countries).forEach(country => {
            if (!window.appConfig.blockedCountries.includes(country)) {
                select.append(`<option value="${country}">${getCountryFlag(country)} ${country}</option>`);
            }
        });
    }
    
    function updateBlockedCountriesList() {
        const container = $('#blockedCountriesList');
        container.empty();
        
        if (!window.appConfig.blockedCountries || window.appConfig.blockedCountries.length === 0) {
            container.html('<p class="text-muted">No countries are currently blocked.</p>');
            return;
        }
        
        window.appConfig.blockedCountries.forEach(country => {
            const tag = $(`
                <span class="blocked-country-tag">
                    ${getCountryFlag(country)} ${country}
                    <button class="btn btn-xs btn-secondary" onclick="unblockCountry('${country}')">
                        <i class="fa fa-times"></i>
                    </button>
                </span>
            `);
            container.append(tag);
        });
    }
    
    function initControls() {
        if (window.appConfig.geoBlocking) {
            $('#blockCountryBtn').click(function() {
                const country = $('#countrySelect').val();
                if (!country) {
                    alert(window.appConfig.translations.pleaseSelectCountry);
                    return;
                }
                
                const confirmMessage = window.appConfig.translations.blockTrafficFrom + ' ' + country + '?';
                if (confirm(confirmMessage)) {
                    // In real implementation, use actual API call:
                    // ajaxCall('/api/webguard/service/blockIP', {
                    //     ip: getCountryRepresentativeIP(country),
                    //     reason: 'Geographic_block_' + country.replace(/\s+/g, '_'),
                    //     block_type: 'geographic',
                    //     duration: 86400
                    // }, function(response) {
                    //     if (response.status === 'ok') {
                    //         window.appConfig.blockedCountries.push(country);
                    //         alert(country + ' ' + window.appConfig.translations.blockedSuccessfully);
                    //         // Update UI
                    //         $('#countrySelect option[value="' + country + '"]').remove();
                    //         updateBlockedCountriesList();
                    //         if (currentGeoData) {
                    //             updateCountryTable(currentGeoData.countries || {});
                    //         }
                    //         $('#blockedCountries').text(window.appConfig.blockedCountries.length);
                    //     } else {
                    //         alert('Error: ' + (response.message || 'Failed to block country'));
                    //     }
                    // }, function(error) {
                    //     alert('Error blocking country: ' + error);
                    // });
                    
                    // Mock implementation for demo
                    window.appConfig.blockedCountries.push(country);
                    alert(country + ' ' + window.appConfig.translations.blockedSuccessfully);
                    $('#countrySelect option[value="' + country + '"]').remove();
                    updateBlockedCountriesList();
                    if (currentGeoData) {
                        updateCountryTable(currentGeoData.countries || {});
                        updateMapMarkers(currentGeoData.countries || {});
                    }
                    $('#blockedCountries').text(window.appConfig.blockedCountries.length);
                }
            });
        }
        
        // Auto-refresh data every 5 minutes
        setInterval(function() {
            if (!document.hidden) {
                loadGeoData();
            }
        }, 300000); // 5 minutes
    }
    
    // Helper function to get a representative IP for a country (for blocking purposes)
    function getCountryRepresentativeIP(country) {
        // These are example IPs - in production you would use real IP ranges for countries
        const countryIPs = {
            'China': '1.2.3.4',
            'Russia': '5.6.7.8', 
            'North Korea': '9.10.11.12',
            'Iran': '13.14.15.16',
            'Turkey': '17.18.19.20'
        };
        return countryIPs[country] || '192.0.2.1'; // RFC 5737 test IP as fallback
    }
    
    // Helper functions
    function getSeverityColor(severity) {
        if (!severity) return 'default';
        switch(severity.toLowerCase()) {
            case 'critical':
                return 'danger';
            case 'high':
                return 'danger';
            case 'medium':
                return 'warning';
            case 'low':
                return 'success';
            default:
                return 'default';
        }
    }
    
    function getSeverityGradient(severity) {
        if (!severity) return 'linear-gradient(90deg, #6c757d, #545b62)';
        switch(severity.toLowerCase()) {
            case 'critical':
                return 'linear-gradient(90deg, #8B0000, #A0000A)';
            case 'high':
                return 'linear-gradient(90deg, #dc3545, #c82333)';
            case 'medium':
                return 'linear-gradient(90deg, #ffc107, #e0a800)';
            case 'low':
                return 'linear-gradient(90deg, #17a2b8, #138496)';
            default:
                return 'linear-gradient(90deg, #6c757d, #545b62)';
        }
    }
    
    function getCountryFlag(country) {
        const flags = {
            'China': '🇨🇳', 'Russia': '🇷🇺', 'United States': '🇺🇸', 'Brazil': '🇧🇷',
            'India': '🇮🇳', 'Germany': '🇩🇪', 'France': '🇫🇷', 'United Kingdom': '🇬🇧',
            'Japan': '🇯🇵', 'South Korea': '🇰🇷', 'Turkey': '🇹🇷', 'Iran': '🇮🇷',
            'Ukraine': '🇺🇦', 'Poland': '🇵🇱', 'Vietnam': '🇻🇳', 'Italy': '🇮🇹',
            'Spain': '🇪🇸', 'Netherlands': '🇳🇱', 'Canada': '🇨🇦', 'Australia': '🇦🇺',
            'Mexico': '🇲🇽', 'Argentina': '🇦🇷', 'South Africa': '🇿🇦', 'Egypt': '🇪🇬',
            'Nigeria': '🇳🇬', 'Israel': '🇮🇱', 'Saudi Arabia': '🇸🇦', 'Thailand': '🇹🇭',
            'Singapore': '🇸🇬', 'Indonesia': '🇮🇩', 'North Korea': '🇰🇵', 'Pakistan': '🇵🇰'
        };
        return flags[country] || '🏳️';
    }
    
    // Global functions for country actions
    window.blockCountry = function(country) {
        const confirmMessage = window.appConfig.translations.blockTrafficFrom + ' ' + country + '?';
        if (confirm(confirmMessage)) {
            // In real implementation, use actual API call
            // Mock implementation
            if (!window.appConfig.blockedCountries.includes(country)) {
                window.appConfig.blockedCountries.push(country);
                alert(country + ' ' + window.appConfig.translations.blockedSuccessfully);
                location.reload();
            }
        }
    };
    
    window.unblockCountry = function(country) {
        const confirmMessage = window.appConfig.translations.unblockTrafficFrom + ' ' + country + '?';
        if (confirm(confirmMessage)) {
            // In real implementation, use actual API call
            // Mock implementation
            const index = window.appConfig.blockedCountries.indexOf(country);
            if (index > -1) {
                window.appConfig.blockedCountries.splice(index, 1);
                alert(country + ' ' + window.appConfig.translations.unblockedSuccessfully);
                location.reload();
            }
        }
    };
    
    window.viewCountryDetails = function(country) {
        if (currentGeoData && currentGeoData.countries && currentGeoData.countries[country]) {
            const data = currentGeoData.countries[country];
            let details = 'Country: ' + country + '\n';
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
});
</script>