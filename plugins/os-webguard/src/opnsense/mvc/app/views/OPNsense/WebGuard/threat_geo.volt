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

.map-container, .country-list-container, .analysis-card, .table-container {
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

/* FIXED MODAL STYLES */
.country-details-modal {
    display: none;
    position: fixed;
    z-index: 10000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
}

.country-details-modal.show {
    display: block !important;
}

.country-details-content {
    background-color: #fefefe;
    margin: 5% auto;
    padding: 0;
    border-radius: 8px;
    width: 90%;
    max-width: 800px;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}

.modal-header {
    background: #f8f9fa;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid #dee2e6;
    border-radius: 8px 8px 0 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.modal-title {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
    color: #1f2937;
}

.close-modal {
    background: none;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
    color: #6b7280;
    padding: 0;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    transition: all 0.2s;
}

.close-modal:hover {
    color: #374151;
    background-color: #f3f4f6;
}

.modal-body {
    padding: 1.5rem;
}

.details-section {
    margin-bottom: 1.5rem;
}

.details-section h4 {
    margin: 0 0 1rem 0;
    color: #1f2937;
    border-bottom: 2px solid #e5e7eb;
    padding-bottom: 0.5rem;
}

.details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1rem;
}

.detail-item {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 6px;
    border-left: 4px solid #3b82f6;
}

.detail-label {
    font-weight: 600;
    color: #6b7280;
    font-size: 0.875rem;
    margin-bottom: 0.25rem;
}

.detail-value {
    color: #1f2937;
    font-size: 1.1rem;
    font-weight: 500;
}

.threats-list {
    max-height: 300px;
    overflow-y: auto;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
}

.threat-item {
    padding: 0.75rem;
    border-bottom: 1px solid #f3f4f6;
    transition: background-color 0.2s;
}

.threat-item:hover {
    background-color: #f8f9fa;
}

.threat-item:last-child {
    border-bottom: none;
}

.threat-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.threat-ip {
    font-family: monospace;
    font-weight: 600;
    color: #dc2626;
}

.threat-time {
    font-size: 0.875rem;
    color: #6b7280;
}

.threat-details {
    display: flex;
    gap: 1rem;
    font-size: 0.875rem;
}

.threat-type {
    background: #dbeafe;
    color: #1e40af;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
}

.modal-actions {
    padding: 1rem 1.5rem;
    border-top: 1px solid #dee2e6;
    background: #f8f9fa;
    border-radius: 0 0 8px 8px;
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
}

.modal-actions button {
    margin: 0;
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
    
    .popup-actions {
        flex-direction: column;
    }
    
    .country-details-content {
        margin: 2% auto;
        width: 95%;
    }
    
    .details-grid {
        grid-template-columns: 1fr;
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
        <div class="col-md-3">
            <div class="geo-stat-card">
                <div class="stat-icon">
                    <i class="fa fa-map-marker"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="uniqueIPs">0</div>
                    <div class="stat-label">{{ lang._('Unique IPs') }}</div>
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
                                <th>{{ lang._('Actions') }}</th>
                            </tr>
                        </thead>
                        <tbody id="countryTableBody">
                            <tr>
                                <td colspan="7" class="text-center">
                                    <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading threat data...') }}
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- FIXED Country Details Modal -->
<div id="countryDetailsModal" class="country-details-modal">
    <div class="country-details-content">
        <div class="modal-header">
            <h3 class="modal-title" id="modalCountryTitle">Country Details</h3>
            <button type="button" class="close-modal" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">
            <div class="details-section">
                <h4>{{ lang._('Overview') }}</h4>
                <div class="details-grid">
                    <div class="detail-item">
                        <div class="detail-label">{{ lang._('Total Threats') }}</div>
                        <div class="detail-value" id="modalTotalThreats">0</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">{{ lang._('Percentage of Total') }}</div>
                        <div class="detail-value" id="modalPercentage">0%</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">{{ lang._('Unique IPs') }}</div>
                        <div class="detail-value" id="modalUniqueIPs">0</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">{{ lang._('Region') }}</div>
                        <div class="detail-value" id="modalRegion">Unknown</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">{{ lang._('Top Attack Type') }}</div>
                        <div class="detail-value" id="modalAttackType">Unknown</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">{{ lang._('Severity Level') }}</div>
                        <div class="detail-value" id="modalSeverity">Low</div>
                    </div>
                </div>
            </div>
            
            <div class="details-section">
                <h4>{{ lang._('Recent Threats') }}</h4>
                <div id="modalThreatsList" class="threats-list">
                    <div class="text-center p-3">
                        <i class="fa fa-spinner fa-spin"></i> {{ lang._('Loading threat details...') }}
                    </div>
                </div>
            </div>
        </div>
        <div class="modal-actions">
            <button type="button" class="btn btn-secondary" id="modalCloseBtn">
                <i class="fa fa-times"></i> {{ lang._('Close') }}
            </button>
            <button type="button" class="btn btn-info" id="modalViewAllThreats">
                <i class="fa fa-list"></i> {{ lang._('View All Threats') }}
            </button>
        </div>
    </div>
</div>

<script type="text/javascript">
    // Initialize app configuration with JavaScript
    window.appConfig = {
        translations: {
            detailedAnalysisFor: 'Detailed analysis for',
            loadingData: 'Loading threat data...',
            noDataAvailable: 'No data available',
            loadingThreatDetails: 'Loading threat details...',
            noThreatsFound: 'No threats found for this country',
            viewingAllThreats: 'Viewing all threats from',
            threatDetails: 'Threat Details'
        }
    };

    // Country coordinates mapping for map display
    var countryCoordinates = {
        // United States variations
        'United States': [39.8283, -98.5795],
        'United States of America': [39.8283, -98.5795],
        'USA': [39.8283, -98.5795],
        'US': [39.8283, -98.5795],
        
        // Europe
        'Germany': [51.1657, 10.4515],
        'France': [46.6034, 1.8883],
        'United Kingdom': [55.3781, -3.4360],
        'Italy': [41.8719, 12.5674],
        'Spain': [40.4637, -3.7492],
        'Netherlands': [52.1326, 5.2913],
        'Russia': [61.5240, 105.3188],
        'Poland': [51.9194, 19.1451],
        'Belgium': [50.8503, 4.3517],
        'Switzerland': [46.8182, 8.2275],
        'Austria': [47.5162, 14.5501],
        'Czech Republic': [49.8175, 15.4730],
        'Sweden': [60.1282, 18.6435],
        'Norway': [60.4720, 8.4689],
        'Denmark': [56.2639, 9.5018],
        'Finland': [61.9241, 25.7482],
        'Ukraine': [48.3794, 31.1656],
        'Turkey': [38.9637, 35.2433],
        
        // Asia
        'China': [35.8617, 104.1954],
        'Japan': [36.2048, 138.2529],
        'India': [20.5937, 78.9629],
        'South Korea': [35.9078, 127.7669],
        'Indonesia': [-0.7893, 113.9213],
        'Thailand': [15.8700, 100.9925],
        'Singapore': [1.3521, 103.8198],
        'Malaysia': [4.2105, 101.9758],
        'Philippines': [12.8797, 121.7740],
        'Vietnam': [14.0583, 108.2772],
        'Iran': [32.4279, 53.6880],
        'Pakistan': [30.3753, 69.3451],
        'Bangladesh': [23.6850, 90.3563],
        'Israel': [31.0461, 34.8516],
        'Saudi Arabia': [23.8859, 45.0792],
        
        // North America
        'Canada': [56.1304, -106.3468],
        'Mexico': [23.6345, -102.5528],
        
        // South America
        'Brazil': [-14.2350, -51.9253],
        'Argentina': [-38.4161, -63.6167],
        'Chile': [-35.6751, -71.5430],
        'Colombia': [4.5709, -74.2973],
        'Peru': [-9.1900, -75.0152],
        
        // Africa
        'South Africa': [-30.5595, 22.9375],
        'Egypt': [26.0975, 30.0444],
        'Nigeria': [9.0820, 8.6753],
        'Morocco': [31.7917, -7.0926],
        'Kenya': [-0.0236, 37.9062],
        'Ethiopia': [9.1450, 40.4897],
        
        // Oceania
        'Australia': [-25.2744, 133.7751],
        'New Zealand': [-40.9006, 174.8860],
        
        // Fallback for unknown/other
        'Unknown': [0, 0],
        'Other': [0, 0],
        'XX': [0, 0],
        '': [0, 0]
    };
    
    $(document).ready(function() {
        var regionChart, timelineChart, attackTypesChart, severityChart, heatmapChart, worldMap;
        var currentGeoData = null;
        var mapLegend = null;
        var currentSelectedCountry = null;
        
        // Initialize
        initLeafletMap();
        
        // Load data with delay to ensure map is ready
        setTimeout(function() {
            loadGeoData();
        }, 1000);
        
        // FIXED: Initialize modal handlers properly
        initModalHandlers();
        
        // FIXED: Modal event handlers
        function initModalHandlers() {
            console.log('Initializing modal handlers...');
            
            // Close modal when clicking X button
            $('.close-modal').off('click').on('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                console.log('Close modal clicked');
                closeCountryDetails();
            });
            
            // Close modal when clicking Close button
            $('#modalCloseBtn').off('click').on('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                console.log('Modal close button clicked');
                closeCountryDetails();
            });
            
            // Close modal when clicking outside
            $('#countryDetailsModal').off('click').on('click', function(e) {
                if (e.target === this) {
                    console.log('Clicked outside modal');
                    closeCountryDetails();
                }
            });
            
            // Prevent modal content clicks from closing modal
            $('.country-details-content').off('click').on('click', function(e) {
                e.stopPropagation();
            });
            
            // View all threats button
            $('#modalViewAllThreats').off('click').on('click', function(e) {
                e.preventDefault();
                if (currentSelectedCountry) {
                    // Redirect to threats page with country filter
                    window.location.href = '/ui/webguard/threats?country=' + encodeURIComponent(currentSelectedCountry);
                }
            });
            
            // Escape key handler
            $(document).off('keyup.modals').on('keyup.modals', function(e) {
                if (e.keyCode === 27) { // ESC key
                    console.log('ESC key pressed');
                    closeCountryDetails();
                }
            });
        }
        
        function loadGeoData() {
            console.log('Loading geographic threat data...');
            
            // Show loading state
            $('#countryList').html('<div class="loading-message"><i class="fa fa-spinner fa-spin"></i> ' + window.appConfig.translations.loadingData + '</div>');
            $('#countryTableBody').html('<tr><td colspan="7" class="text-center"><i class="fa fa-spinner fa-spin"></i> ' + window.appConfig.translations.loadingData + '</td></tr>');
            
            // Load real geographic threat data from OPNsense API
            $.ajax({
                url: '/api/webguard/service/getGeoStats',
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
                            initCharts(currentGeoData);
                        } else {
                            console.log('No geographic data available');
                            loadSampleGeoData();
                        }
                    } else {
                        console.log('Invalid API response:', response);
                        loadSampleGeoData();
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Failed to load geo data:', {
                        status: status,
                        error: error,
                        response: xhr.responseText
                    });
                    
                    // Load sample data for demo
                    loadSampleGeoData();
                }
            });
        }

        function loadSampleGeoData() {
            console.log('Loading sample geo data for demonstration...');
            
            // Generate sample data
            var sampleData = {
                countries: {
                    'United States': {
                        count: 45,
                        percentage: 22.1,
                        unique_ips: 15,
                        type: 'SQL Injection',
                        severity: 'high',
                        region: 'North America',
                        code: 'US'
                    },
                    'China': {
                        count: 38,
                        percentage: 18.6,
                        unique_ips: 12,
                        type: 'Brute Force',
                        severity: 'medium',
                        region: 'Asia',
                        code: 'CN'
                    },
                    'Russia': {
                        count: 29,
                        percentage: 14.2,
                        unique_ips: 10,
                        type: 'XSS Attack',
                        severity: 'medium',
                        region: 'Europe',
                        code: 'RU'
                    },
                    'Germany': {
                        count: 22,
                        percentage: 10.8,
                        unique_ips: 8,
                        type: 'Path Traversal',
                        severity: 'low',
                        region: 'Europe',
                        code: 'DE'
                    },
                    'France': {
                        count: 18,
                        percentage: 8.8,
                        unique_ips: 6,
                        type: 'Bot Activity',
                        severity: 'low',
                        region: 'Europe',
                        code: 'FR'
                    },
                    'United Kingdom': {
                        count: 15,
                        percentage: 7.4,
                        unique_ips: 5,
                        type: 'CSRF',
                        severity: 'medium',
                        region: 'Europe',
                        code: 'GB'
                    },
                    'Brazil': {
                        count: 12,
                        percentage: 5.9,
                        unique_ips: 4,
                        type: 'File Upload',
                        severity: 'high',
                        region: 'South America',
                        code: 'BR'
                    },
                    'Japan': {
                        count: 10,
                        percentage: 4.9,
                        unique_ips: 3,
                        type: 'Command Injection',
                        severity: 'high',
                        region: 'Asia',
                        code: 'JP'
                    },
                    'India': {
                        count: 8,
                        percentage: 3.9,
                        unique_ips: 2,
                        type: 'Authentication Bypass',
                        severity: 'medium',
                        region: 'Asia',
                        code: 'IN'
                    },
                    'Other': {
                        count: 25,
                        percentage: 12.3,
                        unique_ips: 8,
                        type: 'Various',
                        severity: 'low',
                        region: 'Unknown',
                        code: 'XX'
                    }
                },
                total_countries: 10,
                total_threats: 204,
                top_countries: {}
            };
            
            // Calculate top countries
            sampleData.top_countries = sampleData.countries;
            
            currentGeoData = sampleData;
            updateGeoStats(currentGeoData);
            updateCountryList(currentGeoData.countries);
            updateCountryTable(currentGeoData.countries);
            updateMapMarkers(currentGeoData.countries);
            initCharts(currentGeoData);
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
            if (!worldMap) {
                console.warn('World map not initialized');
                return;
            }
            
            var loadingDiv = document.getElementById('mapLoading');
            if (loadingDiv) {
                loadingDiv.remove();
            }
            
            // Clear existing markers
            worldMap.eachLayer(function(layer) {
                if (layer instanceof L.CircleMarker) {
                    worldMap.removeLayer(layer);
                }
            });
            
            console.log('Available countries for mapping:', Object.keys(countries));
            
            var markerCount = 0;
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var data = countries[country];
                    
                    console.log('Processing country:', country);
                    
                    // Try multiple coordinate lookups
                    var coords = countryCoordinates[country] || 
                                countryCoordinates[country.trim()] ||
                                findCoordinatesByPartialMatch(country);
                    
                    // For 'Other' countries, place marker at a neutral location
                    if (country === 'Other' && (!coords || (coords[0] === 0 && coords[1] === 0))) {
                        coords = [0, 0]; // Equator, Atlantic Ocean
                    }
                    
                    console.log('Coordinates found for', country, ':', coords);
                    
                    if (coords && coords.length === 2) {
                        var lat = coords[0];
                        var lng = coords[1];
                        var severity = (data.severity || 'medium').toLowerCase();
                        var count = data.count || 0;
                        var color, size;
                        
                        // Better color and size mapping
                        switch (severity) {
                            case 'critical':
                                color = '#8B0000';
                                size = Math.min(Math.sqrt(count) * 4, 50);
                                break;
                            case 'high':
                                color = '#dc3545';
                                size = Math.min(Math.sqrt(count) * 3, 40);
                                break;
                            case 'medium':
                                color = '#ffc107';
                                size = Math.min(Math.sqrt(count) * 2.5, 35);
                                break;
                            default:
                                color = '#28a745';
                                size = Math.min(Math.sqrt(count) * 2, 30);
                        }
                        
                        // Special styling for 'Other' countries
                        if (country === 'Other') {
                            color = '#6c757d'; // Gray color for unknown locations
                            size = Math.min(Math.sqrt(count) * 2, 25);
                        }
                        
                        // Ensure minimum size
                        size = Math.max(size, 10);
                        
                        console.log('Creating marker for', country, 'at', [lat, lng], 'with size', size, 'and color', color);
                        
                        var marker = L.circleMarker([lat, lng], {
                            radius: size,
                            fillColor: color,
                            color: '#ffffff',
                            weight: 3,
                            opacity: 1,
                            fillOpacity: 0.8
                        }).addTo(worldMap);
                        
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
                                '</div>' +
                                '<div class="popup-actions">' +
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
                                weight: 4,
                                fillOpacity: 1.0
                            });
                        });
                        
                        marker.on('mouseout', function() {
                            this.setStyle({
                                weight: 3,
                                fillOpacity: 0.8
                            });
                        });
                        
                        markerCount++;
                    } else {
                        console.warn('No coordinates found for country:', country);
                    }
                }
            }
            
            console.log('Successfully added', markerCount, 'markers to map');
            
            addMapLegend();
        }

        function findCoordinatesByPartialMatch(country) {
            var searchTerm = country.toLowerCase().trim();
            
            // First try exact match
            for (var key in countryCoordinates) {
                if (key.toLowerCase() === searchTerm) {
                    return countryCoordinates[key];
                }
            }
            
            // Try partial matches for common patterns
            if (searchTerm.includes('united') && searchTerm.includes('states')) {
                return countryCoordinates['United States'];
            }
            if (searchTerm.includes('united') && searchTerm.includes('kingdom')) {
                return countryCoordinates['United Kingdom'];
            }
            if (searchTerm === 'other' || searchTerm === 'unknown') {
                return [0, 0]; // Neutral waters
            }
            
            return null;
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
                    '<div class="legend-item">' +
                        '<span class="legend-dot" style="background-color: #6c757d;"></span>' +
                        '<span>Other/Unknown</span>' +
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
            var totalUniqueIPs = 0;
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var count = countries[country].count || 0;
                    if (count > maxCount) {
                        maxCount = count;
                        topCountry = country;
                    }
                    totalUniqueIPs += countries[country].unique_ips || 0;
                }
            }
            
            $('#topThreatCountry').text(topCountry);
            $('#uniqueIPs').text(totalUniqueIPs);
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
            
            var topCountries = countryArray.slice(0, 15);
            
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
                    var countryName = $(this).data('country');
                    var coords = countryCoordinates[countryName];
                    if (coords && worldMap) {
                        if (countryName === 'Other') {
                            worldMap.setView([0, 0], 3);
                        } else {
                            worldMap.setView(coords, 5);
                        }
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
                tbody.html('<tr><td colspan="7" class="text-center">' + window.appConfig.translations.noDataAvailable + '</td></tr>');
                return;
            }
            
            // Sort by threat count descending
            countryArray.sort(function(a, b) {
                return (b[1].count || 0) - (a[1].count || 0);
            });
            
            for (var i = 0; i < countryArray.length; i++) {
                var country = countryArray[i][0];
                var data = countryArray[i][1];
                
                var severityBadge = '<span class="label label-' + getSeverityColor(data.severity || 'medium') + '">' + (data.severity || 'medium') + '</span>';
                
                // Create unique IDs for buttons to avoid conflicts
                var detailsBtnId = 'details-btn-' + i;
                
                var actionButtons = '<button class="btn btn-xs btn-info" id="' + detailsBtnId + '" data-country="' + country + '">' +
                                       '<i class="fa fa-eye"></i> Details' +
                                   '</button>';
                
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
                    '<td>' +
                        '<div class="btn-group">' + actionButtons + '</div>' +
                    '</td>' +
                '</tr>');
                
                tbody.append(row);
                
                // Attach event handler
                (function(countryName) {
                    $('#' + detailsBtnId).click(function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        viewCountryDetails(countryName);
                    });
                })(country);
            }
        }

        // FIXED: Country Details Function
        function viewCountryDetails(country) {
            console.log('Opening details for country:', country);
            currentSelectedCountry = country;
            
            if (currentGeoData && currentGeoData.countries && currentGeoData.countries[country]) {
                var data = currentGeoData.countries[country];
                
                // Update modal title and basic info
                $('#modalCountryTitle').html(getCountryFlag(country) + ' ' + window.appConfig.translations.detailedAnalysisFor + ' ' + country);
                $('#modalTotalThreats').text((data.count || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","));
                $('#modalPercentage').text((data.percentage || 0) + '%');
                $('#modalUniqueIPs').text(data.unique_ips || 0);
                $('#modalRegion').text(data.region || 'Unknown');
                $('#modalAttackType').text(data.type || 'Unknown');
                $('#modalSeverity').html('<span class="label label-' + getSeverityColor(data.severity) + '">' + (data.severity || 'Low') + '</span>');
                
                // Load specific threats for this country
                loadCountryThreats(country);
                
                // Show modal with proper display
                $('#countryDetailsModal').css('display', 'block').addClass('show');
                
                // Re-initialize handlers after showing modal
                initModalHandlers();
                
            } else {
                alert('No detailed information available for ' + country);
            }
        }

        function loadCountryThreats(country) {
            $('#modalThreatsList').html('<div class="text-center p-3"><i class="fa fa-spinner fa-spin"></i> ' + window.appConfig.translations.loadingThreatDetails + '</div>');
            
            // For demo purposes, generate sample threats
            setTimeout(function() {
                var sampleThreats = generateSampleThreats(country);
                displayCountryThreats(sampleThreats);
            }, 1000);
        }

        function generateSampleThreats(country) {
            var threats = [];
            var threatTypes = ['SQL Injection', 'XSS Attack', 'Brute Force', 'Path Traversal', 'CSRF', 'File Upload'];
            var severities = ['low', 'medium', 'high'];
            
            for (var i = 0; i < 10; i++) {
                var ip = generateSampleIP();
                var threatType = threatTypes[Math.floor(Math.random() * threatTypes.length)];
                var severity = severities[Math.floor(Math.random() * severities.length)];
                var timestamp = new Date(Date.now() - Math.random() * 86400000); // Random time in last 24h
                
                threats.push({
                    ip_address: ip,
                    threat_type: threatType,
                    severity: severity,
                    timestamp: timestamp.toISOString(),
                    port: Math.floor(Math.random() * 65535),
                    protocol: Math.random() > 0.5 ? 'TCP' : 'UDP'
                });
            }
            
            return threats;
        }

        function generateSampleIP() {
            return Math.floor(Math.random() * 255) + '.' +
                   Math.floor(Math.random() * 255) + '.' +
                   Math.floor(Math.random() * 255) + '.' +
                   Math.floor(Math.random() * 255);
        }

        function displayCountryThreats(threats) {
            var threatsList = $('#modalThreatsList');
            threatsList.empty();
            
            if (!threats || threats.length === 0) {
                threatsList.html('<div class="alert alert-info text-center">' + window.appConfig.translations.noThreatsFound + '</div>');
                return;
            }
            
            threats.forEach(function(threat) {
                var ip = threat.ip_address || 'Unknown';
                var timestamp = threat.timestamp || new Date().toISOString();
                var threatType = threat.threat_type || 'Unknown';
                var severity = threat.severity || 'medium';
                
                var timeStr = new Date(timestamp).toLocaleString();
                
                var threatItem = $('<div class="threat-item">' +
                    '<div class="threat-header">' +
                        '<span class="threat-ip">' + ip + '</span>' +
                        '<span class="threat-time">' + timeStr + '</span>' +
                    '</div>' +
                    '<div class="threat-details">' +
                        '<span class="threat-type">' + threatType + '</span>' +
                        '<span class="label label-' + getSeverityColor(severity) + '">' + severity + '</span>' +
                        '<span>Port: ' + (threat.port || 'N/A') + '</span>' +
                        '<span>Protocol: ' + (threat.protocol || 'N/A') + '</span>' +
                    '</div>' +
                '</div>');
                
                threatsList.append(threatItem);
            });
        }

        // FIXED: Close country details function
        function closeCountryDetails() {
            console.log('Closing country details modal');
            $('#countryDetailsModal').removeClass('show').css('display', 'none');
            currentSelectedCountry = null;
        }

        // Chart initialization functions
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
            var ctx2 = document.getElementById('timelineChart').getContext('2d');
            
            // Generate sample timeline data
            var labels = [];
            var data = [];
            
            for (var i = 0; i < 24; i += 4) {
                var hourStr = i < 10 ? '0' + i : i.toString();
                labels.push(hourStr + ':00');
                data.push(Math.floor(Math.random() * 20) + 5);
            }
            
            timelineChart = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Geographic Threats',
                        data: data,
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { 
                            beginAtZero: true, 
                            title: { display: true, text: 'Threats' },
                            ticks: { stepSize: 1 }
                        },
                        x: { title: { display: true, text: 'Time (UTC)' } }
                    },
                    plugins: {
                        legend: { position: 'top' }
                    }
                }
            });
        }

        function initHeatmapChart() {
            var ctx5 = document.getElementById('heatmapChart').getContext('2d');
            var hours = [];
            var activity = [];
            
            // Generate 24 hours with realistic activity patterns
            var peakHours = [8, 9, 10, 14, 18, 21];
            
            for (var i = 0; i < 24; i++) {
                var hourStr = i < 10 ? '0' + i : i.toString();
                hours.push(hourStr + ':00');
                
                var baseActivity = Math.floor(Math.random() * 3) + 1;
                if (peakHours.indexOf(i) !== -1) {
                    baseActivity += Math.floor(Math.random() * 6) + 3;
                }
                activity.push(baseActivity);
            }
            
            var maxActivity = Math.max.apply(null, activity);
            
            heatmapChart = new Chart(ctx5, {
                type: 'bar',
                data: {
                    labels: hours,
                    datasets: [{
                        label: 'Threat Activity',
                        data: activity,
                        backgroundColor: activity.map(function(value) {
                            var intensity = maxActivity > 0 ? value / maxActivity : 0;
                            var red = 255;
                            var green = Math.floor(255 - (intensity * 200));
                            var blue = Math.floor(255 - (intensity * 200));
                            return 'rgba(' + red + ', ' + green + ', ' + blue + ', 0.8)';
                        }),
                        borderWidth: 1,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { 
                        y: { 
                            beginAtZero: true, 
                            title: { display: true, text: 'Activity Level' },
                            ticks: { stepSize: 1 }
                        },
                        x: { title: { display: true, text: 'Hour (UTC)' } }
                    },
                    plugins: { 
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return 'Activity: ' + context.parsed.y + ' threats';
                                }
                            }
                        }
                    }
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
                'Oceania': ['Australia'],
                'Unknown': ['Other']
            };
            
            var regionData = {};
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var data = countries[country];
                    var region = 'Unknown';
                    
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
                    // Capitalize first letter to match severity keys
                    severity = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
                    if (severityData.hasOwnProperty(severity)) {
                        severityData[severity] = (severityData[severity] || 0) + (data.count || 0);
                    }
                }
            }
            return severityData;
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
                'United States': '🇺🇸',
                'China': '🇨🇳',
                'Russia': '🇷🇺',
                'Brazil': '🇧🇷',
                'India': '🇮🇳',
                'Germany': '🇩🇪',
                'France': '🇫🇷',
                'United Kingdom': '🇬🇧',
                'Japan': '🇯🇵',
                'South Korea': '🇰🇷',
                'Turkey': '🇹🇷',
                'Iran': '🇮🇷',
                'Ukraine': '🇺🇦',
                'Poland': '🇵🇱',
                'Vietnam': '🇻🇳',
                'Italy': '🇮🇹',
                'Spain': '🇪🇸',
                'Netherlands': '🇳🇱',
                'Canada': '🇨🇦',
                'Australia': '🇦🇺',
                'Mexico': '🇲🇽',
                'Argentina': '🇦🇷',
                'South Africa': '🇿🇦',
                'Egypt': '🇪🇬',
                'Nigeria': '🇳🇬',
                'Israel': '🇮🇱',
                'Saudi Arabia': '🇸🇦',
                'Thailand': '🇹🇭',
                'Singapore': '🇸🇬',
                'Indonesia': '🇮🇩',
                'North Korea': '🇰🇵',
                'Pakistan': '🇵🇰',
                'Belgium': '🇧🇪',
                'Switzerland': '🇨🇭',
                'Sweden': '🇸🇪',
                'Norway': '🇳🇴',
                'Finland': '🇫🇮',
                'Denmark': '🇩🇰',
                'Austria': '🇦🇹',
                'Ireland': '🇮🇪',
                'Portugal': '🇵🇹',
                'Greece': '🇬🇷',
                'Romania': '🇷🇴',
                'Bulgaria': '🇧🇬',
                'Hungary': '🇭🇺',
                'Czech Republic': '🇨🇿',
                'Slovakia': '🇸🇰',
                'Croatia': '🇭🇷',
                'Serbia': '🇷🇸',
                'Other': '🏳️',
                'Unknown': '🏳️'
            };
            
            return flags[country] || '🏳️';
        }
        
        // Global functions for country actions - FIXED
        window.viewCountryDetails = viewCountryDetails;
        window.closeCountryDetails = closeCountryDetails;
        
        // Auto-refresh every 5 minutes, but only if page is visible
        setInterval(function() {
            if (!document.hidden) {
                console.log('Auto-refreshing geo data...');
                loadGeoData();
            }
        }, 300000);
        
        // Initialize everything when document is ready
        console.log('Geographic interface initialized successfully');
    });
</script>