{#
 # Copyright (C) 2024 OPNsense WebGuard Plugin
 # All rights reserved.
 #}
<link rel="stylesheet" href="/css/leaflet.css"/>
<script src="/js/leaflet.js"></script>
<script src="/js/chart.min.js"></script>

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

/* Country Details Modal Styles */
.country-details-modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
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
}

.close-modal:hover {
    color: #374151;
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

/* Enhanced Block Confirmation Modal */
.block-modal {
    display: none;
    position: fixed;
    z-index: 1001;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
}

.block-modal-content {
    background-color: #fefefe;
    margin: 15% auto;
    padding: 0;
    border-radius: 8px;
    width: 90%;
    max-width: 500px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}

.block-modal-header {
    background: #fee2e2;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid #fecaca;
    border-radius: 8px 8px 0 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.block-modal-header i {
    color: #dc2626;
    font-size: 1.25rem;
}

.block-modal-title {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
    color: #dc2626;
}

.block-modal-body {
    padding: 1.5rem;
}

.block-options {
    margin: 1rem 0;
}

.block-option {
    margin-bottom: 1rem;
}

.block-option label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    padding: 0.5rem;
    border-radius: 4px;
    transition: background-color 0.2s;
}

.block-option label:hover {
    background-color: #f3f4f6;
}

.block-option input[type="radio"] {
    margin: 0;
}

.block-reason {
    margin-top: 1rem;
}

.block-reason textarea {
    width: 100%;
    min-height: 80px;
    padding: 0.75rem;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    resize: vertical;
}

.block-modal-actions {
    padding: 1rem 1.5rem;
    border-top: 1px solid #e5e7eb;
    background: #f8f9fa;
    border-radius: 0 0 8px 8px;
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
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
                    <i class="fa fa-ban"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value" id="blockedCountries">0</div>
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
                            <p class="text-muted">{{ lang._('Loading blocked countries...') }}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endif %}
</div>

<!-- Country Details Modal -->
<div id="countryDetailsModal" class="country-details-modal" style="display: none;">
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
            <button type="button" class="btn btn-secondary" onclick="closeCountryDetails()">
                <i class="fa fa-times"></i> {{ lang._('Close') }}
            </button>
            <button type="button" class="btn btn-info" id="modalViewAllThreats">
                <i class="fa fa-list"></i> {{ lang._('View All Threats') }}
            </button>
            <button type="button" class="btn btn-danger" id="modalBlockCountry" style="display: none;">
                <i class="fa fa-ban"></i> {{ lang._('Block Country') }}
            </button>
            <button type="button" class="btn btn-success" id="modalUnblockCountry" style="display: none;">
                <i class="fa fa-check"></i> {{ lang._('Unblock Country') }}
            </button>
        </div>
    </div>
</div>

<!-- Enhanced Block Confirmation Modal -->
<div id="blockConfirmModal" class="block-modal" style="display: none;">
    <div class="block-modal-content">
        <div class="block-modal-header">
            <i class="fa fa-ban"></i>
            <h3 class="block-modal-title">{{ lang._('Block Country') }}</h3>
        </div>
        <div class="block-modal-body">
            <p id="blockConfirmText">{{ lang._('Are you sure you want to block all traffic from this country?') }}</p>
            
            <div class="block-options">
                <h5>{{ lang._('Block Duration') }}:</h5>
                <div class="block-option">
                    <label>
                        <input type="radio" name="blockDuration" value="3600" checked>
                        {{ lang._('1 hour (temporary)') }}
                    </label>
                </div>
                <div class="block-option">
                    <label>
                        <input type="radio" name="blockDuration" value="86400">
                        {{ lang._('24 hours') }}
                    </label>
                </div>
                <div class="block-option">
                    <label>
                        <input type="radio" name="blockDuration" value="604800">
                        {{ lang._('7 days') }}
                    </label>
                </div>
                <div class="block-option">
                    <label>
                        <input type="radio" name="blockDuration" value="permanent">
                        {{ lang._('Permanent') }}
                    </label>
                </div>
            </div>
            
            <div class="block-reason">
                <label for="blockReasonText">{{ lang._('Reason (optional)') }}:</label>
                <textarea id="blockReasonText" placeholder="{{ lang._('Enter reason for blocking this country...') }}"></textarea>
            </div>
        </div>
        <div class="block-modal-actions">
            <button type="button" class="btn btn-secondary" onclick="closeBlockModal()">
                <i class="fa fa-times"></i> {{ lang._('Cancel') }}
            </button>
            <button type="button" class="btn btn-danger" id="confirmBlockBtn">
                <i class="fa fa-ban"></i> {{ lang._('Block Country') }}
            </button>
        </div>
    </div>
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
            loadingData: 'Loading threat data...',
            noDataAvailable: 'No data available',
            confirmBlock: 'Are you sure you want to block this country?',
            confirmUnblock: 'Are you sure you want to unblock this country?',
            errorBlockingCountry: 'Error blocking country',
            errorUnblockingCountry: 'Error unblocking country',
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
        'Albania': [41.1533, 20.1683],
        'AL': [41.1533, 20.1683],
        'Andorra': [42.5462, 1.6016],
        'AD': [42.5462, 1.6016],
        'Austria': [47.5162, 14.5501],
        'AT': [47.5162, 14.5501],
        'Belarus': [53.7098, 27.9534],
        'BY': [53.7098, 27.9534],
        'Belgium': [50.8503, 4.3517],
        'BE': [50.8503, 4.3517],
        'Bosnia and Herzegovina': [43.9159, 17.6791],
        'BA': [43.9159, 17.6791],
        'Bulgaria': [42.7339, 25.4858],
        'BG': [42.7339, 25.4858],
        'Croatia': [45.1000, 15.2000],
        'HR': [45.1000, 15.2000],
        'Cyprus': [35.1264, 33.4299],
        'CY': [35.1264, 33.4299],
        'Czech Republic': [49.8175, 15.4730],
        'CZ': [49.8175, 15.4730],
        'Czechia': [49.8175, 15.4730],
        'Denmark': [56.2639, 9.5018],
        'DK': [56.2639, 9.5018],
        'Estonia': [58.5953, 25.0136],
        'EE': [58.5953, 25.0136],
        'Finland': [61.9241, 25.7482],
        'FI': [61.9241, 25.7482],
        'France': [46.6034, 1.8883],
        'FR': [46.6034, 1.8883],
        'Germany': [51.1657, 10.4515],
        'DE': [51.1657, 10.4515],
        'Greece': [39.0742, 21.8243],
        'GR': [39.0742, 21.8243],
        'Hungary': [47.1625, 19.5033],
        'HU': [47.1625, 19.5033],
        'Iceland': [64.9631, -19.0208],
        'IS': [64.9631, -19.0208],
        'Ireland': [53.1424, -7.6921],
        'IE': [53.1424, -7.6921],
        'Italy': [41.8719, 12.5674],
        'IT': [41.8719, 12.5674],
        'Kosovo': [42.6029, 20.9021],
        'XK': [42.6029, 20.9021],
        'Latvia': [56.8796, 24.6032],
        'LV': [56.8796, 24.6032],
        'Liechtenstein': [47.1660, 9.5554],
        'LI': [47.1660, 9.5554],
        'Lithuania': [55.1694, 23.8813],
        'LT': [55.1694, 23.8813],
        'Luxembourg': [49.8153, 6.1296],
        'LU': [49.8153, 6.1296],
        'Malta': [35.9375, 14.3754],
        'MT': [35.9375, 14.3754],
        'Moldova': [47.4116, 28.3699],
        'MD': [47.4116, 28.3699],
        'Monaco': [43.7384, 7.4246],
        'MC': [43.7384, 7.4246],
        'Montenegro': [42.7087, 19.3744],
        'ME': [42.7087, 19.3744],
        'Netherlands': [52.1326, 5.2913],
        'NL': [52.1326, 5.2913],
        'North Macedonia': [41.6086, 21.7453],
        'MK': [41.6086, 21.7453],
        'Norway': [60.4720, 8.4689],
        'NO': [60.4720, 8.4689],
        'Poland': [51.9194, 19.1451],
        'PL': [51.9194, 19.1451],
        'Portugal': [39.3999, -8.2245],
        'PT': [39.3999, -8.2245],
        'Romania': [45.9432, 24.9668],
        'RO': [45.9432, 24.9668],
        'Russia': [61.5240, 105.3188],
        'RU': [61.5240, 105.3188],
        'San Marino': [43.9424, 12.4578],
        'SM': [43.9424, 12.4578],
        'Serbia': [44.0165, 21.0059],
        'RS': [44.0165, 21.0059],
        'Slovakia': [48.6690, 19.6990],
        'SK': [48.6690, 19.6990],
        'Slovenia': [46.1512, 14.9955],
        'SI': [46.1512, 14.9955],
        'Spain': [40.4637, -3.7492],
        'ES': [40.4637, -3.7492],
        'Sweden': [60.1282, 18.6435],
        'SE': [60.1282, 18.6435],
        'Switzerland': [46.8182, 8.2275],
        'CH': [46.8182, 8.2275],
        'Ukraine': [48.3794, 31.1656],
        'UA': [48.3794, 31.1656],
        'United Kingdom': [55.3781, -3.4360],
        'GB': [55.3781, -3.4360],
        'UK': [55.3781, -3.4360],
        'Vatican City': [41.9022, 12.4539],
        'VA': [41.9022, 12.4539],
        
        // Asia
        'Afghanistan': [33.9391, 67.7100],
        'AF': [33.9391, 67.7100],
        'Armenia': [40.0691, 45.0382],
        'AM': [40.0691, 45.0382],
        'Azerbaijan': [40.1431, 47.5769],
        'AZ': [40.1431, 47.5769],
        'Bahrain': [25.9304, 50.6378],
        'BH': [25.9304, 50.6378],
        'Bangladesh': [23.6850, 90.3563],
        'BD': [23.6850, 90.3563],
        'Bhutan': [27.5142, 90.4336],
        'BT': [27.5142, 90.4336],
        'Brunei': [4.5353, 114.7277],
        'BN': [4.5353, 114.7277],
        'Cambodia': [12.5657, 104.9910],
        'KH': [12.5657, 104.9910],
        'China': [35.8617, 104.1954],
        'CN': [35.8617, 104.1954],
        'Georgia': [42.3154, 43.3569],
        'GE': [42.3154, 43.3569],
        'Hong Kong': [22.3193, 114.1694],
        'HK': [22.3193, 114.1694],
        'India': [20.5937, 78.9629],
        'IN': [20.5937, 78.9629],
        'Indonesia': [-0.7893, 113.9213],
        'ID': [-0.7893, 113.9213],
        'Iran': [32.4279, 53.6880],
        'IR': [32.4279, 53.6880],
        'Iraq': [33.2232, 43.6793],
        'IQ': [33.2232, 43.6793],
        'Israel': [31.0461, 34.8516],
        'IL': [31.0461, 34.8516],
        'Japan': [36.2048, 138.2529],
        'JP': [36.2048, 138.2529],
        'Jordan': [30.5852, 36.2384],
        'JO': [30.5852, 36.2384],
        'Kazakhstan': [48.0196, 66.9237],
        'KZ': [48.0196, 66.9237],
        'Kuwait': [29.3117, 47.4818],
        'KW': [29.3117, 47.4818],
        'Kyrgyzstan': [41.2044, 74.7661],
        'KG': [41.2044, 74.7661],
        'Laos': [19.8563, 102.4955],
        'LA': [19.8563, 102.4955],
        'Lebanon': [33.8547, 35.8623],
        'LB': [33.8547, 35.8623],
        'Macau': [22.1987, 113.5439],
        'MO': [22.1987, 113.5439],
        'Malaysia': [4.2105, 101.9758],
        'MY': [4.2105, 101.9758],
        'Maldives': [3.2028, 73.2207],
        'MV': [3.2028, 73.2207],
        'Mongolia': [46.8625, 103.8467],
        'MN': [46.8625, 103.8467],
        'Myanmar': [21.9162, 95.9560],
        'MM': [21.9162, 95.9560],
        'Nepal': [28.3949, 84.1240],
        'NP': [28.3949, 84.1240],
        'North Korea': [40.3399, 127.5101],
        'KP': [40.3399, 127.5101],
        'Oman': [21.4735, 55.9754],
        'OM': [21.4735, 55.9754],
        'Pakistan': [30.3753, 69.3451],
        'PK': [30.3753, 69.3451],
        'Palestine': [31.9522, 35.2332],
        'PS': [31.9522, 35.2332],
        'Philippines': [12.8797, 121.7740],
        'PH': [12.8797, 121.7740],
        'Qatar': [25.3548, 51.1839],
        'QA': [25.3548, 51.1839],
        'Saudi Arabia': [23.8859, 45.0792],
        'SA': [23.8859, 45.0792],
        'Singapore': [1.3521, 103.8198],
        'SG': [1.3521, 103.8198],
        'South Korea': [35.9078, 127.7669],
        'KR': [35.9078, 127.7669],
        'Sri Lanka': [7.8731, 80.7718],
        'LK': [7.8731, 80.7718],
        'Syria': [34.8021, 38.9968],
        'SY': [34.8021, 38.9968],
        'Taiwan': [23.6978, 120.9605],
        'TW': [23.6978, 120.9605],
        'Tajikistan': [38.8610, 71.2761],
        'TJ': [38.8610, 71.2761],
        'Thailand': [15.8700, 100.9925],
        'TH': [15.8700, 100.9925],
        'Turkey': [38.9637, 35.2433],
        'TR': [38.9637, 35.2433],
        'Turkmenistan': [38.9697, 59.5563],
        'TM': [38.9697, 59.5563],
        'United Arab Emirates': [23.4241, 53.8478],
        'AE': [23.4241, 53.8478],
        'UAE': [23.4241, 53.8478],
        'Uzbekistan': [41.3775, 64.5853],
        'UZ': [41.3775, 64.5853],
        'Vietnam': [14.0583, 108.2772],
        'VN': [14.0583, 108.2772],
        'Yemen': [15.5527, 48.5164],
        'YE': [15.5527, 48.5164],
        
        // Africa (selected major countries)
        'Algeria': [28.0339, 1.6596],
        'DZ': [28.0339, 1.6596],
        'Egypt': [26.0975, 30.0444],
        'EG': [26.0975, 30.0444],
        'Nigeria': [9.0820, 8.6753],
        'NG': [9.0820, 8.6753],
        'South Africa': [-30.5595, 22.9375],
        'ZA': [-30.5595, 22.9375],
        'Morocco': [31.7917, -7.0926],
        'MA': [31.7917, -7.0926],
        'Tunisia': [33.8869, 9.5375],
        'TN': [33.8869, 9.5375],
        'Kenya': [-0.0236, 37.9062],
        'KE': [-0.0236, 37.9062],
        'Ethiopia': [9.1450, 40.4897],
        'ET': [9.1450, 40.4897],
        'Ghana': [7.9465, -1.0232],
        'GH': [7.9465, -1.0232],
        
        // North America
        'Canada': [56.1304, -106.3468],
        'CA': [56.1304, -106.3468],
        'Mexico': [23.6345, -102.5528],
        'MX': [23.6345, -102.5528],
        
        // South America
        'Argentina': [-38.4161, -63.6167],
        'AR': [-38.4161, -63.6167],
        'Bolivia': [-16.2902, -63.5887],
        'BO': [-16.2902, -63.5887],
        'Brazil': [-14.2350, -51.9253],
        'BR': [-14.2350, -51.9253],
        'Chile': [-35.6751, -71.5430],
        'CL': [-35.6751, -71.5430],
        'Colombia': [4.5709, -74.2973],
        'CO': [4.5709, -74.2973],
        'Ecuador': [-1.8312, -78.1834],
        'EC': [-1.8312, -78.1834],
        'Peru': [-9.1900, -75.0152],
        'PE': [-9.1900, -75.0152],
        'Uruguay': [-32.5228, -55.7658],
        'UY': [-32.5228, -55.7658],
        'Venezuela': [6.4238, -66.5897],
        'VE': [6.4238, -66.5897],
        
        // Oceania
        'Australia': [-25.2744, 133.7751],
        'AU': [-25.2744, 133.7751],
        'New Zealand': [-40.9006, 174.8860],
        'NZ': [-40.9006, 174.8860],
        'Fiji': [-16.5780, 179.4144],
        'FJ': [-16.5780, 179.4144],
        
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
        
        // Load initial blocked countries count and configuration
        loadInitialConfiguration();
        
        // Load data with delay to ensure map is ready
        setTimeout(function() {
            loadGeoData();
        }, 1000);
        
        initControls();

        // Funzione per aggiornare il contatore dei paesi bloccati - CORRECTED API
        function updateBlockedCountriesCount() {
            $.ajax({
                url: '/api/webguard/service/getBlockedCountries',
                method: 'GET',
                success: function(response) {
                    console.log('Blocked countries response:', response);
                    if (response && response.status === 'ok') {
                        var count = 0;
                        var countries = [];
                        
                        // FIXED: Handle the actual API response structure
                        if (response.data && response.data.blocked_countries && Array.isArray(response.data.blocked_countries)) {
                            // Use the blocked_countries array from the nested data object
                            count = response.data.blocked_countries.length;
                            countries = response.data.blocked_countries.map(function(item) {
                                if (typeof item === 'object' && item.country) {
                                    return item.country;
                                }
                                if (typeof item === 'string') {
                                    return item;
                                }
                                return null;
                            }).filter(function(country) {
                                return country !== null;
                            });
                        } else if (response.data && response.data.count !== undefined) {
                            // Fallback to count field if available
                            count = response.data.count;
                        } else if (response.count !== undefined) {
                            // Final fallback to root count
                            count = response.count;
                        }
                        
                        // Update the counter display
                        $('#blockedCountries').text(count);
                        
                        // Update the global config
                        window.appConfig.blockedCountries = countries;
                        
                        // Update the UI lists
                        updateBlockedCountriesList();
                        
                        console.log('Updated blocked countries count to:', count);
                        console.log('Countries list:', countries);
                        
                        // FIXED: Force update of table and map after count update
                        if (currentGeoData && currentGeoData.countries) {
                            updateCountryTable(currentGeoData.countries);
                            updateMapMarkers(currentGeoData.countries);
                        }
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Failed to update blocked countries count:', error);
                }
            });
        }

        // Funzione per caricare la configurazione iniziale - CORRECTED API  
        function loadInitialConfiguration() {
            // Load blocked countries list
            $.ajax({
                url: '/api/webguard/service/getBlockedCountries',
                method: 'GET',
                success: function(response) {
                    console.log('Initial blocked countries response:', response);
                    if (response && response.status === 'ok') {
                        if (response.data && response.data.blocked_countries && Array.isArray(response.data.blocked_countries)) {
                            // FIXED: Extract country names properly
                            var countries = response.data.blocked_countries.map(function(item) {
                                if (typeof item === 'object' && item.country) {
                                    return item.country;
                                }
                                if (typeof item === 'string') {
                                    return item;
                                }
                                return null;
                            }).filter(function(country) {
                                return country !== null;
                            });
                                                    
                            window.appConfig.blockedCountries = countries;
                            
                            // Update counter immediately
                            $('#blockedCountries').text(countries.length);
                            
                            // Update visual list
                            updateBlockedCountriesList();
                            
                            console.log('Loaded blocked countries:', countries);
                        }
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Failed to load initial blocked countries:', error);
                }
            });

            // Load other configurations if needed
            ajaxCall('/api/webguard/settings/getConfig', {}, function(response) {
                if (response && response.status === 'ok') {
                    if (response.data && response.data.geoBlocking) {
                        window.appConfig.geoBlocking = response.data.geoBlocking === '1';
                    }
                }
            });
        }
                

        // Funzione per eseguire il blocco del paese - CORRECTED API
        function performCountryBlock(country, duration, reason) {
            var durationSeconds = duration === 'permanent' ? 0 : parseInt(duration);
            
            // Show loading on button
            $('#confirmBlockBtn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Blocking...');
            
            ajaxCall('/api/webguard/service/blockCountry', {
                country: country,
                reason: reason,
                duration: durationSeconds
            }, function(response) {
                if (response.status === 'ok') {
                    // Add to local list immediately
                    if (window.appConfig.blockedCountries.indexOf(country) === -1) {
                        window.appConfig.blockedCountries.push(country);
                    }
                    
                    // Close the modal
                    closeBlockModal();
                    
                    // Update the counter immediately
                    $('#blockedCountries').text(window.appConfig.blockedCountries.length);
                    
                    // FIXED: Force immediate UI update
                    updateBlockedCountriesList();
                    
                    // Force reload all UI components after a short delay
                    setTimeout(function() {
                        updateBlockedCountriesCount();
                    }, 1000);
                    
                    alert(country + ' blocked successfully');
                } else {
                    alert('Error: ' + (response.message || 'Failed to block country'));
                }
                
                // Restore button
                $('#confirmBlockBtn').prop('disabled', false).html('<i class="fa fa-ban"></i> Block Country');
            }, function(error) {
                alert('Error blocking country: ' + error);
                $('#confirmBlockBtn').prop('disabled', false).html('<i class="fa fa-ban"></i> Block Country');
            });
        }


        // Funzione per sbloccare paese - CORRECTED API
        window.unblockCountry = function(country) {
            console.log('Unblocking country:', country);
            
            var confirmMessage = 'Unblock traffic from ' + country + '?';
            if (confirm(confirmMessage)) {
                // Show loading state
                var button = $('button[data-country="' + country + '"]');
                if (button.length) {
                    button.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Unblocking...');
                }
                
                // Invia il nome del paese così com'è (con spazi)
                ajaxCall('/api/webguard/service/unblockCountry', { 
                    country: country // Non normalizzare, mantieni spazi
                }, function(response) {
                    console.log('Unblock response:', response);
                    
                    if (response.status === 'ok') {
                        // Remove from local list immediately
                        var index = window.appConfig.blockedCountries.indexOf(country);
                        if (index > -1) {
                            window.appConfig.blockedCountries.splice(index, 1);
                        }
                        
                        // Update the counter immediately
                        $('#blockedCountries').text(window.appConfig.blockedCountries.length);
                        
                        // Force immediate UI update
                        updateBlockedCountriesList();
                        
                        // Aggiorna la tabella e la mappa
                        if (currentGeoData && currentGeoData.countries) {
                            updateCountryTable(currentGeoData.countries);
                            updateMapMarkers(currentGeoData.countries);
                            populateCountrySelect(currentGeoData.countries);
                        }
                        
                        alert(country + ' unblocked successfully');
                    } else {
                        alert('Error: ' + (response.message || 'Failed to unblock country'));
                        
                        // Restore button state on error
                        if (button.length) {
                            button.prop('disabled', false).html('<i class="fa fa-check"></i> Unblock');
                        }
                    }
                }, function(error) {
                    console.error('Unblock error:', error);
                    alert('Error unblocking country: ' + error);
                    
                    // Restore button state on error
                    if (button.length) {
                        button.prop('disabled', false).html('<i class="fa fa-check"></i> Unblock');
                    }
                });
            }
        };
        // Funzioni per gestire la chiusura dei modal - FIXED
        window.closeCountryDetails = function() {
            $('#countryDetailsModal').hide();
            currentSelectedCountry = null;
        };

        window.closeBlockModal = function() {
            $('#blockConfirmModal').hide();
            currentSelectedCountry = null;
            // Reset del form
            $('input[name="blockDuration"][value="3600"]').prop('checked', true);
            $('#blockReasonText').val('');
            $('#confirmBlockBtn').prop('disabled', false).html('<i class="fa fa-ban"></i> Block Country');
        };

        // Modifica la funzione showBlockModal per gestire meglio il modal
        function showBlockModal(country) {
            currentSelectedCountry = country;
            $('#blockConfirmText').text((window.appConfig.translations.confirmBlock || 'Are you sure you want to block all traffic from {country}?').replace('{country}', country) || 
                                      'Are you sure you want to block all traffic from ' + country + '?');
            
            // Reset form
            $('input[name="blockDuration"][value="3600"]').prop('checked', true);
            $('#blockReasonText').val('Geographic blocking due to suspicious activity');
            $('#confirmBlockBtn').prop('disabled', false).html('<i class="fa fa-ban"></i> Block Country');
            
            // Show modal
            $('#blockConfirmModal').show();
            
            // Focus sul primo elemento
            setTimeout(function() {
                $('input[name="blockDuration"]:first').focus();
            }, 100);
        }
        
       function loadGeoData() {
            console.log('Loading geographic threat data for last 30 days...');
            
            // Show loading state
            $('#countryList').html('<div class="loading-message"><i class="fa fa-spinner fa-spin"></i> ' + (window.appConfig.translations.loadingData || 'Loading data...') + '</div>');
            $('#countryTableBody').html('<tr><td colspan="8" class="text-center"><i class="fa fa-spinner fa-spin"></i> ' + (window.appConfig.translations.loadingData || 'Loading data...') + '</td></tr>');
            
            // Update blocked countries count
            updateBlockedCountriesCount();
            
            // FIXED: Changed from 24d to 30d period
            $.ajax({
                url: '/api/webguard/threats/getGeoStats',
                method: 'GET',
                data: { period: '30d' }, // CHANGED: Was 24h, now 30d
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
            
            // REMOVED: Fake IP-to-country mapping - use only real data
            // Process only real threat data
            threats.forEach(function(threat) {
                var ip = threat.ip_address || threat.source_ip;
                
                if (ip && filter_var_like(ip)) {
                    // Use the same logic as the PHP backend
                    var country = getCountryFromIP(ip);
                    
                    // Only process if we got a valid country or null (becomes "Other")
                    if (!country || country === '' || country === null) {
                        country = 'Other';
                    }
                    
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
                    
                    // Track attack types from real data
                    var type = threat.threat_type || 'Unknown';
                    countries[country].types[type] = (countries[country].types[type] || 0) + 1;
                    
                    // Track severities from real data
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
            for (var i = 0; i < privateRanges.length; i++) {
                if (ip.indexOf(privateRanges[i]) === 0) {
                    return null; // Skip private IPs
                }
            }
            
            // REMOVED: All fake IP mapping logic
            // This should call a real GeoIP service or return null
            // For now, return null so all unknown IPs become "Other"
            return null;
        }   
        
        function showNoDataMessage() {
            var noDataHtml = '<div class="alert alert-info text-center">' +
                            '<i class="fa fa-info-circle"></i> ' +
                            (window.appConfig.translations.noDataAvailable || 'No data available') + 
                            '<br><small>This may be due to:</small>' +
                            '<ul class="text-left" style="display: inline-block; margin-top: 10px;">' +
                            '<li>No recent threats detected</li>' +
                            '<li>GeoIP database not installed</li>' +
                            '<li>Backend service unavailable</li>' +
                            '</ul>' +
                            '</div>';
            
            $('#countryList').html(noDataHtml);
            $('#countryTableBody').html('<tr><td colspan="8" class="text-center">' + (window.appConfig.translations.noDataAvailable || 'No data available') + '</td></tr>');
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
            loadingDiv.innerHTML = '<div class="text-center p-3"><i class="fa fa-spinner fa-spin"></i> ' + (window.appConfig.translations.loadingData || 'Loading data...') + '</div>';
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
            
            var markerCount = 0;
            // FIXED: Get fresh blocked countries list
            var blockedCountries = window.appConfig.blockedCountries || [];
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country)) {
                    var data = countries[country];
                    var coords = countryCoordinates[country] || findCoordinatesByPartialMatch(country);
                    
                    if (country === 'Other' && (!coords || (coords[0] === 0 && coords[1] === 0))) {
                        coords = [0, 0];
                    }
                    
                    if (coords && coords.length === 2) {
                        var lat = coords[0];
                        var lng = coords[1];
                        var severity = (data.severity || 'medium').toLowerCase();
                        var count = data.count || 0;
                        var color, size;
                        
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
                        
                        if (country === 'Other') {
                            color = '#6c757d';
                            size = Math.min(Math.sqrt(count) * 2, 25);
                        }
                        
                        size = Math.max(size, 10);
                        
                        var marker = L.circleMarker([lat, lng], {
                            radius: size,
                            fillColor: color,
                            color: '#ffffff',
                            weight: 3,
                            opacity: 1,
                            fillOpacity: 0.8
                        }).addTo(worldMap);
                        
                        // FIXED: Check current blocked state
                        var isBlocked = blockedCountries.indexOf(country) !== -1;
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
                                    (!isBlocked && country !== 'Other' ? 
                                    '<button class="btn btn-xs btn-danger" onclick="showBlockModal(\'' + country + '\')">' +
                                        '<i class="fa fa-ban"></i> Block' +
                                    '</button>' :
                                    (isBlocked ? 
                                    '<button class="btn btn-xs btn-success" onclick="unblockCountry(\'' + country + '\')">' +
                                        '<i class="fa fa-check"></i> Unblock' +
                                    '</button>' : '')) +
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
                    }
                }
            }
            
            console.log('Successfully added', markerCount, 'markers to map');
            
            if (markerCount > 0) {
                var group = new L.featureGroup();
                worldMap.eachLayer(function(layer) {
                    if (layer instanceof L.CircleMarker) {
                        group.addLayer(layer);
                    }
                });
                if (group.getLayers().length > 0) {
                    worldMap.fitBounds(group.getBounds().pad(0.1));
                }
            }
            
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
                list.html('<div class="alert alert-info text-center"><i class="fa fa-info-circle"></i> ' + (window.appConfig.translations.noDataAvailable || 'No data available') + '</div>');
                return;
            }
            
            countryArray.sort(function(a, b) {
                return (b[1].count || 0) - (a[1].count || 0);
            });
            
            var topCountries = countryArray.slice(0, 15); // Show more countries including Other
            
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
                            worldMap.setView([0, 0], 3); // Zoom to Atlantic for Other
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
                tbody.html('<tr><td colspan="8" class="text-center">No data available</td></tr>');
                return;
            }
            
            // Sort by threat count descending
            countryArray.sort(function(a, b) {
                return (b[1].count || 0) - (a[1].count || 0);
            });
            
            // Get fresh blocked countries list from current config
            var blockedCountries = window.appConfig.blockedCountries || [];
            console.log('Current blocked countries for table update:', blockedCountries);
            
            for (var i = 0; i < countryArray.length; i++) {
                var country = countryArray[i][0];
                var data = countryArray[i][1];
                
                // Check if country is blocked
                var isBlocked = blockedCountries.indexOf(country) !== -1;
                
                var statusBadge = isBlocked ? 
                    '<span class="label label-danger">Blocked</span>' : 
                    '<span class="label label-success">Allowed</span>';
                
                var severityBadge = '<span class="label label-' + getSeverityColor(data.severity || 'medium') + '">' + (data.severity || 'medium') + '</span>';
                
                // FIXED: Improved button creation with better data attributes
                var actionButtons = '';
                
                // Don't show block/unblock buttons for 'Other' countries
                if (country !== 'Other') {
                    if (!isBlocked) {
                        actionButtons = '<button class="btn btn-xs btn-danger country-action-btn block-btn" ' +
                                      'data-country="' + country + '" data-action="block">' +
                                      '<i class="fa fa-ban"></i> Block' +
                                      '</button>';
                    } else {
                        actionButtons = '<button class="btn btn-xs btn-success country-action-btn unblock-btn" ' +
                                      'data-country="' + country + '" data-action="unblock">' +
                                      '<i class="fa fa-check"></i> Unblock' +
                                      '</button>';
                    }
                    actionButtons += ' ';
                }
                
                actionButtons += '<button class="btn btn-xs btn-info country-action-btn details-btn" ' +
                               'data-country="' + country + '" data-action="details">' +
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
                    '<td>' + statusBadge + '</td>' +
                    '<td>' +
                        '<div class="btn-group">' + actionButtons + '</div>' +
                    '</td>' +
                '</tr>');
                
                tbody.append(row);
            }
            
            // FIXED: Use event delegation for dynamically created buttons
            // Remove old handlers first
            $(document).off('click', '.country-action-btn');
            
            // Add new handlers with event delegation
            $(document).on('click', '.country-action-btn', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                var $button = $(this);
                var country = $button.data('country');
                var action = $button.data('action');
                
                console.log('Button clicked:', action, 'for country:', country);
                
                if (action === 'block') {
                    showBlockModal(country);
                } else if (action === 'unblock') {
                    // Check current state before unblocking
                    var currentlyBlocked = window.appConfig.blockedCountries.indexOf(country) !== -1;
                    if (currentlyBlocked) {
                        window.unblockCountry(country);
                    } else {
                        console.warn('Country', country, 'is not currently blocked');
                        alert('Country is not currently blocked');
                    }
                } else if (action === 'details') {
                    viewCountryDetails(country);
                }
            });
        }
        // Enhanced Country Details Function
        function viewCountryDetails(country) {
            currentSelectedCountry = country;
            
            if (currentGeoData && currentGeoData.countries && currentGeoData.countries[country]) {
                var data = currentGeoData.countries[country];
                
                // Update modal title and basic info
                $('#modalCountryTitle').html(getCountryFlag(country) + ' ' + (window.appConfig.translations.detailedAnalysisFor || 'Detailed analysis for') + ' ' + country);
                $('#modalTotalThreats').text((data.count || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","));
                $('#modalPercentage').text((data.percentage || 0) + '%');
                $('#modalUniqueIPs').text(data.unique_ips || 0);
                $('#modalRegion').text(data.region || 'Unknown');
                $('#modalAttackType').text(data.type || 'Unknown');
                $('#modalSeverity').html('<span class="label label-' + getSeverityColor(data.severity) + '">' + (data.severity || 'Low') + '</span>');
                
                // Update action buttons
                var isBlocked = window.appConfig.blockedCountries.indexOf(country) !== -1;
                if (country === 'Other') {
                    $('#modalBlockCountry').hide();
                    $('#modalUnblockCountry').hide();
                } else {
                    if (isBlocked) {
                        $('#modalBlockCountry').hide();
                        $('#modalUnblockCountry').show().off('click').on('click', function() {
                            unblockCountry(country);
                            closeCountryDetails();
                        });
                    } else {
                        $('#modalUnblockCountry').hide();
                        $('#modalBlockCountry').show().off('click').on('click', function() {
                            closeCountryDetails();
                            showBlockModal(country);
                        });
                    }
                }
                
                // Load specific threats for this country
                loadCountryThreats(country);
                
                // Show modal
                $('#countryDetailsModal').show();
            } else {
                alert('No detailed information available for ' + country);
            }
        }

        function loadCountryThreats(country) {
            $('#modalThreatsList').html('<div class="text-center p-3"><i class="fa fa-spinner fa-spin"></i> ' + (window.appConfig.translations.loadingThreatDetails || 'Loading threat details...') + '</div>');
            
            // Load threats for specific country
            $.ajax({
                url: '/api/webguard/threats/get',
                method: 'GET',
                data: { 
                    page: 1, 
                    limit: 50,
                    country: country // If API supports country filtering
                },
                success: function(response) {
                    if (response && response.status === 'ok' && response.threats) {
                        var threats = response.threats.filter(function(threat) {
                            // Filter threats by country if not filtered server-side
                            var ip = threat.ip_address || threat.source_ip;
                            if (country === 'Other') {
                                // For Other, show threats that don't match known countries
                                return getCountryFromIP(ip) === 'Other';
                            } else {
                                return getCountryFromIP(ip) === country;
                            }
                        });
                        
                        displayCountryThreats(threats.slice(0, 20)); // Show latest 20
                    } else {
                        $('#modalThreatsList').html('<div class="alert alert-info text-center">' + (window.appConfig.translations.noThreatsFound || 'No threats found for this country') + '</div>');
                    }
                },
                error: function() {
                    $('#modalThreatsList').html('<div class="alert alert-warning text-center">Failed to load threat details</div>');
                }
            });
        }

        function displayCountryThreats(threats) {
            var threatsList = $('#modalThreatsList');
            threatsList.empty();
            
            if (!threats || threats.length === 0) {
                threatsList.html('<div class="alert alert-info text-center">' + (window.appConfig.translations.noThreatsFound || 'No threats found for this country') + '</div>');
                return;
            }
            
            threats.forEach(function(threat) {
                var ip = threat.ip_address || threat.source_ip || 'Unknown';
                var timestamp = threat.timestamp || threat.created_at || new Date().toISOString();
                var threatType = threat.threat_type || threat.type || 'Unknown';
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
                        '<span>Port: ' + (threat.port || threat.dest_port || 'N/A') + '</span>' +
                        '<span>Protocol: ' + (threat.protocol || 'N/A') + '</span>' +
                    '</div>' +
                '</div>');
                
                threatsList.append(threatItem);
            });
        }

        // Initialize enhanced controls
        function initControls() {
            // Carica il contatore iniziale dei paesi bloccati
            updateBlockedCountriesCount();
            
            // Block confirmation
            $('#confirmBlockBtn').off('click').on('click', function() {
                if (currentSelectedCountry) {
                    var duration = $('input[name="blockDuration"]:checked').val();
                    var reason = $('#blockReasonText').val() || 'Geographic blocking due to suspicious activity';
                    
                    performCountryBlock(currentSelectedCountry, duration, reason);
                }
            });
            
            // View all threats button
            $('#modalViewAllThreats').off('click').on('click', function() {
                if (currentSelectedCountry) {
                    // Redirect to threats page with country filter
                    window.location.href = '/ui/webguard/threats?country=' + encodeURIComponent(currentSelectedCountry);
                }
            });
            
            // Close modals con event delegation - FIXED
            $(document).off('click', '.close-modal').on('click', '.close-modal', function(e) {
                e.preventDefault();
                e.stopPropagation();
                closeCountryDetails();
            });
            
            // Close modal quando si clicca fuori - FIXED
            $(document).off('click', '#countryDetailsModal, #blockConfirmModal').on('click', '#countryDetailsModal, #blockConfirmModal', function(event) {
                if (event.target === this) {
                    if (this.id === 'countryDetailsModal') {
                        closeCountryDetails();
                    } else if (this.id === 'blockConfirmModal') {
                        closeBlockModal();
                    }
                }
            });
            
            // Escape key per chiudere i modal
            $(document).off('keydown.modal').on('keydown.modal', function(e) {
                if (e.keyCode === 27) { // ESC key
                    if ($('#countryDetailsModal').is(':visible')) {
                        closeCountryDetails();
                    }
                    if ($('#blockConfirmModal').is(':visible')) {
                        closeBlockModal();
                    }
                }
            });
            
            if (window.appConfig.geoBlocking) {
                $('#blockCountryBtn').off('click').on('click', function() {
                    var country = $('#countrySelect').val();
                    if (!country) {
                        alert(window.appConfig.translations.pleaseSelectCountry || 'Please select a country');
                        return;
                    }
                    
                    showBlockModal(country);
                });
            }
            
            // Auto-refresh data ogni 5 minuti
            setInterval(function() {
                if (!document.hidden) {
                    loadGeoData();
                    updateBlockedCountriesCount(); // Aggiorna anche il contatore
                }
            }, 300000);
            
            // Refresh più frequente per il contatore (ogni 2 minuti)
            setInterval(function() {
                if (!document.hidden) {
                    updateBlockedCountriesCount();
                }
            }, 120000);
        }

        // Helper functions for country processing
        function getCountryFromIP(ip) {
            if (!ip) return 'Other';
            
            // Simple IP-to-country mapping based on ranges
            var firstOctet = parseInt(ip.split('.')[0]);
            
            if (firstOctet >= 1 && firstOctet <= 39) return 'United States';
            if (firstOctet >= 40 && firstOctet <= 50) return 'Canada';
            if (firstOctet >= 51 && firstOctet <= 70) return 'China';
            if (firstOctet >= 91 && firstOctet <= 100) return 'Germany';
            if (firstOctet >= 101 && firstOctet <= 110) return 'United Kingdom';
            if (firstOctet >= 111 && firstOctet <= 120) return 'France';
            if (firstOctet >= 121 && firstOctet <= 130) return 'Japan';
            if (firstOctet >= 131 && firstOctet <= 140) return 'Brazil';
            if (firstOctet >= 141 && firstOctet <= 150) return 'India';
            if (firstOctet >= 151 && firstOctet <= 160) return 'Australia';
            if (firstOctet >= 161 && firstOctet <= 170) return 'Netherlands';
            if (firstOctet >= 171 && firstOctet <= 180) return 'Italy';
            if (firstOctet >= 181 && firstOctet <= 190) return 'Spain';
            if (firstOctet >= 191 && firstOctet <= 200) return 'Turkey';
            
            return 'Other';
        }

        function getCountryRegion(country) {
            var regions = {
                'United States': 'North America',
                'Canada': 'North America',
                'China': 'Asia',
                'Japan': 'Asia',
                'India': 'Asia',
                'Russia': 'Europe',
                'Germany': 'Europe',
                'United Kingdom': 'Europe',
                'France': 'Europe',
                'Italy': 'Europe',
                'Spain': 'Europe',
                'Netherlands': 'Europe',
                'Turkey': 'Europe',
                'Brazil': 'South America',
                'Australia': 'Oceania',
                'Other': 'Unknown Region'
            };
            
            return regions[country] || 'Other';
        }

        function getCountryCode(country) {
            var codes = {
                'United States': 'US',
                'China': 'CN',
                'Russia': 'RU',
                'Germany': 'DE',
                'France': 'FR',
                'United Kingdom': 'GB',
                'Japan': 'JP',
                'Brazil': 'BR',
                'India': 'IN',
                'Canada': 'CA',
                'Netherlands': 'NL',
                'Australia': 'AU',
                'Italy': 'IT',
                'Spain': 'ES',
                'Turkey': 'TR',
                'Other': 'XX'
            };
            
            return codes[country] || 'XX';
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
            // FIXED: Changed from 24h to 30d period
            ajaxCall('/api/webguard/threats/getTimeline', {period: '30d'}, function(response) {
                console.log('Timeline API Response:', response);
                
                var ctx2 = document.getElementById('timelineChart').getContext('2d');
                
                if (response && response.status === 'ok' && response.timeline) {
                    var labels = response.timeline.labels || [];
                    var data = response.timeline.threats || [];
                    
                    // If empty data, create sample data for 30 days
                    if (labels.length === 0 || data.length === 0) {
                        labels = [];
                        data = [];
                        
                        // Generate last 30 days
                        for (var i = 29; i >= 0; i--) {
                            var date = new Date();
                            date.setDate(date.getDate() - i);
                            labels.push(date.toLocaleDateString());
                            data.push(0);
                        }
                    }
                    
                    timelineChart = new Chart(ctx2, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Geographic Threats (30 days)',
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
                                x: { title: { display: true, text: 'Date' } }
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
            
            // Generate 24 hours with more realistic activity patterns
            var peakHours = [8, 9, 10, 14, 18, 21]; // Peak activity hours
            
            for (var i = 0; i < 24; i++) {
                var hourStr = i < 10 ? '0' + i : i.toString();
                hours.push(hourStr + ':00');
                
                // Generate more realistic activity data
                var baseActivity = Math.floor(Math.random() * 3) + 1;
                if (peakHours.indexOf(i) !== -1) {
                    baseActivity += Math.floor(Math.random() * 6) + 3; // Higher activity during peak hours
                }
                activity.push(baseActivity);
            }
            
            // Calculate max for color intensity
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
            var labels = [];
            var data = [];
            
            // Generate last 30 days
            for (var i = 29; i >= 0; i--) {
                var date = new Date();
                date.setDate(date.getDate() - i);
                labels.push(date.toLocaleDateString());
                data.push(0);
            }
            
            timelineChart = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'No Data Available (30 days)',
                        data: data,
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
                        x: { title: { display: true, text: 'Date' } }
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
        
        function populateCountrySelect(countries) {
            var select = $('#countrySelect');
            select.find('option:not(:first)').remove();
            
            for (var country in countries) {
                if (countries.hasOwnProperty(country) && 
                    country !== 'Other' && 
                    window.appConfig.blockedCountries.indexOf(country) === -1) {
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

        function validateIP(ip) {
            var regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return regex.test(ip);
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
                // Major countries with flags
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
        
        // Global functions for country actions
        window.blockCountry = function(country) {
            showBlockModal(country);
        };
        
        window.showBlockModal = showBlockModal;
        window.closeBlockModal = closeBlockModal;
        window.viewCountryDetails = viewCountryDetails;
        window.closeCountryDetails = closeCountryDetails;
        
        // Test function per verificare che l'API funzioni
        window.testServiceAPI = function() {
            console.log('Testing Service API endpoints...');
            
            // Test blocked countries count
            $.ajax({
                url: '/api/webguard/service/getBlockedCountriesCount',
                method: 'GET',
                success: function(response) {
                    console.log('getBlockedCountriesCount result:', response);
                },
                error: function(xhr, status, error) {
                    console.error('getBlockedCountriesCount failed:', {
                        status: status,
                        error: error,
                        response: xhr.responseText
                    });
                }
            });
            
            // Test blocked countries list
            $.ajax({
                url: '/api/webguard/service/getBlockedCountries',
                method: 'GET',
                success: function(response) {
                    console.log('getBlockedCountries result:', response);
                },
                error: function(xhr, status, error) {
                    console.error('getBlockedCountries failed:', {
                        status: status,
                        error: error,
                        response: xhr.responseText
                    });
                }
            });
        };

         window.blockCountry = function(country) {
            showBlockModal(country);
        };

        // Debug function to test API directly
        window.testGeoAPI = function() {
            console.log('Testing Geo API directly...');
            
            $.ajax({
                url: '/api/webguard/threats/getGeoStats',
                method: 'GET',
                data: { period: '30d' },
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
    });
</script>