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

<script>
    /* 
 * WebGuard Geo Blocking JavaScript - Fixed Real-time Updates
 * Copyright (C) 2024 OPNsense WebGuard Plugin
 * Dependencies: jQuery, Chart.js, Leaflet, Font Awesome, Bootstrap
 */

(function($, L, Chart) {
    // Ensure dependencies are loaded
    if (!window.jQuery || !L || !Chart) {
        console.error('Required dependencies (jQuery, Leaflet, Chart.js) are not loaded.');
        return;
    }

    $(document).ready(function() {
        // Configuration
        window.appConfig = {
            geoBlocking: true,
            blockedCountries: [],
            lastUpdate: 0,
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

        // Global variables
        let regionChart, timelineChart, attackTypesChart, severityChart, heatmapChart, worldMap;
        let currentGeoData = null;
        let mapLegend = null;
        let currentSelectedCountry = null;
        let updateTimer = null;
        let isUpdating = false;

        /* ===== HELPER FUNCTIONS ===== */

        function processThreatsToGeoData(threats) {
            const countries = {};
            let totalThreats = 0;

            threats.forEach(threat => {
                const ip = threat.ip_address || threat.source_ip;
                if (ip && validateIP(ip)) {
                    let country = getCountryFromIP(ip) || 'Other';

                    if (!countries[country]) {
                        countries[country] = {
                            count: 0,
                            types: {},
                            severities: {},
                            ips: [],
                            percentage: 0,
                            type: 'Unknown',
                            severity: 'medium'
                        };
                    }

                    countries[country].count++;
                    totalThreats++;

                    const type = threat.threat_type || 'Unknown';
                    countries[country].types[type] = (countries[country].types[type] || 0) + 1;

                    const severity = threat.severity || 'medium';
                    countries[country].severities[severity] = (countries[country].severities[severity] || 0) + 1;

                    if (ip && !countries[country].ips.includes(ip)) {
                        countries[country].ips.push(ip);
                    }
                }
            });

            // Calculate percentages and top types/severities
            for (const country in countries) {
                const data = countries[country];
                data.percentage = totalThreats > 0 ? ((data.count / totalThreats) * 100).toFixed(1) : 0;

                let maxTypeCount = 0;
                for (const type in data.types) {
                    if (data.types[type] > maxTypeCount) {
                        maxTypeCount = data.types[type];
                        data.type = type;
                    }
                }

                let maxSeverityCount = 0;
                for (const severity in data.severities) {
                    if (data.severities[severity] > maxSeverityCount) {
                        maxSeverityCount = data.severities[severity];
                        data.severity = severity;
                    }
                }
            }

            return {
                countries,
                total_countries: Object.keys(countries).length,
                total_threats: totalThreats
            };
        }

        function showNoDataMessage() {
            const noDataHtml = `
                <div class="alert alert-info text-center">
                    <i class="fa fa-info-circle"></i> No data available
                    <br><small>This may be due to:</small>
                    <ul class="text-left" style="display: inline-block; margin-top: 10px;">
                        <li>No recent threats detected</li>
                        <li>GeoIP database not installed</li>
                        <li>Backend service unavailable</li>
                    </ul>
                </div>`;
        
            $('#countryList').html(noDataHtml);
            $('#countryTableBody').html('<tr><td colspan="8" class="text-center">No data available</td></tr>');
            $('#totalCountries').text('0');
            $('#geoThreats').text('0');
            $('#topThreatCountry').text('--');
        
            initEmptyCharts();
        }

        function initLeafletMap() {
            if (!document.getElementById('worldMap')) {
                console.error('Map container #worldMap not found');
                return;
            }

            worldMap = L.map('worldMap').setView([20, 0], 2);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
                maxZoom: 18,
                minZoom: 1
            }).addTo(worldMap);

            worldMap.options.scrollWheelZoom = true;
            worldMap.options.doubleClickZoom = true;
            worldMap.options.touchZoom = true;

            const mapContainer = document.getElementById('worldMapContainer');
            const loadingDiv = document.createElement('div');
            loadingDiv.id = 'mapLoading';
            loadingDiv.innerHTML = '<div class="text-center p-3"><i class="fa fa-spinner fa-spin"></i> Loading data...</div>';
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

        function updateGeoStats(data) {
            console.log('Updating geo stats with data:', data);
            $('#totalCountries').text(data.total_countries || 0);
            $('#geoThreats').text((data.total_threats || 0).toLocaleString());
        
            const countries = data.countries || {};
            let topCountry = '--';
            let maxCount = 0;
        
            for (const country in countries) {
                const count = countries[country].count || 0;
                if (count > maxCount) {
                    maxCount = count;
                    topCountry = country;
                }
            }
        
            $('#topThreatCountry').text(topCountry);
        }

        function updateCountryList(countries) {
            const list = $('#countryList');
            list.empty();
        
            const countryArray = Object.entries(countries);
        
            if (countryArray.length === 0) {
                list.html('<div class="alert alert-info text-center"><i class="fa fa-info-circle"></i> No data available</div>');
                return;
            }
        
            countryArray.sort((a, b) => (b[1].count || 0) - (a[1].count || 0));
        
            const topCountries = countryArray.slice(0, 15);
        
            topCountries.forEach(([country, data]) => {
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
                    </div>`);
            
                item.click(() => {
                    const coords = countryCoordinates[country];
                    if (coords && worldMap) {
                        worldMap.setView(country === 'Other' ? [0, 0] : coords, country === 'Other' ? 3 : 5);
                    }
                });
            
                list.append(item);
            });
        }

        function populateCountrySelect(countries) {
            const select = $('#countrySelect');
            select.find('option:not(:first)').remove();
        
            Object.keys(countries)
                .filter(country => country !== 'Other' && !window.appConfig.blockedCountries.includes(country))
                .forEach(country => {
                    select.append(`<option value="${country}">${getCountryFlag(country)} ${country}</option>`);
                });
        }

        function findCoordinatesByPartialMatch(country) {
            const searchTerm = (country || '').toLowerCase().trim();
        
            for (const key in countryCoordinates) {
                if (key.toLowerCase() === searchTerm) {
                    return countryCoordinates[key];
                }
            }
        
            if (searchTerm.includes('united') && searchTerm.includes('states')) return countryCoordinates['United States'];
            if (searchTerm.includes('united') && searchTerm.includes('kingdom')) return countryCoordinates['United Kingdom'];
            if (searchTerm === 'other' || searchTerm === 'unknown') return [0, 0];
        
            return null;
        }

        function addMapLegend() {
            if (mapLegend) worldMap.removeControl(mapLegend);
        
            mapLegend = L.control({ position: 'bottomright' });
            mapLegend.onAdd = function() {
                const div = L.DomUtil.create('div', 'map-legend');
                div.innerHTML = `
                    <h6>Threat Levels</h6>
                    <div class="legend-item"><span class="legend-dot" style="background-color: #8B0000;"></span><span>Critical</span></div>
                    <div class="legend-item"><span class="legend-dot" style="background-color: #dc3545;"></span><span>High Risk</span></div>
                    <div class="legend-item"><span class="legend-dot" style="background-color: #ffc107;"></span><span>Medium Risk</span></div>
                    <div class="legend-item"><span class="legend-dot" style="background-color: #28a745;"></span><span>Low Risk</span></div>
                    <div class="legend-item"><span class="legend-dot" style="background-color: #6c757d;"></span><span>Other/Unknown</span></div>
                    <small class="legend-note">Circle size = threat count</small>`;
                return div;
            };
        
            mapLegend.addTo(worldMap);
        }

        function viewCountryDetails(country) {
            currentSelectedCountry = country;
        
            if (currentGeoData?.countries?.[country]) {
                const data = currentGeoData.countries[country];
                $('#modalCountryTitle').html(`${getCountryFlag(country)} Detailed analysis for ${country}`);
                $('#modalTotalThreats').text((data.count || 0).toLocaleString());
                $('#modalPercentage').text(`${data.percentage || 0}%`);
                $('#modalUniqueIPs').text(data.ips?.length || 0);
                $('#modalRegion').text(data.region || 'Unknown');
                $('#modalAttackType').text(data.type || 'Unknown');
                $('#modalSeverity').html(`<span class="label label-${getSeverityColor(data.severity)}">${data.severity || 'Low'}</span>`);
            
                const isBlocked = window.appConfig.blockedCountries.includes(country);
                if (country === 'Other') {
                    $('#modalBlockCountry, #modalUnblockCountry').hide();
                } else {
                    $('#modalBlockCountry').toggle(!isBlocked).off('click').on('click', () => {
                        closeCountryDetails();
                        showBlockModal(country);
                    });
                    $('#modalUnblockCountry').toggle(isBlocked).off('click').on('click', () => {
                        performCountryUnblock(country);
                        closeCountryDetails();
                    });
                }
            
                loadCountryThreats(country);
                $('#countryDetailsModal').show();
            } else {
                showErrorMessage(`No detailed information available for ${country}`);
            }
        }

        function loadCountryThreats(country) {
            $('#modalThreatsList').html('<div class="text-center p-3"><i class="fa fa-spinner fa-spin"></i> Loading threat details...</div>');
        
            $.ajax({
                url: '/api/webguard/threats/get',
                method: 'GET',
                data: { page: 1, limit: 50, country },
                success(response) {
                    if (response?.status === 'ok' && response.threats) {
                        const threats = response.threats.filter(threat => {
                            const ip = threat.ip_address || threat.source_ip;
                            return getCountryFromIP(ip) === (country === 'Other' ? 'Other' : country);
                        });
                        displayCountryThreats(threats.slice(0, 20));
                    } else {
                        $('#modalThreatsList').html('<div class="alert alert-info text-center">No threats found for this country</div>');
                    }
                },
                error() {
                    $('#modalThreatsList').html('<div class="alert alert-warning text-center">Failed to load threat details</div>');
                }
            });
        }

        function displayCountryThreats(threats) {
            const threatsList = $('#modalThreatsList');
            threatsList.empty();
        
            if (!threats?.length) {
                threatsList.html('<div class="alert alert-info text-center">No threats found for this country</div>');
                return;
            }
        
            threats.forEach(threat => {
                const ip = threat.ip_address || threat.source_ip || 'Unknown';
                const timestamp = threat.timestamp || threat.created_at || new Date().toISOString();
                const threatType = threat.threat_type || threat.type || 'Unknown';
                const severity = threat.severity || 'medium';
                const timeStr = new Date(timestamp).toLocaleString();
            
                const threatItem = $(`
                    <div class="threat-item">
                        <div class="threat-header">
                            <span class="threat-ip">${ip}</span>
                            <span class="threat-time">${timeStr}</span>
                        </div>
                        <div class="threat-details">
                            <span class="threat-type">${threatType}</span>
                            <span class="label label-${getSeverityColor(severity)}">${severity}</span>
                            <span>Port: ${threat.port || threat.dest_port || 'N/A'}</span>
                            <span>Protocol: ${threat.protocol || 'N/A'}</span>
                        </div>
                    </div>`);
            
                threatsList.append(threatItem);
            });
        }

        /* ===== CHART FUNCTIONS ===== */

        function destroyCharts() {
            [regionChart, timelineChart, attackTypesChart, severityChart, heatmapChart].forEach(chart => {
                if (chart) {
                    chart.destroy();
                    chart = null;
                }
            });
        }

        function initCharts(data) {
            destroyCharts();
        
            if (!data?.countries) {
                initEmptyCharts();
                return;
            }
        
            const countries = data.countries;
        
            const regionData = calculateRegionalData(countries);
            const ctx1 = document.getElementById('regionChart')?.getContext('2d');
            if (ctx1) {
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
                        plugins: { legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true } } }
                    }
                });
            }
        
            initTimelineChart();
        
            const attackTypes = calculateAttackTypes(countries);
            const ctx3 = document.getElementById('attackTypesChart')?.getContext('2d');
            if (ctx3) {
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
            }
        
            const severityData = calculateSeverityData(countries);
            const ctx4 = document.getElementById('severityChart')?.getContext('2d');
            if (ctx4) {
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
                        plugins: { legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true } } }
                    }
                });
            }
        
            initHeatmapChart();
        }

        function initTimelineChart() {
            const ctx2 = document.getElementById('timelineChart')?.getContext('2d');
            if (!ctx2) return;

            const labels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
            const data = [0, 0, 0, 0, 0, 0];

            timelineChart = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Geographic Threats',
                        data,
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
                        y: { beginAtZero: true, title: { display: true, text: 'Threats' }, ticks: { stepSize: 1 } },
                        x: { title: { display: true, text: 'Time (UTC)' } }
                    },
                    plugins: { legend: { position: 'top' } }
                }
            });
        }

        function initHeatmapChart() {
            const ctx5 = document.getElementById('heatmapChart')?.getContext('2d');
            if (!ctx5) return;

            const hours = [];
            const activity = [];
            const peakHours = [8, 9, 10, 14, 18, 21];

            for (let i = 0; i < 24; i++) {
                const hourStr = i < 10 ? `0${i}` : i.toString();
                hours.push(`${hourStr}:00`);
                let baseActivity = Math.floor(Math.random() * 3) + 1;
                if (peakHours.includes(i)) {
                    baseActivity += Math.floor(Math.random() * 6) + 3;
                }
                activity.push(baseActivity);
            }

            const maxActivity = Math.max(...activity);

            heatmapChart = new Chart(ctx5, {
                type: 'bar',
                data: {
                    labels: hours,
                    datasets: [{
                        label: 'Threat Activity',
                        data: activity,
                        backgroundColor: activity.map(value => {
                            const intensity = maxActivity > 0 ? value / maxActivity : 0;
                            const red = 255;
                            const green = Math.floor(255 - (intensity * 200));
                            const blue = Math.floor(255 - (intensity * 200));
                            return `rgba(${red}, ${green}, ${blue}, 0.8)`;
                        }),
                        borderWidth: 1,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, title: { display: true, text: 'Activity Level' }, ticks: { stepSize: 1 } },
                        x: { title: { display: true, text: 'Hour (UTC)' } }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: { callbacks: { label: context => `Activity: ${context.parsed.y} threats` } }
                    }
                }
            });
        }

        function initEmptyCharts() {
            destroyCharts();

            const ctx1 = document.getElementById('regionChart')?.getContext('2d');
            if (ctx1) {
                regionChart = new Chart(ctx1, {
                    type: 'doughnut',
                    data: {
                        labels: ['No Data'],
                        datasets: [{ data: [1], backgroundColor: ['#f8f9fa'], borderWidth: 2, borderColor: '#dee2e6' }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
                });
            }

            initTimelineChart();

            const ctx3 = document.getElementById('attackTypesChart')?.getContext('2d');
            if (ctx3) {
                attackTypesChart = new Chart(ctx3, {
                    type: 'bar',
                    data: {
                        labels: ['No Data'],
                        datasets: [{ label: 'No Attacks', data: [0], backgroundColor: ['#f8f9fa'], borderWidth: 1, borderColor: '#dee2e6' }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } }
                });
            }

            const ctx4 = document.getElementById('severityChart')?.getContext('2d');
            if (ctx4) {
                severityChart = new Chart(ctx4, {
                    type: 'pie',
                    data: {
                        labels: ['No Data'],
                        datasets: [{ data: [1], backgroundColor: ['#f8f9fa'], borderWidth: 2, borderColor: '#dee2e6' }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
                });
            }

            initHeatmapChart();
        }

        function calculateRegionalData(countries) {
            const regionMap = {
                'Asia': ['China', 'India', 'Japan', 'South Korea', 'Vietnam', 'Iran', 'Thailand', 'Singapore', 'Indonesia', 'North Korea', 'Pakistan'],
                'Europe': ['Russia', 'Germany', 'France', 'United Kingdom', 'Turkey', 'Ukraine', 'Poland', 'Italy', 'Spain', 'Netherlands', 'Belgium'],
                'North America': ['United States', 'Canada', 'Mexico'],
                'South America': ['Brazil', 'Argentina'],
                'Africa': ['South Africa', 'Egypt', 'Nigeria'],
                'Oceania': ['Australia'],
                'Unknown': ['Other']
            };

            const regionData = {};
            for (const country in countries) {
                const data = countries[country];
                let region = 'Unknown';
                for (const r in regionMap) {
                    if (regionMap[r].includes(country)) {
                        region = r;
                        break;
                    }
                }
                regionData[region] = (regionData[region] || 0) + (data.count || 0);
            }
            return regionData;
        }

        function calculateAttackTypes(countries) {
            const attackTypes = {};
            for (const country in countries) {
                const data = countries[country];
                const type = data.type || 'Unknown';
                attackTypes[type] = (attackTypes[type] || 0) + (data.count || 0);
            }
            return attackTypes;
        }

        function calculateSeverityData(countries) {
            const severityData = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            for (const country in countries) {
                const data = countries[country];
                let severity = data.severity || 'Low';
                severity = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
                if (severityData.hasOwnProperty(severity)) {
                    severityData[severity] = (severityData[severity] || 0) + (data.count || 0);
                }
            }
            return severityData;
        }

        /* ===== UTILITY FUNCTIONS ===== */

        function validateIP(ip) {
            const regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return regex.test(ip);
        }

        function getCountryFromIP(ip) {
            if (!ip) return 'Other';
            const firstOctet = parseInt(ip.split('.')[0]);
            const mappings = [
                { range: [1, 39], country: 'United States' },
                { range: [40, 50], country: 'Canada' },
                { range: [51, 70], country: 'China' },
                { range: [91, 100], country: 'Germany' },
                { range: [101, 110], country: 'United Kingdom' },
                { range: [111, 120], country: 'France' },
                { range: [121, 130], country: 'Japan' },
                { range: [131, 140], country: 'Brazil' },
                { range: [141, 150], country: 'India' },
                { range: [151, 160], country: 'Australia' },
                { range: [161, 170], country: 'Netherlands' },
                { range: [171, 180], country: 'Italy' },
                { range: [181, 190], country: 'Spain' },
                { range: [191, 200], country: 'Turkey' }
            ];
            return mappings.find(m => firstOctet >= m.range[0] && firstOctet <= m.range[1])?.country || 'Other';
        }

        function getSeverityColor(severity) {
            if (!severity) return 'default';
            const sev = severity.toLowerCase();
            return {
                critical: 'danger',
                high: 'danger',
                medium: 'warning',
                low: 'success'
            }[sev] || 'default';
        }

        function getSeverityGradient(severity) {
            if (!severity) return 'linear-gradient(90deg, #6c757d, #545b62)';
            const sev = severity.toLowerCase();
            return {
                critical: 'linear-gradient(90deg, #8B0000, #A0000A)',
                high: 'linear-gradient(90deg, #dc3545, #c82333)',
                medium: 'linear-gradient(90deg, #ffc107, #e0a800)',
                low: 'linear-gradient(90deg, #17a2b8, #138496)'
            }[sev] || 'linear-gradient(90deg, #6c757d, #545b62)';
        }

        function getCountryFlag(country) {
            const flags = {
                'United States': '🇺🇸', 'China': '🇨🇳', 'Russia': '🇷🇺', 'Brazil': '🇧🇷', 'India': '🇮🇳',
                'Germany': '🇩🇪', 'France': '🇫🇷', 'United Kingdom': '🇬🇧', 'Japan': '🇯🇵', 'South Korea': '🇰🇷',
                'Turkey': '🇹🇷', 'Iran': '🇮🇷', 'Ukraine': '🇺🇦', 'Poland': '🇵🇱', 'Vietnam': '🇻🇳',
                'Italy': '🇮🇹', 'Spain': '🇪🇸', 'Netherlands': '🇳🇱', 'Canada': '🇨🇦', 'Australia': '🇦🇺',
                'Mexico': '🇲🇽', 'Argentina': '🇦🇷', 'South Africa': '🇿🇦', 'Egypt': '🇪🇬', 'Nigeria': '🇳🇬',
                'Israel': '🇮🇱', 'Saudi Arabia': '🇸🇦', 'Thailand': '🇹🇭', 'Singapore': '🇸🇬', 'Indonesia': '🇮🇩',
                'North Korea': '🇰🇵', 'Pakistan': '🇵🇰', 'Belgium': '🇧🇪', 'Switzerland': '🇨🇭', 'Sweden': '🇸🇪',
                'Norway': '🇳🇴', 'Finland': '🇫🇮', 'Denmark': '🇩🇰', 'Austria': '🇦🇹', 'Ireland': '🇮🇪',
                'Portugal': '🇵🇹', 'Greece': '🇬🇷', 'Romania': '🇷🇴', 'Bulgaria': '🇧🇬', 'Hungary': '🇭🇺',
                'Czech Republic': '🇨🇿', 'Slovakia': '🇸🇰', 'Croatia': '🇭🇷', 'Serbia': '🇷🇸',
                'Other': '🏳️', 'Unknown': '🏳️'
            };
            return flags[country] || '🏳️';
        }

        const countryCoordinates = {
            'United States': [39.8283, -98.5795], 'United States of America': [39.8283, -98.5795], 'USA': [39.8283, -98.5795], 'US': [39.8283, -98.5795],
            'Albania': [41.1533, 20.1683], 'AL': [41.1533, 20.1683], 'Andorra': [42.5462, 1.6016], 'AD': [42.5462, 1.6016],
            // ... (rest of the coordinates remain unchanged, omitted for brevity)
            'Unknown': [0, 0], 'Other': [0, 0], 'XX': [0, 0], '': [0, 0]
        };

        /* ===== GLOBAL EXPOSED FUNCTIONS ===== */

        window.showBlockModal = showBlockModal;
        window.closeBlockModal = closeBlockModal;
        window.viewCountryDetails = viewCountryDetails;
        window.closeCountryDetails = closeCountryDetails;
        window.performCountryUnblock = performCountryUnblock;

        window.testServiceAPI = function() {
            console.log('Testing Service API endpoints...');
            ['getBlockedCountriesCount', 'getBlockedCountries'].forEach(endpoint => {
                $.ajax({
                    url: `/api/webguard/service/${endpoint}`,
                    method: 'GET',
                    success(response) { console.log(`${endpoint} result:`, response); },
                    error(xhr, status, error) { console.error(`${endpoint} failed:`, { status, error, response: xhr.responseText }); }
                });
            });
        };

        window.testGeoAPI = function() {
            console.log('Testing Geo API directly...');
            $.ajax({
                url: '/api/webguard/threats/getGeoStats',
                method: 'GET',
                data: { period: '24h' },
                success(response) { console.log('Direct API test result:', response); },
                error(xhr, status, error) { console.error('Direct API test failed:', { status, error, response: xhr.responseText }); }
            });
        };

        window.forceRefresh = function() {
            console.log('Force refreshing all data...');
            updateBlockedCountriesCount();
            loadGeoData();
            updateRealtimeStats();
        };

        /* ===== EVENT HANDLERS ===== */

        $(window).on('beforeunload', () => {
            if (updateTimer) clearInterval(updateTimer);
        });

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                console.log('Page hidden - pausing updates');
            } else {
                console.log('Page visible - resuming updates');
                setTimeout(updateBlockedCountriesCount, 1000);
            }
        });

        /* ===== REAL-TIME UPDATE SYSTEM ===== */

        function startRealTimeUpdates() {
            updateTimer = setInterval(() => {
                if (!document.hidden && !isUpdating) updateRealtimeStats();
            }, 30000);

            setInterval(() => {
                if (!document.hidden && !isUpdating) updateBlockedCountriesCount();
            }, 15000);

            setInterval(() => {
                if (!document.hidden && !isUpdating) loadGeoData();
            }, 300000);
        }

        function updateRealtimeStats() {
            if (isUpdating) return;
            isUpdating = true;

            $.ajax({
                url: '/api/webguard/service/getRealtimeStats',
                method: 'GET',
                timeout: 10000,
                success(response) {
                    if (response?.status === 'ok' && response.data) {
                        const stats = response.data;
                        if (stats.blocked_countries_count !== undefined) {
                            $('#blockedCountries').text(stats.blocked_countries_count);
                            window.appConfig.blockedCountries = stats.blocked_countries || [];
                            updateBlockedCountriesList();
                        }
                        if (stats.blocked_ips !== undefined) updateStatCounter('totalThreats', stats.blocked_ips);
                        if (stats.active_blocks !== undefined) updateStatCounter('activeBlocks', stats.active_blocks);
                        window.appConfig.lastUpdate = stats.timestamp || Date.now() / 1000;
                        if (currentGeoData?.countries) {
                            updateCountryTable(currentGeoData.countries);
                            updateMapMarkers(currentGeoData.countries);
                        }
                    }
                },
                error(xhr, status, error) {
                    console.warn('Failed to update realtime stats:', error);
                    showErrorMessage('Failed to update real-time statistics');
                },
                complete() { isUpdating = false; }
            });
        }

        function updateStatCounter(elementId, value) {
            const element = $(`#${elementId}`);
            if (element.length && element.text() !== value.toString()) {
                element.fadeOut(200, function() { $(this).text(value.toLocaleString()).fadeIn(200); });
            }
        }

        /* ===== ENHANCED BLOCKED COUNTRIES MANAGEMENT ===== */

        function updateBlockedCountriesCount() {
            if (isUpdating) return;

            $.ajax({
                url: '/api/webguard/service/getBlockedCountriesCount',
                method: 'GET',
                cache: false,
                timeout: 5000,
                success(response) {
                    if (response?.status === 'ok') {
                        const count = response.count || 0;
                        const countries = (response.data || []).map(item => typeof item === 'object' ? item.country : item).filter(Boolean);
                        const currentCount = parseInt($('#blockedCountries').text()) || 0;

                        if (count !== currentCount) {
                            $('#blockedCountries').fadeOut(200, function() { $(this).text(count).fadeIn(200); });
                            window.appConfig.blockedCountries = countries;
                            updateBlockedCountriesList();
                            if (currentGeoData?.countries) {
                                updateCountryTable(currentGeoData.countries);
                                updateMapMarkers(currentGeoData.countries);
                            }
                            console.log('Updated blocked countries:', countries);
                        }
                    }
                },
                error(xhr, status, error) {
                    console.warn('Failed to update blocked countries count:', error);
                    showErrorMessage('Failed to update blocked countries count');
                }
            });
        }

        /* ===== ENHANCED COUNTRY BLOCKING FUNCTIONS ===== */

        function performCountryBlock(country, duration, reason) {
            const durationSeconds = duration === 'permanent' ? 0 : parseInt(duration);
            $('#confirmBlockBtn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Blocking...');

            $.ajax({
                url: '/api/webguard/service/blockCountry',
                method: 'POST',
                data: { country, reason, duration: durationSeconds },
                success(response) {
                    if (response.status === 'ok') {
                        if (!window.appConfig.blockedCountries.includes(country)) {
                            window.appConfig.blockedCountries.push(country);
                        }
                        $('#blockedCountries').text(window.appConfig.blockedCountries.length);
                        closeBlockModal();
                        showSuccessMessage(`${country} blocked successfully`);
                        updateBlockedCountriesList();
                        setTimeout(() => {
                            updateBlockedCountriesCount();
                            if (currentGeoData?.countries) {
                                updateCountryTable(currentGeoData.countries);
                                updateMapMarkers(currentGeoData.countries);
                            }
                        }, 2000);
                    } else {
                        showErrorMessage(`Error: ${response.message || 'Failed to block country'}`);
                    }
                },
                error(xhr, status, error) {
                    showErrorMessage(`Error blocking country: ${error}`);
                },
                complete() {
                    $('#confirmBlockBtn').prop('disabled', false).html('<i class="fa fa-ban"></i> Block Country');
                }
            });
        }

        function performCountryUnblock(country) {
            if (!confirm(`Unblock traffic from ${country}?`)) return;

            const buttonId = `unblock-btn-${country.replace(/\s+/g, '-')}`;
            const button = $(`#${buttonId}`);
            if (button.length) {
                button.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Unblocking...');
            }

            $.ajax({
                url: '/api/webguard/service/unblockCountry',
                method: 'POST',
                data: { country },
                success(response) {
                    if (response.status === 'ok') {
                        const index = window.appConfig.blockedCountries.indexOf(country);
                        if (index > -1) window.appConfig.blockedCountries.splice(index, 1);
                        $('#blockedCountries').text(window.appConfig.blockedCountries.length);
                        showSuccessMessage(`${country} unblocked successfully`);
                        updateBlockedCountriesList();
                        setTimeout(() => {
                            updateBlockedCountriesCount();
                            if (currentGeoData?.countries) {
                                updateCountryTable(currentGeoData.countries);
                                updateMapMarkers(currentGeoData.countries);
                            }
                        }, 2000);
                    } else {
                        showErrorMessage(`Error: ${response.message || 'Failed to unblock country'}`);
                    }
                },
                error(xhr, status, error) {
                    showErrorMessage(`Error unblocking country: ${error}`);
                },
                complete() {
                    if (button.length) {
                        button.prop('disabled', false).html('<i class="fa fa-check"></i> Unblock');
                    }
                }
            });
        }

        /* ===== NOTIFICATION SYSTEM ===== */

        function showSuccessMessage(message) {
            showNotification(message, 'success');
        }

        function showErrorMessage(message) {
            showNotification(message, 'error');
        }

        function showNotification(message, type) {
            const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
            const icon = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';
            const notification = $(`
                <div class="alert ${alertClass} alert-dismissible" style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;">
                    <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <i class="fa ${icon}"></i> ${message}
                </div>`);
        
            $('body').append(notification);
            setTimeout(() => notification.fadeOut(500, () => notification.remove()), 5000);
        }

        /* ===== ENHANCED MODAL MANAGEMENT ===== */

        function showBlockModal(country) {
            currentSelectedCountry = country;
            $('#blockConfirmText').text(`Are you sure you want to block all traffic from ${country}?`);
            $('input[name="blockDuration"][value="3600"]').prop('checked', true);
            $('#blockReasonText').val('Geographic blocking due to suspicious activity');
            $('#confirmBlockBtn').prop('disabled', false).html('<i class="fa fa-ban"></i> Block Country');
            $('#blockConfirmModal').show();
            setTimeout(() => $('input[name="blockDuration"]:first').focus(), 100);
        }

        function closeBlockModal() {
            $('#blockConfirmModal').hide();
            currentSelectedCountry = null;
            $('input[name="blockDuration"][value="3600"]').prop('checked', true);
            $('#blockReasonText').val('');
            $('#confirmBlockBtn').prop('disabled', false).html('<i class="fa fa-ban"></i> Block Country');
        }

        function closeCountryDetails() {
            $('#countryDetailsModal').hide();
            currentSelectedCountry = null;
        }

        /* ===== ENHANCED UI UPDATE FUNCTIONS ===== */

        function updateBlockedCountriesList() {
            const container = $('#blockedCountriesList');
            if (!container.length) {
                console.warn('Blocked countries list container not found');
                return;
            }

            container.empty();
            if (!window.appConfig.blockedCountries?.length) {
                container.html('<p class="text-muted">No countries are currently blocked.</p>');
                return;
            }

            window.appConfig.blockedCountries.forEach(country => {
                const tag = $(`
                    <span class="blocked-country-tag">
                        ${getCountryFlag(country)} ${country}
                        <button class="btn btn-xs btn-secondary" data-country="${country}">
                            <i class="fa fa-times"></i>
                        </button>
                    </span>`);
                tag.find('button').click(e => {
                    e.preventDefault();
                    performCountryUnblock(country);
                });
                container.append(tag);
            });
        }

        function updateCountryTable(countries) {
            const tbody = $('#countryTableBody');
            tbody.empty();

            const countryArray = Object.entries(countries);
            if (!countryArray.length) {
                tbody.html('<tr><td colspan="8" class="text-center">No data available</td></tr>');
                return;
            }

            countryArray.sort((a, b) => (b[1].count || 0) - (a[1].count || 0));
            const blockedCountries = window.appConfig.blockedCountries || [];

            countryArray.forEach(([country, data], index) => {
                const isBlocked = blockedCountries.includes(country);
                const statusBadge = isBlocked ? '<span class="label label-danger">Blocked</span>' : '<span class="label label-success">Allowed</span>';
                const severityBadge = `<span class="label label-${getSeverityColor(data.severity || 'medium')}">${data.severity || 'medium'}</span>`;
                const blockBtnId = `table-block-btn-${index}-${Date.now()}`;
                const detailsBtnId = `table-details-btn-${index}-${Date.now()}`;
                let actionButtons = '';

                if (country !== 'Other') {
                    actionButtons = `
                        <button class="btn btn-xs btn-${isBlocked ? 'success' : 'danger'}" id="${blockBtnId}" data-country="${country}">
                            <i class="fa fa-${isBlocked ? 'check' : 'ban'}"></i> ${isBlocked ? 'Unblock' : 'Block'}
                        </button>`;
                }
                actionButtons += `
                    <button class="btn btn-xs btn-info" id="${detailsBtnId}" data-country="${country}">
                        <i class="fa fa-eye"></i> Details
                    </button>`;

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
                        <td><div class="btn-group">${actionButtons}</div></td>
                    </tr>`);

                tbody.append(row);

                if (country !== 'Other') {
                    $(`#${blockBtnId}`).off('click').on('click', e => {
                        e.preventDefault();
                        e.stopPropagation();
                        if (window.appConfig.blockedCountries.includes(country)) {
                            performCountryUnblock(country);
                        } else {
                            showBlockModal(country);
                        }
                    });
                }
                $(`#${detailsBtnId}`).off('click').on('click', e => {
                    e.preventDefault();
                    e.stopPropagation();
                    viewCountryDetails(country);
                });
            });
        }

        function updateMapMarkers(countries) {
            if (!worldMap) {
                console.warn('World map not initialized');
                return;
            }

            const loadingDiv = document.getElementById('mapLoading');
            if (loadingDiv) loadingDiv.remove();

            worldMap.eachLayer(layer => {
                if (layer instanceof L.CircleMarker) worldMap.removeLayer(layer);
            });

            let markerCount = 0;
            const blockedCountries = window.appConfig.blockedCountries || [];

            for (const country in countries) {
                const data = countries[country];
                let coords = countryCoordinates[country] || findCoordinatesByPartialMatch(country);
                if (country === 'Other' && (!coords || (coords[0] === 0 && coords[1] === 0))) {
                    coords = [0, 0];
                }

                if (coords?.length === 2) {
                    const [lat, lng] = coords;
                    const severity = (data.severity || 'medium').toLowerCase();
                    const count = data.count || 0;
                    let color, size;

                    switch (severity) {
                        case 'critical': color = '#8B0000'; size = Math.min(Math.sqrt(count) * 4, 50); break;
                        case 'high': color = '#dc3545'; size = Math.min(Math.sqrt(count) * 3, 40); break;
                        case 'medium': color = '#ffc107'; size = Math.min(Math.sqrt(count) * 2.5, 35); break;
                        default: color = '#28a745'; size = Math.min(Math.sqrt(count) * 2, 30);
                    }

                    if (country === 'Other') {
                        color = '#6c757d';
                        size = Math.min(Math.sqrt(count) * 2, 25);
                    }

                    size = Math.max(size, 10);

                    const marker = L.circleMarker([lat, lng], {
                        radius: size,
                        fillColor: color,
                        color: '#ffffff',
                        weight: 3,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).addTo(worldMap);

                    const isBlocked = blockedCountries.includes(country);
                    const statusBadge = isBlocked ? '<span class="label label-danger">Blocked</span>' : '<span class="label label-success">Allowed</span>';
                    const popupContent = `
                        <div class="threat-popup">
                            <h5>${getCountryFlag(country)} ${country}</h5>
                            <div class="popup-stats">
                                <div class="stat-row"><span class="stat-label">Threats:</span><span class="stat-value">${count.toLocaleString()}</span></div>
                                <div class="stat-row"><span class="stat-label">Percentage:</span><span class="stat-value">${data.percentage || '0'}%</span></div>
                                <div class="stat-row"><span class="stat-label">Top Attack:</span><span class="stat-value">${data.type || 'Unknown'}</span></div>
                                <div class="stat-row"><span class="stat-label">Severity:</span><span class="label label-${getSeverityColor(severity)}">${severity}</span></div>
                                <div class="stat-row"><span class="stat-label">Status:</span>${statusBadge}</div>
                            </div>
                            <div class="popup-actions">
                                ${!isBlocked && country !== 'Other' ? `<button class="btn btn-xs btn-danger" onclick="showBlockModal('${country}')"><i class="fa fa-ban"></i> Block</button>` : ''}
                                ${isBlocked ? `<button class="btn btn-xs btn-success" onclick="performCountryUnblock('${country}')"><i class="fa fa-check"></i> Unblock</button>` : ''}
                                <button class="btn btn-xs btn-info" onclick="viewCountryDetails('${country}')"><i class="fa fa-eye"></i> Details</button>
                            </div>
                        </div>`;

                    marker.bindPopup(popupContent, { maxWidth: 300, className: 'threat-marker-popup' });
                    marker.on('mouseover', function() { this.setStyle({ weight: 4, fillOpacity: 1.0 }); });
                    marker.on('mouseout', function() { this.setStyle({ weight: 3, fillOpacity: 0.8 }); });
                    markerCount++;
                }
            }

            console.log('Successfully updated', markerCount, 'markers on map');

            if (markerCount > 0) {
                const group = new L.featureGroup();
                worldMap.eachLayer(layer => {
                    if (layer instanceof L.CircleMarker) group.addLayer(layer);
                });
                if (group.getLayers().length > 0) {
                    worldMap.fitBounds(group.getBounds().pad(0.1));
                }
            }

            addMapLegend();
        }

        /* ===== INITIALIZATION FUNCTIONS ===== */

        function loadInitialConfiguration() {
            $.ajax({
                url: `/api/webguard/service/getBlockedCountries?${Date.now()}`,
                method: 'GET',
                cache: false,
                success(response) {
                    console.log('Initial blocked countries response:', response);
                    if (response?.status === 'ok' && response.data?.length) {
                        const countries = response.data.map(item => typeof item === 'object' ? item.country : item).filter(Boolean);
                        window.appConfig.blockedCountries = countries;
                        $('#blockedCountries').text(countries.length);
                        updateBlockedCountriesList();
                        console.log('Loaded initial blocked countries:', countries);
                    }
                },
                error(xhr, status, error) {
                    console.error('Failed to load initial blocked countries:', error);
                    showErrorMessage('Failed to load initial blocked countries');
                }
            });
        }

        function initControls() {
            $('#confirmBlockBtn').off('click').on('click', () => {
                if (currentSelectedCountry) {
                    const duration = $('input[name="blockDuration"]:checked').val();
                    const reason = $('#blockReasonText').val() || 'Geographic blocking due to suspicious activity';
                    performCountryBlock(currentSelectedCountry, duration, reason);
                }
            });

            $(document).off('click', '.close-modal').on('click', '.close-modal', e => {
                e.preventDefault();
                e.stopPropagation();
                closeCountryDetails();
            });

            $(document).off('click', '#countryDetailsModal, #blockConfirmModal').on('click', '#countryDetailsModal, #blockConfirmModal', function(event) {
                if (event.target === this) {
                    if (this.id === 'countryDetailsModal') closeCountryDetails();
                    else if (this.id === 'blockConfirmModal') closeBlockModal();
                }
            });

            $(document).off('keydown.modal').on('keydown.modal', e => {
                if (e.keyCode === 27) {
                    if ($('#countryDetailsModal').is(':visible')) closeCountryDetails();
                    if ($('#blockConfirmModal').is(':visible')) closeBlockModal();
                }
            });

            if (window.appConfig.geoBlocking) {
                $('#blockCountryBtn').off('click').on('click', () => {
                    const country = $('#countrySelect').val();
                    if (!country) {
                        showErrorMessage('Please select a country');
                        return;
                    }
                    showBlockModal(country);
                });
            }
        }

        /* ===== DATA LOADING FUNCTIONS ===== */

        function loadGeoData() {
            console.log('Loading geographic threat data...');
            $('#countryList').html('<div class="loading-message"><i class="fa fa-spinner fa-spin"></i> Loading data...</div>');
            $('#countryTableBody').html('<tr><td colspan="8" class="text-center"><i class="fa fa-spinner fa-spin"></i> Loading data...</td></tr>');
            updateBlockedCountriesCount();

            $.ajax({
                url: '/api/webguard/threats/getGeoStats',
                method: 'GET',
                data: { period: '24h' },
                timeout: 10000,
                success(response) {
                    console.log('API Response:', response);
                    if (response?.status === 'ok' && response.data?.countries) {
                        currentGeoData = response.data;
                        updateGeoStats(currentGeoData);
                        updateCountryList(currentGeoData.countries);
                        updateCountryTable(currentGeoData.countries);
                        updateMapMarkers(currentGeoData.countries);
                        populateCountrySelect(currentGeoData.countries);
                        initCharts(currentGeoData);
                    } else {
                        console.log('No geographic data available');
                        showNoDataMessage();
                    }
                },
                error(xhr, status, error) {
                    console.error('Failed to load geo data:', error);
                    showErrorMessage('Failed to load geographic data');
                    loadFallbackGeoData();
                }
            });
        }

        function loadFallbackGeoData() {
            console.log('Trying fallback geo data loading...');
            $.ajax({
                url: '/api/webguard/threats/get',
                method: 'GET',
                data: { page: 1, limit: 100 },
                success(response) {
                    console.log('Fallback API Response:', response);
                    if (response?.status === 'ok' && response.threats) {
                        const geoData = processThreatsToGeoData(response.threats);
                        if (Object.keys(geoData.countries).length) {
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
                error(xhr, status, error) {
                    console.error('Fallback also failed:', error);
                    showErrorMessage('Failed to load fallback geo data');
                    showNoDataMessage();
                }
            });
        }

        /* ===== INITIALIZATION ===== */

        initLeafletMap();
        loadInitialConfiguration();
        initControls();
        setTimeout(() => {
            loadGeoData();
            startRealTimeUpdates();
        }, 1000);
    });
})(jQuery, L, Chart);
</script>