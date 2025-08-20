/**
 * OPNsense Firewall Demo - JavaScript Functions
 * Handles UI interactions, API calls, and real-time updates
 */

// Global variables
let rules = [];
let logCounter = 1;
let autoRefreshInterval;
let isConnected = true;

// Configuration
const CONFIG = {
    API_BASE: '/api',
    REFRESH_INTERVAL: 30000, // 30 seconds
    MAX_LOG_ENTRIES: 100,
    ANIMATION_DURATION: 300
};

// DOM Content Loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

/**
 * Initialize the application
 */
function initializeApp() {
    addLog('🚀 Interfaccia demo caricata');
    loadInitialData();
    setupEventListeners();
    startAutoRefresh();
    updateConnectionStatus();
}

/**
 * Load initial data from the server
 */
function loadInitialData() {
    // Get initial rules from template data if available
    const rulesTableBody = document.getElementById('rulesTableBody');
    if (rulesTableBody && rulesTableBody.children.length > 0) {
        // Extract rules from existing table
        extractRulesFromTable();
    } else {
        // Fetch rules from API
        refreshRules();
    }
}

/**
 * Extract rules from existing table (for initial load)
 */
function extractRulesFromTable() {
    const rows = document.querySelectorAll('#rulesTableBody tr');
    rules = [];
    
    rows.forEach(row => {
        const ruleId = row.getAttribute('data-rule-id');
        const cells = row.querySelectorAll('td');
        
        if (cells.length >= 5) {
            const enabled = cells[0].textContent.includes('Active');
            const description = cells[1].textContent.trim();
            const action = cells[2].textContent.includes('BLOCK') ? 'block' : 'pass';
            const source = cells[3].textContent.trim();
            const destination = cells[4].textContent.trim();
            
            rules.push({
                uuid: ruleId,
                description: description,
                action: action,
                enabled: enabled,
                source: source,
                destination: destination
            });
        }
    });
    
    addLog(`${rules.length} rules loaded from the table`);
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
    
    // Window events
    window.addEventListener('beforeunload', () => {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
        }
    });
    
    // Visibility change (pause/resume when tab is hidden/visible)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            pauseAutoRefresh();
        } else {
            resumeAutoRefresh();
        }
    });
}

/**
 * Handle keyboard shortcuts
 */
function handleKeyboardShortcuts(event) {
    // Ctrl/Cmd + R: Refresh rules
    if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
        event.preventDefault();
        refreshRules();
    }
    
    // Escape: Clear alerts
    if (event.key === 'Escape') {
        clearAlerts();
    }
    
    // Ctrl/Cmd + L: Clear logs
    if ((event.ctrlKey || event.metaKey) && event.key === 'l') {
        event.preventDefault();
        clearLogs();
    }
}

/**
 * Utility Functions
 */

// Show alert message
function showAlert(message, type = 'success', duration = 5000) {
    const alertContainer = document.getElementById('alertContainer');
    if (!alertContainer) return;
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; font-size: 1.2em; cursor: pointer;">&times;</button>
    `;
    
    alertContainer.appendChild(alertDiv);
    
    // Auto-remove after duration
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => alertDiv.remove(), 300);
        }
    }, duration);
}

// Clear all alerts
function clearAlerts() {
    const alertContainer = document.getElementById('alertContainer');
    if (alertContainer) {
        alertContainer.innerHTML = '';
    }
}

// Add log entry
function addLog(message, type = 'info') {
    const logContent = document.getElementById('logContent');
    if (!logContent) return;
    
    const timestamp = new Date().toLocaleString();
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    logEntry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${message}`;
    
    logContent.appendChild(logEntry);
    logContent.scrollTop = logContent.scrollHeight;
    
    // Limit log entries
    const entries = logContent.querySelectorAll('.log-entry');
    if (entries.length > CONFIG.MAX_LOG_ENTRIES) {
        entries[0].remove();
    }
    
    logCounter++;
}

// Clear logs
function clearLogs() {
    const logContent = document.getElementById('logContent');
    if (logContent) {
        logContent.innerHTML = '';
        addLog('Logs cleared by user');
    }
}

// Show/hide loading spinner
function showLoading(show = true) {
    const loading = document.getElementById('loading');
    if (loading) {
        loading.style.display = show ? 'block' : 'none';
    }
}

// Update connection status
function updateConnectionStatus() {
    const statusDots = document.querySelectorAll('.status-dot');
    statusDots.forEach(dot => {
        if (isConnected) {
            dot.classList.remove('status-offline');
            dot.classList.add('status-online');
        } else {
            dot.classList.remove('status-online');
            dot.classList.add('status-offline');
        }
    });
}

/**
 * API Functions
 */

// Generic API call wrapper
async function apiCall(url, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(url, options);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const result = await response.json();
        isConnected = true;
        updateConnectionStatus();
        return result;
        
    } catch (error) {
        isConnected = false;
        updateConnectionStatus();
        console.error('API Error:', error);
        throw error;
    }
}

// Refresh rules from API
async function refreshRules() {
    showLoading(true);
    addLog('Update of rules in progress...');
    
    try {
        const response = await apiCall(`${CONFIG.API_BASE}/rules`);
        
        if (response.success) {
            rules = response.rules;
            updateRulesTable();
            updateStats();
            addLog(`${rules.length} rules successfully updated`);
            showAlert('Rules successfully updated!');
        } else {
            throw new Error(response.error || 'Unknown error');
        }
    } catch (error) {
        addLog(`Rule update error: ${error.message}`);
        showAlert(`Error: ${error.message}`, 'error');
    } finally {
        showLoading(false);
    }
}

// Toggle single rule
async function toggleRule(ruleId, enabled) {
    const ruleDesc = rules.find(r => r.uuid === ruleId)?.description || ruleId;
    addLog(`${enabled ? 'Enabling' : 'Disabling'} rule: ${ruleDesc}...`);
    
    try {
        const response = await apiCall(`${CONFIG.API_BASE}/rules/${ruleId}/toggle`, 'POST', {
            enabled: enabled,
            reason: 'Manual toggle from web interface'
        });
        
        if (response.success) {
            // Update local rule
            const rule = rules.find(r => r.uuid === ruleId);
            if (rule) {
                rule.enabled = enabled;
                updateRulesTable();
                updateStats();
            }
            
            addLog(`Rule ${ruleDesc} ${enabled ? 'enabled' : 'disabled'} successfully`);
            showAlert(response.message);
        } else {
            throw new Error(response.error || 'Error toggle rule');
        }
    } catch (error) {
        addLog(`Rule toggle error: ${error.message}`);
        showAlert(`Error: ${error.message}`, 'error');
    }
}

// Enable all rules
async function enableAllRules() {
    if (!confirm('Are you sure you want to enable all rules?')) {
        return;
    }
    
    addLog('Enabling all rules...');
    let successCount = 0;
    let errorCount = 0;
    
    const disabledRules = rules.filter(rule => !rule.enabled);
    
    for (const rule of disabledRules) {
        try {
            await toggleRule(rule.uuid, true);
            successCount++;
        } catch (error) {
            errorCount++;
            console.error(`Error enabling rule ${rule.uuid}:`, error);
        }
    }
    
    addLog(`${successCount} enabled rules, ${errorCount} errors`);
    
    if (errorCount > 0) {
        showAlert(`${successCount} rules enabled with ${errorCount} errors`, 'warning');
    } else {
        showAlert(`All ${successCount} rules successfully enabled!`);
    }
}

// Disable all rules
async function disableAllRules() {
    if (!confirm('Are you sure you want to disable all rules? This could compromise security.')) {
        return;
    }
    
    addLog('By disabling all rules...');
    let successCount = 0;
    let errorCount = 0;
    
    const enabledRules = rules.filter(rule => rule.enabled);
    
    for (const rule of enabledRules) {
        try {
            await toggleRule(rule.uuid, false);
            successCount++;
        } catch (error) {
            errorCount++;
            console.error(`Error disabling rule ${rule.uuid}:`, error);
        }
    }
    
    addLog(`${successCount} rules disabled, ${errorCount} errors`);
    
    if (errorCount > 0) {
        showAlert(`${successCount} rules disabled with ${errorCount} errors`, 'warning');
    } else {
        showAlert(`All ${successCount} rules successfully disabled!`);
    }
}

/**
 * SIEM Simulation Functions
 */

// Simulate SIEM incident
async function simulateIncident(type, severity) {
    const incidents = {
        'malicious_ip': {
            message: 'Malicious IP detected by intelligence',
            source_ip: '192.168.100.50',
            icon: '🔴'
        },
        'port_scan': {
            message: 'Aggressive port scan detected',
            source_ip: '10.0.0.100',
            icon: '📡'
        },
        'brute_force': {
            message: 'Brute force attack on SSH',
            source_ip: '172.16.50.25',
            icon: '🔓'
        },
        'suspicious_traffic': {
            message: 'Abnormal traffic to critical servers',
            source_ip: 'multiple',
            icon: '🌐'
        }
    };
    
    const incident = incidents[type];
    if (!incident) {
        showAlert('Unrecognised incident type', 'error');
        return;
    }
    
    addLog(`${incident.icon} SIEM ALERT: ${incident.message} (Severity: ${severity.toUpperCase()})`);
    
    try {
        const response = await apiCall(`${CONFIG.API_BASE}/siem/incident`, 'POST', {
            type: type,
            severity: severity,
            source_ip: incident.source_ip,
            timestamp: new Date().toISOString()
        });
        
        if (response.success) {
            addLog(`Incident ID: ${response.incident_id}`);
            
            if (response.actions_taken && response.actions_taken.length > 0) {
                addLog(`Automatic actions performed:`);
                response.actions_taken.forEach(action => {
                    addLog(`   • ${action}`);
                });
                
                // Update rules table
                await refreshRules();
            } else {
                addLog(`No automatic actions configured for this type of incident`);
            }
            
            showAlert(`Incident ${type} successfully managed! ${response.actions_taken?.length || 0} actions performed.`);
        } else {
            throw new Error(response.error || 'Incident management error');
        }
    } catch (error) {
        addLog(`Incident management error: ${error.message}`);
        showAlert(`Incident management error: ${error.message}`, 'error');
    }
}

/**
 * UI Update Functions
 */

// Update rules table
function updateRulesTable() {
    const tbody = document.getElementById('rulesTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    rules.forEach(rule => {
        const row = document.createElement('tr');
        row.setAttribute('data-rule-id', rule.uuid);
        
        const statusClass = rule.enabled ? 'rule-enabled' : 'rule-disabled';
        const statusText = rule.enabled ? '🟢 Active' : '🔴 Deactivate';
        const actionClass = rule.action === 'block' ? 'action-block' : 'action-pass';
        const actionText = rule.action === 'block' ? '🚫 BLOCK' : '✅ PASS';
        const btnClass = rule.enabled ? 'btn-danger' : 'btn-success';
        const btnText = rule.enabled ? '🔴 Disable' : '🟢 Enable';
        
        row.innerHTML = `
            <td><span class="rule-status ${statusClass}">${statusText}</span></td>
            <td>${escapeHtml(rule.description)}</td>
            <td><span class="rule-action ${actionClass}">${actionText}</span></td>
            <td>${escapeHtml(rule.source)}</td>
            <td>${escapeHtml(rule.destination)}</td>
            <td>
                <button class="btn ${btnClass}" onclick="toggleRule('${rule.uuid}', ${!rule.enabled})">
                    ${btnText}
                </button>
            </td>
        `;
        
        tbody.appendChild(row);
    });
    
    // Add animation to new rows
    setTimeout(() => {
        tbody.querySelectorAll('tr').forEach((row, index) => {
            row.style.animation = `slideIn 0.3s ease-out ${index * 0.05}s forwards`;
        });
    }, 50);
}

// Update statistics
function updateStats() {
    const totalRules = rules.length;
    const enabledRules = rules.filter(r => r.enabled).length;
    const disabledRules = totalRules - enabledRules;
    const blockRules = rules.filter(r => r.action === 'block').length;
    
    // Update stats if stats cards exist
    const statElements = {
        'total-rules': totalRules,
        'enabled-rules': enabledRules,
        'disabled-rules': disabledRules,
        'block-rules': blockRules
    };
    
    Object.entries(statElements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            animateNumber(element, parseInt(element.textContent) || 0, value);
        }
    });
}

// Animate number change
function animateNumber(element, start, end, duration = 500) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            current = end;
            clearInterval(timer);
        }
        
        element.textContent = Math.round(current);
    }, 16);
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Auto-refresh functionality
 */

// Start auto-refresh
function startAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    
    autoRefreshInterval = setInterval(() => {
        if (!document.hidden) {
            refreshRules();
        }
    }, CONFIG.REFRESH_INTERVAL);
    
    addLog(`Auto-refresh enabled (every ${CONFIG.REFRESH_INTERVAL / 1000} seconds)`);
}

// Pause auto-refresh
function pauseAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        addLog('Auto-refresh suspended (hidden tab)');
    }
}

// Resume auto-refresh
function resumeAutoRefresh() {
    if (!autoRefreshInterval) {
        startAutoRefresh();
        addLog('Auto-refresh resumed (tab visible)');
    }
}

/**
 * Advanced Features
 */

// Export rules data
function exportRules() {
    const dataStr = JSON.stringify(rules, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `firewall-rules-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    
    addLog('Rules exported to JSON');
    showAlert('Rules successfully exported!');
}

// Import rules data
function importRules(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const importedRules = JSON.parse(e.target.result);
            
            if (Array.isArray(importedRules) && importedRules.length > 0) {
                rules = importedRules;
                updateRulesTable();
                updateStats();
                addLog(`📥 ${importedRules.length} rules imported from files`);
                showAlert(`${importedRules.length} rules successfully imported!`);
            } else {
                throw new Error('Invalid or empty file');
            }
        } catch (error) {
            addLog(`Import error: ${error.message}`);
            showAlert(`Import error: ${error.message}`, 'error');
        }
    };
    
    reader.readAsText(file);
}

// Filter rules
function filterRules(filterType) {
    const rows = document.querySelectorAll('#rulesTableBody tr');
    
    rows.forEach(row => {
        const statusCell = row.querySelector('.rule-status');
        const actionCell = row.querySelector('.rule-action');
        
        let show = true;
        
        switch (filterType) {
            case 'enabled':
                show = statusCell.textContent.includes('Active');
                break;
            case 'disabled':
                show = statusCell.textContent.includes('Deactivate');
                break;
            case 'block':
                show = actionCell.textContent.includes('BLOCK');
                break;
            case 'pass':
                show = actionCell.textContent.includes('PASS');
                break;
            case 'all':
            default:
                show = true;
                break;
        }
        
        row.style.display = show ? '' : 'none';
    });
    
    // Update filter buttons active state
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    const activeBtn = document.querySelector(`[data-filter="${filterType}"]`);
    if (activeBtn) {
        activeBtn.classList.add('active');
    }
    
    addLog(`🔍 Filtro applicato: ${filterType}`);
}

// Search rules
function searchRules(searchTerm) {
    const rows = document.querySelectorAll('#rulesTableBody tr');
    const term = searchTerm.toLowerCase();
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const show = text.includes(term);
        row.style.display = show ? '' : 'none';
    });
    
    const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none');
    addLog(`🔍 Ricerca "${searchTerm}": ${visibleRows.length} results found`);
}

// Bulk operations
function bulkOperation(operation, selectedRules = null) {
    if (!selectedRules) {
        // Get selected checkboxes
        const checkboxes = document.querySelectorAll('input[name="rule-select"]:checked');
        selectedRules = Array.from(checkboxes).map(cb => cb.value);
    }
    
    if (selectedRules.length === 0) {
        showAlert('No rules selected', 'warning');
        return;
    }
    
    const confirmMessage = `Are you sure you want to ${operation} ${selectedRules.length} rule?`;
    if (!confirm(confirmMessage)) {
        return;
    }
    
    addLog(`Bulk operation: ${operation} on ${selectedRules.length} rules`);
    
    let successCount = 0;
    let errorCount = 0;
    
    selectedRules.forEach(async (ruleId) => {
        try {
            const enabled = operation === 'enable';
            await toggleRule(ruleId, enabled);
            successCount++;
        } catch (error) {
            errorCount++;
            console.error(`Error ${operation} rule ${ruleId}:`, error);
        }
    });
    
    setTimeout(() => {
        addLog(`Operation completed: ${successCount} successes, ${errorCount} errors`);
        
        if (errorCount > 0) {
            showAlert(`Operation completed with ${errorCount} errors`, 'warning');
        } else {
            showAlert(`${operation} successfully completed on ${successCount} rules!`);
        }
    }, 1000);
}

/**
 * Monitoring and Health Checks
 */

// Check system health
async function checkSystemHealth() {
    addLog('Checking system status...');
    
    try {
        const response = await apiCall(`${CONFIG.API_BASE}/status`);
        
        if (response.status === 'healthy') {
            addLog(`✅ Sistema operativo: ${response.service}`);
            addLog(`OPNsense: ${response.opnsense_connected ? 'Connected' : 'Disconnected'}`);
            
            const statusText = response.opnsense_connected ? 'Operating system' : 'OPNsense disconnected';
            const statusType = response.opnsense_connected ? 'success' : 'warning';
            
            showAlert(statusText, statusType);
        } else {
            throw new Error('System not operational');
        }
    } catch (error) {
        addLog(`System check error: ${error.message}`);
        showAlert(`System error: ${error.message}`, 'error');
    }
}

// Performance monitoring
function startPerformanceMonitoring() {
    // Monitor API response times
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const start = performance.now();
        try {
            const response = await originalFetch.apply(this, args);
            const duration = performance.now() - start;
            
            if (args[0].includes('/api/')) {
                addLog(`API Response: ${Math.round(duration)}ms - ${args[0]}`);
            }
            
            return response;
        } catch (error) {
            const duration = performance.now() - start;
            addLog(`API Error: ${Math.round(duration)}ms - ${args[0]}`);
            throw error;
        }
    };
}

/**
 * Utility and Helper Functions
 */

// Format timestamp
function formatTimestamp(date = new Date()) {
    return date.toLocaleString('it-IT', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// Generate random incident for demo
function generateRandomIncident() {
    const types = ['malicious_ip', 'port_scan', 'brute_force', 'suspicious_traffic'];
    const severities = ['low', 'medium', 'high', 'critical'];
    
    const randomType = types[Math.floor(Math.random() * types.length)];
    const randomSeverity = severities[Math.floor(Math.random() * severities.length)];
    
    simulateIncident(randomType, randomSeverity);
}

// Toggle dark mode
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    
    localStorage.setItem('darkMode', isDark);
    addLog(`${isDark ? 'Dark' : 'Light'} mode enabled`);
}

// Load user preferences
function loadUserPreferences() {
    // Dark mode preference
    const darkMode = localStorage.getItem('darkMode') === 'true';
    if (darkMode) {
        document.body.classList.add('dark-mode');
    }
    
    // Auto-refresh preference
    const autoRefresh = localStorage.getItem('autoRefresh') !== 'false';
    if (autoRefresh) {
        startAutoRefresh();
    }
}

// Save user preferences
function saveUserPreferences() {
    const darkMode = document.body.classList.contains('dark-mode');
    const autoRefresh = autoRefreshInterval !== null;
    
    localStorage.setItem('darkMode', darkMode);
    localStorage.setItem('autoRefresh', autoRefresh);
}

/**
 * Error Handling and Recovery
 */

// Global error handler
window.addEventListener('error', function(event) {
    addLog(`JavaScript error: ${event.error?.message || 'Unknown error'}`);
    console.error('Global error:', event.error);
});

// Unhandled promise rejection handler
window.addEventListener('unhandledrejection', function(event) {
    addLog(`Promise rejection: ${event.reason?.message || 'Unknown error'}`);
    console.error('Unhandled promise rejection:', event.reason);
});

// Network error recovery
function handleNetworkError() {
    addLog('Attempting to reconnect...');
    
    setTimeout(async () => {
        try {
            await checkSystemHealth();
            addLog('Successful reconnection');
        } catch (error) {
            addLog('Reconnection failed, retry in 30 seconds.');
            setTimeout(handleNetworkError, 30000);
        }
    }, 5000);
}

/**
 * Keyboard shortcuts and accessibility
 */

// Initialize accessibility features
function initializeAccessibility() {
    // Add keyboard navigation
    document.addEventListener('keydown', function(event) {
        // Tab navigation enhancement
        if (event.key === 'Tab') {
            document.body.classList.add('keyboard-navigation');
        }
    });
    
    // Remove keyboard navigation class on mouse use
    document.addEventListener('mousedown', function() {
        document.body.classList.remove('keyboard-navigation');
    });
    
    // Screen reader announcements
    const announcer = document.createElement('div');
    announcer.setAttribute('aria-live', 'polite');
    announcer.setAttribute('aria-atomic', 'true');
    announcer.className = 'sr-only';
    document.body.appendChild(announcer);
    
    window.announceToScreenReader = function(message) {
        announcer.textContent = message;
        setTimeout(() => announcer.textContent = '', 1000);
    };
}

/**
 * Initialize everything when DOM is ready
 */

// Load user preferences on startup
loadUserPreferences();

// Initialize accessibility features
initializeAccessibility();

// Start performance monitoring
startPerformanceMonitoring();

// Check initial system health
setTimeout(checkSystemHealth, 2000);

// Auto-save preferences on page unload
window.addEventListener('beforeunload', saveUserPreferences);

// Expose global functions for inline event handlers
window.refreshRules = refreshRules;
window.toggleRule = toggleRule;
window.enableAllRules = enableAllRules;
window.disableAllRules = disableAllRules;
window.simulateIncident = simulateIncident;
window.clearLogs = clearLogs;
window.exportRules = exportRules;
window.importRules = importRules;
window.filterRules = filterRules;
window.searchRules = searchRules;
window.checkSystemHealth = checkSystemHealth;
window.generateRandomIncident = generateRandomIncident;
window.toggleDarkMode = toggleDarkMode;

// Log successful initialization
addLog('System fully initialised and ready for use');