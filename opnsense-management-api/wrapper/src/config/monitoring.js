'use strict';

const promClient = require('prom-client');
const logger = require('../utils/logger');

// ----- Registry + default process metrics -----
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register, prefix: 'opnsense_api_' });

// ----- Core Metrics (solo quello che serve al wrapper) -----
const httpRequestDuration = new promClient.Histogram({
  name: 'opnsense_api_http_request_duration_seconds',
  help: 'Duration of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.05, 0.1, 0.3, 0.5, 1, 3, 5, 10],
});

const httpRequestsTotal = new promClient.Counter({
  name: 'opnsense_api_http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
});

const opnsenseApiCalls = new promClient.Counter({
  name: 'opnsense_api_calls_total',
  help: 'Total calls to OPNsense API',
  labelNames: ['endpoint', 'method', 'status'],
});

const opnsenseApiDuration = new promClient.Histogram({
  name: 'opnsense_api_call_duration_seconds',
  help: 'Duration of OPNsense API calls',
  labelNames: ['endpoint', 'method'],
  buckets: [0.1, 0.5, 1, 2, 5, 10],
});

const dependencyHealth = new promClient.Gauge({
  name: 'opnsense_api_dependency_health',
  help: 'Dependency health (1=healthy, 0=down)',
  labelNames: ['component'],
});

const authAttempts = new promClient.Counter({
  name: 'opnsense_api_auth_attempts_total',
  help: 'Authentication attempts',
  labelNames: ['result', 'ip_address'],
});

const rateLimitHits = new promClient.Counter({
  name: 'opnsense_api_rate_limit_hits_total',
  help: 'Rate limit hits',
  labelNames: ['ip_address', 'endpoint'],
});

const configChanges = new promClient.Counter({
  name: 'opnsense_api_config_changes_total',
  help: 'Configuration changes performed via wrapper',
  labelNames: ['change_type', 'interface', 'action', 'user_id'],
});

const securityAlerts = new promClient.Counter({
  name: 'opnsense_api_security_alerts_total',
  help: 'Security alerts generated',
  labelNames: ['severity', 'type', 'source'],
});

const firewallRules = new promClient.Gauge({
  name: 'opnsense_api_firewall_rules_total',
  help: 'Total number of firewall rules',
  labelNames: ['interface', 'action', 'enabled'],
});

const activePolicies = new promClient.Gauge({
  name: 'opnsense_api_policies_active_total',
  help: 'Number of active policies',
  labelNames: ['type'],
});

// Register all metrics
[
  httpRequestDuration,
  httpRequestsTotal,
  opnsenseApiCalls,
  opnsenseApiDuration,
  dependencyHealth,
  authAttempts,
  rateLimitHits,
  configChanges,
  securityAlerts,
  firewallRules,
  activePolicies,
].forEach(m => register.registerMetric(m));

// ----- Helper functions per routes/services -----
const metricsHelpers = {
  recordHttpRequest(method, route, statusCode, durationMs) {
    const sc = String(statusCode);
    httpRequestDuration.labels(method, route, sc).observe(durationMs / 1000);
    httpRequestsTotal.labels(method, route, sc).inc();
  },

  recordOpnsenseApiCall(endpoint, method, status, durationMs) {
    opnsenseApiCalls.labels(endpoint, method, status).inc();
    if (durationMs != null) opnsenseApiDuration.labels(endpoint, method).observe(durationMs / 1000);
  },

  recordAuthAttempt(result, ipAddress) {
    authAttempts.labels(result, ipAddress || 'unknown').inc();
  },

  recordRateLimitHit(ipAddress, endpoint) {
    rateLimitHits.labels(ipAddress || 'unknown', endpoint || 'unknown').inc();
  },

  recordConfigurationChange(changeType, labels = {}) {
    const iface = labels.interface || 'na';
    const action = labels.action || 'na';
    const user = labels.user_id != null ? String(labels.user_id) : 'na';
    configChanges.labels(changeType, iface, action, user).inc();
  },

  recordSecurityAlert(severity, type, source) {
    securityAlerts.labels(severity, type, source).inc();
  },

  updateSystemHealth(component, healthy) {
    dependencyHealth.labels(component).set(healthy ? 1 : 0);
  },

  updateFirewallRuleCount(interface, action, enabled, count) {
    firewallRules.labels(interface, action, enabled ? 'true' : 'false').set(count);
  },

  updateActivePolicyCount(type, count) {
    activePolicies.labels(type).set(count);
  },
};

// ----- Health checks -----
const performHealthChecks = async () => {
  try {
    const { testDatabaseConnection, testRedisConnection } = require('./database');
    const { testConnection } = require('./opnsense');

    const dbOK = await testDatabaseConnection().catch(() => false);
    metricsHelpers.updateSystemHealth('database', dbOK);

    const redisOK = await testRedisConnection().catch(() => false);
    metricsHelpers.updateSystemHealth('cache', redisOK);

    const opnOK = await testConnection().catch(() => false);
    metricsHelpers.updateSystemHealth('opnsense_api', opnOK);

    return {
      database: dbOK ? 'healthy' : 'unhealthy',
      cache: redisOK ? 'healthy' : 'unhealthy',
      opnsense_api: opnOK ? 'healthy' : 'unhealthy',
      timestamp: new Date(),
    };
  } catch (err) {
    logger.error('performHealthChecks failed', { error: err.message });
    return {
      database: 'unknown',
      cache: 'unknown',
      opnsense_api: 'unknown',
      timestamp: new Date(),
    };
  }
};

// Initialize monitoring
const initializeMonitoring = () => {
  logger.info('Monitoring initialized - metrics registry ready');
  
  // Set initial health states
  metricsHelpers.updateSystemHealth('database', 0);
  metricsHelpers.updateSystemHealth('cache', 0);
  metricsHelpers.updateSystemHealth('opnsense_api', 0);
};

// Expose metrics per /metrics endpoint (formato Prometheus)
const getMetrics = async () => {
  try {
    return await register.metrics();
  } catch (error) {
    logger.error('Failed to generate metrics', { error: error.message });
    throw error;
  }
};

// Get specific metric by name
const getMetric = (name) => {
  const metrics = {
    httpRequestDuration,
    httpRequestsTotal,
    opnsenseApiCalls,
    opnsenseApiDuration,
    dependencyHealth,
    authAttempts,
    rateLimitHits,
    configChanges,
    securityAlerts,
    firewallRules,
    activePolicies,
  };
  return metrics[name];
};

// ----- Config object minimo per le route che leggono thresholds -----
const monitoringConfig = {
  alerting: {
    thresholds: {
      errorRate: 0.1,
      responseTime: 2000,
    },
  },
  // Aggiunto per compatibilità con routes/monitoring.js
  nagios: {
    criticalThresholds: {
      responseTime: 5000,
      errorRate: 0.05,
      systemHealth: 0.8,
    },
  },
  healthChecks: {
    endpoints: ['/api/v1/health'],
    timeout: 5000,
  },
};

module.exports = {
  register,
  metricsHelpers,
  initializeMonitoring,
  performHealthChecks,
  getMetrics,
  getMetric,
  monitoringConfig,
};