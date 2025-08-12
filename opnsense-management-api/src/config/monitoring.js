const promClient = require('prom-client');
const logger = require('../utils/logger');

// Create a Registry to register metrics
const register = new promClient.Registry();

// Enable default metrics collection (CPU, Memory, etc.)
promClient.collectDefaultMetrics({
  register,
  prefix: 'opnsense_api_',
});

// Custom Metrics for OPNsense Management API
const metrics = {
  // HTTP Request metrics
  httpRequestDuration: new promClient.Histogram({
    name: 'opnsense_api_http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status_code'],
    buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
  }),

  httpRequestsTotal: new promClient.Counter({
    name: 'opnsense_api_http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status_code'],
  }),

  // OPNsense API metrics
  opnsenseApiCalls: new promClient.Counter({
    name: 'opnsense_api_calls_total',
    help: 'Total number of calls to OPNsense API',
    labelNames: ['endpoint', 'method', 'status'],
  }),

  opnsenseApiDuration: new promClient.Histogram({
    name: 'opnsense_api_call_duration_seconds',
    help: 'Duration of OPNsense API calls in seconds',
    labelNames: ['endpoint', 'method'],
    buckets: [0.1, 0.5, 1, 2, 5, 10],
  }),

  opnsenseApiErrors: new promClient.Counter({
    name: 'opnsense_api_errors_total',
    help: 'Total number of OPNsense API errors',
    labelNames: ['endpoint', 'error_type'],
  }),

  // Firewall Rules metrics
  firewallRulesTotal: new promClient.Gauge({
    name: 'opnsense_firewall_rules_total',
    help: 'Total number of firewall rules',
    labelNames: ['interface', 'action'],
  }),

  firewallRuleChanges: new promClient.Counter({
    name: 'opnsense_firewall_rule_changes_total',
    help: 'Total number of firewall rule changes',
    labelNames: ['action', 'user', 'interface'],
  }),

  firewallRuleToggleTime: new promClient.Histogram({
    name: 'opnsense_firewall_rule_toggle_duration_seconds',
    help: 'Time taken to toggle firewall rules',
    labelNames: ['action'],
    buckets: [0.5, 1, 2, 5, 10, 15],
  }),

  // Security metrics
  authenticationAttempts: new promClient.Counter({
    name: 'opnsense_api_auth_attempts_total',
    help: 'Total number of authentication attempts',
    labelNames: ['result', 'ip_address'],
  }),

  rateLimitHits: new promClient.Counter({
    name: 'opnsense_api_rate_limit_hits_total',
    help: 'Total number of rate limit hits',
    labelNames: ['ip_address', 'endpoint'],
  }),

  // System Health metrics
  systemHealth: new promClient.Gauge({
    name: 'opnsense_system_health',
    help: 'OPNsense system health status (1=healthy, 0=unhealthy)',
    labelNames: ['component'],
  }),

  connectionPoolSize: new promClient.Gauge({
    name: 'opnsense_api_db_connections',
    help: 'Number of active database connections',
  }),

  cacheHitRate: new promClient.Gauge({
    name: 'opnsense_api_cache_hit_rate',
    help: 'Cache hit rate percentage',
  }),

  // Alert metrics
  securityAlerts: new promClient.Counter({
    name: 'opnsense_security_alerts_total',
    help: 'Total number of security alerts generated',
    labelNames: ['severity', 'type', 'source'],
  }),

  alertResponseTime: new promClient.Histogram({
    name: 'opnsense_alert_response_duration_seconds',
    help: 'Time taken to respond to security alerts',
    labelNames: ['alert_type', 'action'],
    buckets: [1, 5, 10, 30, 60, 300],
  }),
};

// Register all metrics
Object.values(metrics).forEach(metric => {
  register.registerMetric(metric);
});

// Monitoring Configuration
const monitoringConfig = {
  // Prometheus settings
  prometheus: {
    enabled: process.env.PROMETHEUS_ENABLED !== 'false',
    port: parseInt(process.env.PROMETHEUS_PORT) || 9090,
    metricsPath: '/metrics',
    collectInterval: 10000, // 10 seconds
  },

  // Grafana settings
  grafana: {
    enabled: process.env.GRAFANA_ENABLED !== 'false',
    port: parseInt(process.env.GRAFANA_PORT) || 3001,
    adminUser: process.env.GRAFANA_ADMIN_USER || 'admin',
    adminPassword: process.env.GRAFANA_ADMIN_PASSWORD,
    apiUrl: `http://grafana:3000`,
  },

  // Nagios integration
  nagios: {
    enabled: process.env.NAGIOS_ENABLED !== 'false',
    user: process.env.NAGIOS_USER || 'nagiosadmin',
    password: process.env.NAGIOS_PASS,
    checkInterval: 300000, // 5 minutes
    criticalThresholds: {
      responseTime: 5000, // 5 seconds
      errorRate: 0.05, // 5%
      systemHealth: 0.8, // 80%
    },
  },

  // Health check endpoints
  healthChecks: {
    endpoints: [
      '/api/v1/health',
      '/api/v1/health/database',
      '/api/v1/health/opnsense',
      '/api/v1/health/cache',
    ],
    interval: 30000, // 30 seconds
    timeout: 5000, // 5 seconds
  },

  // Alerting configuration
  alerting: {
    enabled: true,
    channels: {
      email: process.env.ALERT_EMAIL_ENABLED === 'true',
      webhook: process.env.ALERT_WEBHOOK_ENABLED === 'true',
      slack: process.env.ALERT_SLACK_ENABLED === 'true',
    },
    thresholds: {
      errorRate: 0.1, // 10%
      responseTime: 2000, // 2 seconds
      memoryUsage: 0.9, // 90%
      cpuUsage: 0.8, // 80%
    },
  },
};

// Helper functions for metrics
const metricsHelpers = {
  // Record HTTP request metrics
  recordHttpRequest(method, route, statusCode, duration) {
    metrics.httpRequestDuration
      .labels(method, route, statusCode)
      .observe(duration / 1000);
    
    metrics.httpRequestsTotal
      .labels(method, route, statusCode)
      .inc();
  },

  // Record OPNsense API call metrics
  recordOpnsenseApiCall(endpoint, method, status, duration) {
    metrics.opnsenseApiCalls
      .labels(endpoint, method, status)
      .inc();
    
    if (duration) {
      metrics.opnsenseApiDuration
        .labels(endpoint, method)
        .observe(duration / 1000);
    }
  },

  // Record firewall rule changes
  recordRuleChange(action, user, interface) {
    metrics.firewallRuleChanges
      .labels(action, user, interface)
      .inc();
  },

  // Record authentication attempts
  recordAuthAttempt(result, ipAddress) {
    metrics.authenticationAttempts
      .labels(result, ipAddress)
      .inc();
  },

  // Record security alerts
  recordSecurityAlert(severity, type, source) {
    metrics.securityAlerts
      .labels(severity, type, source)
      .inc();
  },

  // Update system health
  updateSystemHealth(component, status) {
    metrics.systemHealth
      .labels(component)
      .set(status ? 1 : 0);
  },

  // Update cache metrics
  updateCacheMetrics(hitRate) {
    metrics.cacheHitRate.set(hitRate);
  },
};

// Initialize monitoring
const initializeMonitoring = () => {
  logger.info('Initializing monitoring system...');
  
  // Set up periodic health checks
  if (monitoringConfig.healthChecks.interval) {
    setInterval(() => {
      performHealthChecks();
    }, monitoringConfig.healthChecks.interval);
  }

  logger.info('Monitoring system initialized successfully');
};

// Perform health checks
const performHealthChecks = async () => {
  try {
    // Database health
    const dbHealth = await checkDatabaseHealth();
    metricsHelpers.updateSystemHealth('database', dbHealth);

    // Cache health
    const cacheHealth = await checkCacheHealth();
    metricsHelpers.updateSystemHealth('cache', cacheHealth);

    // OPNsense API health
    const opnsenseHealth = await checkOpnsenseHealth();
    metricsHelpers.updateSystemHealth('opnsense_api', opnsenseHealth);

  } catch (error) {
    logger.error('Health check error:', error.message);
  }
};

// Individual health check functions
const checkDatabaseHealth = async () => {
  try {
    const { testDatabaseConnection } = require('./database');
    return await testDatabaseConnection();
  } catch (error) {
    return false;
  }
};

const checkCacheHealth = async () => {
  try {
    const { testRedisConnection } = require('./database');
    return await testRedisConnection();
  } catch (error) {
    return false;
  }
};

const checkOpnsenseHealth = async () => {
  try {
    const { testConnection } = require('./opnsense');
    return await testConnection();
  } catch (error) {
    return false;
  }
};

// Get metrics for Prometheus endpoint
const getMetrics = async () => {
  return await register.metrics();
};

// Get metric by name
const getMetric = (name) => {
  return metrics[name];
};

module.exports = {
  register,
  metrics,
  metricsHelpers,
  monitoringConfig,
  initializeMonitoring,
  performHealthChecks,
  getMetrics,
  getMetric,
  checkDatabaseHealth,
  checkCacheHealth,
  checkOpnsenseHealth,
};