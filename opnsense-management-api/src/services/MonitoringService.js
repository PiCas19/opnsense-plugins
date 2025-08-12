const axios = require('axios');
const logger = require('../utils/logger');
const { opnsenseConfig } = require('../config/opnsense');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const AlertService = require('./AlertService');
const User = require('../models/User');

class MonitoringService {
  constructor(user = null) {
    this.user = user;
    this.baseUrl = opnsenseConfig.apiUrl;
    this.apiKey = opnsenseConfig.apiKey;
    this.apiSecret = opnsenseConfig.apiSecret;
    this.alertService = new AlertService(user);
    this.cacheTimeout = process.env.MONITORING_CACHE_TIMEOUT || 60;
    this.maxRetries = process.env.MAX_API_RETRIES || 3;
    this.requestTimeout = process.env.API_REQUEST_TIMEOUT || 10000;
    this.rateLimitMap = new Map(); // For API rate limiting
    this.thresholds = {
      cpu_usage: process.env.CPU_THRESHOLD || 90,
      memory_usage: process.env.MEMORY_THRESHOLD || 85,
      disk_usage: process.env.DISK_THRESHOLD || 95,
      network_bytes_threshold: process.env.NETWORK_THRESHOLD || 1000000000
    };
  }

  /**
   * Rate limiting check
   * @param {string} operation - Operation identifier
   * @param {number} maxRequests - Max requests per minute
   * @returns {boolean} True if allowed
   * @private
   */
  checkRateLimit(operation, maxRequests = 60) {
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    
    if (!this.rateLimitMap.has(operation)) {
      this.rateLimitMap.set(operation, []);
    }
    
    const requests = this.rateLimitMap.get(operation);
    
    // Remove old requests outside the window
    const validRequests = requests.filter(timestamp => now - timestamp < windowMs);
    
    if (validRequests.length >= maxRequests) {
      logger.warn('Rate limit exceeded', { operation, requests_count: validRequests.length });
      return false;
    }
    
    validRequests.push(now);
    this.rateLimitMap.set(operation, validRequests);
    return true;
  }

  /**
   * Safely get from cache with error handling
   * @param {string} key - Cache key
   * @returns {any|null} Cached value or null
   * @private
   */
  async safeGetCache(key) {
    try {
      return await cache.get(key);
    } catch (error) {
      logger.warn('Cache get failed', { key, error: error.message });
      return null;
    }
  }

  /**
   * Safely set cache with error handling
   * @param {string} key - Cache key
   * @param {any} value - Value to cache
   * @param {number} ttl - Time to live
   * @private
   */
  async safeSetCache(key, value, ttl = this.cacheTimeout) {
    try {
      await cache.set(key, value, ttl);
    } catch (error) {
      logger.warn('Cache set failed', { key, error: error.message });
    }
  }

  /**
   * Initialize HTTP client for OPNsense API with retry logic
   * @private
   */
  getHttpClient() {
    return axios.create({
      baseURL: this.baseUrl,
      auth: {
        username: this.apiKey,
        password: this.apiSecret,
      },
      timeout: this.requestTimeout,
      retry: this.maxRetries,
      retryDelay: (retryCount) => {
        return Math.min(1000 * Math.pow(2, retryCount), 10000); // Exponential backoff
      },
    });
  }

  /**
   * Make API request with retry logic
   * @param {string} endpoint - API endpoint
   * @param {Object} params - Request parameters
   * @param {string} operation - Operation name for rate limiting
   * @returns {Object} API response
   * @private
   */
  async makeApiRequest(endpoint, params = {}, operation = 'default') {
    // Check rate limit
    if (!this.checkRateLimit(operation)) {
      throw new Error(`Rate limit exceeded for operation: ${operation}`);
    }

    let lastError;
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const response = await this.getHttpClient().get(endpoint, { params });
        return response.data;
      } catch (error) {
        lastError = error;
        logger.warn('API request failed', {
          endpoint,
          attempt,
          error: error.message,
          status: error.response?.status
        });

        if (attempt < this.maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError;
  }

  /**
   * Collect system metrics with improved error handling
   * @returns {Object} System metrics
   */
  async collectSystemMetrics() {
    try {
      const cacheKey = 'system_metrics';
      const cachedMetrics = await this.safeGetCache(cacheKey);

      if (cachedMetrics) {
        logger.info('Returning cached system metrics', { cache_key: cacheKey });
        return cachedMetrics;
      }

      const data = await this.makeApiRequest('/system/diagnostics/status', {}, 'system_metrics');
      
      const metrics = {
        cpu_usage: Math.min(100, Math.max(0, data.cpu?.usage || 0)),
        memory_usage: Math.min(100, Math.max(0, data.memory?.used_percent || 0)),
        disk_usage: Math.min(100, Math.max(0, data.disk?.used_percent || 0)),
        uptime: Math.max(0, data.system?.uptime || 0),
        timestamp: new Date(),
      };

      // Validate metrics
      if (isNaN(metrics.cpu_usage) || isNaN(metrics.memory_usage) || isNaN(metrics.disk_usage)) {
        throw new Error('Invalid metrics received from API');
      }

      // Record metrics for Prometheus
      metricsHelpers.recordSystemMetric('cpu_usage', metrics.cpu_usage);
      metricsHelpers.recordSystemMetric('memory_usage', metrics.memory_usage);
      metricsHelpers.recordSystemMetric('disk_usage', metrics.disk_usage);

      // Check thresholds and create alerts if necessary
      await this.checkSystemThresholds(metrics);

      // Cache the result
      await this.safeSetCache(cacheKey, metrics, this.cacheTimeout);

      return metrics;
    } catch (error) {
      logger.error('Failed to collect system metrics', { error: error.message });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to collect system metrics: ${error.message}`,
        severity: 'high',
        source: 'monitoring',
        metadata: { error_type: 'api_failure', endpoint: '/system/diagnostics/status' }
      });
      throw error;
    }
  }

  /**
   * Collect network interface metrics with validation
   * @param {string} interfaceName - Optional interface name to filter
   * @returns {Array} Network interface metrics
   */
  async collectNetworkMetrics(interfaceName = null) {
    try {
      // Validate interface name if provided
      if (interfaceName && !/^[a-zA-Z0-9_-]+$/.test(interfaceName)) {
        throw new Error('Invalid interface name format');
      }

      const cacheKey = `network_metrics_${interfaceName || 'all'}`;
      const cachedMetrics = await this.safeGetCache(cacheKey);

      if (cachedMetrics) {
        logger.info('Returning cached network metrics', { cache_key: cacheKey });
        return cachedMetrics;
      }

      const params = interfaceName ? { interface: interfaceName } : {};
      const data = await this.makeApiRequest('/interfaces/statistics', params, 'network_metrics');
      
      const interfaces = Array.isArray(data) ? data : [data];

      const metrics = interfaces
        .filter(intf => intf && intf.name) // Filter out invalid interfaces
        .map((intf) => ({
          interface: intf.name,
          bytes_in: Math.max(0, parseInt(intf.stats?.bytes_in) || 0),
          bytes_out: Math.max(0, parseInt(intf.stats?.bytes_out) || 0),
          packets_in: Math.max(0, parseInt(intf.stats?.packets_in) || 0),
          packets_out: Math.max(0, parseInt(intf.stats?.packets_out) || 0),
          errors_in: Math.max(0, parseInt(intf.stats?.errors_in) || 0),
          errors_out: Math.max(0, parseInt(intf.stats?.errors_out) || 0),
          timestamp: new Date(),
        }));

      // Validate metrics
      for (const metric of metrics) {
        if (Object.values(metric).some(val => typeof val === 'number' && isNaN(val))) {
          logger.warn('Invalid network metric detected', { interface: metric.interface });
          continue;
        }
      }

      // Record metrics for Prometheus
      metrics.forEach((metric) => {
        metricsHelpers.recordNetworkMetric('bytes_in', metric.bytes_in, { interface: metric.interface });
        metricsHelpers.recordNetworkMetric('bytes_out', metric.bytes_out, { interface: metric.interface });
        metricsHelpers.recordNetworkMetric('packets_in', metric.packets_in, { interface: metric.interface });
        metricsHelpers.recordNetworkMetric('packets_out', metric.packets_out, { interface: metric.interface });
      });

      // Check thresholds and create alerts if necessary
      await this.checkNetworkThresholds(metrics);

      // Cache the result
      await this.safeSetCache(cacheKey, metrics, this.cacheTimeout);

      return metrics;
    } catch (error) {
      logger.error('Failed to collect network metrics', {
        error: error.message,
        interface: interfaceName,
      });
      await this.alertService.createSystemAlert({
        type: 'network_error',
        message: `Failed to collect network metrics: ${error.message}`,
        severity: 'medium',
        source: 'monitoring',
        metadata: { 
          error_type: 'api_failure', 
          endpoint: '/interfaces/statistics',
          interface: interfaceName 
        }
      });
      throw error;
    }
  }

  /**
   * Export metrics for Prometheus with role validation
   * @returns {Object} Prometheus metrics
   */
  async exportPrometheusMetrics() {
    try {
      // Verify user has appropriate role if provided
      if (this.user) {
        const user = await User.findByPk(this.user.id);
        if (!user) {
          throw new Error('User not found');
        }
        if (!['admin', 'operator', 'viewer'].includes(user.role)) {
          throw new Error('User does not have permission to export metrics');
        }
      }

      const [systemMetrics, networkMetrics] = await Promise.all([
        this.collectSystemMetrics().catch(error => {
          logger.warn('System metrics collection failed for Prometheus export', { error: error.message });
          return null;
        }),
        this.collectNetworkMetrics().catch(error => {
          logger.warn('Network metrics collection failed for Prometheus export', { error: error.message });
          return null;
        })
      ]);

      const prometheusMetrics = {
        system: systemMetrics,
        network: networkMetrics,
        timestamp: new Date(),
        collector: 'opnsense-monitoring-service'
      };

      logger.info('Prometheus metrics exported successfully', {
        user_id: this.user?.id,
        has_system_metrics: !!systemMetrics,
        has_network_metrics: !!networkMetrics && networkMetrics.length > 0
      });

      return prometheusMetrics;
    } catch (error) {
      logger.error('Failed to export Prometheus metrics', {
        error: error.message,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Check system thresholds and generate alerts with configurable thresholds
   * @param {Object} metrics - System metrics
   * @private
   */
  async checkSystemThresholds(metrics) {
    try {
      const alertPromises = [];

      if (metrics.cpu_usage > this.thresholds.cpu_usage) {
        alertPromises.push(
          this.alertService.createSystemAlert({
            type: 'performance_issue',
            message: `High CPU usage detected: ${metrics.cpu_usage}% (threshold: ${this.thresholds.cpu_usage}%)`,
            severity: metrics.cpu_usage > 95 ? 'critical' : 'high',
            source: 'monitoring',
            metadata: { 
              cpu_usage: metrics.cpu_usage,
              threshold: this.thresholds.cpu_usage,
              metric_type: 'cpu'
            },
          })
        );
      }

      if (metrics.memory_usage > this.thresholds.memory_usage) {
        alertPromises.push(
          this.alertService.createSystemAlert({
            type: 'performance_issue',
            message: `High memory usage detected: ${metrics.memory_usage}% (threshold: ${this.thresholds.memory_usage}%)`,
            severity: metrics.memory_usage > 95 ? 'critical' : 'high',
            source: 'monitoring',
            metadata: { 
              memory_usage: metrics.memory_usage,
              threshold: this.thresholds.memory_usage,
              metric_type: 'memory'
            },
          })
        );
      }

      if (metrics.disk_usage > this.thresholds.disk_usage) {
        alertPromises.push(
          this.alertService.createSystemAlert({
            type: 'performance_issue',
            message: `High disk usage detected: ${metrics.disk_usage}% (threshold: ${this.thresholds.disk_usage}%)`,
            severity: 'critical',
            source: 'monitoring',
            metadata: { 
              disk_usage: metrics.disk_usage,
              threshold: this.thresholds.disk_usage,
              metric_type: 'disk'
            },
          })
        );
      }

      // Execute all alert creations in parallel
      await Promise.allSettled(alertPromises);
    } catch (error) {
      logger.error('Failed to check system thresholds', {
        error: error.message,
        metrics,
      });
    }
  }

  /**
   * Check network thresholds and generate alerts with improved detection
   * @param {Array} metrics - Network metrics
   * @private
   */
  async checkNetworkThresholds(metrics) {
    try {
      const alertPromises = [];

      for (const metric of metrics) {
        // Check for high traffic
        if (metric.bytes_in > this.thresholds.network_bytes_threshold || 
            metric.bytes_out > this.thresholds.network_bytes_threshold) {
          alertPromises.push(
            this.alertService.createSystemAlert({
              type: 'network_anomaly',
              message: `High network traffic on interface ${metric.interface}: ${metric.bytes_in} bytes in, ${metric.bytes_out} bytes out`,
              severity: 'high',
              source: 'monitoring',
              metadata: {
                interface: metric.interface,
                bytes_in: metric.bytes_in,
                bytes_out: metric.bytes_out,
                threshold: this.thresholds.network_bytes_threshold,
                metric_type: 'network_traffic'
              },
            })
          );
        }

        // Check for interface errors
        if (metric.errors_in > 100 || metric.errors_out > 100) {
          alertPromises.push(
            this.alertService.createSystemAlert({
              type: 'network_anomaly',
              message: `High error rate on interface ${metric.interface}: ${metric.errors_in} errors in, ${metric.errors_out} errors out`,
              severity: 'medium',
              source: 'monitoring',
              metadata: {
                interface: metric.interface,
                errors_in: metric.errors_in,
                errors_out: metric.errors_out,
                metric_type: 'network_errors'
              },
            })
          );
        }
      }

      // Execute all alert creations in parallel
      await Promise.allSettled(alertPromises);
    } catch (error) {
      logger.error('Failed to check network thresholds', {
        error: error.message,
        metrics,
      });
    }
  }

  /**
   * Trigger Nagios check with enhanced status determination
   * @returns {Object} Nagios check result
   */
  async triggerNagiosCheck() {
    try {
      const systemMetrics = await this.collectSystemMetrics();
      
      let status = 'OK';
      let statusCode = 0;
      const issues = [];

      // Determine status based on multiple criteria
      if (systemMetrics.cpu_usage > 95 || systemMetrics.memory_usage > 95 || systemMetrics.disk_usage > 98) {
        status = 'CRITICAL';
        statusCode = 2;
        if (systemMetrics.cpu_usage > 95) issues.push(`CPU: ${systemMetrics.cpu_usage}%`);
        if (systemMetrics.memory_usage > 95) issues.push(`Memory: ${systemMetrics.memory_usage}%`);
        if (systemMetrics.disk_usage > 98) issues.push(`Disk: ${systemMetrics.disk_usage}%`);
      } else if (systemMetrics.cpu_usage > this.thresholds.cpu_usage || 
                 systemMetrics.memory_usage > this.thresholds.memory_usage ||
                 systemMetrics.disk_usage > this.thresholds.disk_usage) {
        status = 'WARNING';
        statusCode = 1;
        if (systemMetrics.cpu_usage > this.thresholds.cpu_usage) issues.push(`CPU: ${systemMetrics.cpu_usage}%`);
        if (systemMetrics.memory_usage > this.thresholds.memory_usage) issues.push(`Memory: ${systemMetrics.memory_usage}%`);
        if (systemMetrics.disk_usage > this.thresholds.disk_usage) issues.push(`Disk: ${systemMetrics.disk_usage}%`);
      }

      const message = issues.length > 0 
        ? `System issues detected: ${issues.join(', ')}`
        : `System status: CPU ${systemMetrics.cpu_usage}%, Memory ${systemMetrics.memory_usage}%, Disk ${systemMetrics.disk_usage}%`;

      const result = {
        status,
        status_code: statusCode,
        message,
        metrics: systemMetrics,
        timestamp: new Date()
      };

      logger.info('Nagios check triggered', {
        status,
        status_code: statusCode,
        issues_count: issues.length,
        user_id: this.user?.id
      });

      return result;
    } catch (error) {
      logger.error('Failed to trigger Nagios check', {
        error: error.message,
        user_id: this.user?.id,
      });
      
      return {
        status: 'UNKNOWN',
        status_code: 3,
        message: `Failed to collect metrics: ${error.message}`,
        metrics: null,
        timestamp: new Date()
      };
    }
  }

  /**
   * Trigger PRTG sensor with enhanced data
   * @returns {Object} PRTG sensor result
   */
  async triggerPrtgSensor() {
    try {
      const systemMetrics = await this.collectSystemMetrics();
      const networkMetrics = await this.collectNetworkMetrics();

      const channels = [
        {
          channel: 'CPU Usage',
          value: systemMetrics.cpu_usage,
          unit: 'Percent',
          limitmode: 1,
          limitmaxwarning: this.thresholds.cpu_usage,
          limitmaxerror: 95
        },
        {
          channel: 'Memory Usage',
          value: systemMetrics.memory_usage,
          unit: 'Percent',
          limitmode: 1,
          limitmaxwarning: this.thresholds.memory_usage,
          limitmaxerror: 95
        },
        {
          channel: 'Disk Usage',
          value: systemMetrics.disk_usage,
          unit: 'Percent',
          limitmode: 1,
          limitmaxwarning: this.thresholds.disk_usage,
          limitmaxerror: 98
        }
      ];

      // Add network interface channels
      networkMetrics.forEach((netMetric, index) => {
        if (index < 5) { // Limit to 5 interfaces to avoid too many channels
          channels.push({
            channel: `Network In - ${netMetric.interface}`,
            value: Math.round(netMetric.bytes_in / 1024 / 1024), // Convert to MB
            unit: 'BytesBandwidth'
          });
          channels.push({
            channel: `Network Out - ${netMetric.interface}`,
            value: Math.round(netMetric.bytes_out / 1024 / 1024), // Convert to MB
            unit: 'BytesBandwidth'
          });
        }
      });

      const result = {
        prtg: {
          result: channels,
          text: `System monitored successfully. CPU: ${systemMetrics.cpu_usage}%, Memory: ${systemMetrics.memory_usage}%, Disk: ${systemMetrics.disk_usage}%`
        }
      };

      logger.info('PRTG sensor triggered', {
        channels_count: channels.length,
        system_metrics: systemMetrics,
        user_id: this.user?.id
      });

      return result;
    } catch (error) {
      logger.error('Failed to trigger PRTG sensor', {
        error: error.message,
        user_id: this.user?.id,
      });
      
      return {
        prtg: {
          error: 1,
          text: `Failed to collect metrics: ${error.message}`
        }
      };
    }
  }

  /**
   * Get monitoring health status
   * @returns {Object} Health status
   */
  async getHealthStatus() {
    try {
      const startTime = Date.now();
      
      // Test API connectivity
      let apiStatus = 'healthy';
      let apiResponseTime = 0;
      
      try {
        const apiStart = Date.now();
        await this.makeApiRequest('/system/diagnostics/status', {}, 'health_check');
        apiResponseTime = Date.now() - apiStart;
      } catch (error) {
        apiStatus = 'unhealthy';
        logger.warn('API health check failed', { error: error.message });
      }

      // Test cache connectivity
      let cacheStatus = 'healthy';
      try {
        await this.safeSetCache('health_check', Date.now(), 10);
        await this.safeGetCache('health_check');
      } catch (error) {
        cacheStatus = 'unhealthy';
        logger.warn('Cache health check failed', { error: error.message });
      }

      const totalResponseTime = Date.now() - startTime;

      const health = {
        status: apiStatus === 'healthy' && cacheStatus === 'healthy' ? 'healthy' : 'degraded',
        timestamp: new Date(),
        components: {
          api: {
            status: apiStatus,
            response_time_ms: apiResponseTime
          },
          cache: {
            status: cacheStatus
          }
        },
        total_response_time_ms: totalResponseTime,
        rate_limit_status: {
          active_operations: this.rateLimitMap.size,
          total_requests_last_minute: Array.from(this.rateLimitMap.values())
            .flat()
            .filter(timestamp => Date.now() - timestamp < 60000)
            .length
        }
      };

      return health;
    } catch (error) {
      logger.error('Failed to get health status', { error: error.message });
      return {
        status: 'unhealthy',
        timestamp: new Date(),
        error: error.message
      };
    }
  }
}

module.exports = MonitoringService;