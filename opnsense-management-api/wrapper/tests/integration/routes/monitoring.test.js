/**
 * Integration › routes › monitoring
 * Covers:
 *  - GET  /api/v1/monitoring/metrics
 *  - GET  /api/v1/monitoring/interface/:interface_name
 *  - GET  /api/v1/monitoring/alerts
 *  - POST /api/v1/monitoring/alerts/:id/acknowledge
 *  - GET  /api/v1/monitoring/dashboard
 *  - GET  /api/v1/monitoring/prometheus
 *  - GET  /api/v1/monitoring/events
 *  - GET  /api/v1/monitoring/health
 *  - GET  /api/v1/monitoring/thresholds
 *  - PUT  /api/v1/monitoring/thresholds
 */

const request = require('supertest');

// ---------- MOCK: logger ----------
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));

// ---------- MOCK: auth (authenticate/authorize/PERMISSIONS) ----------
const authenticateMock = jest.fn((req, _res, next) => {
  req.user = { id: 1, username: 'tester', role: 'admin' };
  next();
});
const authorizeMock = jest.fn(() => (req, _res, next) => next());
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (...a) => authenticateMock(...a),
  authorize: (...a) => authorizeMock(...a),
  PERMISSIONS: {
    MONITORING_READ: 'MONITORING_READ',
    MONITORING_WRITE: 'MONITORING_WRITE',
  },
}));

// ---------- MOCK: validation (idParam only, pass-through) ----------
const validators = { idParam: jest.fn((req, _res, next) => next()) };
jest.mock('../../../src/middleware/validation', () => ({ validators }));

// ---------- MOCK: rateLimit (no-op limiter) ----------
const createRateLimiterMock = jest.fn(() => (_req, _res, next) => next());
jest.mock('../../../src/middleware/rateLimit', () => ({
  createRateLimiter: (...a) => createRateLimiterMock(...a),
}));

// ---------- MOCK: MonitoringService (constructor -> instance with methods) ----------
const msMethods = {
  collectSystemMetrics: jest.fn(),
  collectNetworkMetrics: jest.fn(), // accepts optional interface_name
  getHealthStatus: jest.fn(),
};
const MonitoringServiceCtor = jest.fn(() => msMethods);
MonitoringServiceCtor.__methods = msMethods;
jest.mock('../../../src/services/MonitoringService', () => MonitoringServiceCtor);

// ---------- MOCK: config/monitoring ----------
const getMetricsMock = jest.fn();
const performHealthChecksMock = jest.fn();
const monitoringConfigMock = {
  alerting: { thresholds: { error_rate: 1, latency_ms: 500 } },
  nagios: { criticalThresholds: { cpu: 90, mem: 95 } },
};
jest.mock('../../../src/config/monitoring', () => ({
  getMetrics: (...a) => getMetricsMock(...a),
  performHealthChecks: (...a) => performHealthChecksMock(...a),
  monitoringConfig: monitoringConfigMock,
}));

// ---------- MOCK: models ----------
const AlertModel = {
  findAll: jest.fn(),
  findByPk: jest.fn(),
  getStatistics: jest.fn(),
  findCritical: jest.fn(),
  findUnacknowledged: jest.fn(),
};
const AuditLogModel = {
  findAll: jest.fn(),
  findSecurityEvents: jest.fn(),
};
const RuleModel = {
  getStatistics: jest.fn(),
  count: jest.fn(),
};

jest.mock('../../../src/models/Alert', () => AlertModel);
jest.mock('../../../src/models/AuditLog', () => AuditLogModel);
jest.mock('../../../src/models/Rule', () => RuleModel);

// Load the app ONLY after mocks
const app = require('../../../src/app');

describe('routes › monitoring', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  // ---------------- GET /metrics ----------------
  describe('GET /api/v1/monitoring/metrics', () => {
    it('returns system and interface metrics', async () => {
      MonitoringServiceCtor.__methods.collectSystemMetrics.mockResolvedValue({
        cpu_usage: 23.5,
        memory_usage: 64.1,
        disk_usage: 71.2,
        uptime: 12345,
      });
      MonitoringServiceCtor.__methods.collectNetworkMetrics
        .mockResolvedValue([{ name: 'eth0', rx: 1000, tx: 800 }]);

      const res = await request(app).get('/api/v1/monitoring/metrics').expect(200);

      expect(MonitoringServiceCtor).toHaveBeenCalled();
      expect(res.body.success).toBe(true);
      expect(res.body.data.system).toEqual(
        expect.objectContaining({ cpu_usage: expect.any(Number) })
      );
      expect(Array.isArray(res.body.data.interfaces)).toBe(true);
    });

    it('gracefully falls back to empty interfaces if collection fails', async () => {
      MonitoringServiceCtor.__methods.collectSystemMetrics.mockResolvedValue({ cpu_usage: 10 });
      MonitoringServiceCtor.__methods.collectNetworkMetrics.mockRejectedValue(new Error('no nets'));

      const res = await request(app).get('/api/v1/monitoring/metrics').expect(200);
      expect(res.body.data.interfaces).toEqual([]); // .catch(() => []) in route
    });
  });

  // ---------------- GET /interface/:interface_name ----------------
  describe('GET /api/v1/monitoring/interface/:name', () => {
    it('returns metrics for a specific interface', async () => {
      MonitoringServiceCtor.__methods.collectNetworkMetrics.mockResolvedValue([
        { name: 'eth1', rx: 10, tx: 20 },
      ]);

      const res = await request(app).get('/api/v1/monitoring/interface/eth1').expect(200);
      expect(MonitoringServiceCtor.__methods.collectNetworkMetrics).toHaveBeenCalledWith('eth1');
      expect(res.body.data[0]).toEqual(expect.objectContaining({ name: 'eth1' }));
    });

    it('404 when interface not found (empty metrics)', async () => {
      MonitoringServiceCtor.__methods.collectNetworkMetrics.mockResolvedValue([]);
      const res = await request(app).get('/api/v1/monitoring/interface/missing0').expect(404);
      expect(res.body.message || res.text).toMatch(/interface .* not found/i);
    });
  });

  // ---------------- GET /alerts ----------------
  describe('GET /api/v1/monitoring/alerts', () => {
    it('returns filtered alerts with statistics metadata', async () => {
      const alerts = [
        { id: 1, severity: 'critical', type: 'system', status: 'active' },
        { id: 2, severity: 'warning', type: 'network', status: 'active' },
      ];
      AlertModel.findAll.mockResolvedValue(alerts);
      AlertModel.getStatistics.mockResolvedValue({ critical: 1, warning: 1 });

      const res = await request(app)
        .get('/api/v1/monitoring/alerts')
        .query({ severity: 'critical', type: 'system', status: 'active' })
        .expect(200);

      expect(AlertModel.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ severity: 'critical', type: 'system', status: 'active' }),
          order: [['severity', 'DESC'], ['created_at', 'DESC']],
          limit: 100,
          include: expect.any(Array),
        })
      );
      expect(res.body.data).toHaveLength(2);
      expect(res.body.metadata.statistics).toEqual({ critical: 1, warning: 1 });
    });

    it('defaults to status=active when not provided', async () => {
      AlertModel.findAll.mockResolvedValue([]);
      AlertModel.getStatistics.mockResolvedValue({});
      await request(app).get('/api/v1/monitoring/alerts').expect(200);
      expect(AlertModel.findAll).toHaveBeenCalledWith(
        expect.objectContaining({ where: expect.objectContaining({ status: 'active' }) })
      );
    });
  });

  // ---------------- POST /alerts/:id/acknowledge ----------------
  describe('POST /api/v1/monitoring/alerts/:id/acknowledge', () => {
    function makeAlert(overrides = {}) {
      return {
        id: 10,
        status: 'active',
        acknowledged_at: null,
        acknowledge: jest.fn(function (userId, note) {
          this.status = 'acknowledged';
          this.acknowledged_at = new Date('2025-01-01T00:00:00.000Z');
          return Promise.resolve();
        }),
        getResponseTime: jest.fn(() => 3210),
        ...overrides,
      };
    }

    it('acknowledges alert and returns timing', async () => {
      const alert = makeAlert({ id: 42 });
      AlertModel.findByPk.mockResolvedValue(alert);

      const res = await request(app)
        .post('/api/v1/monitoring/alerts/42/acknowledge')
        .send({ note: 'on it' })
        .expect(200);

      expect(AlertModel.findByPk).toHaveBeenCalledWith('42');
      expect(alert.acknowledge).toHaveBeenCalledWith(1, 'on it');
      expect(res.body.data).toEqual(
        expect.objectContaining({
          id: 42,
          status: 'acknowledged',
          response_time: 3210,
        })
      );
    });

    it('404 when alert not found', async () => {
      AlertModel.findByPk.mockResolvedValue(null);
      await request(app).post('/api/v1/monitoring/alerts/999/acknowledge').send({}).expect(404);
    });
  });

  // ---------------- GET /dashboard ----------------
  describe('GET /api/v1/monitoring/dashboard', () => {
    it('returns compact dashboard data assembled from multiple sources', async () => {
      MonitoringServiceCtor.__methods.collectSystemMetrics.mockResolvedValue({
        cpu_usage: 12,
        memory_usage: 34,
        disk_usage: 56,
        uptime: 789,
      });
      MonitoringServiceCtor.__methods.collectNetworkMetrics.mockResolvedValue([
        { name: 'lan', rx: 100, tx: 50 },
      ]);
      performHealthChecksMock.mockResolvedValue({
        database: 'healthy', cache: 'healthy', opnsense_api: 'healthy',
      });

      AlertModel.getStatistics.mockResolvedValue({ critical: 2, warning: 1 });
      AlertModel.findCritical.mockResolvedValue([{ id: 1 }, { id: 2 }]);
      AlertModel.findUnacknowledged.mockResolvedValue([{ id: 3 }]);

      RuleModel.getStatistics.mockResolvedValue([{ interface: 'lan', action: 'pass', count: '2' }]);
      RuleModel.count
        .mockResolvedValueOnce(10) // total
        .mockResolvedValueOnce(7); // active

      AuditLogModel.findSecurityEvents.mockResolvedValue(
        Array.from({ length: 15 }).map((_, i) => ({ id: i + 1, level: 'security' }))
      );

      const res = await request(app).get('/api/v1/monitoring/dashboard').expect(200);

      expect(res.body.data.alerts).toEqual(
        expect.objectContaining({ total: 3, critical: 2, unacknowledged: 1 })
      );
      expect(res.body.data.firewall).toEqual(
        expect.objectContaining({ total_rules: 10, active_rules: 7, inactive_rules: 3 })
      );
      expect(res.body.data.security.recent_events.length).toBe(10); // sliced
      expect(res.body.data.system_health).toEqual(
        expect.objectContaining({ database: true, cache: true, opnsense_api: true })
      );
    });
  });

  // ---------------- GET /prometheus ----------------
  describe('GET /api/v1/monitoring/prometheus', () => {
    it('returns Prometheus-formatted metrics with correct content type', async () => {
      getMetricsMock.mockResolvedValue('# HELP metric\nmetric{label="a"} 1\n');

      const res = await request(app).get('/api/v1/monitoring/prometheus').expect(200);
      expect(res.headers['content-type']).toMatch(/text\/plain/);
      expect(res.text).toContain('metric{label="a"} 1');
    });
  });

  // ---------------- GET /events ----------------
  describe('GET /api/v1/monitoring/events', () => {
    it('returns recent events with level filter, limit and 24h window; also aggregates per level', async () => {
      // First call -> events list
      AuditLogModel.findAll
        .mockResolvedValueOnce([
          { audit_id: 'a1', level: 'info', action: 'x', timestamp: new Date().toISOString() },
          { audit_id: 'a2', level: 'warning', action: 'y', timestamp: new Date().toISOString() },
        ])
        // Second call -> grouped stats
        .mockResolvedValueOnce([
          { level: 'info', count: '1' },
          { level: 'warning', count: '1' },
        ]);

      const res = await request(app)
        .get('/api/v1/monitoring/events')
        .query({ limit: 50, level: 'info', hours: 24 })
        .expect(200);

      // Assert first findAll invocation received proper options
      expect(AuditLogModel.findAll).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({
          where: expect.objectContaining({
            // timestamp: { [Op.gte]: Date(ago) }  — cannot check symbol here, just existence
            timestamp: expect.any(Object),
            level: 'info',
          }),
          limit: 50,
          order: [['timestamp', 'DESC']],
          attributes: expect.arrayContaining(['audit_id', 'level', 'action']),
        })
      );

      // Second call for stats
      expect(AuditLogModel.findAll).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          attributes: expect.arrayContaining(['level']),
          group: ['level'],
          raw: true,
        })
      );

      expect(res.body.metadata.statistics).toEqual({ info: 1, warning: 1 });
      expect(res.body.metadata.count).toBe(2);
    });
  });

  // ---------------- GET /health ----------------
  describe('GET /api/v1/monitoring/health', () => {
    it('returns monitoring service health status', async () => {
      MonitoringServiceCtor.__methods.getHealthStatus.mockResolvedValue({
        system: 'ok',
        checks: { cpu: 'ok', mem: 'ok' },
      });

      const res = await request(app).get('/api/v1/monitoring/health').expect(200);
      expect(res.body.data).toEqual(expect.objectContaining({ system: 'ok' }));
    });
  });

  // ---------------- GET /thresholds ----------------
  describe('GET /api/v1/monitoring/thresholds', () => {
    it('returns thresholds from monitoringConfig', async () => {
      const res = await request(app).get('/api/v1/monitoring/thresholds').expect(200);
      expect(res.body.data.alerts).toEqual(monitoringConfigMock.alerting.thresholds);
      expect(res.body.data.nagios).toEqual(monitoringConfigMock.nagios.criticalThresholds);
      expect(res.body.data.system).toEqual(
        expect.objectContaining({ cpu_critical: expect.any(Number) })
      );
    });
  });

  // ---------------- PUT /thresholds ----------------
  describe('PUT /api/v1/monitoring/thresholds', () => {
    it('400 when warning >= critical for CPU thresholds', async () => {
      const payload = { system: { cpu_warning: 90, cpu_critical: 80 } };
      const res = await request(app).put('/api/v1/monitoring/thresholds').send(payload).expect(400);
      expect(res.body.success).toBe(false);
      expect(String(res.body.error || res.body.message)).toMatch(/warning threshold/i);
    });

    it('200 and logs update when thresholds valid', async () => {
      const payload = {
        system: { cpu_warning: 70, cpu_critical: 90 },
        firewall: { rule_count_warning: 1000 },
        alerts: { latency_ms: 400 },
      };
      const res = await request(app).put('/api/v1/monitoring/thresholds').send(payload).expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual(
        expect.objectContaining({ updated_by: 'tester', updated_at: expect.any(String) })
      );
    });
  });
});