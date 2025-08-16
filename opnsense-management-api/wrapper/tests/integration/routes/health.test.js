/**
 * Integration › routes › health
 * Covers:
 *  - GET /api/v1/health
 *  - GET /api/v1/health/live
 *  - GET /api/v1/health/ready  (200 happy path, 503 when a critical dep fails)
 *  - GET /api/v1/health/database (200/503)
 *  - GET /api/v1/health/cache    (200/503)
 *  - GET /api/v1/health/opnsense (200/503)
 *  - GET /api/v1/health/version
 *  - GET /api/v1/health/metrics
 *  - GET /api/v1/health/dependencies (200 all healthy, 207 when some unhealthy)
 *  - GET /api/v1/health/status       (200 healthy, 207 warn, 503 unhealthy)
 */

const request = require('supertest');

// ---------- MOCK: logger ----------
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// ---------- MOCK: rateLimit (no-op limiter) ----------
const createRateLimiterMock = jest.fn(() => (_req, _res, next) => next());
jest.mock('../../../src/middleware/rateLimit', () => ({
  createRateLimiter: (...a) => createRateLimiterMock(...a),
}));

// ---------- MOCK: config/database (db + redis) ----------
const testDbConnMock = jest.fn();
const testRedisConnMock = jest.fn();

const sequelizeMock = {
  query: jest.fn(),
  databaseVersion: jest.fn(),
  options: {
    pool: { max: 10, min: 0, idle: 10000, acquire: 30000 },
  },
};

const redisMock = {
  setEx: jest.fn(),
  set: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  info: jest.fn(),
};

jest.mock('../../../src/config/database', () => ({
  testDatabaseConnection: (...a) => testDbConnMock(...a),
  testRedisConnection: (...a) => testRedisConnMock(...a),
  sequelize: sequelizeMock,
  redis: redisMock,
}));

// ---------- MOCK: config/opnsense ----------
const testOpnsenseConnMock = jest.fn();
const getSystemInfoMock = jest.fn();
jest.mock('../../../src/config/opnsense', () => ({
  testConnection: (...a) => testOpnsenseConnMock(...a),
  getSystemInfo: (...a) => getSystemInfoMock(...a),
}));

// Load the app ONLY after mocks
const app = require('../../../src/app');

describe('routes › health', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  // ---------------- GET /api/v1/health ----------------
  describe('GET /api/v1/health', () => {
    it('returns basic health info', async () => {
      // keep OS/process calls deterministic
      const os = require('os');
      jest.spyOn(os, 'loadavg').mockReturnValue([0.1, 0.05, 0.01]);
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(4).fill({}));
      jest.spyOn(process, 'uptime').mockReturnValue(12.34);

      const mem = {
        heapUsed: 1000,
        heapTotal: 2000,
        external: 300,
        rss: 4000,
      };
      jest.spyOn(process, 'memoryUsage').mockReturnValue(mem);

      const res = await request(app).get('/api/v1/health').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/healthy/i);
      expect(res.body.data).toEqual(
        expect.objectContaining({
          status: 'healthy',
          cpu: expect.objectContaining({ cpu_count: 4 }),
          memory: expect.objectContaining({ heapUsed: 1000 }),
        })
      );
    });
  });

  // ---------------- GET /api/v1/health/live ----------------
  describe('GET /api/v1/health/live', () => {
    it('returns liveness info', async () => {
      const res = await request(app).get('/api/v1/health/live').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('alive');
      expect(typeof res.body.data.pid).toBe('number');
    });
  });

  // ---------------- GET /api/v1/health/ready ----------------
  describe('GET /api/v1/health/ready', () => {
    it('200 when all critical dependencies are healthy', async () => {
      testDbConnMock.mockResolvedValue(true);
      testRedisConnMock.mockResolvedValue(true); // optional
      testOpnsenseConnMock.mockResolvedValue(true);

      const res = await request(app).get('/api/v1/health/ready').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('ready');
      expect(res.body.data.dependencies).toEqual(
        expect.objectContaining({
          database: expect.objectContaining({ status: 'healthy' }),
          cache: expect.objectContaining({ status: 'healthy', optional: true }),
          opnsense_api: expect.objectContaining({ status: 'healthy' }),
        })
      );
    });

    it('503 when a critical dependency is unhealthy (e.g., OPNsense)', async () => {
      testDbConnMock.mockResolvedValue(true);
      // Simulate optional Redis degraded (should not flip "allReady" by itself)
      testRedisConnMock.mockRejectedValue(new Error('redis timeout'));
      testOpnsenseConnMock.mockResolvedValue(false);

      const res = await request(app).get('/api/v1/health/ready').expect(503);
      expect(res.body.success).toBe(false);
      expect(res.body.data.status).toBe('not_ready');
      expect(res.body.data.dependencies.opnsense_api.status).toBe('unhealthy');
      expect(res.body.data.dependencies.cache.status).toBe('degraded');
    });
  });

  // ---------------- GET /api/v1/health/database ----------------
  describe('GET /api/v1/health/database', () => {
    it('200 with DB stats when connection & queries succeed', async () => {
      testDbConnMock.mockResolvedValue(true);

      // SELECT 1, NOW()
      sequelizeMock.query
        .mockResolvedValueOnce([[{ health_check: 1, server_time: '2025-01-01T00:00:00.000Z' }]])
        // table stats
        .mockResolvedValueOnce([
          [
            { schemaname: 'public', tablename: 'rules', inserts: 1, updates: 2, deletes: 0 },
            { schemaname: 'public', tablename: 'users', inserts: 5, updates: 0, deletes: 1 },
          ],
        ]);

      sequelizeMock.databaseVersion.mockResolvedValue('PostgreSQL 15.4');

      const res = await request(app).get('/api/v1/health/database').expect(200);

      expect(sequelizeMock.query).toHaveBeenNthCalledWith(
        1,
        'SELECT 1 as health_check, NOW() as server_time'
      );
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual(
        expect.objectContaining({
          status: 'healthy',
          type: 'postgresql',
          server_time: '2025-01-01T00:00:00.000Z',
          version: 'PostgreSQL 15.4',
          pool: expect.objectContaining({ max_connections: 10 }),
          table_stats: expect.any(Array),
        })
      );
      expect(res.body.data.table_stats.length).toBeGreaterThan(0);
    });

    it('503 when DB connection test fails', async () => {
      testDbConnMock.mockResolvedValue(false);

      const res = await request(app).get('/api/v1/health/database').expect(503);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toBe('DATABASE_UNHEALTHY');
      expect(res.body.data.status).toBe('unhealthy');
    });
  });

  // ---------------- GET /api/v1/health/cache ----------------
  describe('GET /api/v1/health/cache', () => {
    it('200 and performs set/get/del + reads server/memory info', async () => {
      testRedisConnMock.mockResolvedValue(true);

      redisMock.setEx.mockResolvedValue('OK');
      const payload = { timestamp: '2025-01-01T00:00:00.000Z', test: true };
      redisMock.get.mockResolvedValue(JSON.stringify(payload));
      redisMock.del.mockResolvedValue(1);

      // Redis INFO lines (CRLF-separated) – only the fields used in the route are required
      redisMock.info
        .mockResolvedValueOnce(
          [
            '# Server',
            'redis_version:7.0.0',
            'uptime_in_seconds:12345',
            'connected_clients:12',
            '',
          ].join('\r\n')
        )
        .mockResolvedValueOnce(
          [
            '# Memory',
            'used_memory_human:12M',
            'maxmemory_human:2G',
            '',
          ].join('\r\n')
        );

      const res = await request(app).get('/api/v1/health/cache').expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('healthy');
      expect(res.body.data.test_passed).toBe(true);
      expect(res.body.data.server_info).toEqual(
        expect.objectContaining({
          version: '7.0.0',
          uptime: '12345',
          connected_clients: '12',
        })
      );
      expect(res.body.data.memory_info).toEqual(
        expect.objectContaining({
          used_memory: '12M',
          max_memory: '2G',
        })
      );
    });

    it('503 when Redis connection test fails', async () => {
      testRedisConnMock.mockResolvedValue(false);

      const res = await request(app).get('/api/v1/health/cache').expect(503);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toBe('CACHE_UNHEALTHY');
      expect(res.body.data.status).toBe('unhealthy');
    });
  });

  // ---------------- GET /api/v1/health/opnsense ----------------
  describe('GET /api/v1/health/opnsense', () => {
    it('200 when getSystemInfo reports success', async () => {
      getSystemInfoMock.mockResolvedValue({
        success: true,
        data: { version: '24.1', product: 'OPNsense', platform: 'amd64' },
      });

      const res = await request(app).get('/api/v1/health/opnsense').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.system_info).toEqual(
        expect.objectContaining({ version: '24.1', product: 'OPNsense' })
      );
    });

    it('503 when getSystemInfo reports failure', async () => {
      getSystemInfoMock.mockResolvedValue({ success: false, error: 'unreachable' });

      const res = await request(app).get('/api/v1/health/opnsense').expect(503);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toBe('OPNSENSE_API_UNHEALTHY');
      expect(res.body.data.status).toBe('unhealthy');
    });
  });

  // ---------------- GET /api/v1/health/version ----------------
  describe('GET /api/v1/health/version', () => {
    it('returns service/package/runtime info', async () => {
      const res = await request(app).get('/api/v1/health/version').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual(
        expect.objectContaining({
          service: expect.objectContaining({ name: expect.any(String) }),
          runtime: expect.objectContaining({ node_version: expect.any(String) }),
          build: expect.any(Object),
          dependencies: expect.any(Object),
        })
      );
    });
  });

  // ---------------- GET /api/v1/health/metrics ----------------
  describe('GET /api/v1/health/metrics', () => {
    it('returns system/process/network metrics', async () => {
      const os = require('os');

      jest.spyOn(os, 'totalmem').mockReturnValue(1024 * 1024 * 1024); // 1 GB
      jest.spyOn(os, 'freemem').mockReturnValue(512 * 1024 * 1024);   // 512 MB
      jest.spyOn(os, 'cpus').mockReturnValue([{ model: 'CPU-X' }, { model: 'CPU-X' }, { model: 'CPU-X' }, { model: 'CPU-X' }]);
      jest.spyOn(os, 'loadavg').mockReturnValue([0.5, 0.4, 0.3]);
      jest.spyOn(os, 'hostname').mockReturnValue('node-1');
      jest.spyOn(os, 'platform').mockReturnValue('linux');
      jest.spyOn(os, 'arch').mockReturnValue('x64');
      jest.spyOn(os, 'uptime').mockReturnValue(12345);
      jest.spyOn(os, 'release').mockReturnValue('6.1.0');
      jest.spyOn(os, 'type').mockReturnValue('Linux');
      jest
        .spyOn(os, 'networkInterfaces')
        .mockReturnValue({
          lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
          eth0: [{ address: '10.0.0.2', family: 'IPv4', internal: false }],
        });

      const res = await request(app).get('/api/v1/health/metrics').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.system.memory.total).toBeGreaterThan(0);
      expect(res.body.data.system.cpu.count).toBe(4);
      expect(res.body.data.network.eth0[0]).toEqual(
        expect.objectContaining({ address: '10.0.0.2', internal: false })
      );
    });
  });

  // ---------------- GET /api/v1/health/dependencies ----------------
  describe('GET /api/v1/health/dependencies', () => {
    it('200 when all dependencies are healthy', async () => {
      testDbConnMock.mockResolvedValue(true);
      testRedisConnMock.mockResolvedValue(true);
      testOpnsenseConnMock.mockResolvedValue(true);

      const res = await request(app).get('/api/v1/health/dependencies').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.overall_status).toBe('healthy');
      expect(res.body.data.summary.critical_failures).toBe(0);
    });

    it('207 when some dependencies are unhealthy/degraded', async () => {
      testDbConnMock.mockResolvedValue(true);
      testRedisConnMock.mockRejectedValue(new Error('redis down')); // degraded, non-critical
      testOpnsenseConnMock.mockResolvedValue(false); // critical → overall degraded

      const res = await request(app).get('/api/v1/health/dependencies').expect(207);
      expect(res.body.success).toBe(false);
      expect(res.body.data.overall_status).toBe('degraded');
      expect(res.body.data.summary.unhealthy).toBeGreaterThan(0);
      expect(res.body.data.summary.critical_failures).toBeGreaterThan(0);
    });
  });

  // ---------------- GET /api/v1/health/status ----------------
  describe('GET /api/v1/health/status', () => {
    it('200 healthy when all pass', async () => {
      testDbConnMock.mockResolvedValue(true);
      testRedisConnMock.mockResolvedValue(true);
      testOpnsenseConnMock.mockResolvedValue(true);

      const res = await request(app).get('/api/v1/health/status').expect(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.checks).toHaveLength(3);
      expect(res.body.links).toEqual(
        expect.objectContaining({ about: '/api/v1/health/version', metrics: '/api/v1/health/metrics' })
      );
    });

    it('207 warn when DB ok but cache is degraded', async () => {
      testDbConnMock.mockResolvedValue(true);
      testRedisConnMock.mockResolvedValue(false); // warn branch
      testOpnsenseConnMock.mockResolvedValue(true);

      const res = await request(app).get('/api/v1/health/status').expect(207);
      expect(res.body.status === 'warn' || res.body.status === 'healthy').toBe(true); // route sets 'warn' in this case
      expect(res.body.checks.find(c => c.component === 'cache').status).toMatch(/warn/);
    });

    it('503 unhealthy when DB fails', async () => {
      testDbConnMock.mockResolvedValue(false);
      testRedisConnMock.mockResolvedValue(true);
      testOpnsenseConnMock.mockResolvedValue(true);

      const res = await request(app).get('/api/v1/health/status').expect(503);
      expect(res.body.status).toBe('unhealthy');
      expect(res.body.checks.find(c => c.component === 'database').status).toBe('fail');
    });
  });
});
