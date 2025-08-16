/**
 * Integration › routes › admin
 * Full endpoint coverage:
 *  - GET    /api/v1/admin/users
 *  - POST   /api/v1/admin/users
 *  - PUT    /api/v1/admin/users/:id
 *  - DELETE /api/v1/admin/users/:id
 *  - GET    /api/v1/admin/audit-logs
 *  - GET    /api/v1/admin/system/info
 */

const { Op } = require('sequelize');
const request = require('supertest');

// --------- Base mocks ----------
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));
jest.mock('../../../src/middleware/rateLimit', () => () => (_req, _res, next) => next());
jest.mock('../../../src/middleware/audit', () => () => (_req, _res, next) => next());
// The admin router declares "no auth", but if the app mounts it behind auth, bypass it here:
jest.mock('../../../src/middleware/auth', () => () => (req, _res, next) => { req.user = { id: 1, role: 'admin' }; next(); });

// Models
const UserMock = {
  findAndCountAll: jest.fn(),
  create: jest.fn(),
  findByPk: jest.fn(),
  count: jest.fn(),
};
const AuditLogMock = {
  findAndCountAll: jest.fn(),
  count: jest.fn(),
};

jest.mock('../../../src/models/User', () => UserMock);
jest.mock('../../../src/models/AuditLog', () => AuditLogMock);

// DB (used in /system/info)
const queryMock = jest.fn();
jest.mock('../../../src/config/database', () => ({
  sequelize: { query: (...a) => queryMock(...a) },
}));

// Express app
const app = require('../../../src/app');

// Utils: build user instances consistent with what the router expects
function makeUser(overrides = {}) {
  const obj = {
    id: 10,
    username: 'alice',
    email: 'alice@example.com',
    role: 'admin',
    is_active: true,
    createdAt: new Date('2025-01-01T00:00:00.000Z'),
    toSafeJSON: function () {
      const { id, username, email, role, is_active, createdAt } = this;
      return { id, username, email, role, is_active, createdAt };
    },
    update: jest.fn().mockResolvedValue(true),
    destroy: jest.fn().mockResolvedValue(true),
    ...overrides,
  };
  return obj;
}

describe('routes › admin', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ------------------ GET /users ------------------
  describe('GET /api/v1/admin/users', () => {
    it('returns users with search/role filters and pagination; asserts where/offset/limit', async () => {
      const rows = [makeUser({ id: 1 }), makeUser({ id: 2 }), makeUser({ id: 3 })];
      UserMock.findAndCountAll.mockImplementation(async (opts) => {
        // Assert arguments passed to the model
        expect(opts.limit).toBe(3);
        expect(opts.offset).toBe(3); // page=2, limit=3
        expect(opts.order).toEqual([['createdAt', 'DESC']]);
        // attributes.exclude contains password & related fields
        expect(opts.attributes.exclude).toEqual(
          expect.arrayContaining([
            'password',
            'two_factor_secret',
            'backup_codes',
            'email_verification_token',
            'password_reset_token',
          ])
        );
        // where uses Op.or and Op.iLike on username/email
        expect(opts.where[Op.or][0].username[Op.iLike]).toBe('%adm%');
        expect(opts.where[Op.or][1].email[Op.iLike]).toBe('%adm%');
        expect(opts.where.role).toBe('admin');
        return { count: 5, rows };
      });

      const res = await request(app)
        .get('/api/v1/admin/users')
        .query({ page: 2, limit: 3, search: 'adm', role: 'admin' })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBe(3);
      expect(res.body.pagination).toEqual(
        expect.objectContaining({ total: 5, page: 2, limit: 3, total_pages: Math.ceil(5 / 3) })
      );
    });

    it('uses default page/limit and no filters when query is empty', async () => {
      UserMock.findAndCountAll.mockResolvedValue({ count: 1, rows: [makeUser()] });

      const res = await request(app).get('/api/v1/admin/users').expect(200);

      expect(UserMock.findAndCountAll).toHaveBeenCalledWith(
        expect.objectContaining({
          limit: 20, // default
          offset: 0,
        })
      );
      expect(res.body.data[0]).toHaveProperty('username');
    });
  });

  // ------------------ POST /users ------------------
  describe('POST /api/v1/admin/users', () => {
    it('creates a user (is_active defaults to true) and returns 201 with toSafeJSON', async () => {
      const created = makeUser({ id: 99, username: 'bob', email: 'b@example.com', role: 'operator' });
      UserMock.create.mockResolvedValue(created);

      const payload = { username: 'bob', email: 'b@example.com', password: 'Password#1', role: 'operator' };
      const res = await request(app).post('/api/v1/admin/users').send(payload).expect(201);

      // create is called with is_active default true
      expect(UserMock.create).toHaveBeenCalledWith(expect.objectContaining({ ...payload, is_active: true }));
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual(created.toSafeJSON());
    });
  });

  // ------------------ PUT /users/:id ------------------
  describe('PUT /api/v1/admin/users/:id', () => {
    it('updates and returns the user (via toSafeJSON)', async () => {
      const u = makeUser({ id: 7, username: 'eve', email: 'e@example.com' });
      UserMock.findByPk.mockResolvedValue(u);

      const res = await request(app)
        .put('/api/v1/admin/users/7')
        .send({ role: 'viewer', is_active: false })
        .expect(200);

      expect(UserMock.findByPk).toHaveBeenCalledWith('7');
      expect(u.update).toHaveBeenCalledWith(expect.objectContaining({ role: 'viewer', is_active: false }));
      expect(res.body.data).toEqual(u.toSafeJSON());
    });

    it('404 when user does not exist', async () => {
      UserMock.findByPk.mockResolvedValue(null);
      const res = await request(app).put('/api/v1/admin/users/404').send({ role: 'admin' }).expect(404);
      expect(res.body.message || res.text).toMatch(/user not found/i);
    });
  });

  // ------------------ DELETE /users/:id ------------------
  describe('DELETE /api/v1/admin/users/:id', () => {
    it('deletes the user and returns 200', async () => {
      const u = makeUser({ id: 11 });
      UserMock.findByPk.mockResolvedValue(u);

      const res = await request(app).delete('/api/v1/admin/users/11').expect(200);
      expect(u.destroy).toHaveBeenCalled();
      expect(res.body.success).toBe(true);
    });

    it('404 when user does not exist', async () => {
      UserMock.findByPk.mockResolvedValue(null);
      const res = await request(app).delete('/api/v1/admin/users/999').expect(404);
      expect(res.body.message || res.text).toMatch(/user not found/i);
    });
  });

  // ------------------ GET /audit-logs ------------------
  describe('GET /api/v1/admin/audit-logs', () => {
    it('applies level/action/user_id filters and date range (timestamp gte/lte) + pagination', async () => {
      const rows = [{ id: 1, action: 'toggle_rule', level: 'info' }];
      AuditLogMock.findAndCountAll.mockImplementation(async (opts) => {
        // Verify constructed where clause
        expect(opts.where.level).toBe('security');
        expect(opts.where.action[Op.iLike]).toBe('%toggle%');
        expect(opts.where.user_id).toBe(2);
        expect(opts.where.timestamp[Op.gte]).toEqual(new Date('2025-01-01'));
        expect(opts.where.timestamp[Op.lte]).toEqual(new Date('2025-01-31'));
        expect(opts.limit).toBe(10);
        expect(opts.offset).toBe(10); // page=2
        expect(opts.order).toEqual([['timestamp', 'DESC']]);
        return { count: 42, rows };
      });

      const res = await request(app)
        .get('/api/v1/admin/audit-logs')
        .query({
          page: 2,
          limit: 10,
          level: 'security',
          action: 'toggle',
          user_id: 2,
          start_date: '2025-01-01',
          end_date: '2025-01-31',
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual(rows);
      expect(res.body.pagination.total).toBe(42);
      expect(res.body.pagination.total_pages).toBe(Math.ceil(42 / 10));
    });

    it('uses defaults page=1 limit=50 when no filters are provided', async () => {
      AuditLogMock.findAndCountAll.mockResolvedValue({ count: 0, rows: [] });

      await request(app).get('/api/v1/admin/audit-logs').expect(200);

      expect(AuditLogMock.findAndCountAll).toHaveBeenCalledWith(
        expect.objectContaining({ limit: 50, offset: 0 })
      );
    });
  });

  // ------------------ GET /system/info ------------------
  describe('GET /api/v1/admin/system/info', () => {
    it('returns system, DB and app info; executes SELECT version()', async () => {
      // Mock OS
      const os = require('os');
      jest.spyOn(os, 'hostname').mockReturnValue('node-1');
      jest.spyOn(os, 'platform').mockReturnValue('linux');
      jest.spyOn(os, 'arch').mockReturnValue('x64');
      jest.spyOn(os, 'uptime').mockReturnValue(1234);
      jest.spyOn(os, 'totalmem').mockReturnValue(1024);
      jest.spyOn(os, 'freemem').mockReturnValue(256);
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(8).fill({}));
      jest.spyOn(os, 'loadavg').mockReturnValue([0.5, 0.4, 0.3]);

      // DB query → SELECT version()
      queryMock.mockResolvedValue([[{ version: 'PostgreSQL 15.4' }]]);

      // Counts
      UserMock.count
        .mockResolvedValueOnce(10) // total users
        .mockResolvedValueOnce(7); // active users
      AuditLogMock.count.mockResolvedValue(123);

      const res = await request(app).get('/api/v1/admin/system/info').expect(200);

      expect(queryMock).toHaveBeenCalledWith('SELECT version()');
      expect(res.body.data.system).toEqual(
        expect.objectContaining({
          hostname: 'node-1',
          platform: 'linux',
          arch: 'x64',
          uptime: 1234,
          cpu: 8,
        })
      );
      expect(res.body.data.database).toEqual(
        expect.objectContaining({ connected: true, version: 'PostgreSQL 15.4' })
      );
      expect(res.body.data.application).toEqual(
        expect.objectContaining({ user_count: 10, active_users: 7, recent_audit_logs: 123 })
      );
      expect(() => new Date(res.body.data.timestamp)).not.toThrow();
    });

    it('DB down → connected=false and error populated', async () => {
      queryMock.mockRejectedValue(new Error('db down'));
      UserMock.count.mockResolvedValueOnce(0).mockResolvedValueOnce(0);
      AuditLogMock.count.mockResolvedValue(0);

      const res = await request(app).get('/api/v1/admin/system/info').expect(200);

      expect(res.body.data.database.connected).toBe(false);
      expect(String(res.body.data.database.error)).toMatch(/db down/i);
    });
  });
});