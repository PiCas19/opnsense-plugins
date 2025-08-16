/**
 * Integration › routes › firewall
 * Covers:
 *  - GET    /api/v1/firewall/rules
 *  - GET    /api/v1/firewall/rules/:id
 *  - POST   /api/v1/firewall/rules
 *  - PUT    /api/v1/firewall/rules/:id
 *  - PATCH  /api/v1/firewall/rules/:id/toggle
 *  - DELETE /api/v1/firewall/rules/:id
 *  - PATCH  /api/v1/firewall/rules/bulk
 *  - POST   /api/v1/firewall/rules/sync
 *  - POST   /api/v1/firewall/apply
 *  - GET    /api/v1/firewall/interfaces
 *  - GET    /api/v1/firewall/stats
 *  - GET    /api/v1/firewall/rules/unused
 *  - GET    /api/v1/firewall/rules/redundant
 */

const request = require('supertest');

// ---------- MOCK: logger ----------
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));

// ---------- MOCK: auth (authenticate/authorize/PERMISSIONS) ----------
const authorizeMock = jest.fn(() => (req, _res, next) => next());
const authenticateMock = jest.fn((req, _res, next) => { req.user = { id: 1, username: 'tester' }; next(); });
const PERMISSIONS = {
  FIREWALL_READ: 'FIREWALL_READ',
  FIREWALL_WRITE: 'FIREWALL_WRITE',
  FIREWALL_DELETE: 'FIREWALL_DELETE',
  FIREWALL_TOGGLE: 'FIREWALL_TOGGLE',
};
jest.mock('../../../src/middleware/auth', () => ({
  authorize: (...args) => authorizeMock(...args),
  authenticate: (...args) => authenticateMock(...args),
  PERMISSIONS: { FIREWALL_READ: 'FIREWALL_READ', FIREWALL_WRITE: 'FIREWALL_WRITE', FIREWALL_DELETE: 'FIREWALL_DELETE', FIREWALL_TOGGLE: 'FIREWALL_TOGGLE' },
}));

// ---------- MOCK: validation (no-op middlewares, assertable) ----------
const validators = {
  firewallRulesQuery: jest.fn((req, _res, next) => next()),
  idParam: jest.fn((req, _res, next) => next()),
  createFirewallRule: jest.fn((req, _res, next) => next()),
  updateFirewallRule: jest.fn((req, _res, next) => next()),
  toggleFirewallRule: jest.fn((req, _res, next) => next()),
  bulkFirewallOperation: jest.fn((req, _res, next) => next()),
};
jest.mock('../../../src/middleware/validation', () => ({ validators }));

// ---------- MOCK: audit ----------
const auditLog = jest.fn().mockResolvedValue();
const AUDITED_ACTIONS = {
  API_ACCESS: 'api_access',
  RULE_CREATE: 'rule_create',
  RULE_UPDATE: 'rule_update',
  RULE_TOGGLE: 'rule_toggle',
  RULE_DELETE: 'rule_delete',
  SYSTEM_ACCESS: 'system_access',
  CONFIG_CHANGE: 'config_change',
};
jest.mock('../../../src/middleware/audit', () => ({
  auditLog: (...a) => auditLog(...a),
  AUDITED_ACTIONS: {
    API_ACCESS: 'api_access',
    RULE_CREATE: 'rule_create',
    RULE_UPDATE: 'rule_update',
    RULE_TOGGLE: 'rule_toggle',
    RULE_DELETE: 'rule_delete',
    SYSTEM_ACCESS: 'system_access',
    CONFIG_CHANGE: 'config_change',
  },
}));

// ---------- MOCK: rateLimit ----------
const createRateLimiter = jest.fn(() => (_req, _res, next) => next());
jest.mock('../../../src/middleware/rateLimit', () => ({ createRateLimiter: (...a) => createRateLimiter(...a) }));

// ---------- MOCK: RuleService (constructor -> instance with methods) ----------
const rsMethods = {
  getRules: jest.fn(),
  createRule: jest.fn(),
  updateRule: jest.fn(),
  bulkOperation: jest.fn(),
  syncPendingRules: jest.fn(),
};
const RuleServiceCtor = jest.fn(() => rsMethods);
RuleServiceCtor.__methods = rsMethods;
jest.mock('../../../src/services/RuleService', () => RuleServiceCtor);

// ---------- MOCK: OpnsenseService (constructor -> instance with methods) ----------
const osMethods = {
  createRule: jest.fn(),
  updateRule: jest.fn(),
  toggleRule: jest.fn(),
  deleteRule: jest.fn(),
  applyChanges: jest.fn(),
  getInterfaces: jest.fn(),
};
const OpnsenseServiceCtor = jest.fn(() => osMethods);
OpnsenseServiceCtor.__methods = osMethods;
jest.mock('../../../src/services/OpnsenseService', () => OpnsenseServiceCtor);

// ---------- MOCK: Rule model ----------
const RuleModel = {
  findByPk: jest.fn(),
  getStatistics: jest.fn(),
  count: jest.fn(),
  findUnused: jest.fn(),
  findRedundant: jest.fn(),
};
jest.mock('../../../src/models/Rule', () => RuleModel);

// Load the app ONLY after mocks
const app = require('../../../src/app');

// Helper to build a Sequelize-like "Rule" instance
function makeRule(overrides = {}) {
  const base = {
    id: 100,
    uuid: 'uuid-100',
    description: 'allow all',
    interface: 'lan',
    action: 'pass',
    enabled: true,
    suspended: false,
    opnsense_uuid: 'opn-100',
    sync_status: 'pending',
    sync_error: null,
    update: jest.fn(function (patch) {
      Object.assign(this, patch);
      return Promise.resolve(this);
    }),
    destroy: jest.fn().mockResolvedValue(true),
  };
  return Object.assign(base, overrides);
}

describe('routes › firewall', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ----------------- GET /rules -----------------
  describe('GET /api/v1/firewall/rules', () => {
    it('lists rules with filters and pagination; calls RuleService.getRules and auditLog', async () => {
      RuleServiceCtor.__methods.getRules.mockResolvedValue({
        data: [{ id: 1 }, { id: 2 }],
        pagination: { total: 2, page: 2, limit: 10, total_pages: 1 },
      });

      const res = await request(app)
        .get('/api/v1/firewall/rules')
        .query({
          page: 2,
          limit: 10,
          search: 'ssh',
          interface: 'lan',
          action: 'pass',
          enabled: 'true',
          protocol: 'tcp',
        })
        .expect(200);

      expect(RuleServiceCtor).toHaveBeenCalledWith(expect.objectContaining({ id: 1 })); // constructed with req.user
      expect(RuleServiceCtor.__methods.getRules).toHaveBeenCalledWith(
        2, 10,
        expect.objectContaining({ search: 'ssh', interface: 'lan', action: 'pass', enabled: true, protocol: 'tcp' })
      );
      expect(res.body.data.length).toBe(2);
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.API_ACCESS, 'info',
        expect.objectContaining({ action: 'list_firewall_rules', count: 2 })
      );
    });
  });

  // ----------------- GET /rules/:id -----------------
  describe('GET /api/v1/firewall/rules/:id', () => {
    it('returns a rule including creator', async () => {
      RuleModel.findByPk.mockResolvedValue(makeRule({ id: 5 }));
      const res = await request(app).get('/api/v1/firewall/rules/5').expect(200);
      expect(RuleModel.findByPk).toHaveBeenCalledWith('5', expect.any(Object));
      expect(res.body.data).toEqual(expect.objectContaining({ id: 5 }));
    });

    it('404 when rule does not exist', async () => {
      RuleModel.findByPk.mockResolvedValue(null);
      const res = await request(app).get('/api/v1/firewall/rules/404').expect(404);
      expect(res.body.message || res.text).toMatch(/firewall rule not found/i);
    });
  });

  // ----------------- POST /rules -----------------
  describe('POST /api/v1/firewall/rules', () => {
    it('creates rule, syncs with OPNsense (OK) and audits', async () => {
      const rule = makeRule({ id: 10, uuid: 'u-10', opnsense_uuid: null, sync_status: 'pending' });
      RuleServiceCtor.__methods.createRule.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.createRule.mockResolvedValue('opn-10');

      const payload = {
        description: 'allow all',
        interface: 'lan',
        action: 'pass',
        protocol: 'any',
        source: { type: 'any' },
        destination: { type: 'any' },
      };

      const res = await request(app).post('/api/v1/firewall/rules').send(payload).expect(201);

      expect(RuleServiceCtor.__methods.createRule).toHaveBeenCalledWith(
        expect.objectContaining({ description: 'allow all', created_by: 1, sync_status: 'pending' })
      );
      expect(OpnsenseServiceCtor).toHaveBeenCalled(); // instance for sync
      expect(OpnsenseServiceCtor.__methods.createRule).toHaveBeenCalled();
      expect(rule.update).toHaveBeenCalledWith(expect.objectContaining({ opnsense_uuid: 'opn-10', sync_status: 'synced' }));

      expect(res.body.data).toEqual(expect.objectContaining({ id: 10, uuid: 'u-10' }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.RULE_CREATE, 'info',
        expect.objectContaining({ rule_id: 10 })
      );
    });

    it('sync fails → sync_status: failed but request still succeeds', async () => {
      const rule = makeRule({ id: 11, uuid: 'u-11', opnsense_uuid: null, sync_status: 'pending' });
      RuleServiceCtor.__methods.createRule.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.createRule.mockRejectedValue(new Error('opnsense down'));

      const res = await request(app).post('/api/v1/firewall/rules').send({ description: 'x' }).expect(201);

      expect(rule.update).toHaveBeenCalledWith(expect.objectContaining({ sync_status: 'failed', sync_error: 'opnsense down' }));
      expect(res.body.data.sync_status).toBe('failed');
    });
  });

  // ----------------- PUT /rules/:id -----------------
  describe('PUT /api/v1/firewall/rules/:id', () => {
    it('updates rule and syncs (OK)', async () => {
      const rule = makeRule({ id: 20, opnsense_uuid: 'opn-20', sync_status: 'pending' });
      RuleServiceCtor.__methods.updateRule.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.updateRule.mockResolvedValue({ ok: true });

      const res = await request(app).put('/api/v1/firewall/rules/20').send({ description: 'new' }).expect(200);

      expect(RuleServiceCtor.__methods.updateRule).toHaveBeenCalledWith('20', expect.objectContaining({ description: 'new', updated_by: 1 }));
      expect(rule.update).toHaveBeenCalledWith(expect.objectContaining({ sync_status: 'synced', sync_error: null }));
      expect(res.body.data).toEqual(expect.objectContaining({ id: 20, sync_status: 'synced' }));

      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.RULE_UPDATE, 'info',
        expect.objectContaining({ rule_id: 20 })
      );
    });

    it('sync fails → status becomes failed', async () => {
      const rule = makeRule({ id: 21, opnsense_uuid: 'opn-21', sync_status: 'pending' });
      RuleServiceCtor.__methods.updateRule.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.updateRule.mockRejectedValue(new Error('sync err'));

      const res = await request(app).put('/api/v1/firewall/rules/21').send({}).expect(200);
      expect(rule.update).toHaveBeenCalledWith(expect.objectContaining({ sync_status: 'failed', sync_error: 'sync err' }));
      expect(res.body.data.sync_status).toBe('failed');
    });
  });

  // ----------------- PATCH /rules/:id/toggle -----------------
  describe('PATCH /api/v1/firewall/rules/:id/toggle', () => {
    it('toggles enabled + apply_immediately → applyChanges is called', async () => {
      const rule = makeRule({ id: 30, enabled: false, opnsense_uuid: 'opn-30' });
      RuleModel.findByPk.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.toggleRule.mockResolvedValue({ ok: true });
      OpnsenseServiceCtor.__methods.applyChanges.mockResolvedValue({ ok: true });

      const res = await request(app)
        .patch('/api/v1/firewall/rules/30/toggle')
        .send({ enabled: true, apply_immediately: true })
        .expect(200);

      expect(rule.update).toHaveBeenCalledWith(expect.objectContaining({ enabled: true, sync_status: 'pending' }));
      expect(OpnsenseServiceCtor.__methods.toggleRule).toHaveBeenCalledWith('opn-30', true);
      expect(OpnsenseServiceCtor.__methods.applyChanges).toHaveBeenCalled();
      expect(res.body.data).toEqual(expect.objectContaining({ id: 30, enabled: true, applied: true }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.RULE_TOGGLE, 'info',
        expect.objectContaining({ previous_state: false, new_state: true, applied_immediately: true })
      );
    });

    it('toggle fails → sync_status: failed but returns 200', async () => {
      const rule = makeRule({ id: 31, enabled: true, opnsense_uuid: 'opn-31' });
      RuleModel.findByPk.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.toggleRule.mockRejectedValue(new Error('down'));

      const res = await request(app).patch('/api/v1/firewall/rules/31/toggle').send({ enabled: false }).expect(200);
      expect(rule.update).toHaveBeenCalledWith(expect.objectContaining({ sync_status: 'failed', sync_error: 'down' }));
      expect(res.body.data.sync_status).toBe('failed');
    });

    it('404 when rule does not exist', async () => {
      RuleModel.findByPk.mockResolvedValue(null);
      await request(app).patch('/api/v1/firewall/rules/999/toggle').send({ enabled: true }).expect(404);
    });
  });

  // ----------------- DELETE /rules/:id -----------------
  describe('DELETE /api/v1/firewall/rules/:id', () => {
    it('deletes rule, tries to remove it from OPNsense too', async () => {
      const rule = makeRule({ id: 40, opnsense_uuid: 'opn-40' });
      RuleModel.findByPk.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.deleteRule.mockResolvedValue({ ok: true });

      const res = await request(app).delete('/api/v1/firewall/rules/40').expect(200);

      expect(OpnsenseServiceCtor.__methods.deleteRule).toHaveBeenCalledWith('opn-40');
      expect(rule.destroy).toHaveBeenCalled();
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.RULE_DELETE, 'warning',
        expect.objectContaining({ rule_id: 40 })
      );
      expect(res.body.success).toBe(true);
    });

    it('OPNsense delete fails → warn but delete locally', async () => {
      const rule = makeRule({ id: 41, opnsense_uuid: 'opn-41' });
      RuleModel.findByPk.mockResolvedValue(rule);
      OpnsenseServiceCtor.__methods.deleteRule.mockRejectedValue(new Error('fail'));
      const res = await request(app).delete('/api/v1/firewall/rules/41').expect(200);
      expect(rule.destroy).toHaveBeenCalled();
      expect(res.body.success).toBe(true);
    });

    it('404 when rule does not exist', async () => {
      RuleModel.findByPk.mockResolvedValue(null);
      await request(app).delete('/api/v1/firewall/rules/404').expect(404);
    });
  });

  // ----------------- PATCH /rules/bulk -----------------
  describe('PATCH /api/v1/firewall/rules/bulk', () => {
    it('executes bulk operation and audits', async () => {
      RuleServiceCtor.__methods.bulkOperation.mockResolvedValue({ updated: [1, 2, 3], operation: 'enable' });
      const res = await request(app)
        .patch('/api/v1/firewall/rules/bulk')
        .send({ rule_ids: [1, 2, 3], operation: 'enable', apply_immediately: false })
        .expect(200);

      expect(RuleServiceCtor.__methods.bulkOperation).toHaveBeenCalledWith([1, 2, 3], 'enable', false);
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.RULE_UPDATE, 'info',
        expect.objectContaining({ bulk_operation: 'enable', rule_count: 3 })
      );
      expect(res.body.data).toEqual(expect.objectContaining({ updated: [1, 2, 3] }));
    });
  });

  // ----------------- POST /rules/sync -----------------
  describe('POST /api/v1/firewall/rules/sync', () => {
    it('synchronizes pending rules', async () => {
      RuleServiceCtor.__methods.syncPendingRules.mockResolvedValue({ total: 5, synced: 4, failed: 1 });
      const res = await request(app).post('/api/v1/firewall/rules/sync').expect(200);
      expect(res.body.data).toEqual({ total: 5, synced: 4, failed: 1 });
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.SYSTEM_ACCESS, 'info',
        expect.objectContaining({ action: 'sync_rules', synced_count: 4, failed_count: 1, total_pending: 5 })
      );
    });
  });

  // ----------------- POST /apply -----------------
  describe('POST /api/v1/firewall/apply', () => {
    it('applies configuration on OPNsense and audits', async () => {
      OpnsenseServiceCtor.__methods.applyChanges.mockResolvedValue({ ok: true });
      const res = await request(app).post('/api/v1/firewall/apply').expect(200);
      expect(OpnsenseServiceCtor.__methods.applyChanges).toHaveBeenCalled();
      expect(res.body.data).toEqual(expect.objectContaining({ ok: true }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.CONFIG_CHANGE, 'critical', expect.any(Object)
      );
    });
  });

  // ----------------- GET /interfaces -----------------
  describe('GET /api/v1/firewall/interfaces', () => {
    it('returns network interfaces', async () => {
      OpnsenseServiceCtor.__methods.getInterfaces.mockResolvedValue([{ name: 'lan' }, { name: 'wan' }]);
      const res = await request(app).get('/api/v1/firewall/interfaces').expect(200);
      expect(res.body.data).toEqual([{ name: 'lan' }, { name: 'wan' }]);
    });
  });

  // ----------------- GET /stats -----------------
  describe('GET /api/v1/firewall/stats', () => {
    it('returns aggregated firewall statistics', async () => {
      // getStatistics: counts per interface/action
      RuleModel.getStatistics.mockResolvedValue([
        { interface: 'lan', action: 'pass', count: '2' },
        { interface: 'lan', action: 'block', count: '1' },
        { interface: 'wan', action: 'pass', count: '1' },
      ]);
      // total and filtered counts
      RuleModel.count.mockImplementation(async (opts) => {
        const w = opts?.where || {};
        if (w.enabled === true && w.suspended === false) return 3; // active
        if (w.sync_status === 'pending') return 2; // pending
        if (w.sync_status === 'failed') return 1; // failed
        return 6; // total
      });

      const res = await request(app).get('/api/v1/firewall/stats').expect(200);

      expect(res.body.data.rules).toEqual(
        expect.objectContaining({
          total: 6,
          active: 3,
          inactive: 3,         // total - active
          pending_sync: 2,
          failed_sync: 1,
        })
      );

      expect(res.body.data.by_interface).toEqual({
        lan: { pass: 2, block: 1 },
        wan: { pass: 1 },
      });

      expect(res.body.data.sync_status).toEqual({ pending: 2, failed: 1, synced: 6 - 2 - 1 });
    });
  });

  // ----------------- GET /rules/unused -----------------
  describe('GET /api/v1/firewall/rules/unused', () => {
    it('returns unused rules with count', async () => {
      RuleModel.findUnused.mockResolvedValue([{ id: 1 }, { id: 2 }]);
      const res = await request(app).get('/api/v1/firewall/rules/unused').expect(200);
      expect(res.body.count).toBe(2);
      expect(res.body.data[0]).toHaveProperty('id', 1);
    });
  });

  // ----------------- GET /rules/redundant -----------------
  describe('GET /api/v1/firewall/rules/redundant', () => {
    it('returns redundant rules with count', async () => {
      RuleModel.findRedundant.mockResolvedValue([{ id: 3 }]);
      const res = await request(app).get('/api/v1/firewall/rules/redundant').expect(200);
      expect(res.body.count).toBe(1);
      expect(res.body.data[0]).toHaveProperty('id', 3);
    });
  });
});