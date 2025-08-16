/**
 * Integration › routes › policies
 * Covers:
 *  - GET    /api/v1/policies
 *  - GET    /api/v1/policies/:id
 *  - POST   /api/v1/policies
 *  - PUT    /api/v1/policies/:id
 *  - POST   /api/v1/policies/:id/activate
 *  - POST   /api/v1/policies/:id/deactivate
 *  - POST   /api/v1/policies/:id/approve
 *  - DELETE /api/v1/policies/:id
 *  - GET    /api/v1/policies/stats
 *  - GET    /api/v1/policies/active
 *  - GET    /api/v1/policies/expiring
 *  - GET    /api/v1/policies/:id/export  (json + yaml)
 *  - POST   /api/v1/policies/:id/clone
 *  - GET    /api/v1/policies/:id/history
 *  - POST   /api/v1/policies/check-expiry
 *  - POST   /api/v1/policies/validate
 *  - POST   /api/v1/policies/import      (validate_only + real import/overwrite)
 *  - PATCH  /api/v1/policies/bulk        (enable/disable + delete/approve/reject)
 */

const request = require('supertest');

// ---------- logger ----------
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));

// ---------- rateLimit (no-op limiter) ----------
const createRateLimiterMock = jest.fn(() => (_req, _res, next) => next());
jest.mock('../../../src/middleware/rateLimit', () => ({
  createRateLimiter: (...a) => createRateLimiterMock(...a),
}));

// ---------- auth (authenticate/authorize/PERMISSIONS) ----------
const authenticateMock = jest.fn((req, _res, next) => {
  req.user = { id: 1, username: 'tester', email: 't@example.com', role: 'admin' };
  next();
});
const authorizeMock = jest.fn(() => (_req, _res, next) => next());
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (...a) => authenticateMock(...a),
  authorize: (...a) => authorizeMock(...a),
  PERMISSIONS: {
    POLICY_READ: 'POLICY_READ',
    POLICY_WRITE: 'POLICY_WRITE',
    POLICY_DELETE: 'POLICY_DELETE',
  },
}));

// ---------- validation (no-op, just to assert presence) ----------
const validators = {
  searchQuery: jest.fn((req, _res, next) => next()),
  idParam: jest.fn((req, _res, next) => next()),
  createPolicy: jest.fn((req, _res, next) => next()),
  updatePolicy: jest.fn((req, _res, next) => next()),
};
jest.mock('../../../src/middleware/validation', () => ({ validators }));

// ---------- audit ----------
const auditLog = jest.fn().mockResolvedValue();
const AUDITED_ACTIONS = {
  API_ACCESS: 'api_access',
  POLICY_CREATE: 'policy_create',
  POLICY_UPDATE: 'policy_update',
  POLICY_DELETE: 'policy_delete',
  SYSTEM_ACCESS: 'system_access',
};
jest.mock('../../../src/middleware/audit', () => ({
  auditLog: (...a) => auditLog(...a),
  AUDITED_ACTIONS: {
    API_ACCESS: 'api_access',
    POLICY_CREATE: 'policy_create',
    POLICY_UPDATE: 'policy_update',
    POLICY_DELETE: 'policy_delete',
    SYSTEM_ACCESS: 'system_access',
  },
}));

// ---------- services ----------
const psMethods = {
  getPolicies: jest.fn(),
  getPolicyById: jest.fn(),
  createPolicy: jest.fn(),
  updatePolicy: jest.fn(),
  deletePolicy: jest.fn(),
  exportPolicies: jest.fn(),
  clonePolicy: jest.fn(),
  validatePolicyConfiguration: jest.fn(),
  importPolicies: jest.fn(),
  bulkUpdatePolicies: jest.fn(),
};
const PolicyServiceCtor = jest.fn(() => psMethods);
PolicyServiceCtor.__methods = psMethods;
jest.mock('../../../src/services/PolicyService', () => PolicyServiceCtor);

// ---------- models ----------
const PolicyModel = {
  findAll: jest.fn(),
  findByPk: jest.fn(),
  findOne: jest.fn(),
  count: jest.fn(),
  findExpiring: jest.fn(),
  findActive: jest.fn(),
  checkExpiring: jest.fn(),
};
const RuleModel = {
  findAll: jest.fn(),
};
const AuditLogModel = {
  findAll: jest.fn(),
};
const UserModel = {}; // included via associations but not directly used

jest.mock('../../../src/models/Policy', () => PolicyModel);
jest.mock('../../../src/models/Rule', () => RuleModel);
jest.mock('../../../src/models/AuditLog', () => AuditLogModel);
jest.mock('../../../src/models/User', () => UserModel);

// ---------- yamljs (for export?format=yaml) ----------
const yamlStringifyMock = jest.fn(() => 'yaml: true\n');
jest.mock('yamljs', () => ({ stringify: (...a) => yamlStringifyMock(...a) }));

// Load Express app AFTER mocks
const app = require('../../../src/app');

// Helpers
function makePolicy(over = {}) {
  const base = {
    id: 10,
    name: 'P-Allow-SSH',
    type: 'firewall',
    rules: [1, 2],
    enabled: true,
    version: 3,
    priority: 50,
    approval_status: 'approved',
    schedule: null,
    conditions: {},
    metadata: {},
    expires_at: new Date(Date.now() + 7 * 864e5).toISOString(),
    auto_renew: false,
    createdBy: { id: 2, username: 'alice', email: 'a@example.com' },
    updatedBy: { id: 3, username: 'bob', email: 'b@example.com' },
    approver: { id: 1, username: 'tester', email: 't@example.com' },
    isActive: jest.fn(() => true),
    isInSchedule: jest.fn(() => false),
    getEffectivenessScore: jest.fn(() => 0.87),
    getNextActivation: jest.fn(() => null),
    toJSON: function () {
      const { id, name, type, rules, enabled, version, priority, approval_status, createdBy, updatedBy, approver, expires_at, auto_renew } = this;
      return { id, name, type, rules, enabled, version, priority, approval_status, createdBy, updatedBy, approver, expires_at, auto_renew };
    },
  };
  return Object.assign(base, over);
}

describe('routes › policies', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ------------- GET /api/v1/policies -------------
  describe('GET /api/v1/policies', () => {
    it('lists policies with filters + pagination and audits', async () => {
      PolicyServiceCtor.__methods.getPolicies.mockResolvedValue({
        data: [{ id: 1 }, { id: 2 }, { id: 3 }],
        pagination: { total: 3, page: 2, limit: 3, total_pages: 1 },
      });

      const pList = [makePolicy({ id: 1 }), makePolicy({ id: 2 }), makePolicy({ id: 3 })];
      PolicyModel.findAll.mockResolvedValue(pList);

      const res = await request(app)
        .get('/api/v1/policies')
        .query({ page: 2, limit: 3, search: 'ssh', type: 'firewall', enabled: 'true', approval_status: 'approved', created_by: '2' })
        .expect(200);

      expect(PolicyServiceCtor).toHaveBeenCalledWith(expect.objectContaining({ id: 1 })); // constructed with req.user
      expect(PolicyServiceCtor.__methods.getPolicies).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'ssh', type: 'firewall', enabled: true, approval_status: 'approved', created_by: 2 }),
        { page: 2, limit: 3 }
      );
      expect(PolicyModel.findAll).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({ id: expect.any(Object) }),
        include: expect.any(Array),
      }));
      expect(res.body.data).toHaveLength(3);
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.API_ACCESS, 'info',
        expect.objectContaining({ action: 'list_policies', count: 3 })
      );
    });
  });

  // ------------- GET /api/v1/policies/:id -------------
  describe('GET /api/v1/policies/:id', () => {
    it('returns policy with associated rules and user joins', async () => {
      PolicyServiceCtor.__methods.getPolicyById.mockResolvedValue(makePolicy({ id: 7 }));
      const base = makePolicy({ id: 7, rules: [11, 12] });
      PolicyModel.findByPk.mockResolvedValue(base);
      RuleModel.findAll.mockResolvedValue([
        { id: 11, description: 'r1', interface: 'lan', action: 'pass', enabled: true },
        { id: 12, description: 'r2', interface: 'wan', action: 'block', enabled: false },
      ]);

      const res = await request(app).get('/api/v1/policies/7').expect(200);
      expect(PolicyServiceCtor.__methods.getPolicyById).toHaveBeenCalledWith(7);
      expect(RuleModel.findAll).toHaveBeenCalled();
      expect(res.body.data).toEqual(expect.objectContaining({
        id: 7,
        associated_rules: expect.arrayContaining([expect.objectContaining({ id: 11 })]),
      }));
    });

    it('404 when not found (service)', async () => {
      PolicyServiceCtor.__methods.getPolicyById.mockResolvedValue(null);
      await request(app).get('/api/v1/policies/404').expect(404);
    });

    it('404 when not found (re-fetch include)', async () => {
      PolicyServiceCtor.__methods.getPolicyById.mockResolvedValue({ id: 8 });
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).get('/api/v1/policies/8').expect(404);
    });
  });

  // ------------- POST /api/v1/policies -------------
  describe('POST /api/v1/policies', () => {
    it('creates policy (unique name & valid rules) and audits', async () => {
      PolicyModel.findOne.mockResolvedValue(null); // no duplicate
      RuleModel.findAll.mockResolvedValue([{ id: 1 }, { id: 2 }]); // all exist
      PolicyServiceCtor.__methods.createPolicy.mockResolvedValue({ id: 99, name: 'P-NEW', rules: [1, 2] });
      PolicyModel.findByPk.mockResolvedValue(makePolicy({ id: 99, name: 'P-NEW' }));

      const res = await request(app)
        .post('/api/v1/policies')
        .send({ name: 'P-NEW', type: 'firewall', rules: [1, 2], enabled: true })
        .expect(201);

      expect(PolicyModel.findOne).toHaveBeenCalledWith(expect.objectContaining({ where: { name: 'P-NEW' } }));
      expect(PolicyServiceCtor.__methods.createPolicy).toHaveBeenCalled();
      expect(res.body.data).toEqual(expect.objectContaining({ id: 99, name: 'P-NEW' }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.POLICY_CREATE, 'info', expect.objectContaining({ policy_id: 99 })
      );
    });

    it('409 when name already exists', async () => {
      PolicyModel.findOne.mockResolvedValue({ id: 1, name: 'dup' });
      const r = await request(app).post('/api/v1/policies').send({ name: 'dup', type: 'firewall', rules: [] }).expect(409);
      expect(String(r.body.message || r.text)).toMatch(/already exists/i);
    });

    it('400 when some referenced rules are missing', async () => {
      PolicyModel.findOne.mockResolvedValue(null);
      RuleModel.findAll.mockResolvedValue([{ id: 1 }]); // missing #2
      await request(app).post('/api/v1/policies').send({ name: 'X', type: 'firewall', rules: [1, 2] }).expect(400);
    });
  });

  // ------------- PUT /api/v1/policies/:id -------------
  describe('PUT /api/v1/policies/:id', () => {
    it('updates policy; uniqueness and rules validated; audits', async () => {
      const existing = makePolicy({ id: 7, name: 'Old' });
      PolicyModel.findByPk.mockResolvedValueOnce(existing); // for existence check
      PolicyModel.findOne.mockResolvedValue(null);          // name free
      RuleModel.findAll.mockResolvedValue([{ id: 1 }, { id: 2 }]);
      PolicyServiceCtor.__methods.updatePolicy.mockResolvedValue({ id: 7, name: 'New' });
      PolicyModel.findByPk.mockResolvedValueOnce(makePolicy({ id: 7, name: 'New' })); // reload with users

      const res = await request(app)
        .put('/api/v1/policies/7')
        .send({ name: 'New', rules: [1, 2], priority: 60 })
        .expect(200);

      expect(PolicyModel.findOne).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({ name: 'New', id: expect.any(Object) }),
      }));
      expect(PolicyServiceCtor.__methods.updatePolicy).toHaveBeenCalledWith(7, expect.objectContaining({ name: 'New' }));
      expect(res.body.data).toEqual(expect.objectContaining({ id: 7, name: 'New' }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.POLICY_UPDATE, 'info', expect.objectContaining({ policy_id: 7 })
      );
    });

    it('400 when rules array references missing rules', async () => {
      PolicyModel.findByPk.mockResolvedValue(makePolicy({ id: 8 }));
      RuleModel.findAll.mockResolvedValue([{ id: 1 }]); // missing id 2
      await request(app).put('/api/v1/policies/8').send({ rules: [1, 2] }).expect(400);
    });

    it('404 when policy not found', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).put('/api/v1/policies/404').send({}).expect(404);
    });
  });

  // ------------- POST /api/v1/policies/:id/activate -------------
  describe('POST /api/v1/policies/:id/activate', () => {
    it('activates policy when approved', async () => {
      PolicyModel.findByPk.mockResolvedValueOnce(makePolicy({ id: 5, approval_status: 'approved', enabled: false }));
      PolicyServiceCtor.__methods.updatePolicy.mockResolvedValue({ id: 5 });
      PolicyModel.findByPk.mockResolvedValueOnce(makePolicy({ id: 5, enabled: true }));

      const res = await request(app).post('/api/v1/policies/5/activate').send({}).expect(200);
      expect(res.body.data).toEqual(expect.objectContaining({ id: 5, enabled: true }));
    });

    it('400 when not approved yet', async () => {
      PolicyModel.findByPk.mockResolvedValue(makePolicy({ id: 6, approval_status: 'pending_approval' }));
      const r = await request(app).post('/api/v1/policies/6/activate').send({}).expect(400);
      expect(String(r.body.message || r.text)).toMatch(/approved/i);
    });

    it('404 when policy not found', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).post('/api/v1/policies/404/activate').expect(404);
    });
  });

  // ------------- POST /api/v1/policies/:id/deactivate -------------
  describe('POST /api/v1/policies/:id/deactivate', () => {
    it('deactivates policy', async () => {
      PolicyModel.findByPk.mockResolvedValueOnce(makePolicy({ id: 9, enabled: true }));
      PolicyServiceCtor.__methods.updatePolicy.mockResolvedValue({ id: 9 });
      PolicyModel.findByPk.mockResolvedValueOnce(makePolicy({ id: 9, enabled: false }));

      const res = await request(app).post('/api/v1/policies/9/deactivate').send({}).expect(200);
      expect(res.body.data.enabled).toBe(false);
    });

    it('404 when policy not found', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).post('/api/v1/policies/404/deactivate').expect(404);
    });
  });

  // ------------- POST /api/v1/policies/:id/approve -------------
  describe('POST /api/v1/policies/:id/approve', () => {
    it('403 when user is not admin', async () => {
      authenticateMock.mockImplementationOnce((req, _res, next) => {
        req.user = { id: 2, username: 'op', role: 'viewer' };
        next();
      });
      await request(app).post('/api/v1/policies/1/approve').send({ comments: 'ok' }).expect(403);
    });

    it('approves policy when admin and not already approved', async () => {
      const p = makePolicy({ id: 12, approval_status: 'pending_approval' });
      PolicyModel.findByPk.mockResolvedValueOnce(p); // pre fetch
      PolicyServiceCtor.__methods.updatePolicy.mockResolvedValue({ id: 12 });
      PolicyModel.findByPk.mockResolvedValueOnce(makePolicy({ id: 12, approval_status: 'approved' })); // reload

      const res = await request(app).post('/api/v1/policies/12/approve').send({ comments: 'LGTM' }).expect(200);
      expect(res.body.data.approval_status).toBe('approved');
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.POLICY_UPDATE, 'info', expect.objectContaining({ action: 'approve' })
      );
    });

    it('400 when already approved', async () => {
      PolicyModel.findByPk.mockResolvedValue(makePolicy({ id: 13, approval_status: 'approved' }));
      await request(app).post('/api/v1/policies/13/approve').send({}).expect(400);
    });

    it('404 when not found', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).post('/api/v1/policies/404/approve').send({}).expect(404);
    });
  });

  // ------------- DELETE /api/v1/policies/:id -------------
  describe('DELETE /api/v1/policies/:id', () => {
    it('deletes existing policy and audits', async () => {
      PolicyModel.findByPk.mockResolvedValue(makePolicy({ id: 15 }));
      PolicyServiceCtor.__methods.deletePolicy.mockResolvedValue(true);

      const res = await request(app).delete('/api/v1/policies/15').expect(200);
      expect(PolicyServiceCtor.__methods.deletePolicy).toHaveBeenCalledWith(15);
      expect(res.body.success).toBe(true);
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.POLICY_DELETE, 'warning', expect.any(Object)
      );
    });

    it('404 when policy not found', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).delete('/api/v1/policies/404').expect(404);
    });
  });

  // ------------- GET /api/v1/policies/stats -------------
  describe('GET /api/v1/policies/stats', () => {
    it('returns totals, by_type and expiring list', async () => {
      // First findAll (aggregates) -> single row with raw numbers as strings
      PolicyModel.findAll
        .mockResolvedValueOnce([{ total: '10', enabled: '7', approved: '6', pending_approval: '2' }])
        // Second findAll (by_type)
        .mockResolvedValueOnce([
          { type: 'firewall', count: '6' },
          { type: 'network', count: '4' },
        ]);
      PolicyModel.findExpiring.mockResolvedValue([
        makePolicy({ id: 21, name: 'Soon1', expires_at: new Date(Date.now() + 2 * 864e5).toISOString() }),
        makePolicy({ id: 22, name: 'Soon2', expires_at: new Date(Date.now() + 4 * 864e5).toISOString() }),
      ]);

      const res = await request(app).get('/api/v1/policies/stats').expect(200);

      expect(res.body.data.totals).toEqual(
        expect.objectContaining({ total: 10, active: 7, inactive: 3, approved: 6, pending_approval: 2, expiring_soon: 2 })
      );
      expect(res.body.data.by_type).toEqual({ firewall: 6, network: 4 });
      expect(res.body.data.expiring_policies.length).toBe(2);
    });
  });

  // ------------- GET /api/v1/policies/active -------------
  describe('GET /api/v1/policies/active', () => {
    it('returns active policies with computed flags', async () => {
      PolicyModel.findActive.mockResolvedValue([makePolicy({ id: 31 }), makePolicy({ id: 32 })]);

      const res = await request(app).get('/api/v1/policies/active').expect(200);
      expect(res.body.count).toBe(2);
      expect(res.body.data[0]).toHaveProperty('is_in_schedule', false);
      expect(res.body.data[0]).toHaveProperty('effectiveness_score', 0.87);
    });
  });

  // ------------- GET /api/v1/policies/expiring -------------
  describe('GET /api/v1/policies/expiring', () => {
    it('returns expiring policies and metadata', async () => {
      PolicyModel.findExpiring.mockResolvedValue([
        makePolicy({ id: 41, name: 'E1', auto_renew: true,  expires_at: new Date(Date.now() + 3 * 864e5).toISOString() }),
        makePolicy({ id: 42, name: 'E2', auto_renew: false, expires_at: new Date(Date.now() + 5 * 864e5).toISOString() }),
      ]);

      const res = await request(app).get('/api/v1/policies/expiring').query({ days: 7 }).expect(200);
      expect(PolicyModel.findExpiring).toHaveBeenCalledWith(7, expect.any(Object));
      expect(res.body.data.length).toBe(2);
      expect(res.body.metadata.auto_renewable).toBe(1);
    });
  });

  // ------------- GET /api/v1/policies/:id/export -------------
  describe('GET /api/v1/policies/:id/export', () => {
    it('exports as JSON (default) with filtered payload', async () => {
      const p = makePolicy({ id: 50, name: 'ExportMe' });
      PolicyModel.findByPk.mockResolvedValue(p);
      PolicyServiceCtor.__methods.exportPolicies.mockResolvedValue({
        export_metadata: { total: 2, generated_at: 't' },
        policies: [{ name: 'ExportMe' }, { name: 'Other' }],
      });

      const res = await request(app).get('/api/v1/policies/50/export').expect(200);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.body.data.policies).toEqual([{ name: 'ExportMe' }]);
    });

    it('exports as YAML when format=yaml', async () => {
      const p = makePolicy({ id: 51, name: 'YAMLMe' });
      PolicyModel.findByPk.mockResolvedValue(p);
      PolicyServiceCtor.__methods.exportPolicies.mockResolvedValue({
        export_metadata: { total: 1 },
        policies: [{ name: 'YAMLMe' }],
      });

      const res = await request(app).get('/api/v1/policies/51/export').query({ format: 'yaml' }).expect(200);
      expect(res.headers['content-type']).toMatch(/application\/x-yaml/);
      expect(res.text).toContain('yaml:');
      expect(yamlStringifyMock).toHaveBeenCalled();
    });

    it('404 when policy not found', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).get('/api/v1/policies/404/export').expect(404);
    });
  });

  // ------------- POST /api/v1/policies/:id/clone -------------
  describe('POST /api/v1/policies/:id/clone', () => {
    it('400 when new_name is missing', async () => {
      await request(app).post('/api/v1/policies/60/clone').send({}).expect(400);
    });

    it('clones policy (copy_rules=true), returns 201 and audits', async () => {
      const src = makePolicy({ id: 60, name: 'SRC', rules: [1, 2], priority: 10 });
      PolicyModel.findByPk.mockResolvedValueOnce(src);
      PolicyServiceCtor.__methods.clonePolicy.mockResolvedValue({ id: 61 });
      PolicyModel.findByPk.mockResolvedValueOnce(makePolicy({ id: 61, name: 'CLONED', rules: [1, 2] }));

      const res = await request(app).post('/api/v1/policies/60/clone').send({ new_name: 'CLONED', copy_rules: true }).expect(201);
      expect(PolicyServiceCtor.__methods.clonePolicy).toHaveBeenCalledWith(60, expect.objectContaining({ name: 'CLONED' }));
      expect(res.body.data).toEqual(expect.objectContaining({ name: 'CLONED', source_policy: { id: 60, name: 'SRC' } }));
    });

    it('404 when source policy does not exist', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).post('/api/v1/policies/404/clone').send({ new_name: 'X' }).expect(404);
    });
  });

  // ------------- GET /api/v1/policies/:id/history -------------
  describe('GET /api/v1/policies/:id/history', () => {
    it('returns change history limited to 50', async () => {
      PolicyModel.findByPk.mockResolvedValue(makePolicy({ id: 70 }));
      AuditLogModel.findAll.mockResolvedValue([{ audit_id: 'a1' }, { audit_id: 'a2' }]);

      const res = await request(app).get('/api/v1/policies/70/history').expect(200);
      expect(AuditLogModel.findAll).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({ related_entity_type: 'policy', related_entity_id: '70' }),
        limit: 50,
      }));
      expect(res.body.data.history.length).toBe(2);
    });

    it('404 when policy not found', async () => {
      PolicyModel.findByPk.mockResolvedValue(null);
      await request(app).get('/api/v1/policies/404/history').expect(404);
    });
  });

  // ------------- POST /api/v1/policies/check-expiry -------------
  describe('POST /api/v1/policies/check-expiry', () => {
    it('returns expiring summary and audits', async () => {
      PolicyModel.checkExpiring.mockResolvedValue([
        makePolicy({ id: 80, name: 'A', auto_renew: true }),
        makePolicy({ id: 81, name: 'B', auto_renew: false }),
      ]);

      const res = await request(app).post('/api/v1/policies/check-expiry').expect(200);
      expect(res.body.data).toEqual(expect.objectContaining({
        expiring_policies: 2,
        auto_renewed: 1,
        requires_attention: 1,
      }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.SYSTEM_ACCESS, 'info',
        expect.objectContaining({ action: 'check_policy_expiry', expiring_count: 2 })
      );
    });
  });

  // ------------- POST /api/v1/policies/validate -------------
  describe('POST /api/v1/policies/validate', () => {
    it('detects duplicate name and disabled rules; merges service validation', async () => {
      PolicyModel.findOne.mockResolvedValue({ id: 1, name: 'dup' }); // duplicate name
      RuleModel.findAll.mockResolvedValue([{ id: 1, enabled: false }]); // one disabled, but total mismatch triggers additional error
      PolicyServiceCtor.__methods.validatePolicyConfiguration.mockResolvedValue({
        valid: false,
        errors: ['type invalid'],
        warnings: ['priority low'],
        suggestions: ['consider schedule'],
      });

      const res = await request(app)
        .post('/api/v1/policies/validate')
        .send({ name: 'dup', type: 'firewall', rules: [1, 2], configuration: {} })
        .expect(200);

      expect(res.body.success).toBe(false);
      expect(res.body.data.errors.join(' ')).toMatch(/already exists/i);
      expect(res.body.data.warnings.join(' ')).toMatch(/disabled/i);
      expect(res.body.data.suggestions).toContain('consider schedule');
    });

    it('valid configuration path', async () => {
      PolicyModel.findOne.mockResolvedValue(null);
      RuleModel.findAll.mockResolvedValue([{ id: 1, enabled: true }]);
      PolicyServiceCtor.__methods.validatePolicyConfiguration.mockResolvedValue({
        valid: true, errors: [], warnings: [], suggestions: [],
      });

      const res = await request(app).post('/api/v1/policies/validate').send({ name: 'ok', rules: [1] }).expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.is_valid).toBe(true);
    });
  });

  // ------------- POST /api/v1/policies/import -------------
  describe('POST /api/v1/policies/import', () => {
    it('400 when policy_data missing', async () => {
      await request(app).post('/api/v1/policies/import').send({}).expect(400);
    });

    it('validate_only=true returns validation status without creating', async () => {
      PolicyModel.findOne.mockResolvedValue(null);
      RuleModel.findAll.mockResolvedValue([{ id: 1 }]);

      const res = await request(app)
        .post('/api/v1/policies/import')
        .send({ validate_only: true, policy_data: { name: 'P', type: 'firewall', rules: [1] } })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.is_valid).toBe(true);
    });

    it('validate_only=false with errors -> 400 ValidationError', async () => {
      // Missing rules triggers error
      const r = await request(app)
        .post('/api/v1/policies/import')
        .send({ validate_only: false, policy_data: { name: 'X', type: 'firewall', rules: [] } })
        .expect(400);
      expect(String(r.body.message || r.text)).toMatch(/validation failed/i);
    });

    it('imports successfully and audits (overwrite path)', async () => {
      PolicyModel.findOne.mockResolvedValue({ id: 10, name: 'P' }); // existing -> overwrite allowed
      RuleModel.findAll.mockResolvedValue([{ id: 1 }]);
      PolicyServiceCtor.__methods.importPolicies.mockResolvedValue({
        imported_policies: [{ id: 123, name: 'P' }],
      });

      const res = await request(app)
        .post('/api/v1/policies/import')
        .send({ policy_data: { name: 'P', type: 'firewall', rules: [1] }, overwrite: true })
        .expect(201);

      expect(res.body.data).toEqual(expect.objectContaining({ id: 123, name: 'P', overwritten: true }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.POLICY_CREATE, 'info',
        expect.objectContaining({ action: 'import_policy', overwrite: true })
      );
    });
  });

  // ------------- PATCH /api/v1/policies/bulk -------------
  describe('PATCH /api/v1/policies/bulk', () => {
    it('400 when ids missing/too many or invalid operation', async () => {
      await request(app).patch('/api/v1/policies/bulk').send({}).expect(400);
      await request(app).patch('/api/v1/policies/bulk').send({ policy_ids: Array.from({ length: 51 }, (_, i) => i + 1), operation: 'enable' }).expect(400);
      await request(app).patch('/api/v1/policies/bulk').send({ policy_ids: [1], operation: 'nope' }).expect(400);
    });

    it('403 approve/reject when not admin', async () => {
      authenticateMock.mockImplementationOnce((req, _res, next) => {
        req.user = { id: 5, username: 'viewer', role: 'viewer' };
        next();
      });
      await request(app).patch('/api/v1/policies/bulk').send({ policy_ids: [1], operation: 'approve' }).expect(403);
    });

    it('enable operation uses bulkUpdatePolicies and audits', async () => {
      PolicyServiceCtor.__methods.bulkUpdatePolicies.mockResolvedValue({ updated_count: 3 });
      const res = await request(app).patch('/api/v1/policies/bulk').send({ policy_ids: [1, 2, 3], operation: 'enable' }).expect(200);

      expect(PolicyServiceCtor.__methods.bulkUpdatePolicies).toHaveBeenCalledWith([1, 2, 3], { enabled: true });
      expect(res.body.data).toEqual(expect.objectContaining({ successful: 3, failed: 0 }));
      expect(auditLog).toHaveBeenCalledWith(
        expect.any(Object), AUDITED_ACTIONS.POLICY_UPDATE, 'info',
        expect.objectContaining({ bulk_operation: 'enable', policy_count: 3, successful: 3, failed: 0 })
      );
    });

    it('delete/approve/reject loop handles successes and failures', async () => {
      // delete path with one failing id
      PolicyServiceCtor.__methods.deletePolicy.mockResolvedValueOnce(true);  // id 7
      PolicyServiceCtor.__methods.deletePolicy.mockRejectedValueOnce(new Error('nope')); // id 8 fails
      PolicyServiceCtor.__methods.deletePolicy.mockResolvedValueOnce(true);  // id 9
      PolicyModel.findByPk.mockResolvedValue({ id: 8, name: 'P8' }); // for error details

      const res = await request(app).patch('/api/v1/policies/bulk').send({ policy_ids: [7, 8, 9], operation: 'delete' }).expect(200);

      expect(res.body.data.successful).toBe(2);
      expect(res.body.data.failed).toBe(1);
      expect(res.body.data.errors[0]).toEqual(expect.objectContaining({ policy_id: 8, policy_name: 'P8' }));
    });
  });
});
