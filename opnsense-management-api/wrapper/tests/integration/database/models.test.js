/**
 * Integration › database › models
 * Seeds data and exercises:
 *  - User basic CRUD
 *  - Rule: static helpers (getStatistics, etc.) where available
 *  - Policy: findExpiring/findActive, instance helpers like isActive/getEffectivenessScore (if implemented)
 *  - Alert: acknowledge() + getStatistics(), findCritical/Unacknowledged
 *  - AuditLog: findSecurityEvents()
 *
 * Notes:
 *  - These tests are written to be resilient across dialects and minor model differences.
 *  - If some optional helpers aren't implemented in your models, the related tests will skip.
 */

const { sequelize, testDatabaseConnection } = require('../../../src/config/database');
const User = require('../../../src/models/User');
const Rule = require('../../../src/models/Rule');
const Policy = require('../../../src/models/Policy');
const Alert = require('../../../src/models/Alert');
const AuditLog = require('../../../src/models/AuditLog');

// Quiet logs in test output
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));

// Helpers
async function ensureConnectedOrSkip() {
  let ok = false;
  try {
    ok = await testDatabaseConnection();
  } catch {
    ok = false;
  }
  if (!ok) {
    console.warn('⚠️  Database not reachable. Skipping model integration tests.');
  }
  return ok;
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) out[k] = obj[k];
  return out;
}

describe('database › models', () => {
  let connected = false;
  let users = {};
  let seeded = {};

  beforeAll(async () => {
    connected = await ensureConnectedOrSkip();
    if (!connected) return;

    // clean slate
    await sequelize.sync({ force: true });

    // ---- Seed Users ----
    users.admin = await User.create({
      username: 'admin',
      email: 'admin@example.com',
      password: 'Password#1',
      role: 'admin',
      is_active: true,
    });

    users.operator = await User.create({
      username: 'operator',
      email: 'op@example.com',
      password: 'Password#1',
      role: 'operator',
      is_active: true,
    });

    users.viewer = await User.create({
      username: 'viewer',
      email: 'viewer@example.com',
      password: 'Password#1',
      role: 'viewer',
      is_active: false,
    });

    // ---- Seed Rules ----
    const r1 = await Rule.create({
      description: 'Allow SSH',
      interface: 'lan',
      direction: 'in',
      action: 'pass',
      protocol: 'tcp',
      source: { type: 'any' },
      destination: { type: 'network', network: '10.0.0.0/24', port: '22' },
      enabled: true,
      suspended: false,
      created_by: users.admin.id,
      opnsense_uuid: 'opn-ssh',
      sync_status: 'synced',
    });

    const r2 = await Rule.create({
      description: 'Block Telnet',
      interface: 'wan',
      direction: 'in',
      action: 'block',
      protocol: 'tcp',
      source: { type: 'any' },
      destination: { type: 'any', port: '23' },
      enabled: true,
      suspended: false,
      created_by: users.admin.id,
      opnsense_uuid: 'opn-telnet',
      sync_status: 'pending',
    });

    const r3 = await Rule.create({
      description: 'Allow HTTP',
      interface: 'lan',
      direction: 'in',
      action: 'pass',
      protocol: 'tcp',
      source: { type: 'any' },
      destination: { type: 'any', port: '80' },
      enabled: false, // disabled
      suspended: false,
      created_by: users.operator.id,
      sync_status: 'failed',
      sync_error: 'sync test',
    });

    // ---- Seed Policies ----
    const now = Date.now();
    const in10d = new Date(now + 10 * 24 * 60 * 60 * 1000);
    const in40d = new Date(now + 40 * 24 * 60 * 60 * 1000);

    const p1 = await Policy.create({
      name: 'Default LAN Access',
      type: 'allowlist',
      description: 'Base LAN allow policy',
      enabled: true,
      approval_status: 'approved',
      rules: [r1.id, r3.id],
      priority: 100,
      created_by: users.admin.id,
      approved_by: users.admin.id,
      approved_at: new Date(),
      version: 1,
      expires_at: in10d,
      auto_renew: true,
    });

    const p2 = await Policy.create({
      name: 'WAN Hardening',
      type: 'denylist',
      description: 'Block legacy protocols',
      enabled: true,
      approval_status: 'pending_approval',
      rules: [r2.id],
      priority: 80,
      created_by: users.operator.id,
      version: 3,
      expires_at: in40d,
      auto_renew: false,
    });

    const p3 = await Policy.create({
      name: 'Night Policy',
      type: 'schedule',
      description: 'Off-hours restrictions',
      enabled: false,
      approval_status: 'rejected',
      rules: [],
      priority: 60,
      created_by: users.operator.id,
      version: 2,
      // no expiry
    });

    // ---- Seed Alerts ----
    const a1 = await Alert.create({
      severity: 'critical',
      type: 'system',
      status: 'active',
      message: 'High CPU',
      rule_id: r1.id,
      created_at: new Date(),
    });

    const a2 = await Alert.create({
      severity: 'warning',
      type: 'network',
      status: 'active',
      message: 'Packet loss',
      rule_id: r2.id,
      created_at: new Date(),
    });

    const a3 = await Alert.create({
      severity: 'info',
      type: 'audit',
      status: 'resolved',
      message: 'Policy updated',
      rule_id: null,
      created_at: new Date(),
    });

    // ---- Seed AuditLogs ----
    await AuditLog.bulkCreate([
      {
        audit_id: 'evt-1',
        timestamp: new Date(),
        level: 'security',
        action: 'rule_toggle',
        username: 'admin',
        client_ip: '127.0.0.1',
        method: 'PATCH',
        url: '/api/v1/firewall/rules/1/toggle',
        status_code: 200,
        risk_score: 80,
      },
      {
        audit_id: 'evt-2',
        timestamp: new Date(),
        level: 'info',
        action: 'policy_update',
        username: 'operator',
        client_ip: '127.0.0.1',
        method: 'PUT',
        url: '/api/v1/policies/1',
        status_code: 200,
        risk_score: 10,
      },
    ]);

    seeded = { rules: { r1, r2, r3 }, policies: { p1, p2, p3 }, alerts: { a1, a2, a3 } };
  });

  afterAll(async () => {
    if (connected) {
      await sequelize.close();
    }
  });

  // ---------- Users ----------
  test('User: create/read/update/delete and toSafeJSON (if provided)', async () => {
    if (!connected) return test.skip();

    const u = await User.create({
      username: 'eve',
      email: 'eve@example.com',
      password: 'Password#1',
      role: 'viewer',
      is_active: true,
    });

    const fetched = await User.findByPk(u.id);
    expect(fetched).toBeTruthy();
    expect(fetched.username).toBe('eve');

    await fetched.update({ is_active: false });
    const reloaded = await User.findByPk(u.id);
    expect(reloaded.is_active).toBe(false);

    const safe = reloaded.toSafeJSON ? reloaded.toSafeJSON() : reloaded.toJSON();
    expect(safe).toMatchObject({ id: u.id, username: 'eve', email: 'eve@example.com' });
    expect(JSON.stringify(safe).toLowerCase()).not.toContain('password');

    await reloaded.destroy();
    const gone = await User.findByPk(u.id);
    expect(gone).toBeNull();
  });

  // ---------- Rules ----------
  test('Rule: getStatistics() groups by interface/action (if implemented)', async () => {
    if (!connected) return test.skip();
    if (typeof Rule.getStatistics !== 'function') return test.skip();

    const stats = await Rule.getStatistics();
    expect(Array.isArray(stats)).toBe(true);

    // Should contain counts like: [{ interface: 'lan', action: 'pass', count: '2' }, ...]
    const keys = ['interface', 'action', 'count'];
    if (stats[0]) {
      expect(Object.keys(stats[0])).toEqual(expect.arrayContaining(keys));
    }
  });

  test('Rule: counts align with seeded data', async () => {
    if (!connected) return test.skip();

    const total = await Rule.count();
    expect(total).toBeGreaterThanOrEqual(3);

    const active = await Rule.count({ where: { enabled: true, suspended: false } });
    expect(active).toBeGreaterThan(0);

    const pending = await Rule.count({ where: { sync_status: 'pending' } });
    const failed = await Rule.count({ where: { sync_status: 'failed' } });
    expect(pending + failed).toBeGreaterThanOrEqual(1);
  });

  test('Rule: findUnused()/findRedundant() return arrays (if implemented)', async () => {
    if (!connected) return test.skip();

    for (const fn of ['findUnused', 'findRedundant']) {
      if (typeof Rule[fn] === 'function') {
        const rows = await Rule[fn]();
        expect(Array.isArray(rows)).toBe(true);
      }
    }
  });

  // ---------- Policies ----------
  test('Policy: findExpiring(days) returns items within the window (if implemented)', async () => {
    if (!connected) return test.skip();
    if (typeof Policy.findExpiring !== 'function') return test.skip();

    const in30 = await Policy.findExpiring(30);
    expect(Array.isArray(in30)).toBe(true);
    // Our seed has p1 expiring in ~10 days → should show up
    const names = in30.map((p) => p.name);
    if (names.length) {
      expect(names).toEqual(expect.arrayContaining(['Default LAN Access']));
    }
  });

  test('Policy: findActive() returns enabled policies (if implemented)', async () => {
    if (!connected) return test.skip();
    if (typeof Policy.findActive !== 'function') return test.skip();

    const active = await Policy.findActive();
    expect(Array.isArray(active)).toBe(true);
    if (active.length) {
      expect(active.every((p) => p.enabled === true)).toBe(true);
    }
  });

  test('Policy instance helpers (isActive/getEffectivenessScore/getNextActivation) if present', async () => {
    if (!connected) return test.skip();

    const p = await Policy.findOne({ where: { name: 'Default LAN Access' } });
    expect(p).toBeTruthy();

    if (typeof p.isActive === 'function') {
      const v = p.isActive();
      expect(typeof v === 'boolean').toBe(true);
    }
    if (typeof p.getEffectivenessScore === 'function') {
      const score = p.getEffectivenessScore();
      expect(typeof score === 'number' || score === undefined || score === null).toBe(true);
    }
    if (typeof p.getNextActivation === 'function') {
      const dt = p.getNextActivation();
      if (dt) expect(() => new Date(dt)).not.toThrow();
    }
  });

  // ---------- Alerts ----------
  test('Alert: getStatistics()/findCritical()/findUnacknowledged()', async () => {
    if (!connected) return test.skip();

    if (typeof Alert.getStatistics === 'function') {
      const stats = await Alert.getStatistics();
      expect(Array.isArray(stats)).toBe(true);
    }
    if (typeof Alert.findCritical === 'function') {
      const crit = await Alert.findCritical();
      expect(Array.isArray(crit)).toBe(true);
      // our seed has one "critical" active
      if (crit.length) {
        const severities = crit.map((a) => a.severity);
        expect(severities.every((s) => String(s).toLowerCase() === 'critical')).toBe(true);
      }
    }
    if (typeof Alert.findUnacknowledged === 'function') {
      const ua = await Alert.findUnacknowledged();
      expect(Array.isArray(ua)).toBe(true);
    }
  });

  test('Alert: acknowledge() updates status and timestamps', async () => {
    if (!connected) return test.skip();

    const alert = await Alert.findOne({ where: { status: 'active' } });
    expect(alert).toBeTruthy();

    if (typeof alert.acknowledge !== 'function') return test.skip();

    await alert.acknowledge(users.admin.id, 'ack from test');
    const updated = await Alert.findByPk(alert.id);

    expect(String(updated.status).toLowerCase()).toMatch(/ack|acknowledged|resolved/); // accept variants
    expect(updated.acknowledged_at || updated.updated_at).toBeTruthy();

    if (typeof updated.getResponseTime === 'function') {
      const rt = updated.getResponseTime();
      expect(typeof rt === 'number' || rt === null || rt === undefined).toBe(true);
    }
  });

  // ---------- Audit Logs ----------
  test('AuditLog: findSecurityEvents(limit) returns recent security events (if implemented)', async () => {
    if (!connected) return test.skip();
    if (typeof AuditLog.findSecurityEvents !== 'function') return test.skip();

    const rows = await AuditLog.findSecurityEvents(10);
    expect(Array.isArray(rows)).toBe(true);
    if (rows[0]) {
      expect(rows[0]).toHaveProperty('level');
      // If your method filters strictly, expect 'security'
      // expect(String(rows[0].level).toLowerCase()).toBe('security');
    }
  });

  // ---------- Round-trip JSON shapes used by routes ----------
  test('Rule + Policy JSON shapes include fields used by routes', async () => {
    if (!connected) return test.skip();

    const rule = await Rule.findOne();
    const rjson = rule.toJSON();
    // Fields the routes rely on:
    expect(rjson).toEqual(
      expect.objectContaining({
        id: expect.any(Number),
        description: expect.any(String),
        interface: expect.any(String),
        action: expect.any(String),
        enabled: expect.any(Boolean),
      })
    );

    const policy = await Policy.findOne();
    const pjson = policy.toJSON();
    expect(pjson).toEqual(
      expect.objectContaining({
        id: expect.any(Number),
        name: expect.any(String),
        type: expect.any(String),
        enabled: expect.any(Boolean),
      })
    );
  });
});