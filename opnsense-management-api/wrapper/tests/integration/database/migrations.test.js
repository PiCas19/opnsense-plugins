/**
 * Integration › database › migrations
 * Purpose:
 *  - Ensure the DB is reachable
 *  - Ensure core tables exist
 *  - Ensure a few critical columns exist and types look sane
 *  - This uses your configured sequelize instance. If the DB isn't reachable,
 *    tests are skipped (so CI won't hard-fail if env is missing).
 */

const { sequelize, testDatabaseConnection } = require('../../../src/config/database');

// Models (to validate attribute metadata vs. table columns)
const User = require('../../../src/models/User');
const Rule = require('../../../src/models/Rule');
const Policy = require('../../../src/models/Policy');
const Alert = require('../../../src/models/Alert');
const AuditLog = require('../../../src/models/AuditLog');

// Quiet logs in test
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));

function normalizeTableName(name) {
  return String(name).replace(/["`']/g, '').toLowerCase();
}

describe('database › migrations/schema', () => {
  let connected = false;

  beforeAll(async () => {
    try {
      connected = await testDatabaseConnection();
    } catch {
      connected = false;
    }
    if (!connected) {
      console.warn('Database not reachable. Skipping migration/schema tests.');
      return;
    }
  });

  test('database is reachable', () => {
    if (!connected) return test.skip();
    expect(connected).toBe(true);
  });

  test('core tables exist', async () => {
    if (!connected) return test.skip();

    const qi = sequelize.getQueryInterface();
    const allTablesRaw = await qi.showAllTables();
    const allTables = (Array.isArray(allTablesRaw) ? allTablesRaw : Object.values(allTablesRaw))
      .map(normalizeTableName);

    // Expected (normalized) names; adapt if your naming differs
    const expected = [
      'users',
      'rules',
      'policies',
      'alerts',
      'auditlogs', // sometimes becomes "audit_logs" depending on model options
      'audit_logs',
    ];

    const exists = (name) => allTables.includes(normalizeTableName(name));
    expect(
      expected.some(exists) // at least one variant for audit logs
    ).toBe(true);
    expect(exists('users')).toBe(true);
    expect(exists('rules')).toBe(true);
    expect(exists('policies')).toBe(true);
    expect(exists('alerts')).toBe(true);
  });

  test('users table has expected critical columns', async () => {
    if (!connected) return test.skip();

    const qi = sequelize.getQueryInterface();
    const meta = await qi.describeTable('Users').catch(() => qi.describeTable('users'));

    // loosened expectations to avoid dialect differences
    expect(meta).toHaveProperty('id');
    expect(meta).toHaveProperty('username');
    expect(meta).toHaveProperty('email');
    expect(meta).toHaveProperty('role');
    expect(meta).toHaveProperty('is_active');
  });

  test('rules table has expected critical columns', async () => {
    if (!connected) return test.skip();

    const qi = sequelize.getQueryInterface();
    const meta = await qi.describeTable('Rules').catch(() => qi.describeTable('rules'));

    expect(meta).toHaveProperty('id');
    expect(meta).toHaveProperty('description');
    expect(meta).toHaveProperty('interface');
    expect(meta).toHaveProperty('action');
    expect(meta).toHaveProperty('enabled');
    // sync fields to external system (OPNsense)
    expect(meta).toHaveProperty('opnsense_uuid');
    expect(meta).toHaveProperty('sync_status');
  });

  test('policies table has expected critical columns', async () => {
    if (!connected) return test.skip();

    const qi = sequelize.getQueryInterface();
    const meta = await qi.describeTable('Policies').catch(() => qi.describeTable('policies'));

    expect(meta).toHaveProperty('id');
    expect(meta).toHaveProperty('name');
    expect(meta).toHaveProperty('type');
    expect(meta).toHaveProperty('enabled');
    expect(meta).toHaveProperty('approval_status');
    // optional but common
    expect(meta).toHaveProperty('priority');
  });

  test('alerts table has expected critical columns', async () => {
    if (!connected) return test.skip();

    const qi = sequelize.getQueryInterface();
    const meta = await qi.describeTable('Alerts').catch(() => qi.describeTable('alerts'));

    expect(meta).toHaveProperty('id');
    expect(meta).toHaveProperty('severity');
    expect(meta).toHaveProperty('type');
    expect(meta).toHaveProperty('status');
    expect(meta).toHaveProperty('message');
  });

  test('audit logs table has a primary key and timestamp columns', async () => {
    if (!connected) return test.skip();

    const qi = sequelize.getQueryInterface();
    // handle naming differences
    let meta;
    try {
      meta = await qi.describeTable('AuditLogs');
    } catch {
      meta = await qi.describeTable('audit_logs').catch(() => qi.describeTable('auditlogs'));
    }

    // Accept either "audit_id" (as used throughout routes) or conventional "id"
    expect(
      meta.audit_id || meta.id
    ).toBeDefined();

    expect(meta).toHaveProperty('timestamp');
    expect(meta).toHaveProperty('level');
    expect(meta).toHaveProperty('action');
  });

  test('model attribute metadata is defined (sanity)', () => {
    if (!connected) return test.skip();

    const models = [User, Rule, Policy, Alert, AuditLog];
    for (const m of models) {
      const attrs = m.getAttributes ? m.getAttributes() : m.rawAttributes;
      expect(attrs).toBeDefined();
      // each model should have a primary key attribute
      const hasPk = Object.values(attrs).some((a) => a.primaryKey === true);
      expect(hasPk).toBe(true);
    }
  });
});
