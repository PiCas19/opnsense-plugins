// RuleService unit tests

jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// Mock models (Sequelize-like)
const RuleMock = {
  findAll: jest.fn(),
  findByPk: jest.fn(),
  update: jest.fn(),
  create: jest.fn(),
  destroy: jest.fn(),
};
const AuditLogMock = {
  create: jest.fn(),
};

jest.mock('../../../src/models/Rule', () => RuleMock);
jest.mock('../../../src/models/AuditLog', () => AuditLogMock);

// Mock OpnsenseService usato da RuleService
const OpnsenseServiceMock = {
  toggleRule: jest.fn(),
  bulkEnable: jest.fn(),
  bulkDisable: jest.fn(),
  reload: jest.fn(),
  backupRules: jest.fn(),
};
jest.mock('../../../src/services/OpnsenseService', () => OpnsenseServiceMock);

const logger = require('../../../src/utils/logger');
const RuleService = require('../../../src/services/RuleService');

function makeRule(overrides = {}) {
  const base = {
    rule_id: 42,
    enabled: true,
    save: jest.fn().mockResolvedValue(true),
    toJSON: function () { return { rule_id: this.rule_id, enabled: this.enabled }; },
  };
  return Object.assign(base, overrides);
}

describe('RuleService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('listRules', () => {
    it('ritorna array e chiama Rule.findAll con eventuali filtri', async () => {
      RuleMock.findAll.mockResolvedValue([makeRule({ rule_id: 1 }), makeRule({ rule_id: 2 })]);

      const out = await RuleService.listRules({ enabled: true });
      expect(Array.isArray(out)).toBe(true);
      expect(out[0]).toHaveProperty('rule_id');
      expect(RuleMock.findAll).toHaveBeenCalled();
      expect(logger.debug).toHaveBeenCalled();
    });

    it('propaga errori del DB', async () => {
      RuleMock.findAll.mockRejectedValue(new Error('db down'));
      await expect(RuleService.listRules({})).rejects.toThrow(/db down/i);
      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('toggleRule', () => {
    it('toggles enabled, chiama OpnsenseService.toggleRule e crea audit log', async () => {
      const rule = makeRule({ rule_id: 100, enabled: false });
      RuleMock.findByPk.mockResolvedValue(rule);
      OpnsenseServiceMock.toggleRule.mockResolvedValue({ ok: true });

      const result = await RuleService.toggleRule(100, { userId: 1, ip: '127.0.0.1' });

      expect(RuleMock.findByPk).toHaveBeenCalledWith(100);
      expect(rule.save).toHaveBeenCalled(); // stato cambiato sul DB
      expect(OpnsenseServiceMock.toggleRule).toHaveBeenCalledWith(100, true);
      expect(AuditLogMock.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'toggle_rule',
          resource: 'firewall/rules/100',
          user_id: 1,
        })
      );
      expect(result).toEqual(expect.objectContaining({ rule_id: 100, enabled: true }));
    });

    it('se rule non esiste → errore NotFound', async () => {
      RuleMock.findByPk.mockResolvedValue(null);
      await expect(RuleService.toggleRule(999)).rejects.toThrow(/not found|non trovata/i);
      expect(OpnsenseServiceMock.toggleRule).not.toHaveBeenCalled();
    });

    it('se chiamata a OPNsense fallisce → ripropaga errore e logga', async () => {
      const rule = makeRule({ rule_id: 7, enabled: true });
      RuleMock.findByPk.mockResolvedValue(rule);
      OpnsenseServiceMock.toggleRule.mockRejectedValue(new Error('opnsense error'));

      await expect(RuleService.toggleRule(7)).rejects.toThrow(/opnsense/i);
      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('bulkEnable / bulkDisable', () => {
    it('bulkEnable chiama Opnsense e ritorna risultato sintetico', async () => {
      OpnsenseServiceMock.bulkEnable.mockResolvedValue({ updated: [1, 2, 3] });
      const res = await RuleService.bulkEnable([1, 2, 3], { userId: 2 });
      expect(OpnsenseServiceMock.bulkEnable).toHaveBeenCalledWith([1, 2, 3]);
      expect(AuditLogMock.create).toHaveBeenCalled();
      expect(res).toEqual(expect.objectContaining({ updated: [1, 2, 3] }));
    });

    it('bulkDisable chiama Opnsense e ritorna risultato', async () => {
      OpnsenseServiceMock.bulkDisable.mockResolvedValue({ updated: [4, 5] });
      const res = await RuleService.bulkDisable([4, 5], { userId: 2 });
      expect(OpnsenseServiceMock.bulkDisable).toHaveBeenCalledWith([4, 5]);
      expect(AuditLogMock.create).toHaveBeenCalled();
      expect(res).toEqual(expect.objectContaining({ updated: [4, 5] }));
    });
  });

  describe('reload / backup', () => {
    it('reload chiama OpnsenseService.reload', async () => {
      OpnsenseServiceMock.reload.mockResolvedValue({ ok: true });
      const res = await RuleService.reload({ userId: 9 });
      expect(OpnsenseServiceMock.reload).toHaveBeenCalled();
      expect(AuditLogMock.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'firewall_reload' }));
      expect(res).toEqual(expect.objectContaining({ ok: true }));
    });

    it('backupRules ritorna Buffer/string e crea audit', async () => {
      OpnsenseServiceMock.backupRules.mockResolvedValue(Buffer.from('{"rules": []}'));
      const res = await RuleService.backupRules({ userId: 9 });
      expect(OpnsenseServiceMock.backupRules).toHaveBeenCalled();
      expect(AuditLogMock.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'firewall_backup' }));
      expect(Buffer.isBuffer(res) || typeof res === 'string').toBe(true);
    });
  });
});