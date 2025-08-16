// PolicyService unit tests

jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const PolicyMock = {
  findAll: jest.fn(),
  findByPk: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  destroy: jest.fn(),
};
const AuditLogMock = { create: jest.fn() };

jest.mock('../../../src/models/Policy', () => PolicyMock);
jest.mock('../../../src/models/AuditLog', () => AuditLogMock);

const logger = require('../../../src/utils/logger');
const PolicyService = require('../../../src/services/PolicyService');

describe('PolicyService', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('listPolicies', () => {
    it('restituisce array di policy', async () => {
      PolicyMock.findAll.mockResolvedValue([{ policy_id: 1 }, { policy_id: 2 }]);
      const out = await PolicyService.listPolicies({ tag: 'opnsense' });
      expect(Array.isArray(out)).toBe(true);
      expect(PolicyMock.findAll).toHaveBeenCalled();
      expect(logger.debug).toHaveBeenCalled();
    });
  });

  describe('createPolicy', () => {
    it('crea policy e scrive audit log', async () => {
      const payload = { name: 'Allow LAN', rules: [{ action: 'pass' }] };
      PolicyMock.create.mockResolvedValue({ policy_id: 10, ...payload });

      const res = await PolicyService.createPolicy(payload, { userId: 1 });
      expect(PolicyMock.create).toHaveBeenCalledWith(expect.objectContaining(payload));
      expect(AuditLogMock.create).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'policy_create', user_id: 1 })
      );
      expect(res).toHaveProperty('policy_id', 10);
    });

    it('propaga errori del DB', async () => {
      PolicyMock.create.mockRejectedValue(new Error('unique violation'));
      await expect(PolicyService.createPolicy({ name: 'x' }, { userId: 1 }))
        .rejects.toThrow(/unique/i);
      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('updatePolicy', () => {
    it('aggiorna parzialmente una policy', async () => {
      const found = { policy_id: 5, name: 'Old', update: jest.fn().mockResolvedValue(true), toJSON: () => ({ policy_id: 5, name: 'New' }) };
      PolicyMock.findByPk.mockResolvedValue(found);

      const res = await PolicyService.updatePolicy(5, { name: 'New' }, { userId: 2 });
      expect(PolicyMock.findByPk).toHaveBeenCalledWith(5);
      expect(found.update).toHaveBeenCalledWith(expect.objectContaining({ name: 'New' }));
      expect(AuditLogMock.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'policy_update' }));
      expect(res).toEqual(expect.objectContaining({ policy_id: 5 }));
    });

    it('policy non trovata → errore', async () => {
      PolicyMock.findByPk.mockResolvedValue(null);
      await expect(PolicyService.updatePolicy(99, { name: 'x' })).rejects.toThrow(/not found|non trovata/i);
    });
  });

  describe('deletePolicy', () => {
    it('elimina policy e logga', async () => {
      const found = { policy_id: 3, destroy: jest.fn().mockResolvedValue(true) };
      PolicyMock.findByPk.mockResolvedValue(found);

      const res = await PolicyService.deletePolicy(3, { userId: 1 });
      expect(found.destroy).toHaveBeenCalled();
      expect(AuditLogMock.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'policy_delete' }));
      expect(res).toEqual(expect.objectContaining({ deleted: true }));
    });
  });
});