// AlertService unit tests  (file di test chiamato "AlertsService.test.js" come nel tuo albero, ma importa AlertService)

jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const AlertModelMock = {
  findAll: jest.fn(),
  findByPk: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
};
const AuditLogMock = { create: jest.fn() };

jest.mock('../../../src/models/Alert', () => AlertModelMock);
jest.mock('../../../src/models/AuditLog', () => AuditLogMock);

const logger = require('../../../src/utils/logger');
const AlertService = require('../../../src/services/AlertService');

describe('AlertService', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('listAlerts', () => {
    it('restituisce elenco alert filtrabile', async () => {
      AlertModelMock.findAll.mockResolvedValue([{ alert_id: 1 }, { alert_id: 2 }]);
      const res = await AlertService.listAlerts({ severity: 'high' });
      expect(Array.isArray(res)).toBe(true);
      expect(AlertModelMock.findAll).toHaveBeenCalled();
    });
  });

  describe('createAlert', () => {
    it('crea alert e scrive audit', async () => {
      const payload = { title: 'OPNsense offline', severity: 'critical', details: { ping: 'timeout' } };
      AlertModelMock.create.mockResolvedValue({ alert_id: 99, ...payload });

      const res = await AlertService.createAlert(payload, { userId: 5 });
      expect(AlertModelMock.create).toHaveBeenCalledWith(expect.objectContaining(payload));
      expect(AuditLogMock.create).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'alert_create', user_id: 5 })
      );
      expect(res).toHaveProperty('alert_id', 99);
    });
  });

  describe('acknowledgeAlert', () => {
    it('segna come acknowledged e logga', async () => {
      const found = {
        alert_id: 10,
        acknowledged: false,
        update: jest.fn().mockResolvedValue(true),
        toJSON: () => ({ alert_id: 10, acknowledged: true }),
      };
      AlertModelMock.findByPk.mockResolvedValue(found);

      const res = await AlertService.acknowledgeAlert(10, { userId: 1 });
      expect(AlertModelMock.findByPk).toHaveBeenCalledWith(10);
      expect(found.update).toHaveBeenCalledWith(expect.objectContaining({ acknowledged: true }));
      expect(AuditLogMock.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'alert_ack' }));
      expect(res).toEqual(expect.objectContaining({ alert_id: 10 }));
    });

    it('alert non trovato → errore', async () => {
      AlertModelMock.findByPk.mockResolvedValue(null);
      await expect(AlertService.acknowledgeAlert(777, { userId: 1 })).rejects.toThrow(/not found|non trovato/i);
      expect(logger.warn).toHaveBeenCalled();
    });
  });
});