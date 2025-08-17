// tests/unit/services/AlertsService.test.js

// Mock logger
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// Mock models
const AlertModelMock = {
  findAll: jest.fn(),
  findByPk: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  destroy: jest.fn(),
  count: jest.fn(),
  findOne: jest.fn(),
};

const AuditLogMock = { 
  create: jest.fn() 
};

const UserMock = {
  findByPk: jest.fn()
};

jest.mock('../../../src/models/Alert', () => AlertModelMock);
jest.mock('../../../src/models/AuditLog', () => AuditLogMock);
jest.mock('../../../src/models/User', () => UserMock);

const logger = require('../../../src/utils/logger');
const AlertService = require('../../../src/services/AlertService');

describe('AlertService', () => {
  // Helper functions usando fixtures globali
  const resetMocks = () => {
    jest.clearAllMocks();
    logger.info.mockClear();
    logger.warn.mockClear();
    logger.error.mockClear();
    logger.debug.mockClear();
  };

  beforeEach(() => {
    resetMocks();
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in AlertsService test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  describe('listAlerts', () => {
    it('restituisce elenco alert filtrabile con dati dai fixtures', async () => {
      const testAlerts = [
        fixtures.createTestAlert('security', 'high'),
        fixtures.createTestAlert('performance', 'medium'),
        fixtures.createTestAlert('configuration', 'low')
      ];

      const mockDbAlerts = testAlerts.map(alert => ({
        alert_id: parseInt(alert.id.replace('alert-', '')) || fixtures.random.number(1, 1000),
        title: alert.title,
        type: alert.type,
        severity: alert.severity,
        description: alert.description,
        status: alert.status,
        acknowledged: alert.acknowledged,
        timestamp: alert.timestamp,
        source_ip: alert.source_ip || fixtures.random.ip(),
        created_at: new Date(alert.timestamp),
        updated_at: new Date(alert.timestamp)
      }));

      AlertModelMock.findAll.mockResolvedValue(mockDbAlerts);

      const res = await AlertService.listAlerts({ severity: 'high' });

      expect(Array.isArray(res)).toBe(true);
      expect(AlertModelMock.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ severity: 'high' })
        })
      );
      expect(res.length).toBeGreaterThan(0);
      expect(res[0]).toHaveProperty('alert_id');
      expect(res[0]).toHaveProperty('type');
      expect(res[0]).toHaveProperty('severity');
    });

    it('filtra alert per tipo e severità con dati dai fixtures', async () => {
      const securityAlerts = Array(3).fill().map(() => 
        fixtures.createTestAlert('security', 'critical')
      );

      const mockDbAlerts = securityAlerts.map((alert, index) => ({
        alert_id: index + 1,
        title: alert.title,
        type: 'security',
        severity: 'critical',
        status: alert.status,
        source_ip: fixtures.random.ip(),
        created_at: new Date()
      }));

      AlertModelMock.findAll.mockResolvedValue(mockDbAlerts);

      const res = await AlertService.listAlerts({ 
        type: 'security', 
        severity: 'critical' 
      });

      expect(AlertModelMock.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            type: 'security',
            severity: 'critical'
          })
        })
      );
      expect(res.every(alert => alert.type === 'security')).toBe(true);
      expect(res.every(alert => alert.severity === 'critical')).toBe(true);
    });

    it('supporta paginazione con parametri dai fixtures', async () => {
      const totalAlerts = fixtures.random.number(20, 50);
      const pageSize = 10;
      const page = 2;

      const mockAlerts = Array(pageSize).fill().map((_, index) => ({
        alert_id: (page - 1) * pageSize + index + 1,
        title: `Alert ${index + 1}`,
        type: 'monitoring',
        severity: 'medium',
        source_ip: fixtures.random.ip(),
        created_at: new Date()
      }));

      AlertModelMock.findAll.mockResolvedValue(mockAlerts);
      AlertModelMock.count.mockResolvedValue(totalAlerts);

      const res = await AlertService.listAlerts({ 
        page: page, 
        limit: pageSize 
      });

      expect(AlertModelMock.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          limit: pageSize,
          offset: (page - 1) * pageSize
        })
      );
      expect(res).toHaveLength(pageSize);
    });

    it('gestisce filtri temporali con date dai fixtures', async () => {
      const startDate = new Date('2024-01-01T00:00:00Z');
      const endDate = new Date('2024-01-31T23:59:59Z');

      const alertsInRange = Array(5).fill().map((_, index) => {
        const alert = fixtures.createTestAlert('security', 'medium');
        return {
          alert_id: index + 1,
          title: alert.title,
          type: alert.type,
          severity: alert.severity,
          source_ip: fixtures.random.ip(),
          created_at: new Date(2024, 0, index + 5) // Gennaio 2024
        };
      });

      AlertModelMock.findAll.mockResolvedValue(alertsInRange);

      const res = await AlertService.listAlerts({
        start_date: startDate.toISOString(),
        end_date: endDate.toISOString()
      });

      expect(AlertModelMock.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            created_at: expect.objectContaining({
              [expect.any(Symbol)]: expect.any(Array) // Sequelize Op.between
            })
          })
        })
      );
      expect(res.length).toBe(5);
    });
  });

  describe('createAlert', () => {
    it('crea alert e scrive audit con dati dai fixtures', async () => {
      const testUser = fixtures.createTestUser('admin');
      const sourceIP = fixtures.random.ip();
      
      const payload = {
        title: `OPNsense offline detected from ${sourceIP}`,
        type: 'security',
        severity: 'critical',
        description: 'Firewall connectivity lost',
        source_ip: sourceIP,
        details: { 
          ping: 'timeout',
          last_response: new Date(Date.now() - 300000).toISOString(), // 5 min ago
          correlation_id: fixtures.random.string(16)
        }
      };

      const createdAlert = {
        alert_id: fixtures.random.number(1, 1000),
        ...payload,
        status: 'active',
        acknowledged: false,
        created_at: new Date(),
        updated_at: new Date()
      };

      AlertModelMock.create.mockResolvedValue(createdAlert);
      AuditLogMock.create.mockResolvedValue({ id: fixtures.random.number(1, 1000) });

      const res = await AlertService.createAlert(payload, { userId: testUser.id });

      expect(AlertModelMock.create).toHaveBeenCalledWith(
        expect.objectContaining({
          title: payload.title,
          type: payload.type,
          severity: payload.severity,
          source_ip: sourceIP,
          details: expect.objectContaining({
            ping: 'timeout',
            correlation_id: payload.details.correlation_id
          })
        })
      );

      expect(AuditLogMock.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'alert_create',
          user_id: testUser.id,
          resource_type: 'alert',
          resource_id: createdAlert.alert_id,
          details: expect.objectContaining({
            alert_type: payload.type,
            severity: payload.severity
          })
        })
      );

      expect(res).toHaveProperty('alert_id', createdAlert.alert_id);
      expect(res.source_ip).toBe(sourceIP);
    });

    it('crea alert batch con performance data dai fixtures', async () => {
      const testUser = fixtures.createTestUser('operator');
      const perfData = fixtures.createPerformanceTestData(10);
      
      const batchAlerts = perfData.slice(0, 5).map((data, index) => ({
        title: `Performance Alert ${index + 1}`,
        type: 'performance',
        severity: index < 2 ? 'critical' : 'medium',
        description: `System performance degraded - Rule ${index + 1}`,
        source_ip: fixtures.random.ip(),
        details: {
          rule_uuid: data.uuid,
          processing_time: fixtures.random.number(1000, 5000),
          threshold_exceeded: true
        }
      }));

      // Mock creazione batch
      batchAlerts.forEach((alert, index) => {
        const createdAlert = {
          alert_id: index + 1,
          ...alert,
          status: 'active',
          created_at: new Date()
        };
        AlertModelMock.create.mockResolvedValueOnce(createdAlert);
      });

      const results = [];
      for (const alert of batchAlerts) {
        const result = await AlertService.createAlert(alert, { userId: testUser.id });
        results.push(result);
      }

      expect(results).toHaveLength(5);
      expect(AlertModelMock.create).toHaveBeenCalledTimes(5);
      expect(AuditLogMock.create).toHaveBeenCalledTimes(5);
      
      results.forEach(result => {
        expect(result).toHaveProperty('alert_id');
        expect(result.type).toBe('performance');
      });
    });

    it('gestisce errori di validazione con dati invalidi', async () => {
      const testUser = fixtures.createTestUser('viewer');
      
      const invalidPayload = {
        title: '', // Vuoto
        type: 'invalid_type',
        severity: 'unknown_severity',
        source_ip: 'invalid.ip.address',
        details: 'should_be_object' // Stringa invece di oggetto
      };

      AlertModelMock.create.mockRejectedValue(
        new Error('Validation failed: Invalid alert data')
      );

      await expect(
        AlertService.createAlert(invalidPayload, { userId: testUser.id })
      ).rejects.toThrow(/validation failed|invalid/i);

      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to create alert'),
        expect.objectContaining({
          error: expect.any(String),
          user_id: testUser.id
        })
      );
    });

    it('crea alert con configurazione rate limiting dai fixtures', async () => {
      const testUser = fixtures.createTestUser('admin');
      const rateLimitConfig = fixtures.createRateLimitConfig();
      const sourceIP = fixtures.random.ip();

      const rateLimitAlert = {
        title: 'Rate limit exceeded',
        type: 'security',
        severity: 'medium',
        description: `IP ${sourceIP} exceeded rate limit`,
        source_ip: sourceIP,
        details: {
          requests_per_minute: rateLimitConfig.max_requests_per_minute + 10,
          limit: rateLimitConfig.max_requests_per_minute,
          time_window: '1 minute',
          user_agent: 'Automated Scanner/1.0',
          blocked_requests: 15
        }
      };

      const createdAlert = {
        alert_id: fixtures.random.number(1, 1000),
        ...rateLimitAlert,
        status: 'active',
        created_at: new Date()
      };

      AlertModelMock.create.mockResolvedValue(createdAlert);

      const res = await AlertService.createAlert(rateLimitAlert, { userId: testUser.id });

      expect(res.details.requests_per_minute).toBeGreaterThan(rateLimitConfig.max_requests_per_minute);
      expect(res.details.limit).toBe(rateLimitConfig.max_requests_per_minute);
      expect(res.source_ip).toBe(sourceIP);
    });
  });

  describe('acknowledgeAlert', () => {
    it('segna come acknowledged e logga con user dai fixtures', async () => {
      const testUser = fixtures.createTestUser('operator');
      const testAlert = fixtures.createTestAlert('security', 'high');
      const alertId = fixtures.random.number(1, 1000);

      const foundAlert = {
        alert_id: alertId,
        title: testAlert.title,
        type: testAlert.type,
        severity: testAlert.severity,
        acknowledged: false,
        acknowledged_by: null,
        acknowledged_at: null,
        update: jest.fn().mockResolvedValue(true),
        toJSON: () => ({
          alert_id: alertId,
          title: testAlert.title,
          acknowledged: true,
          acknowledged_by: testUser.id,
          acknowledged_at: expect.any(Date)
        }),
      };

      AlertModelMock.findByPk.mockResolvedValue(foundAlert);
      UserMock.findByPk.mockResolvedValue(testUser);
      AuditLogMock.create.mockResolvedValue({ id: fixtures.random.number(1, 1000) });

      const res = await AlertService.acknowledgeAlert(alertId, { 
        userId: testUser.id,
        username: testUser.username 
      });

      expect(AlertModelMock.findByPk).toHaveBeenCalledWith(alertId);
      expect(foundAlert.update).toHaveBeenCalledWith(
        expect.objectContaining({
          acknowledged: true,
          acknowledged_by: testUser.id,
          acknowledged_at: expect.any(Date)
        })
      );

      expect(AuditLogMock.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'alert_ack',
          user_id: testUser.id,
          resource_type: 'alert',
          resource_id: alertId,
          details: expect.objectContaining({
            alert_type: testAlert.type,
            severity: testAlert.severity,
            acknowledged_by: testUser.username
          })
        })
      );

      expect(res).toEqual(expect.objectContaining({
        alert_id: alertId,
        acknowledged: true
      }));
    });

    it('alert non trovato → errore con logging', async () => {
      const testUser = fixtures.createTestUser('admin');
      const nonExistentId = fixtures.random.number(9000, 9999);

      AlertModelMock.findByPk.mockResolvedValue(null);

      await expect(
        AlertService.acknowledgeAlert(nonExistentId, { userId: testUser.id })
      ).rejects.toThrow(/not found|non trovato/i);

      expect(AlertModelMock.findByPk).toHaveBeenCalledWith(nonExistentId);
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Alert not found'),
        expect.objectContaining({
          alert_id: nonExistentId,
          user_id: testUser.id
        })
      );
    });

    it('gestisce acknowledge multipli con bulk operation', async () => {
      const testUser = fixtures.createTestUser('admin');
      const testAlerts = Array(5).fill().map(() => fixtures.createTestAlert('security', 'medium'));
      
      const alertIds = testAlerts.map((_, index) => index + 1);
      const foundAlerts = testAlerts.map((alert, index) => ({
        alert_id: index + 1,
        title: alert.title,
        type: alert.type,
        acknowledged: false,
        update: jest.fn().mockResolvedValue(true),
        toJSON: () => ({
          alert_id: index + 1,
          acknowledged: true,
          acknowledged_by: testUser.id
        })
      }));

      // Mock findByPk per ogni alert
      alertIds.forEach((id, index) => {
        AlertModelMock.findByPk.mockResolvedValueOnce(foundAlerts[index]);
      });

      const results = [];
      for (const alertId of alertIds) {
        const result = await AlertService.acknowledgeAlert(alertId, { userId: testUser.id });
        results.push(result);
      }

      expect(results).toHaveLength(5);
      expect(AlertModelMock.findByPk).toHaveBeenCalledTimes(5);
      expect(AuditLogMock.create).toHaveBeenCalledTimes(5);

      results.forEach((result, index) => {
        expect(result.alert_id).toBe(index + 1);
        expect(result.acknowledged).toBe(true);
      });
    });

    it('impedisce double acknowledge dello stesso alert', async () => {
      const testUser = fixtures.createTestUser('operator');
      const alertId = fixtures.random.number(1, 1000);
      const testAlert = fixtures.createTestAlert('performance', 'low');

      const alreadyAcknowledgedAlert = {
        alert_id: alertId,
        title: testAlert.title,
        acknowledged: true,
        acknowledged_by: fixtures.createTestUser('admin').id,
        acknowledged_at: new Date(Date.now() - 3600000), // 1 hour ago
        update: jest.fn(),
        toJSON: () => ({
          alert_id: alertId,
          acknowledged: true
        })
      };

      AlertModelMock.findByPk.mockResolvedValue(alreadyAcknowledgedAlert);

      await expect(
        AlertService.acknowledgeAlert(alertId, { userId: testUser.id })
      ).rejects.toThrow(/already acknowledged|già riconosciuto/i);

      expect(alreadyAcknowledgedAlert.update).not.toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('already acknowledged'),
        expect.objectContaining({
          alert_id: alertId,
          user_id: testUser.id
        })
      );
    });
  });

  describe('deleteAlert', () => {
    it('elimina alert e registra audit log', async () => {
      const testUser = fixtures.createTestUser('admin');
      const testAlert = fixtures.createTestAlert('configuration', 'low');
      const alertId = fixtures.random.number(1, 1000);

      const foundAlert = {
        alert_id: alertId,
        title: testAlert.title,
        type: testAlert.type,
        severity: testAlert.severity,
        status: 'resolved',
        destroy: jest.fn().mockResolvedValue(true),
        toJSON: () => ({
          alert_id: alertId,
          title: testAlert.title,
          type: testAlert.type
        })
      };

      AlertModelMock.findByPk.mockResolvedValue(foundAlert);
      AuditLogMock.create.mockResolvedValue({ id: fixtures.random.number(1, 1000) });

      const res = await AlertService.deleteAlert(alertId, { userId: testUser.id });

      expect(AlertModelMock.findByPk).toHaveBeenCalledWith(alertId);
      expect(foundAlert.destroy).toHaveBeenCalled();
      expect(AuditLogMock.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'alert_delete',
          user_id: testUser.id,
          resource_type: 'alert',
          resource_id: alertId
        })
      );

      expect(res).toBe(true);
    });

    it('impedisce eliminazione alert attivi critici senza permessi', async () => {
      const testUser = fixtures.createTestUser('viewer'); // Ruolo con permessi limitati
      const alertId = fixtures.random.number(1, 1000);

      const criticalAlert = {
        alert_id: alertId,
        type: 'security',
        severity: 'critical',
        status: 'active',
        acknowledged: false
      };

      AlertModelMock.findByPk.mockResolvedValue(criticalAlert);

      await expect(
        AlertService.deleteAlert(alertId, { userId: testUser.id })
      ).rejects.toThrow(/permission denied|permesso negato/i);

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Permission denied'),
        expect.objectContaining({
          alert_id: alertId,
          user_id: testUser.id,
          user_role: testUser.role
        })
      );
    });
  });

  describe('getAlertStats', () => {
    it('restituisce statistiche alert con dati dai fixtures', async () => {
      const testAlerts = [
        fixtures.createTestAlert('security', 'critical'),
        fixtures.createTestAlert('security', 'high'),
        fixtures.createTestAlert('performance', 'medium'),
        fixtures.createTestAlert('configuration', 'low'),
        fixtures.createTestAlert('security', 'critical') // Duplicate per test count
      ];

      const mockStats = {
        total: testAlerts.length,
        by_severity: {
          critical: 2,
          high: 1,
          medium: 1,
          low: 1
        },
        by_type: {
          security: 3,
          performance: 1,
          configuration: 1
        },
        by_status: {
          active: 4,
          acknowledged: 1,
          resolved: 0
        }
      };

      AlertModelMock.count.mockResolvedValue(testAlerts.length);
      AlertModelMock.findAll.mockImplementation((options) => {
        // Simula raggruppamenti Sequelize
        if (options.group) {
          return Promise.resolve([
            { severity: 'critical', count: 2 },
            { severity: 'high', count: 1 },
            { severity: 'medium', count: 1 },
            { severity: 'low', count: 1 }
          ]);
        }
        return Promise.resolve(testAlerts);
      });

      const stats = await AlertService.getAlertStats();

      expect(stats).toEqual(expect.objectContaining({
        total: expect.any(Number),
        by_severity: expect.any(Object),
        by_type: expect.any(Object)
      }));

      expect(stats.total).toBeGreaterThan(0);
      expect(Object.keys(stats.by_severity)).toContain('critical');
      expect(Object.keys(stats.by_type)).toContain('security');
    });
  });

  describe('Error Handling', () => {
    it('gestisce errori database gracefully', async () => {
      const dbError = new Error('Database connection lost');
      AlertModelMock.findAll.mockRejectedValue(dbError);

      await expect(AlertService.listAlerts()).rejects.toThrow('Database connection lost');

      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Database error'),
        expect.objectContaining({
          error: 'Database connection lost'
        })
      );
    });

    it('gestisce timeout su operazioni lunghe', async () => {
      const testUser = fixtures.createTestUser('admin');
      const timeoutError = new Error('Operation timeout');
      
      AlertModelMock.create.mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(timeoutError), 100);
        });
      });

      const payload = fixtures.createTestAlert('security', 'high');

      await expect(
        AlertService.createAlert(payload, { userId: testUser.id })
      ).rejects.toThrow('Operation timeout');
    });

    it('gestisce validazione payload con dati corrotti', async () => {
      const testUser = fixtures.createTestUser('admin');
      
      const corruptedPayload = {
        title: null,
        type: undefined,
        severity: {},
        details: 'not-an-object',
        source_ip: '999.999.999.999'
      };

      const validationError = new Error('Invalid payload format');
      AlertModelMock.create.mockRejectedValue(validationError);

      await expect(
        AlertService.createAlert(corruptedPayload, { userId: testUser.id })
      ).rejects.toThrow('Invalid payload format');
    });
  });

  describe('Integration Tests', () => {
    it('workflow completo: create → acknowledge → resolve', async () => {
      const testUser = fixtures.createTestUser('admin');
      const sourceIP = fixtures.random.ip();
      
      // 1. Create alert
      const alertPayload = {
        title: `Security breach detected from ${sourceIP}`,
        type: 'security',
        severity: 'critical',
        source_ip: sourceIP,
        details: {
          attack_type: 'brute_force',
          failed_attempts: 25,
          time_window: '5 minutes'
        }
      };

      const createdAlert = {
        alert_id: fixtures.random.number(1, 1000),
        ...alertPayload,
        status: 'active',
        acknowledged: false,
        created_at: new Date()
      };

      AlertModelMock.create.mockResolvedValue(createdAlert);

      const createResult = await AlertService.createAlert(alertPayload, { userId: testUser.id });
      expect(createResult.alert_id).toBeDefined();

      // 2. Acknowledge alert
      const acknowledgeAlert = {
        ...createdAlert,
        update: jest.fn().mockResolvedValue(true),
        toJSON: () => ({ ...createdAlert, acknowledged: true })
      };

      AlertModelMock.findByPk.mockResolvedValue(acknowledgeAlert);

      const ackResult = await AlertService.acknowledgeAlert(createdAlert.alert_id, { userId: testUser.id });
      expect(ackResult.acknowledged).toBe(true);

      // Verifica audit trail
      expect(AuditLogMock.create).toHaveBeenCalledTimes(2); // Create + Acknowledge
    });

    it('gestisce alert con firewall rules dai fixtures', async () => {
      const testUser = fixtures.createTestUser('operator');
      const firewallRule = fixtures.createTestFirewallRule(true, 0);
      
      const ruleAlert = {
        title: `Firewall rule ${firewallRule.uuid} triggered multiple times`,
        type: 'security',
        severity: 'medium',
        source_ip: firewallRule.source_net || fixtures.random.ip(),
        details: {
          rule_uuid: firewallRule.uuid,
          rule_description: firewallRule.description,
          interface: firewallRule.interface,
          protocol: firewallRule.protocol,
          trigger_count: fixtures.random.number(10, 100),
          time_period: '1 hour'
        }
      };

      const createdAlert = {
        alert_id: fixtures.random.number(1, 1000),
        ...ruleAlert,
        status: 'active',
        created_at: new Date()
      };

      AlertModelMock.create.mockResolvedValue(createdAlert);

      const result = await AlertService.createAlert(ruleAlert, { userId: testUser.id });

      expect(result.details.rule_uuid).toBe(firewallRule.uuid);
      expect(result.details.interface).toBe(firewallRule.interface);
      expect(result.source_ip).toBeValidIP();
    });
  });
});