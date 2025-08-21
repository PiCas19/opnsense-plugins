/**
 * @swagger
 * /api/rules/sync:
 *   post:
 *     summary: Sincronizza regole con OPNsense
 *     description: Forza la sincronizzazione di tutte le regole pending con OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sincronizzazione completata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/sync', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('apply_config')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti per sincronizzare regole'
      });
    }

    // Trova regole che necessitano sincronizzazione
    const pendingRules = await Rule.findAll({
      where: {
        [Rule.sequelize.Op.or]: [
          { sync_status: 'pending' },
          { sync_status: 'failed' },
          { sync_status: null }
        ]
      }
    });

    let synced = 0;
    let failed = 0;
    const errors = [];

    for (const rule of pendingRules) {
      try {
        // Verifica se il metodo syncToOPNsense esiste
        if (rule.syncToOPNsense && typeof rule.syncToOPNsense === 'function') {
          await rule.syncToOPNsense();
        } else {
          // Fallback manuale
          const ruleForOPNsense = rule.toOpnsenseFormat ? 
            rule.toOpnsenseFormat() : 
            {
              description: rule.description,
              interface: rule.interface,
              action: rule.action,
              protocol: rule.protocol || 'any',
              enabled: rule.enabled,
              source_config: rule.source_config,
              destination_config: rule.destination_config
            };

          let opnsenseResult;
          if (rule.opnsense_uuid) {
            // Aggiorna regola esistente
            opnsenseResult = await OpnsenseService.updateRule(rule.opnsense_uuid, ruleForOPNsense);
          } else {
            // Crea nuova regola
            opnsenseResult = await OpnsenseService.createRule(ruleForOPNsense);
            await rule.update({ opnsense_uuid: opnsenseResult.uuid });
          }

          await rule.update({
            sync_status: 'synced',
            last_synced_at: new Date(),
            sync_error: null
          });
        }
        synced++;
      } catch (error) {
        failed++;
        errors.push({
          rule_id: rule.id,
          uuid: rule.uuid || rule.id,
          error: error.message
        });
        
        await rule.update({
          sync_status: 'failed',
          sync_error: error.message
        });
        
        logger.error('Errore sincronizzazione regola', {
          rule_id: rule.id,
          error: error.message
        });
      }
    }

    logger.info('Sincronizzazione bulk completata', {
      synced,
      failed,
      total: pendingRules.length,
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Sincronizzazione completata',
      data: {
        synced,
        failed,
        total: pendingRules.length,
        errors: errors.length > 0 ? errors : undefined
      }
    });

  } catch (error) {
    logger.error('Errore nella sincronizzazione bulk', {
      error: error.message,
      stack: error.stack,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nella sincronizzazione',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

/**
 * @swagger
 * /api/rules/statistics:
 *   get:
 *     summary: Statistiche regole
 *     description: Ottieni statistiche sulle regole firewall
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Statistiche recuperate con successo
 *       401:
 *         description: Token di accesso richiesto
 */
router.get('/statistics', asyncHandler(async (req, res) => {
  try {
    const [
      totalRules,
      activeRules,
      byInterface,
      byAction,
      syncStats
    ] = await Promise.all([
      Rule.count(),
      Rule.count({ where: { enabled: true } }),
      Rule.findAll({
        attributes: [
          'interface',
          [Rule.sequelize.fn('COUNT', '*'), 'count']
        ],
        group: ['interface'],
        raw: true
      }),
      Rule.findAll({
        attributes: [
          'action',
          [Rule.sequelize.fn('COUNT', '*'), 'count']
        ],
        group: ['action'],
        raw: true
      }),
      Rule.findAll({
        attributes: [
          'sync_status',
          [Rule.sequelize.fn('COUNT', '*'), 'count']
        ],
        group: ['sync_status'],
        raw: true
      })
    ]);

    const syncStatusMap = syncStats.reduce((acc, item) => {
      acc[item.sync_status || 'unknown'] = parseInt(item.count);
      return acc;
    }, {});

    res.json({
      success: true,
      message: 'Statistiche recuperate con successo',
      data: {
        total_rules: totalRules,
        active_rules: activeRules,
        by_interface: byInterface,
        by_action: byAction,
        sync_status: syncStatusMap
      }
    });

  } catch (error) {
    logger.error('Errore nel recupero statistiche', {
      error: error.message,
      stack: error.stack,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nel recupero delle statistiche',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

/**
 * @swagger
 * /api/rules/{uuid}/clone:
 *   post:
 *     summary: Clona regola
 *     description: Crea una copia di una regola esistente
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: UUID della regola da clonare
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *                 description: Nuova descrizione per la regola clonata
 *                 example: "Copia di: Block malicious IPs"
 *     responses:
 *       201:
 *         description: Regola clonata con successo
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/:uuid/clone', validateUUID, asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('create_rules')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti per clonare regole'
      });
    }

    const { uuid } = req.params;
    const { description } = req.body;

    // Cerca la regola usando uuid o id
    let originalRule = await Rule.findOne({ where: { uuid } });
    if (!originalRule && !isNaN(uuid)) {
      // Fallback: prova a cercare per ID se UUID non trovato
      originalRule = await Rule.findByPk(uuid);
    }

    if (!originalRule) {
      return res.status(404).json({
        success: false,
        message: 'Regola originale non trovata'
      });
    }

    // Clona la regola
    const clonedData = {
      ...originalRule.dataValues,
      id: undefined, // Rimuovi ID per permettere auto-increment
      uuid: undefined, // Genera nuovo UUID se presente
      description: description || `Copia di: ${originalRule.description}`,
      created_by: req.user.id,
      opnsense_uuid: null, // Reset UUID OPNsense
      sync_status: 'pending',
      sync_error: null,
      last_synced_at: null,
      created_at: undefined,
      updated_at: undefined
    };

    const clonedRule = await Rule.create(clonedData);

    logger.info('Regola clonata', {
      original_id: originalRule.id,
      original_uuid: originalRule.uuid || originalRule.id,
      cloned_id: clonedRule.id,
      cloned_uuid: clonedRule.uuid || clonedRule.id,
      user: req.user.username
    });

    res.status(201).json({
      success: true,
      message: 'Regola clonata con successo',
      data: {
        id: clonedRule.id,
        uuid: clonedRule.uuid || clonedRule.id,
        description: clonedRule.description
      }
    });

  } catch (error) {
    logger.error('Errore nella clonazione regola', {
      uuid: req.params.uuid,
      error: error.message,
      stack: error.stack,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nella clonazione della regola',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

/**
 * @swagger
 * /api/rules/bulk:
 *   post:
 *     summary: Operazioni bulk su regole
 *     description: Esegue operazioni su multiple regole contemporaneamente
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - operation
 *               - rule_uuids
 *             properties:
 *               operation:
 *                 type: string
 *                 enum: [enable, disable, delete]
 *                 description: Operazione da eseguire
 *               rule_uuids:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Lista UUID/ID delle regole
 *                 minItems: 1
 *                 maxItems: 50
 *     responses:
 *       200:
 *         description: Operazione bulk completata
 *       400:
 *         description: Parametri non validi
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/bulk', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    const { operation, rule_uuids } = req.body;

    // Validazione input
    if (!operation || !rule_uuids || !Array.isArray(rule_uuids)) {
      return res.status(400).json({
        success: false,
        message: 'Parametri operation e rule_uuids richiesti'
      });
    }

    const validOperations = ['enable', 'disable', 'delete'];
    if (!validOperations.includes(operation)) {
      return res.status(400).json({
        success: false,
        message: `Operazione non valida. Usare: ${validOperations.join(', ')}`
      });
    }

    if (rule_uuids.length === 0 || rule_uuids.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Lista UUID deve contenere tra 1 e 50 elementi'
      });
    }

    // Verifica permessi
    const requiredPermission = operation === 'delete' ? 'delete_rules' : 'update_rules';
    if (!user || !user.hasPermission(requiredPermission)) {
      return res.status(403).json({
        success: false,
        message: `Permessi insufficienti per operazione: ${operation}`
      });
    }

    // Trova regole
    const rules = await Rule.findAll({
      where: {
        [Rule.sequelize.Op.or]: [
          { uuid: rule_uuids },
          { id: rule_uuids.filter(id => !isNaN(id)) }
        ]
      }
    });

    if (rules.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Nessuna regola trovata con gli identificatori forniti'
      });
    }

    const results = {
      success: 0,
      failed: 0,
      errors: []
    };

    for (const rule of rules) {
      try {
        switch (operation) {
          case 'enable':
          case 'disable':
            const enabled = operation === 'enable';
            await rule.update({ 
              enabled, 
              updated_by: req.user.id 
            });
            
            // Sincronizza con OPNsense se possibile
            if (rule.opnsense_uuid) {
              try {
                await OpnsenseService.toggleRule(rule.opnsense_uuid, enabled);
                await rule.update({
                  sync_status: 'synced',
                  last_synced_at: new Date(),
                  sync_error: null
                });
              } catch (syncError) {
                await rule.update({
                  sync_status: 'failed',
                  sync_error: syncError.message
                });
              }
            }
            break;

          case 'delete':
            // Elimina da OPNsense se sincronizzata
            if (rule.opnsense_uuid) {
              try {
                await OpnsenseService.deleteRule(rule.opnsense_uuid);
              } catch (syncError) {
                logger.warn('Errore eliminazione regola da OPNsense durante bulk delete', {
                  rule_id: rule.id,
                  rule_uuid: rule.uuid || rule.id,
                  error: syncError.message
                });
              }
            }
            await rule.destroy();
            break;
        }
        
        results.success++;
      } catch (error) {
        results.failed++;
        results.errors.push({
          rule_id: rule.id,
          rule_uuid: rule.uuid || rule.id,
          error: error.message
        });
      }
    }

    logger.info('Operazione bulk completata', {
      operation,
      total: rules.length,
      success: results.success,
      failed: results.failed,
      user: req.user.username
    });

    res.json({
      success: true,
      message: `Operazione ${operation} completata`,
      data: {
        operation,
        total: rules.length,
        success: results.success,
        failed: results.failed,
        errors: results.errors.length > 0 ? results.errors : undefined
      }
    });

  } catch (error) {
    logger.error('Errore nell\'operazione bulk', {
      operation: req.body.operation,
      error: error.message,
      stack: error.stack,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nell\'operazione bulk',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

module.exports = router;const express = require('express');
const { authenticate } = require('../middleware/auth');
const { validateRule, validateUUID, validateSearchQuery } = require('../middleware/validation');
const Rule = require('../models/Rule');
const User = require('../models/User'); 
const OpnsenseService = require('../services/OpnsenseService');
const asyncHandler = require('express-async-handler');
const logger = require('../utils/logger');

const router = express.Router();

// Applica autenticazione a tutte le rotte
router.use(authenticate);

/**
 * @swagger
 * /api/rules:
 *   get:
 *     summary: Ottieni lista regole firewall
 *     description: Recupera tutte le regole firewall con opzioni di filtro e paginazione
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Numero pagina
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 25
 *         description: Elementi per pagina
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Ricerca nella descrizione
 *       - in: query
 *         name: interface
 *         schema:
 *           type: string
 *           enum: [wan, lan, dmz, opt1, opt2, opt3, opt4]
 *         description: Filtra per interfaccia
 *       - in: query
 *         name: action
 *         schema:
 *           type: string
 *           enum: [pass, block, reject]
 *         description: Filtra per azione
 *       - in: query
 *         name: enabled
 *         schema:
 *           type: boolean
 *         description: Filtra per stato abilitato
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [sequence, description, action, interface, created_at]
 *           default: sequence
 *         description: Campo di ordinamento
 *       - in: query
 *         name: sortOrder
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: asc
 *         description: Direzione ordinamento
 *     responses:
 *       200:
 *         description: Lista regole recuperata con successo
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.get('/', validateSearchQuery, asyncHandler(async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 25, 
      search, 
      interface: iface, 
      action, 
      enabled, 
      sortBy = 'sequence', 
      sortOrder = 'asc' 
    } = req.query;

    const offset = (page - 1) * limit;
    const where = {};
    const order = [[sortBy, sortOrder.toUpperCase()]];

    // Costruisci filtri
    if (search) {
      where.description = { [Rule.sequelize.Op.iLike]: `%${search}%` };
    }
    if (iface) where.interface = iface;
    if (action) where.action = action;
    if (enabled !== undefined) where.enabled = enabled;

    // Solo regole approvate per utenti non admin
    const user = await User.findByPk(req.user.id);
    if (user.role !== 'admin') {
      // Assumiamo che ci sia un campo approval_status o simile
      // Se non esiste, rimuovi questa riga
      if (Rule.rawAttributes.approval_status) {
        where.approval_status = 'approved';
      }
    }

    const { count, rows } = await Rule.findAndCountAll({
      where,
      offset: parseInt(offset),
      limit: parseInt(limit),
      order,
      include: [
        {
          model: User,
          as: 'createdBy',
          attributes: ['id', 'username', 'first_name', 'last_name'],
          required: false
        }
      ]
    });

    logger.info('Lista regole recuperata', {
      count,
      page,
      limit,
      user: req.user.username,
      filters: { search, iface, action, enabled }
    });

    res.json({
      success: true,
      message: 'Regole recuperate con successo',
      data: rows,
      meta: {
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(count / limit)
      }
    });

  } catch (error) {
    logger.error('Errore nel recupero lista regole', {
      error: error.message,
      stack: error.stack,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nel recupero delle regole',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

/**
 * @swagger
 * /api/rules/{uuid}:
 *   get:
 *     summary: Ottieni regola specifica
 *     description: Recupera una singola regola firewall per UUID
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: UUID della regola
 *     responses:
 *       200:
 *         description: Regola recuperata con successo
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 */
router.get('/:uuid', validateUUID, asyncHandler(async (req, res) => {
  const { uuid } = req.params;
  
  const rule = await Rule.findOne({
    where: { uuid },
    include: [
      {
        model: User,
        as: 'createdBy',
        attributes: ['id', 'username', 'first_name', 'last_name']
      },
      {
        model: User,
        as: 'updatedBy',
        attributes: ['id', 'username', 'first_name', 'last_name']
      }
    ]
  });

  if (!rule) {
    return res.status(404).json({
      success: false,
      message: 'Regola non trovata'
    });
  }

  logger.info('Regola recuperata', { uuid, user: req.user.username });

  res.json({
    success: true,
    message: 'Regola recuperata con successo',
    data: rule
  });
}));

/**
 * @swagger
 * /api/rules:
 *   post:
 *     summary: Crea nuova regola firewall
 *     description: Crea una nuova regola firewall e la sincronizza con OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - description
 *               - interface
 *               - action
 *             properties:
 *               description:
 *                 type: string
 *                 description: Descrizione della regola
 *                 example: Block malicious IPs
 *               interface:
 *                 type: string
 *                 enum: [wan, lan, dmz, opt1, opt2, opt3, opt4]
 *                 description: Interfaccia di rete
 *               action:
 *                 type: string
 *                 enum: [pass, block, reject]
 *                 description: Azione da intraprendere
 *               protocol:
 *                 type: string
 *                 enum: [tcp, udp, icmp, any]
 *                 default: any
 *                 description: Protocollo
 *               enabled:
 *                 type: boolean
 *                 default: true
 *                 description: Regola abilitata
 *               source_config:
 *                 type: object
 *                 properties:
 *                   type:
 *                     type: string
 *                     enum: [any, single, network]
 *                   address:
 *                     type: string
 *                     description: Indirizzo IP (per type=single)
 *                   network:
 *                     type: string
 *                     description: Rete CIDR (per type=network)
 *                   port:
 *                     type: integer
 *                     minimum: 1
 *                     maximum: 65535
 *               destination_config:
 *                 type: object
 *                 properties:
 *                   type:
 *                     type: string
 *                     enum: [any, single, network]
 *                   address:
 *                     type: string
 *                     description: Indirizzo IP (per type=single)
 *                   network:
 *                     type: string
 *                     description: Rete CIDR (per type=network)
 *                   port:
 *                     type: integer
 *                     minimum: 1
 *                     maximum: 65535
 *     responses:
 *       201:
 *         description: Regola creata con successo
 *       400:
 *         description: Dati regola non validi
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/', validateRule, asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('create_rules')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti per creare regole'
      });
    }

    const ruleData = {
      ...req.body,
      created_by: req.user.id
    };

    // Crea regola nel database
    const rule = await Rule.create(ruleData);

    // Tenta sincronizzazione con OPNsense
    let syncResult = {
      opnsense_uuid: null,
      sync_status: 'pending',
      sync_error: null
    };

    try {
      // Verifica se il modello Rule ha il metodo toOpnsenseFormat
      const ruleForOPNsense = rule.toOpnsenseFormat ? 
        rule.toOpnsenseFormat() : 
        {
          description: rule.description,
          interface: rule.interface,
          action: rule.action,
          protocol: rule.protocol || 'any',
          enabled: rule.enabled,
          source_config: rule.source_config,
          destination_config: rule.destination_config
        };

      const opnsenseResult = await OpnsenseService.createRule(ruleForOPNsense);
      
      syncResult = {
        opnsense_uuid: opnsenseResult.uuid,
        sync_status: 'synced',
        last_synced_at: new Date(),
        sync_error: null
      };
    } catch (opnsenseError) {
      logger.error('Errore sincronizzazione regola con OPNsense', {
        rule_id: rule.id,
        error: opnsenseError.message
      });
      syncResult = {
        sync_status: 'failed',
        sync_error: opnsenseError.message
      };
    }

    // Aggiorna regola con risultato sincronizzazione
    await rule.update(syncResult);

    logger.info('Regola creata', {
      rule_id: rule.id,
      uuid: rule.uuid || rule.id,
      description: rule.description,
      sync_status: syncResult.sync_status,
      user: req.user.username
    });

    res.status(201).json({
      success: true,
      message: 'Regola creata con successo',
      data: {
        id: rule.id,
        uuid: rule.uuid || rule.id,
        opnsense_uuid: syncResult.opnsense_uuid,
        sync_status: syncResult.sync_status,
        sync_error: syncResult.sync_error
      }
    });

  } catch (error) {
    logger.error('Errore nella creazione regola', {
      error: error.message,
      stack: error.stack,
      ruleData: req.body,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nella creazione della regola',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

/**
 * @swagger
 * /api/rules/{uuid}:
 *   put:
 *     summary: Aggiorna regola firewall
 *     description: Aggiorna una regola firewall esistente e la sincronizza con OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: UUID della regola
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RuleRequest'
 *     responses:
 *       200:
 *         description: Regola aggiornata con successo
 *       404:
 *         description: Regola non trovata
 *       400:
 *         description: Dati regola non validi
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.put('/:uuid', validateUUID, validateRule, asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user.hasPermission('update_rules')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti per aggiornare regole'
    });
  }

  const { uuid } = req.params;
  const rule = await Rule.findOne({ where: { uuid } });

  if (!rule) {
    return res.status(404).json({
      success: false,
      message: 'Regola non trovata'
    });
  }

  try {
    const updateData = {
      ...req.body,
      updated_by: req.user.id
    };

    // Aggiorna regola nel database
    await rule.update(updateData);

    // Tenta sincronizzazione con OPNsense
    let syncResult = {
      sync_status: 'pending',
      sync_error: null
    };

    try {
      if (rule.opnsense_uuid) {
        await OpnsenseService.updateRule(rule.opnsense_uuid, rule.toOpnsenseFormat());
        syncResult = {
          sync_status: 'synced',
          last_synced_at: new Date(),
          sync_error: null
        };
      }
    } catch (opnsenseError) {
      logger.error('Errore sincronizzazione aggiornamento regola con OPNsense', {
        rule_id: rule.id,
        error: opnsenseError.message
      });
      syncResult = {
        sync_status: 'failed',
        sync_error: opnsenseError.message
      };
    }

    // Aggiorna stato sincronizzazione
    await rule.update(syncResult);

    logger.info('Regola aggiornata', {
      rule_id: rule.id,
      uuid: rule.uuid,
      sync_status: syncResult.sync_status,
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Regola aggiornata con successo',
      data: {
        sync_status: syncResult.sync_status,
        sync_error: syncResult.sync_error
      }
    });

  } catch (error) {
    logger.error('Errore nell\'aggiornamento regola', {
      rule_id: rule.id,
      error: error.message,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nell\'aggiornamento della regola',
      error: error.message
    });
  }
}));

/**
 * @swagger
 * /api/rules/{uuid}:
 *   delete:
 *     summary: Elimina regola firewall
 *     description: Elimina una regola firewall dal database e da OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: UUID della regola
 *     responses:
 *       200:
 *         description: Regola eliminata con successo
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.delete('/:uuid', validateUUID, asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user.hasPermission('delete_rules')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti per eliminare regole'
    });
  }

  const { uuid } = req.params;
  const rule = await Rule.findOne({ where: { uuid } });

  if (!rule) {
    return res.status(404).json({
      success: false,
      message: 'Regola non trovata'
    });
  }

  try {
    // Elimina da OPNsense se sincronizzata
    if (rule.opnsense_uuid) {
      try {
        await OpnsenseService.deleteRule(rule.opnsense_uuid);
      } catch (opnsenseError) {
        logger.warn('Errore eliminazione regola da OPNsense, continuo con eliminazione database', {
          rule_id: rule.id,
          opnsense_uuid: rule.opnsense_uuid,
          error: opnsenseError.message
        });
      }
    }

    // Elimina dal database (soft delete)
    await rule.destroy();

    logger.info('Regola eliminata', {
      rule_id: rule.id,
      uuid: rule.uuid,
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Regola eliminata con successo'
    });

  } catch (error) {
    logger.error('Errore nell\'eliminazione regola', {
      rule_id: rule.id,
      error: error.message,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nell\'eliminazione della regola',
      error: error.message
    });
  }
}));

/**
 * @swagger
 * /api/rules/{uuid}/toggle:
 *   patch:
 *     summary: Abilita/disabilita regola
 *     description: Cambia lo stato abilitato di una regola firewall
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: UUID della regola
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - enabled
 *             properties:
 *               enabled:
 *                 type: boolean
 *                 description: Stato abilitato della regola
 *                 example: true
 *     responses:
 *       200:
 *         description: Stato regola modificato con successo
 *       404:
 *         description: Regola non trovata
 *       400:
 *         description: Stato enabled richiesto
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.patch('/:uuid/toggle', validateUUID, asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user.hasPermission('toggle_rules')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti per modificare stato regole'
    });
  }

  const { uuid } = req.params;
  const { enabled } = req.body;

  if (typeof enabled !== 'boolean') {
    return res.status(400).json({
      success: false,
      message: 'Parametro enabled richiesto (boolean)'
    });
  }

  const rule = await Rule.findOne({ where: { uuid } });

  if (!rule) {
    return res.status(404).json({
      success: false,
      message: 'Regola non trovata'
    });
  }

  try {
    // Aggiorna stato nel database
    await rule.update({
      enabled,
      updated_by: req.user.id
    });

    // Sincronizza con OPNsense
    let syncResult = {
      sync_status: 'pending',
      sync_error: null
    };

    try {
      if (rule.opnsense_uuid) {
        await OpnsenseService.toggleRule(rule.opnsense_uuid, enabled);
        syncResult = {
          sync_status: 'synced',
          last_synced_at: new Date(),
          sync_error: null
        };
      }
    } catch (opnsenseError) {
      logger.error('Errore toggle regola in OPNsense', {
        rule_id: rule.id,
        error: opnsenseError.message
      });
      syncResult = {
        sync_status: 'failed',
        sync_error: opnsenseError.message
      };
    }

    // Aggiorna stato sincronizzazione
    await rule.update(syncResult);

    logger.info('Regola toggle effettuato', {
      rule_id: rule.id,
      uuid: rule.uuid,
      enabled,
      sync_status: syncResult.sync_status,
      user: req.user.username
    });

    res.json({
      success: true,
      message: `Regola ${enabled ? 'abilitata' : 'disabilitata'} con successo`,
      data: {
        sync_status: syncResult.sync_status,
        sync_error: syncResult.sync_error
      }
    });

  } catch (error) {
    logger.error('Errore nel toggle regola', {
      rule_id: rule.id,
      error: error.message,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nel cambio stato regola',
      error: error.message
    });
  }
}));

/**
 * @swagger
 * /api/rules/apply:
 *   post:
 *     summary: Applica configurazione firewall
 *     description: Applica tutte le modifiche pending alla configurazione OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Configurazione applicata con successo
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 *       502:
 *         description: Errore comunicazione con OPNsense
 */
router.post('/apply', asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user.hasPermission('apply_config')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti per applicare configurazione'
    });
  }

  try {
    await OpnsenseService.applyConfig();

    logger.info('Configurazione applicata manualmente', {
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Configurazione applicata con successo'
    });

  } catch (error) {
    logger.error('Errore nell\'applicazione configurazione', {
      error: error.message,
      user: req.user.username
    });

    res.status(502).json({
      success: false,
      message: 'Errore nell\'applicazione della configurazione',
      error: error.message
    });
  }
}));

/**
 * @swagger
 * /api/rules/sync:
 *   post:
 *     summary: Sincronizza regole con OPNsense
 *     description: Forza la sincronizzazione di tutte le regole pending con OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sincronizzazione completata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/sync', asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user.hasPermission('apply_config')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti per sincronizzare regole'
    });
  }

  try {
    const pendingRules = await Rule.findNeedingSync();
    let synced = 0;
    let failed = 0;
    const errors = [];

    for (const rule of pendingRules) {
      try {
        await rule.syncToOPNsense();
        synced++;
      } catch (error) {
        failed++;
        errors.push({
          rule_id: rule.id,
          uuid: rule.uuid,
          error: error.message
        });
        logger.error('Errore sincronizzazione regola', {
          rule_id: rule.id,
          error: error.message
        });
      }
    }

    logger.info('Sincronizzazione bulk completata', {
      synced,
      failed,
      total: pendingRules.length,
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Sincronizzazione completata',
      data: {
        synced,
        failed,
        total: pendingRules.length,
        errors: errors.length > 0 ? errors : undefined
      }
    });

  } catch (error) {
    logger.error('Errore nella sincronizzazione bulk', {
      error: error.message,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nella sincronizzazione',
      error: error.message
    });
  }
}));

/**
 * @swagger
 * /api/rules/statistics:
 *   get:
 *     summary: Statistiche regole
 *     description: Ottieni statistiche sulle regole firewall
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Statistiche recuperate con successo
 *       401:
 *         description: Token di accesso richiesto
 */
router.get('/statistics', asyncHandler(async (req, res) => {
  try {
    const [
      totalRules,
      activeRules,
      byInterface,
      byAction,
      syncStats
    ] = await Promise.all([
      Rule.count(),
      Rule.count({ where: { enabled: true, suspended: false } }),
      Rule.findAll({
        attributes: [
          'interface',
          [Rule.sequelize.fn('COUNT', '*'), 'count']
        ],
        group: ['interface'],
        raw: true
      }),
      Rule.findAll({
        attributes: [
          'action',
          [Rule.sequelize.fn('COUNT', '*'), 'count']
        ],
        group: ['action'],
        raw: true
      }),
      Rule.findAll({
        attributes: [
          'sync_status',
          [Rule.sequelize.fn('COUNT', '*'), 'count']
        ],
        group: ['sync_status'],
        raw: true
      })
    ]);

    const syncStatusMap = syncStats.reduce((acc, item) => {
      acc[item.sync_status || 'unknown'] = parseInt(item.count);
      return acc;
    }, {});

    res.json({
      success: true,
      message: 'Statistiche recuperate con successo',
      data: {
        total_rules: totalRules,
        active_rules: activeRules,
        by_interface: byInterface,
        by_action: byAction,
        sync_status: syncStatusMap
      }
    });

  } catch (error) {
    logger.error('Errore nel recupero statistiche', {
      error: error.message,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nel recupero delle statistiche',
      error: error.message
    });
  }
}));

/**
 * @swagger
 * /api/rules/{uuid}/clone:
 *   post:
 *     summary: Clona regola
 *     description: Crea una copia di una regola esistente
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: UUID della regola da clonare
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *                 description: Nuova descrizione per la regola clonata
 *                 example: "Copia di: Block malicious IPs"
 *     responses:
 *       201:
 *         description: Regola clonata con successo
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/:uuid/clone', validateUUID, asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user.hasPermission('create_rules')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti per clonare regole'
    });
  }

  const { uuid } = req.params;
  const { description } = req.body;

  const originalRule = await Rule.findOne({ where: { uuid } });

  if (!originalRule) {
    return res.status(404).json({
      success: false,
      message: 'Regola originale non trovata'
    });
  }

  try {
    const clonedRule = await originalRule.cloneRule(description);
    await clonedRule.update({ created_by: req.user.id });

    logger.info('Regola clonata', {
      original_uuid: uuid,
      cloned_uuid: clonedRule.uuid,
      user: req.user.username
    });

    res.status(201).json({
      success: true,
      message: 'Regola clonata con successo',
      data: {
        uuid: clonedRule.uuid,
        description: clonedRule.description
      }
    });

  } catch (error) {
    logger.error('Errore nella clonazione regola', {
      original_uuid: uuid,
      error: error.message,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nella clonazione della regola',
      error: error.message
    });
  }
}));

/**
 * @swagger
 * /api/rules/bulk:
 *   post:
 *     summary: Operazioni bulk su regole
 *     description: Esegue operazioni su multiple regole contemporaneamente
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - operation
 *               - rule_uuids
 *             properties:
 *               operation:
 *                 type: string
 *                 enum: [enable, disable, delete]
 *                 description: Operazione da eseguire
 *               rule_uuids:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uuid
 *                 description: Lista UUID delle regole
 *                 minItems: 1
 *                 maxItems: 50
 *     responses:
 *       200:
 *         description: Operazione bulk completata
 *       400:
 *         description: Parametri non validi
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/bulk', asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  const { operation, rule_uuids } = req.body;

  // Validazione input
  if (!operation || !rule_uuids || !Array.isArray(rule_uuids)) {
    return res.status(400).json({
      success: false,
      message: 'Parametri operation e rule_uuids richiesti'
    });
  }

  const validOperations = ['enable', 'disable', 'delete'];
  if (!validOperations.includes(operation)) {
    return res.status(400).json({
      success: false,
      message: `Operazione non valida. Usare: ${validOperations.join(', ')}`
    });
  }

  if (rule_uuids.length === 0 || rule_uuids.length > 50) {
    return res.status(400).json({
      success: false,
      message: 'Lista UUID deve contenere tra 1 e 50 elementi'
    });
  }

  // Verifica permessi
  const requiredPermission = operation === 'delete' ? 'delete_rules' : 'update_rules';
  if (!user.hasPermission(requiredPermission)) {
    return res.status(403).json({
      success: false,
      message: `Permessi insufficienti per operazione: ${operation}`
    });
  }

  try {
    const rules = await Rule.findAll({
      where: { uuid: rule_uuids }
    });

    if (rules.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Nessuna regola trovata con gli UUID forniti'
      });
    }

    const results = {
      success: 0,
      failed: 0,
      errors: []
    };

    for (const rule of rules) {
      try {
        switch (operation) {
          case 'enable':
          case 'disable':
            const enabled = operation === 'enable';
            await rule.update({ 
              enabled, 
              updated_by: req.user.id 
            });
            
            // Sincronizza con OPNsense se possibile
            if (rule.opnsense_uuid) {
              try {
                await OpnsenseService.toggleRule(rule.opnsense_uuid, enabled);
                await rule.update({
                  sync_status: 'synced',
                  last_synced_at: new Date()
                });
              } catch (syncError) {
                await rule.update({
                  sync_status: 'failed',
                  sync_error: syncError.message
                });
              }
            }
            break;

          case 'delete':
            // Elimina da OPNsense se sincronizzata
            if (rule.opnsense_uuid) {
              try {
                await OpnsenseService.deleteRule(rule.opnsense_uuid);
              } catch (syncError) {
                logger.warn('Errore eliminazione regola da OPNsense durante bulk delete', {
                  rule_uuid: rule.uuid,
                  error: syncError.message
                });
              }
            }
            await rule.destroy();
            break;
        }
        
        results.success++;
      } catch (error) {
        results.failed++;
        results.errors.push({
          rule_uuid: rule.uuid,
          error: error.message
        });
      }
    }

    logger.info('Operazione bulk completata', {
      operation,
      total: rules.length,
      success: results.success,
      failed: results.failed,
      user: req.user.username
    });

    res.json({
      success: true,
      message: `Operazione ${operation} completata`,
      data: {
        operation,
        total: rules.length,
        success: results.success,
        failed: results.failed,
        errors: results.errors.length > 0 ? results.errors : undefined
      }
    });

  } catch (error) {
    logger.error('Errore nell\'operazione bulk', {
      operation,
      error: error.message,
      user: req.user.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nell\'operazione bulk',
      error: error.message
    });
  }
}));

module.exports = router;