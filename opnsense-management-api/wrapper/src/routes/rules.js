const express = require('express');
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
 * components:
 *   schemas:
 *     RuleRequest:
 *       type: object
 *       required:
 *         - description
 *         - interface
 *         - action
 *       properties:
 *         description:
 *           type: string
 *           description: Descrizione della regola
 *           example: Block malicious IPs
 *         interface:
 *           type: string
 *           enum: [wan, lan, dmz, opt1, opt2, opt3, opt4]
 *           description: Interfaccia di rete
 *         action:
 *           type: string
 *           enum: [pass, block, reject]
 *           description: Azione da intraprendere
 *         protocol:
 *           type: string
 *           enum: [tcp, udp, icmp, any]
 *           default: any
 *           description: Protocollo
 *         enabled:
 *           type: boolean
 *           default: true
 *           description: Regola abilitata
 *         sequence:
 *           type: integer
 *           minimum: 1
 *           maximum: 9999
 *           description: Priorità (più basso = più alta priorità)
 *         direction:
 *           type: string
 *           enum: [in, out]
 *           default: in
 *           description: Direzione traffico
 *         log_enabled:
 *           type: boolean
 *           default: false
 *           description: Logging abilitato
 *         source_config:
 *           type: object
 *           properties:
 *             type:
 *               type: string
 *               enum: [any, single, network]
 *             address:
 *               type: string
 *               description: Indirizzo IP (per type=single)
 *             network:
 *               type: string
 *               description: Rete CIDR (per type=network)
 *             port:
 *               type: integer
 *               minimum: 1
 *               maximum: 65535
 *         destination_config:
 *           type: object
 *           properties:
 *             type:
 *               type: string
 *               enum: [any, single, network]
 *             address:
 *               type: string
 *               description: Indirizzo IP (per type=single)
 *             network:
 *               type: string
 *               description: Rete CIDR (per type=network)
 *             port:
 *               type: integer
 *               minimum: 1
 *               maximum: 65535
 *         category:
 *           type: string
 *           description: Categoria regola
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *         risk_level:
 *           type: string
 *           enum: [low, medium, high, critical]
 *           default: medium
 *         business_justification:
 *           type: string
 *           description: Giustificazione business
 *         expires_at:
 *           type: string
 *           format: date-time
 *           description: Data scadenza
 *         auto_disable_on_expiry:
 *           type: boolean
 *           default: false
 * 
 *     RuleResponse:
 *       allOf:
 *         - $ref: '#/components/schemas/Rule'
 *         - type: object
 *           properties:
 *             source:
 *               type: string
 *               description: Sorgente formattata
 *             destination:
 *               type: string
 *               description: Destinazione formattata
 * 
 *     RulesList:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Regole recuperate con successo
 *         data:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/RuleResponse'
 *         meta:
 *           type: object
 *           properties:
 *             total:
 *               type: integer
 *             page:
 *               type: integer
 *             limit:
 *               type: integer
 *             pages:
 *               type: integer
 */

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
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/RulesList'
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.get('/', validateSearchQuery, asyncHandler(async (req, res) => {
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
    where.approval_status = 'approved';
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
        attributes: ['id', 'username', 'first_name', 'last_name']
      }
    ]
  });

  logger.info('Rules list retrieved', {
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
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Regola recuperata con successo
 *                 data:
 *                   $ref: '#/components/schemas/RuleResponse'
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

  logger.info('Rule retrieved', { uuid, user: req.user.username });

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
 *             $ref: '#/components/schemas/RuleRequest'
 *           examples:
 *             blockRule:
 *               summary: Regola di blocco
 *               value:
 *                 description: Block malicious IPs
 *                 interface: wan
 *                 action: block
 *                 protocol: any
 *                 source_config:
 *                   type: network
 *                   network: 192.168.100.0/24
 *                 destination_config:
 *                   type: any
 *                 enabled: true
 *                 log_enabled: true
 *                 risk_level: high
 *             allowRule:
 *               summary: Regola di permesso
 *               value:
 *                 description: Allow SSH access
 *                 interface: lan
 *                 action: pass
 *                 protocol: tcp
 *                 source_config:
 *                   type: network
 *                   network: 192.168.1.0/24
 *                 destination_config:
 *                   type: single
 *                   address: 192.168.216.1
 *                   port: 22
 *                 enabled: true
 *                 risk_level: medium
 *     responses:
 *       201:
 *         description: Regola creata con successo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Regola creata con successo
 *                 data:
 *                   type: object
 *                   properties:
 *                     uuid:
 *                       type: string
 *                       format: uuid
 *                     opnsense_uuid:
 *                       type: string
 *                       format: uuid
 *       400:
 *         description: Dati regola non validi
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.post('/', validateRule, asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user.hasPermission('create_rules')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti'
    });
  }

  const ruleData = {
    ...req.body,
    created_by: req.user.id
  };

  // Crea regola nel database
  const rule = await Rule.create(ruleData);

  // Tenta sincronizzazione con OPNsense
  try {
    const opnsenseResult = await OpnsenseService.createRule(rule.toOpnsenseFormat());
    await rule.update({
      opnsense_uuid: opnsenseResult.uuid,
      sync_status: 'synced',
      last_synced_at: new Date()
    });
  } catch (opnsenseError) {
    logger.error('Failed to sync rule with OPNsense', {
      rule_id: rule.id,
      error: opnsenseError.message
    });
    await rule.update({
      sync_status: 'failed',
      sync_error: opnsenseError.message
    });
  }

  logger.info('Rule created', {
    rule_id: rule.id,
    uuid: rule.uuid,
    description: rule.description,
    user: req.user.username
  });

  res.status(201).json({
    success: true,
    message: 'Regola creata con successo',
    data: {
      uuid: rule.uuid,
      opnsense_uuid: rule,
      opnsense_uuid: rule.opnsense_uuid,
     sync_status: rule.sync_status
   }
 });
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
*         content:
*           application/json:
*             schema:
*               $ref: '#/components/schemas/Success'
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
     message: 'Permessi insufficienti'
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

 const updateData = {
   ...req.body,
   updated_by: req.user.id
 };

 // Aggiorna regola nel database
 await rule.update(updateData);

 // Tenta sincronizzazione con OPNsense
 try {
   if (rule.opnsense_uuid) {
     await OpnsenseService.updateRule(rule.opnsense_uuid, rule.toOpnsenseFormat());
     await rule.update({
       sync_status: 'synced',
       last_synced_at: new Date(),
       sync_error: null
     });
   }
 } catch (opnsenseError) {
   logger.error('Failed to sync updated rule with OPNsense', {
     rule_id: rule.id,
     error: opnsenseError.message
   });
   await rule.update({
     sync_status: 'failed',
     sync_error: opnsenseError.message
   });
 }

 logger.info('Rule updated', {
   rule_id: rule.id,
   uuid: rule.uuid,
   user: req.user.username
 });

 res.json({
   success: true,
   message: 'Regola aggiornata con successo'
 });
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
*         content:
*           application/json:
*             schema:
*               $ref: '#/components/schemas/Success'
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
     message: 'Permessi insufficienti'
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

 // Elimina da OPNsense se sincronizzata
 try {
   if (rule.opnsense_uuid) {
     await OpnsenseService.deleteRule(rule.opnsense_uuid);
   }
 } catch (opnsenseError) {
   logger.warn('Failed to delete rule from OPNsense, continuing with database deletion', {
     rule_id: rule.id,
     error: opnsenseError.message
   });
 }

 // Soft delete dal database
 await rule.destroy();

 logger.info('Rule deleted', {
   rule_id: rule.id,
   uuid: rule.uuid,
   user: req.user.username
 });

 res.json({
   success: true,
   message: 'Regola eliminata con successo'
 });
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
*         content:
*           application/json:
*             schema:
*               $ref: '#/components/schemas/Success'
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
     message: 'Permessi insufficienti'
   });
 }

 const { uuid } = req.params;
 const { enabled } = req.body;

 if (typeof enabled !== 'boolean') {
   return res.status(400).json({
     success: false,
     message: 'Stato enabled richiesto (boolean)'
   });
 }

 const rule = await Rule.findOne({ where: { uuid } });

 if (!rule) {
   return res.status(404).json({
     success: false,
     message: 'Regola non trovata'
   });
 }

 // Aggiorna stato nel database
 await rule.update({
   enabled,
   updated_by: req.user.id
 });

 // Sincronizza con OPNsense
 try {
   if (rule.opnsense_uuid) {
     await OpnsenseService.toggleRule(rule.opnsense_uuid, enabled);
     await rule.update({
       sync_status: 'synced',
       last_synced_at: new Date(),
       sync_error: null
     });
   }
 } catch (opnsenseError) {
   logger.error('Failed to toggle rule in OPNsense', {
     rule_id: rule.id,
     error: opnsenseError.message
   });
   await rule.update({
     sync_status: 'failed',
     sync_error: opnsenseError.message
   });
 }

 logger.info('Rule toggled', {
   rule_id: rule.id,
   uuid: rule.uuid,
   enabled,
   user: req.user.username
 });

 res.json({
   success: true,
   message: `Regola ${enabled ? 'abilitata' : 'disabilitata'} con successo`
 });
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
*         content:
*           application/json:
*             schema:
*               $ref: '#/components/schemas/Success'
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
     message: 'Permessi insufficienti'
   });
 }

 try {
   await OpnsenseService.applyConfig();

   logger.info('Configuration applied manually', {
     user: req.user.username
   });

   res.json({
     success: true,
     message: 'Configurazione applicata con successo'
   });
 } catch (error) {
   logger.error('Failed to apply configuration', {
     error: error.message,
     user: req.user.username
   });

   res.status(502).json({
     success: false,
     message: 'Errore nell\'applicazione della configurazione'
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
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 success:
*                   type: boolean
*                   example: true
*                 message:
*                   type: string
*                   example: Sincronizzazione completata
*                 data:
*                   type: object
*                   properties:
*                     synced:
*                       type: integer
*                       description: Numero di regole sincronizzate
*                     failed:
*                       type: integer
*                       description: Numero di regole fallite
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
     message: 'Permessi insufficienti'
   });
 }

 const pendingRules = await Rule.findNeedingSync();
 let synced = 0;
 let failed = 0;

 for (const rule of pendingRules) {
   try {
     await rule.syncToOPNsense();
     synced++;
   } catch (error) {
     failed++;
     logger.error('Failed to sync rule', {
       rule_id: rule.id,
       error: error.message
     });
   }
 }

 logger.info('Bulk sync completed', {
   synced,
   failed,
   user: req.user.username
 });

 res.json({
   success: true,
   message: 'Sincronizzazione completata',
   data: {
     synced,
     failed
   }
 });
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
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 success:
*                   type: boolean
*                   example: true
*                 message:
*                   type: string
*                   example: Statistiche recuperate con successo
*                 data:
*                   type: object
*                   properties:
*                     total_rules:
*                       type: integer
*                     active_rules:
*                       type: integer
*                     by_interface:
*                       type: array
*                       items:
*                         type: object
*                         properties:
*                           interface:
*                             type: string
*                           count:
*                             type: integer
*                     by_action:
*                       type: array
*                       items:
*                         type: object
*                         properties:
*                           action:
*                             type: string
*                           count:
*                             type: integer
*                     sync_status:
*                       type: object
*                       properties:
*                         synced:
*                           type: integer
*                         pending:
*                           type: integer
*                         failed:
*                           type: integer
*       401:
*         description: Token di accesso richiesto
*/
router.get('/statistics', asyncHandler(async (req, res) => {
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

 res.json({
   success: true,
   message: 'Statistiche recuperate con successo',
   data: {
     total_rules: totalRules,
     active_rules: activeRules,
     by_interface: byInterface,
     by_action: byAction,
     sync_status: syncStats.reduce((acc, item) => {
       acc[item.sync_status] = parseInt(item.count);
       return acc;
     }, {})
   }
 });
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
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 success:
*                   type: boolean
*                   example: true
*                 message:
*                   type: string
*                   example: Regola clonata con successo
*                 data:
*                   type: object
*                   properties:
*                     uuid:
*                       type: string
*                       format: uuid
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
     message: 'Permessi insufficienti'
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

 const clonedRule = await originalRule.cloneRule(description);
 await clonedRule.update({ created_by: req.user.id });

 logger.info('Rule cloned', {
   original_uuid: uuid,
   cloned_uuid: clonedRule.uuid,
   user: req.user.username
 });

 res.status(201).json({
   success: true,
   message: 'Regola clonata con successo',
   data: {
     uuid: clonedRule.uuid
   }
 });
}));

module.exports = router;