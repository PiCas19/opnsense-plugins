const express = require('express');
const { authenticate } = require('../middleware/auth');
const { validateRule, validateSearchQuery } = require('../middleware/validation');
const { asyncHandler } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

// Crea il router PRIMA di tutto
const router = express.Router();

// Import dei modelli DOPO aver creato il router
const User = require('../models/User'); 
const Rule = require('../models/Rule');
const OpnsenseService = require('../services/OpnsenseService');

// Applica autenticazione a tutte le rotte
router.use(authenticate);

/**
 * @swagger
 * /api/rules:
 *   get:
 *     summary: Ottieni lista regole firewall
 *     description: Recupera tutte le regole firewall dal database locale e da OPNsense con opzioni di filtro e paginazione
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
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
      sortBy = 'id', 
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
    if (user && user.role !== 'admin') {
      // Verifica se esiste il campo approval_status
      if (Rule.rawAttributes && Rule.rawAttributes.approval_status) {
        where.approval_status = 'approved';
      }
    }

    // Recupera regole dal database locale
    const { count, rows } = await Rule.findAndCountAll({
      where,
      offset: parseInt(offset),
      limit: parseInt(limit),
      order
    });

    // Tenta di recuperare anche regole da OPNsense per confronto
    let opnsenseRules = [];
    try {
      const connectionTest = await OpnsenseService.testConnection();
      if (connectionTest.success) {
        opnsenseRules = await OpnsenseService.getRules();
      }
    } catch (opnsenseError) {
      logger.warn('Impossibile recuperare regole da OPNsense', {
        error: opnsenseError.message,
        user: req.user.username
      });
    }

    // Arricchisci le regole locali con info OPNsense
    const enrichedRules = rows.map(rule => {
      const opnsenseMatch = opnsenseRules.find(opRule => 
        opRule.uuid === rule.opnsense_uuid || 
        opRule.description === rule.description
      );
      
      return {
        ...rule.toJSON(),
        opnsense_status: opnsenseMatch ? 'found' : 'not_found',
        opnsense_enabled: opnsenseMatch?.enabled || null
      };
    });

    logger.info('Lista regole recuperata', {
      count,
      page,
      limit,
      opnsense_rules_found: opnsenseRules.length,
      user: req.user.username,
      filters: { search, iface, action, enabled }
    });

    res.json({
      success: true,
      message: 'Regole recuperate con successo',
      data: enrichedRules,
      meta: {
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(count / limit),
        opnsense_connection: opnsenseRules.length > 0
      }
    });

  } catch (error) {
    logger.error('Errore nel recupero lista regole', {
      error: error.message,
      stack: error.stack,
      user: req.user?.username
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
 * /api/rules/{id}:
 *   get:
 *     summary: Ottieni regola specifica
 *     description: Recupera una singola regola firewall per ID dal database locale e verifica su OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID della regola
 *     responses:
 *       200:
 *         description: Regola recuperata con successo
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 */
router.get('/:id', asyncHandler(async (req, res) => {
  try {
    const { id } = req.params;
    
    // Cerca per ID (numerico) o UUID se presente
    let rule;
    if (!isNaN(id)) {
      rule = await Rule.findByPk(id);
    } else {
      // Se il modello ha il campo uuid
      if (Rule.rawAttributes && Rule.rawAttributes.uuid) {
        rule = await Rule.findOne({ where: { uuid: id } });
      }
    }

    if (!rule) {
      return res.status(404).json({
        success: false,
        message: 'Regola non trovata'
      });
    }

    // Verifica stato su OPNsense se sincronizzata
    let opnsenseStatus = null;
    if (rule.opnsense_uuid) {
      try {
        const connectionTest = await OpnsenseService.testConnection();
        if (connectionTest.success) {
          const opnsenseRule = await OpnsenseService.getRule(rule.opnsense_uuid);
          opnsenseStatus = {
            found: !!opnsenseRule,
            enabled: opnsenseRule?.enabled || null,
            last_modified: opnsenseRule?.last_modified || null
          };
        }
      } catch (opnsenseError) {
        logger.warn('Errore verifica regola su OPNsense', {
          rule_id: rule.id,
          opnsense_uuid: rule.opnsense_uuid,
          error: opnsenseError.message
        });
        opnsenseStatus = { error: opnsenseError.message };
      }
    }

    logger.info('Regola recuperata', { 
      rule_id: rule.id, 
      opnsense_status: opnsenseStatus,
      user: req.user.username 
    });

    res.json({
      success: true,
      message: 'Regola recuperata con successo',
      data: {
        ...rule.toJSON(),
        opnsense_status: opnsenseStatus
      }
    });

  } catch (error) {
    logger.error('Errore nel recupero regola', {
      id: req.params.id,
      error: error.message,
      user: req.user?.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nel recupero della regola',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
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
 *               interface:
 *                 type: string
 *                 description: Interfaccia di rete
 *               action:
 *                 type: string
 *                 enum: [pass, block, reject]
 *                 description: Azione da intraprendere
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

    // Tenta sincronizzazione con OPNsense (senza applicare config)
    let syncResult = {
      opnsense_uuid: null,
      sync_status: 'pending',
      sync_error: null
    };

    try {
      // Test connessione OPNsense prima di procedere
      const connectionTest = await OpnsenseService.testConnection();
      
      if (!connectionTest.success) {
        throw new Error(`OPNsense non raggiungibile: ${JSON.stringify(connectionTest.tests)}`);
      }

      // Prepara dati per OPNsense
      const ruleForOPNsense = {
        description: rule.description,
        interface: rule.interface,
        action: rule.action,
        protocol: rule.protocol || 'any',
        enabled: rule.enabled !== false,
        source_config: rule.source_config || { type: 'any' },
        destination_config: rule.destination_config || { type: 'any' },
        log_enabled: rule.log_enabled || false,
        direction: rule.direction || 'in'
      };

      logger.info('Tentativo creazione regola OPNsense', {
        rule_id: rule.id,
        ruleForOPNsense
      });

      const opnsenseResult = await OpnsenseService.createRule(ruleForOPNsense);
      
      syncResult = {
        opnsense_uuid: opnsenseResult.uuid,
        sync_status: 'synced_pending_apply',
        last_synced_at: new Date(),
        sync_error: null
      };

      logger.info('Regola creata in OPNsense, configurazione non ancora applicata', {
        rule_id: rule.id,
        opnsense_uuid: opnsenseResult.uuid
      });

    } catch (opnsenseError) {
      logger.error('Errore sincronizzazione regola con OPNsense', {
        rule_id: rule.id,
        error: opnsenseError.message,
        stack: opnsenseError.stack
      });
      
      syncResult = {
        sync_status: 'failed',
        sync_error: opnsenseError.message
      };
    }

    // Aggiorna regola con risultato sincronizzazione
    if (Rule.rawAttributes.sync_status) {
      await rule.update(syncResult);
    }

    logger.info('Regola creata nel database', {
      rule_id: rule.id,
      description: rule.description,
      sync_status: syncResult.sync_status,
      user: req.user.username
    });

    res.status(201).json({
      success: true,
      message: syncResult.sync_status === 'synced_pending_apply' 
        ? 'Regola creata con successo. Usa /api/rules/apply per applicare la configurazione.'
        : 'Regola creata nel database. Sincronizzazione con OPNsense fallita.',
      data: {
        id: rule.id,
        uuid: rule.uuid || rule.id,
        opnsense_uuid: syncResult.opnsense_uuid,
        sync_status: syncResult.sync_status,
        sync_error: syncResult.sync_error
      },
      next_steps: syncResult.sync_status === 'synced_pending_apply' 
        ? 'Chiamare POST /api/rules/apply per applicare le modifiche al firewall'
        : 'Controllare i log e riprovare la sincronizzazione'
    });

  } catch (error) {
    logger.error('Errore nella creazione regola', {
      error: error.message,
      stack: error.stack,
      ruleData: req.body,
      user: req.user?.username
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
 * /api/rules/{id}:
 *   put:
 *     summary: Aggiorna regola firewall
 *     description: Aggiorna una regola firewall esistente nel database locale
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID della regola
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *                 description: Descrizione della regola
 *               interface:
 *                 type: string
 *                 description: Interfaccia di rete
 *               action:
 *                 type: string
 *                 enum: [pass, block, reject]
 *                 description: Azione da intraprendere
 *               protocol:
 *                 type: string
 *                 description: Protocollo (TCP, UDP, ICMP, any)
 *               enabled:
 *                 type: boolean
 *                 description: Regola abilitata/disabilitata
 *               source_config:
 *                 type: object
 *                 description: Configurazione sorgente
 *                 properties:
 *                   type:
 *                     type: string
 *                     enum: [any, network, host, alias]
 *                   value:
 *                     type: string
 *                     description: Indirizzo IP, rete o alias
 *                   port:
 *                     type: string
 *                     description: Porta o range di porte
 *               destination_config:
 *                 type: object
 *                 description: Configurazione destinazione
 *                 properties:
 *                   type:
 *                     type: string
 *                     enum: [any, network, host, alias]
 *                   value:
 *                     type: string
 *                     description: Indirizzo IP, rete o alias
 *                   port:
 *                     type: string
 *                     description: Porta o range di porte
 *               log_enabled:
 *                 type: boolean
 *                 description: Logging abilitato
 *               direction:
 *                 type: string
 *                 enum: [in, out]
 *                 description: Direzione traffico
 *     responses:
 *       200:
 *         description: Regola aggiornata con successo
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
 *                   example: Regola aggiornata con successo
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     description:
 *                       type: string
 *                     enabled:
 *                       type: boolean
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.put('/:id', validateRule, asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('update_rules')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti per aggiornare regole'
      });
    }

    const { id } = req.params;
    
    // Cerca regola
    let rule;
    if (!isNaN(id)) {
      rule = await Rule.findByPk(id);
    } else if (Rule.rawAttributes && Rule.rawAttributes.uuid) {
      rule = await Rule.findOne({ where: { uuid: id } });
    }

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

    logger.info('Regola aggiornata', {
      rule_id: rule.id,
      changes: Object.keys(updateData),
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Regola aggiornata con successo',
      data: {
        id: rule.id,
        description: rule.description,
        enabled: rule.enabled,
        action: rule.action,
        interface: rule.interface
      }
    });

  } catch (error) {
    logger.error('Errore nell\'aggiornamento regola', {
      id: req.params.id,
      error: error.message,
      user: req.user?.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nell\'aggiornamento della regola',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

/**
 * @swagger
 * /api/rules/{id}/toggle:
 *   patch:
 *     summary: Toggle/Forza stato regola su OPNsense
 *     description: Usa l'endpoint nativo toggle_rule di OPNsense. Se "enabled" è omesso, lo stato viene invertito su OPNsense. Se "enabled" è presente, viene forzato (true/false).
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID della regola
 *       - in: query
 *         name: apply
 *         schema:
 *           type: boolean
 *         description: Se true applica subito la configurazione su OPNsense
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               enabled:
 *                 type: boolean
 *                 description: Se omesso, esegue il toggle puro su OPNsense
 *     responses:
 *       200:
 *         description: Stato regola cambiato con successo su OPNsense
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 *       502:
 *         description: Errore comunicazione con OPNsense
 */
router.patch('/:id/toggle', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('update_rules')) {
      return res.status(403).json({ success: false, message: 'Permessi insufficienti per modificare regole' });
    }

    const { id } = req.params;

    // enabled può essere boolean/"1"/"0"/"true"/"false"/omesso
    let { enabled } = req.body ?? {};
    if (enabled === '' || enabled === undefined || enabled === null) {
      enabled = null; // toggle puro
    } else if (typeof enabled === 'string') {
      enabled = enabled === 'true' || enabled === '1';
    } else if (typeof enabled !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'Campo "enabled" deve essere boolean, "1"/"0", "true"/"false" oppure omesso per toggle'
      });
    }

    const applyNow = String(req.query.apply || '').toLowerCase() === 'true';

    // trova regola locale
    let rule;
    if (!isNaN(id)) rule = await Rule.findByPk(id);
    else if (Rule.rawAttributes?.uuid) rule = await Rule.findOne({ where: { uuid: id } });

    if (!rule) return res.status(404).json({ success: false, message: 'Regola non trovata' });
    if (!rule.opnsense_uuid) {
      return res.status(400).json({ success: false, message: 'Regola non sincronizzata con OPNsense' });
    }

    // test connessione
    const connectionTest = await OpnsenseService.testConnection();
    if (!connectionTest.success) {
      return res.status(502).json({
        success: false,
        message: 'OPNsense non raggiungibile',
        details: connectionTest
      });
    }

    // toggle semplice tramite endpoint nativo
    const result = await OpnsenseService.toggleRule(rule.opnsense_uuid, enabled);

    // apply opzionale
    if (applyNow) await OpnsenseService.applyConfig();

    // aggiorna DB locale solo se stato forzato
    if (enabled !== null) {
      const payload = { enabled };
      if (Rule.rawAttributes?.sync_status) payload.sync_status = applyNow ? 'synced' : 'synced_pending_apply';
      if (Rule.rawAttributes?.last_synced_at) payload.last_synced_at = new Date();
      await rule.update(payload);
    }

    logger.info('Toggle eseguito su OPNsense', {
      rule_id: rule.id, opnsense_uuid: rule.opnsense_uuid, forcedEnabled: enabled, apply: applyNow, user: req.user.username
    });

    return res.json({
      success: true,
      message: `Toggle su OPNsense eseguito${applyNow ? ' e applicato' : ''}${enabled === null ? '' : ` (stato forzato a ${enabled ? 'abilitato' : 'disabilitato'})`}`,
      data: {
        id: rule.id,
        uuid: rule.uuid || String(rule.id),
        description: rule.description,
        interface: rule.interface,
        action: rule.action,
        opnsense_uuid: rule.opnsense_uuid,
        forced_enabled: enabled, // null se toggle puro
        applied: applyNow,
        opnsense_response: result?.opnsense_response || null
      }
    });

  } catch (error) {
    logger.error('Errore nel toggle regola su OPNsense', { id: req.params.id, error: error.message, user: req.user?.username });
    return res.status(502).json({
      success: false,
      message: 'Errore nel cambio stato della regola su OPNsense',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore di comunicazione con OPNsense'
    });
  }
}));



/**
 * @swagger
 * /api/rules/{id}:
 *   delete:
 *     summary: Elimina regola firewall
 *     description: Elimina una regola firewall dal database locale e da OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID della regola
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
router.delete('/:id', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('delete_rules')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti per eliminare regole'
      });
    }

    const { id } = req.params;
    
    // Cerca regola
    let rule;
    if (!isNaN(id)) {
      rule = await Rule.findByPk(id);
    } else if (Rule.rawAttributes && Rule.rawAttributes.uuid) {
      rule = await Rule.findOne({ where: { uuid: id } });
    }

    if (!rule) {
      return res.status(404).json({
        success: false,
        message: 'Regola non trovata'
      });
    }

    let opnsenseResult = { success: false, error: null };

    // Elimina da OPNsense se sincronizzata
    if (rule.opnsense_uuid) {
      try {
        const connectionTest = await OpnsenseService.testConnection();
        if (connectionTest.success) {
          await OpnsenseService.deleteRule(rule.opnsense_uuid);
          opnsenseResult.success = true;
          logger.info('Regola eliminata da OPNsense', {
            rule_id: rule.id,
            opnsense_uuid: rule.opnsense_uuid
          });
        } else {
          throw new Error('OPNsense non raggiungibile');
        }
      } catch (opnsenseError) {
        opnsenseResult.error = opnsenseError.message;
        logger.warn('Errore eliminazione regola da OPNsense', {
          rule_id: rule.id,
          opnsense_uuid: rule.opnsense_uuid,
          error: opnsenseError.message
        });
      }
    }

    // Elimina dal database locale
    await rule.destroy();

    logger.info('Regola eliminata dal database locale', {
      rule_id: rule.id,
      description: rule.description,
      opnsense_deleted: opnsenseResult.success,
      user: req.user.username
    });

    const message = rule.opnsense_uuid 
      ? opnsenseResult.success 
        ? 'Regola eliminata con successo da database locale e OPNsense'
        : `Regola eliminata dal database locale. Errore OPNsense: ${opnsenseResult.error}`
      : 'Regola eliminata con successo dal database locale';

    res.json({
      success: true,
      message: message,
      data: {
        local_deleted: true,
        opnsense_deleted: opnsenseResult.success,
        opnsense_error: opnsenseResult.error
      }
    });

  } catch (error) {
    logger.error('Errore nell\'eliminazione regola', {
      id: req.params.id,
      error: error.message,
      user: req.user?.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nell\'eliminazione della regola',
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
    const totalRules = await Rule.count();
    const activeRules = await Rule.count({ where: { enabled: true } });

    const byInterface = await Rule.findAll({
      attributes: [
        'interface',
        [Rule.sequelize.fn('COUNT', '*'), 'count']
      ],
      group: ['interface'],
      raw: true
    });

    const byAction = await Rule.findAll({
      attributes: [
        'action',
        [Rule.sequelize.fn('COUNT', '*'), 'count']
      ],
      group: ['action'],
      raw: true
    });

    res.json({
      success: true,
      message: 'Statistiche recuperate con successo',
      data: {
        total_rules: totalRules,
        active_rules: activeRules,
        by_interface: byInterface,
        by_action: byAction
      }
    });

  } catch (error) {
    logger.error('Errore nel recupero statistiche', {
      error: error.message,
      user: req.user?.username
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
 * /api/rules/apply:
 *   post:
 *     summary: Applica configurazione firewall
 *     description: Applica tutte le modifiche pending alla configurazione OPNsense e attiva le regole nel firewall
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Configurazione applicata con successo
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
 *                   example: Configurazione applicata con successo
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: 2024-01-15T10:30:00.000Z
 *       401:
 *         description: Token di accesso richiesto
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: Permessi insufficienti per applicare configurazione
 *       502:
 *         description: Errore comunicazione con OPNsense
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: OPNsense non raggiungibile
 *                 details:
 *                   type: object
 *                   description: Dettagli del test di connessione
 *                 suggestion:
 *                   type: string
 *                   example: Verificare la connessione con OPNsense e riprovare
 */  
router.post('/apply', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('apply_config')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti per applicare configurazione'
      });
    }

    logger.info('Tentativo applicazione configurazione OPNsense', {
      user: req.user.username
    });

    // Test connessione prima dell'applicazione
    const connectionTest = await OpnsenseService.testConnection();
    if (!connectionTest.success) {
      return res.status(502).json({
        success: false,
        message: 'OPNsense non raggiungibile',
        details: connectionTest.tests,
        suggestion: 'Verificare la connessione con OPNsense e riprovare'
      });
    }

    // Applica configurazione
    await OpnsenseService.applyConfig();

    // Aggiorna stato delle regole in pending
    if (Rule.rawAttributes.sync_status) {
      await Rule.update(
        { 
          sync_status: 'synced',
          last_applied_at: new Date()
        },
        { 
          where: { 
            sync_status: 'synced_pending_apply' 
          }
        }
      );
    }

    logger.info('Configurazione OPNsense applicata con successo', {
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Configurazione applicata con successo',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Errore nell\'applicazione configurazione', {
      error: error.message,
      stack: error.stack,
      user: req.user?.username
    });

    res.status(502).json({
      success: false,
      message: 'Errore nell\'applicazione della configurazione',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore di comunicazione con OPNsense',
      suggestion: 'Verificare la connessione con OPNsense e riprovare'
    });
  }
}));

module.exports = router;