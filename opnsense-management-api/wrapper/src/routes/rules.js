const express = require('express');
const { authenticate } = require('../middleware/auth');
const { validateRule, validateUUID, validateSearchQuery } = require('../middleware/validation-simple');
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
 *     description: Recupera tutte le regole firewall con opzioni di filtro e paginazione
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

    const { count, rows } = await Rule.findAndCountAll({
      where,
      offset: parseInt(offset),
      limit: parseInt(limit),
      order
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
 *     description: Recupera una singola regola firewall per ID
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

    logger.info('Regola recuperata', { 
      rule_id: rule.id, 
      user: req.user.username 
    });

    res.json({
      success: true,
      message: 'Regola recuperata con successo',
      data: rule
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

    // Tenta sincronizzazione con OPNsense
    let syncResult = {
      opnsense_uuid: null,
      sync_status: 'pending',
      sync_error: null
    };

    try {
      // Prepara dati per OPNsense
      const ruleForOPNsense = {
        description: rule.description,
        interface: rule.interface,
        action: rule.action,
        protocol: rule.protocol || 'any',
        enabled: rule.enabled !== false,
        source_config: rule.source_config || { type: 'any' },
        destination_config: rule.destination_config || { type: 'any' }
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
    if (Rule.rawAttributes.sync_status) {
      await rule.update(syncResult);
    }

    logger.info('Regola creata', {
      rule_id: rule.id,
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
 *     description: Aggiorna una regola firewall esistente
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
 *         description: Regola aggiornata con successo
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
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Regola aggiornata con successo'
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
 * /api/rules/{id}:
 *   delete:
 *     summary: Elimina regola firewall
 *     description: Elimina una regola firewall dal database e da OPNsense
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

    // Elimina da OPNsense se sincronizzata
    if (rule.opnsense_uuid) {
      try {
        await OpnsenseService.deleteRule(rule.opnsense_uuid);
      } catch (opnsenseError) {
        logger.warn('Errore eliminazione regola da OPNsense', {
          rule_id: rule.id,
          error: opnsenseError.message
        });
      }
    }

    // Elimina dal database
    await rule.destroy();

    logger.info('Regola eliminata', {
      rule_id: rule.id,
      user: req.user.username
    });

    res.json({
      success: true,
      message: 'Regola eliminata con successo'
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

module.exports = router;