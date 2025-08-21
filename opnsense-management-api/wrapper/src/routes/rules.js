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
 *     description: Crea una nuova regola firewall nel database (senza sincronizzazione automatica)
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
 *               protocol:
 *                 type: string
 *                 description: Protocollo (TCP, UDP, ICMP, any)
 *                 default: any
 *               enabled:
 *                 type: boolean
 *                 description: Regola abilitata
 *                 default: true
 *               source_config:
 *                 type: object
 *                 description: Configurazione sorgente
 *               destination_config:
 *                 type: object
 *                 description: Configurazione destinazione
 *               log_enabled:
 *                 type: boolean
 *                 description: Logging abilitato
 *                 default: false
 *               direction:
 *                 type: string
 *                 enum: [in, out]
 *                 description: Direzione traffico
 *                 default: in
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

    // Crea regola nel database (senza sincronizzazione)
    const rule = await Rule.create(ruleData);

    logger.info('Regola creata nel database', {
      rule_id: rule.id,
      description: rule.description,
      user: req.user.username
    });

    res.status(201).json({
      success: true,
      message: 'Regola creata con successo nel database',
      data: {
        id: rule.id,
        uuid: rule.uuid || rule.id,
        description: rule.description,
        interface: rule.interface,
        action: rule.action,
        enabled: rule.enabled
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
 *     description: Aggiorna una regola firewall esistente nel database
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

    // Aggiorna regola nel database (senza sincronizzazione)
    await rule.update(updateData);

    logger.info('Regola aggiornata', {
      rule_id: rule.id,
      changes: Object.keys(updateData),
      enabled: rule.enabled,
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
 *     summary: Abilita/Disabilita regola
 *     description: Cambia lo stato enabled di una regola firewall
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
 *             required:
 *               - enabled
 *             properties:
 *               enabled:
 *                 type: boolean
 *                 description: Nuovo stato della regola (true = abilitata, false = disabilitata)
 *     responses:
 *       200:
 *         description: Stato regola cambiato con successo
 *       404:
 *         description: Regola non trovata
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.patch('/:id/toggle', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('update_rules')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti per modificare regole'
      });
    }

    const { id } = req.params;
    const { enabled } = req.body;
    
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

    // Aggiorna solo il campo enabled
    await rule.update({ 
      enabled: enabled,
      updated_by: req.user.id
    });

    logger.info('Stato regola cambiato', {
      rule_id: rule.id,
      enabled: enabled,
      user: req.user.username
    });

    res.json({
      success: true,
      message: `Regola ${enabled ? 'abilitata' : 'disabilitata'} con successo`,
      data: {
        id: rule.id,
        description: rule.description,
        enabled: rule.enabled
      }
    });

  } catch (error) {
    logger.error('Errore nel cambio stato regola', {
      id: req.params.id,
      error: error.message,
      user: req.user?.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nel cambio stato della regola',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno del server'
    });
  }
}));

/**
 * @swagger
 * /api/rules/{id}:
 *   delete:
 *     summary: Elimina regola firewall
 *     description: Elimina una regola firewall dal database
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

    // Elimina dal database (senza sincronizzazione)
    await rule.destroy();

    logger.info('Regola eliminata dal database', {
      rule_id: rule.id,
      description: rule.description,
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
        details: connectionTest.tests
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

/**
 * @swagger
 * /api/rules/test-connection:
 *   get:
 *     summary: Test connessione OPNsense
 *     description: Verifica la connettività e l'autenticazione con il server OPNsense
 *     tags: [Firewall Rules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Test connessione completato
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
 *                   example: Connessione OPNsense OK
 *                 data:
 *                   type: object
 *                   properties:
 *                     success:
 *                       type: boolean
 *                       example: true
 *                     responseTime:
 *                       type: integer
 *                       example: 245
 *                       description: Tempo di risposta in millisecondi
 *                     status:
 *                       type: integer
 *                       example: 200
 *                     timestamp:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 *       500:
 *         description: Errore nel test di connessione
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
 *                   example: Problemi di connessione OPNsense
 *                 data:
 *                   type: object
 *                   properties:
 *                     success:
 *                       type: boolean
 *                       example: false
 *                     error:
 *                       type: string
 *                     code:
 *                       type: string
 *                     status:
 *                       type: integer
 */ 
router.get('/test-connection', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('view_health')) {
      return res.status(403).json({
        success: false,
        message: 'Permessi insufficienti'
      });
    }

    const testResult = await OpnsenseService.testConnection();

    res.json({
      success: testResult.success,
      message: testResult.success ? 'Connessione OPNsense OK' : 'Problemi di connessione OPNsense',
      data: testResult
    });

  } catch (error) {
    logger.error('Errore nel test connessione', {
      error: error.message,
      user: req.user?.username
    });

    res.status(500).json({
      success: false,
      message: 'Errore nel test di connessione',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Errore interno'
    });
  }
}));

module.exports = router;