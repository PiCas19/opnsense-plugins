// routes/rules.js
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { validateRule, validateSearchQuery } = require('../middleware/validation');
const { asyncHandler } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

const User = require('../models/User');
const Rule = require('../models/Rule');
const OpnsenseService = require('../services/OpnsenseService');

// Autenticazione su tutte le rotte
router.use(authenticate);

/**
 * @swagger
 * /api/rules/local:
 *   get:
 *     summary: Elenco regole dal database locale
 *     description: Restituisce esclusivamente le regole presenti nel database locale con filtri e paginazione
 *     tags: [Firewall Rules - Local]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 25 }
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *       - in: query
 *         name: interface
 *         schema: { type: string }
 *       - in: query
 *         name: action
 *         schema: { type: string, enum: [pass, block, reject] }
 *       - in: query
 *         name: enabled
 *         schema: { type: boolean }
 *       - in: query
 *         name: sortBy
 *         schema: { type: string, default: uuid }
 *       - in: query
 *         name: sortOrder
 *         schema: { type: string, enum: [asc, desc], default: asc }
 *     responses:
 *       200:
 *         description: Elenco recuperato
 */
router.get('/local', validateSearchQuery, asyncHandler(async (req, res) => {
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
    const order = [[sortBy, String(sortOrder).toUpperCase()]];

    if (search) {
      where.description = { [Rule.sequelize.Op.iLike]: `%${search}%` };
    }
    if (iface) where.interface = iface;
    if (action) where.action = action;
    if (enabled !== undefined) where.enabled = enabled;

    const user = await User.findByPk(req.user.id);
    if (user && user.role !== 'admin' && Rule.rawAttributes?.approval_status) {
      where.approval_status = 'approved';
    }

    const { count, rows } = await Rule.findAndCountAll({
      where,
      offset: parseInt(offset),
      limit: parseInt(limit),
      order
    });

    logger.info('Regole locali recuperate', {
      count,
      page,
      limit,
      user: req.user.username,
      filters: { search, iface, action, enabled }
    });

    res.json({
      success: true,
      message: 'Regole locali recuperate con successo',
      data: rows,
      meta: {
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(count / limit)
      }
    });
  } catch (error) {
    logger.error('Errore recupero regole locali', { error: error.message, user: req.user?.username });
    res.status(500).json({ success: false, message: 'Errore nel recupero delle regole locali' });
  }
}));

/**
 * @swagger
 * /api/rules/opnsense:
 *   get:
 *     summary: Elenco regole da OPNsense
 *     description: Restituisce esclusivamente le regole dalla piattaforma OPNsense con filtri e paginazione
 *     tags: [Firewall Rules - OPNsense]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 50 }
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *       - in: query
 *         name: interface
 *         schema: { type: string }
 *       - in: query
 *         name: action
 *         schema: { type: string, enum: [pass, block, reject] }
 *       - in: query
 *         name: enabled
 *         schema: { type: boolean }
 *     responses:
 *       200:
 *         description: Elenco recuperato
 */
router.get('/opnsense', asyncHandler(async (req, res) => {
  try {
    // accesso a utenti autenticati; se vuoi reintrodurre i permessi rimetti il check
    logger.info('Accesso a /api/rules/opnsense', { user: req.user?.username, userId: req.user?.id });

    const { page = 1, limit = 50, search, interface: iface, action, enabled } = req.query;

    // test connessione; se fallisce ritorna 502 con dettagli
    const conn = await OpnsenseService.testConnection();
    if (!conn.success) {
      return res.status(502).json({
        success: false,
        message: 'OPNsense non raggiungibile',
        details: { code: conn.code, status: conn.status, error: conn.error }
      });
    }

    let all;
    try {
      all = await OpnsenseService.getRules();
    } catch (e) {
      // qualsiasi errore lato OPNsense deve tornare 502 (bad gateway) e non 500
      return res.status(502).json({
        success: false,
        message: 'Errore nel recupero delle regole da OPNsense',
        details: { error: e.message }
      });
    }

    const filtered = all.filter(r => {
      const bySearch = search ? String(r.description || '').toLowerCase().includes(String(search).toLowerCase()) : true;
      const byIface = iface ? String(r.interface || '').toLowerCase() === String(iface).toLowerCase() : true;
      const byAction = action ? String(r.action || '').toLowerCase() === String(action).toLowerCase() : true;
      const byEnabled =
        enabled !== undefined
          ? (String(r.enabled) === ((enabled === 'false' || enabled === false) ? '0' : '1') ||
             r.enabled === ((enabled === 'false' || enabled === false) ? false : true))
          : true;
      return bySearch && byIface && byAction && byEnabled;
    });

    const p = parseInt(page);
    const l = parseInt(limit);
    const start = (p - 1) * l;
    const end = start + l;

    return res.json({
      success: true,
      message: 'Regole OPNsense recuperate con successo',
      data: filtered.slice(start, end),
      meta: { total: filtered.length, page: p, limit: l, pages: Math.ceil(filtered.length / l) }
    });
  } catch (error) {
    logger.error('Errore inatteso /api/rules/opnsense', { error: error.message, user: req.user?.username });
    return res.status(500).json({ success: false, message: 'Errore inatteso' });
  }
}));


/**
 * @swagger
 * /api/rules/{id}:
 *   get:
 *     summary: Dettaglio regola da OPNsense
 *     description: Restituisce i dettagli di una regola identificata da UUID su OPNsense
 *     tags: [Firewall Rules - OPNsense]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Regola recuperata
 *       404:
 *         description: Regola non trovata
 */
router.get('/:id', asyncHandler(async (req, res) => {
  try {
 
    const { id } = req.params;

    console.log(id);

    const conn = await OpnsenseService.testConnection();
    if (!conn.success) {
      return res.status(502).json({ success: false, message: 'OPNsense non raggiungibile', details: conn });
    }

    const rule = await OpnsenseService.getRule(id);
    console.log(rule);
    if (!rule) {
      return res.status(404).json({ success: false, message: 'Regola non trovata in OPNsense' });
    }

    res.json({ success: true, message: 'Regola recuperata con successo', data: rule });
  } catch (error) {
    logger.error('Errore dettaglio regola OPNsense', { error: error.message, id: req.params.id });
    res.status(500).json({ success: false, message: 'Errore nel recupero della regola OPNsense' });
  }
}));

/**
 * @swagger
 * /api/rules:
 *   post:
 *     summary: Crea nuova regola (DB locale + OPNsense)
 *     description: Crea una nuova regola nel database locale e prova a sincronizzarla su OPNsense senza applicare
 *     tags: [Firewall Rules - Mixed]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [description, interface, action]
 *     responses:
 *       201:
 *         description: Regola creata
 */
router.post('/', validateRule, asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('create_rules')) {
      return res.status(403).json({ success: false, message: 'Permessi insufficienti per creare regole' });
    }

    const ruleData = { ...req.body, created_by: req.user.id };
    const rule = await Rule.create(ruleData);

    let syncResult = { opnsense_uuid: null, sync_status: 'pending', sync_error: null };

    try {
      const connectionTest = await OpnsenseService.testConnection();
      if (!connectionTest.success) throw new Error('OPNsense non raggiungibile');

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

      const opnsenseResult = await OpnsenseService.createRule(ruleForOPNsense);

      syncResult = {
        opnsense_uuid: opnsenseResult.uuid,
        sync_status: 'synced_pending_apply',
        last_synced_at: new Date(),
        sync_error: null
      };
    } catch (err) {
      syncResult = { sync_status: 'failed', sync_error: err.message };
      logger.warn('Sincronizzazione OPNsense fallita in creazione', { error: err.message });
    }

    if (Rule.rawAttributes?.sync_status) {
      await rule.update(syncResult);
    }

    res.status(201).json({
      success: true,
      message: syncResult.sync_status === 'synced_pending_apply'
        ? 'Regola creata. Eseguire /api/rules/apply per applicare.'
        : 'Regola creata nel database. Sincronizzazione con OPNsense non riuscita.',
      data: {
        id: rule.id,
        uuid: rule.uuid || rule.id,
        opnsense_uuid: syncResult.opnsense_uuid,
        sync_status: syncResult.sync_status,
        sync_error: syncResult.sync_error
      }
    });
  } catch (error) {
    logger.error('Errore creazione regola', { error: error.message, user: req.user?.username });
    res.status(500).json({ success: false, message: 'Errore nella creazione della regola' });
  }
}));

/**
 * @swagger
 * /api/rules/{id}:
 *   put:
 *     summary: Aggiorna regola su OPNsense
 *     description: Aggiorna una regola esistente su OPNsense identificata da UUID
 *     tags: [Firewall Rules - OPNsense]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description: { type: string }
 *               interface: { type: string }
 *               action: { type: string, enum: [pass, block, reject] }
 *               protocol: { type: string }
 *               enabled: { type: boolean }
 *               source_config: { type: object }
 *               destination_config: { type: object }
 *               log_enabled: { type: boolean }
 *               direction: { type: string, enum: [in, out] }
 *     responses:
 *       200:
 *         description: Regola aggiornata su OPNsense
 */
router.put('/:id', validateRule, asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('update_rules')) {
      return res.status(403).json({ success: false, message: 'Permessi insufficienti per aggiornare regole' });
    }

    const { id } = req.params;

    const connectionTest = await OpnsenseService.testConnection();
    if (!connectionTest.success) {
      return res.status(502).json({ success: false, message: 'OPNsense non raggiungibile', details: connectionTest });
    }

    const payload = {
      description: req.body.description,
      interface: req.body.interface,
      action: req.body.action,
      protocol: req.body.protocol,
      enabled: req.body.enabled,
      source_config: req.body.source_config,
      destination_config: req.body.destination_config,
      log_enabled: req.body.log_enabled,
      direction: req.body.direction
    };

    const result = await OpnsenseService.updateRule(id, payload);

    res.json({
      success: true,
      message: 'Regola aggiornata su OPNsense',
      data: { uuid: id, opnsense_response: result }
    });
  } catch (error) {
    logger.error('Errore aggiornamento regola OPNsense', { error: error.message, id: req.params.id });
    res.status(502).json({ success: false, message: 'Errore di comunicazione con OPNsense' });
  }
}));

/**
 * @swagger
 * /api/rules/{id}/toggle:
 *   patch:
 *     summary: Abilita o disabilita una regola su OPNsense
 *     tags: [Firewall Rules - OPNsense]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: apply
 *         schema: { type: boolean }
 *         description: Se true applica immediatamente la configurazione
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [enabled]
 *             properties:
 *               enabled: { type: boolean }
 *     responses:
 *       200:
 *         description: Stato modificato
 */
router.patch('/:id/toggle', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('update_rules')) {
      return res.status(403).json({ success: false, message: 'Permessi insufficienti' });
    }

    const { id } = req.params;
    let { enabled } = req.body;
    if (typeof enabled === 'string') enabled = enabled === 'true' || enabled === '1';
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ success: false, message: 'Campo "enabled" booleano richiesto' });
    }
    const applyNow = String(req.query.apply || '').toLowerCase() === 'true';

    const conn = await OpnsenseService.testConnection();
    if (!conn.success) return res.status(502).json({ success: false, message: 'OPNsense non raggiungibile', details: conn });

    const result = await OpnsenseService.toggleRule(id, enabled);
    if (applyNow) await OpnsenseService.applyConfig();

    res.json({
      success: true,
      message: `Regola ${enabled ? 'abilitata' : 'disabilitata'} su OPNsense${applyNow ? ' e applicata' : ''}`,
      data: { uuid: id, opnsense_enabled: enabled, applied: applyNow, opnsense_response: result?.opnsense_response || null }
    });
  } catch (error) {
    logger.error('Errore toggle regola OPNsense', { error: error.message, id: req.params.id });
    res.status(502).json({ success: false, message: 'Errore nel cambio stato della regola su OPNsense' });
  }
}));

/**
 * @swagger
 * /api/rules/{id}:
 *   delete:
 *     summary: Elimina una regola su OPNsense
 *     description: Elimina una regola identificata da UUID direttamente su OPNsense. Non tocca il database locale.
 *     tags: [Firewall Rules - OPNsense]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Regola eliminata su OPNsense
 */
router.delete('/:id', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('delete_rules')) {
      return res.status(403).json({ success: false, message: 'Permessi insufficienti per eliminare regole' });
    }

    const { id } = req.params;

    const conn = await OpnsenseService.testConnection();
    if (!conn.success) {
      return res.status(502).json({ success: false, message: 'OPNsense non raggiungibile', details: conn });
    }

    await OpnsenseService.deleteRule(id);

    res.json({ success: true, message: 'Regola eliminata su OPNsense', data: { uuid: id } });
  } catch (error) {
    logger.error('Errore eliminazione regola OPNsense', { error: error.message, id: req.params.id });
    res.status(502).json({ success: false, message: 'Errore nell\'eliminazione della regola su OPNsense' });
  }
}));

/**
 * @swagger
 * /api/rules/apply:
 *   post:
 *     summary: Applica configurazione su OPNsense
 *     description: Applica le modifiche pendenti su OPNsense
 *     tags: [Firewall Rules - OPNsense]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Configurazione applicata
 */
router.post('/apply', asyncHandler(async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user || !user.hasPermission('apply_config')) {
      return res.status(403).json({ success: false, message: 'Permessi insufficienti per applicare configurazione' });
    }

    const connectionTest = await OpnsenseService.testConnection();
    if (!connectionTest.success) {
      return res.status(502).json({
        success: false,
        message: 'OPNsense non raggiungibile',
        details: connectionTest
      });
    }

    await OpnsenseService.applyConfig();

    res.json({
      success: true,
      message: 'Configurazione applicata con successo',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Errore applicazione configurazione OPNsense', { error: error.message, user: req.user?.username });
    res.status(502).json({ success: false, message: 'Errore nell\'applicazione della configurazione' });
  }
}));

module.exports = router;