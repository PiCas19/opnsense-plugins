const express = require('express');
const { authenticate } = require('../middleware/auth');
const { validateUser, validateUserUpdate, validateSearchQuery } = require('../middleware/validation');
const User = require('../models/User');
const asyncHandler = require('express-async-handler');
const logger = require('../utils/logger');

const router = express.Router();

// Applica autenticazione a tutte le rotte
router.use(authenticate);

/**
 * @swagger
 * components:
 *   schemas:
 *     UserRequest:
 *       type: object
 *       required:
 *         - username
 *         - email
 *         - password
 *       properties:
 *         username:
 *           type: string
 *           minLength: 3
 *           maxLength: 50
 *           pattern: '^[a-zA-Z0-9_-]+$'
 *           description: Nome utente (solo lettere, numeri, _ e -)
 *           example: newuser
 *         email:
 *           type: string
 *           format: email
 *           description: Email utente
 *           example: newuser@example.com
 *         password:
 *           type: string
 *           minLength: 8
 *           pattern: '^[a-zA-Z0-9_-]+$'
 *           description: Password (min 8 char, maiuscola, minuscola, numero, carattere speciale)
 *           example: NewUser123!
 *         first_name:
 *           type: string
 *           maxLength: 50
 *           description: Nome
 *           example: Mario
 *         last_name:
 *           type: string
 *           maxLength: 50
 *           description: Cognome
 *           example: Rossi
 *         role:
 *           type: string
 *           enum: [admin, operator, viewer]
 *           default: viewer
 *           description: Ruolo utente
 *         is_active:
 *           type: boolean
 *           default: true
 *           description: Utente attivo
 *         preferences:
 *           type: object
 *           properties:
 *             theme:
 *               type: string
 *               enum: [light, dark]
 *               default: light
 *             language:
 *               type: string
 *               enum: [it, en]
 *               default: it
 *             timezone:
 *               type: string
 *               default: Europe/Rome
 *             notifications:
 *               type: object
 *               properties:
 *                 email:
 *                   type: boolean
 *                   default: true
 *                 browser:
 *                   type: boolean
 *                   default: true
 *                 critical_only:
 *                   type: boolean
 *                   default: false
 * 
 *     UserUpdateRequest:
 *       type: object
 *       properties:
 *         username:
 *           type: string
 *           minLength: 3
 *           maxLength: 50
 *           pattern: '^[a-zA-Z0-9_-]+$'
 *         email:
 *           type: string
 *           format: email
 *         password:
 *           type: string
 *           minLength: 8
 *           pattern: '^[a-zA-Z0-9_-]+$'
 *         first_name:
 *           type: string
 *           maxLength: 50
 *         last_name:
 *           type: string
 *           maxLength: 50
 *         role:
 *           type: string
 *           enum: [admin, operator, viewer]
 *         is_active:
 *           type: boolean
 *         preferences:
 *           type: object
 * 
 *     UsersList:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Utenti recuperati con successo
 *         data:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/User'
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
 * /api/users:
 *   get:
 *     summary: Ottieni lista utenti
 *     description: Recupera lista utenti con opzioni di filtro e paginazione (solo admin)
 *     tags: [Users]
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
 *         name: role
 *         schema:
 *           type: string
 *           enum: [admin, operator, viewer]
 *         description: Filtra per ruolo
 *       - in: query
 *         name: active
 *         schema:
 *           type: boolean
 *         description: Filtra per stato attivo
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Ricerca in username, nome, cognome, email
 *     responses:
 *       200:
 *         description: Lista utenti recuperata con successo
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UsersList'
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti (solo admin)
 */
router.get('/', validateSearchQuery, asyncHandler(async (req, res) => {
  // Controlla permessi
  const currentUser = await User.findByPk(req.user.id);
  if (!currentUser.hasPermission('view_users')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti'
    });
  }

  const { page = 1, limit = 25, role, active, search } = req.query;
  const offset = (page - 1) * limit;

  const where = {};
  if (role) where.role = role;
  if (active !== undefined) where.is_active = active === 'true';
  
  // Ricerca in campi multipli
  if (search) {
    where[User.sequelize.Op.or] = [
      { username: { [User.sequelize.Op.iLike]: `%${search}%` } },
      { email: { [User.sequelize.Op.iLike]: `%${search}%` } },
      { first_name: { [User.sequelize.Op.iLike]: `%${search}%` } },
      { last_name: { [User.sequelize.Op.iLike]: `%${search}%` } }
    ];
  }

  const { count, rows } = await User.findAndCountAll({
    where,
    offset: parseInt(offset),
    limit: parseInt(limit),
    order: [['created_at', 'DESC']],
    attributes: { exclude: ['password'] }
  });

  logger.info('Users list retrieved', {
    count,
    page,
    limit,
    user: req.user.username,
    filters: { role, active, search }
  });

  res.json({
    success: true,
    message: 'Utenti recuperati con successo',
    data: rows.map(user => user.toSafeJSON()),
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
 * /api/users/me:
 *   get:
 *     summary: Ottieni profilo utente corrente
 *     description: Recupera il profilo dell'utente autenticato
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Profilo utente recuperato
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
 *                   example: Profilo utente recuperato
 *                 data:
 *                   $ref: '#/components/schemas/User'
 *       404:
 *         description: Utente non trovato
 *       401:
 *         description: Token di accesso richiesto
 */
router.get('/me', asyncHandler(async (req, res) => {
  const user = await User.findByPk(req.user.id, {
    attributes: { exclude: ['password'] }
  });

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'Utente non trovato'
    });
  }

  res.json({
    success: true,
    message: 'Profilo utente recuperato',
    data: user.toSafeJSON()
  });
}));

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Ottieni utente specifico
 *     description: Recupera un singolo utente per ID
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID dell'utente
 *     responses:
 *       200:
 *         description: Utente recuperato con successo
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
 *                   example: Utente recuperato con successo
 *                 data:
 *                   $ref: '#/components/schemas/User'
 *       404:
 *         description: Utente non trovato
 *       401:
 *         description: Token di accesso richiesto
 *       403:
 *         description: Permessi insufficienti
 */
router.get('/:id', asyncHandler(async (req, res) => {
  const currentUser = await User.findByPk(req.user.id);
  
  // Gli utenti possono vedere solo il proprio profilo, tranne gli admin
  if (parseInt(req.params.id) !== req.user.id && !currentUser.hasPermission('view_users')) {
    return res.status(403).json({
      success: false,
      message: 'Permessi insufficienti'
    });
  }
  const user = await User.findByPk(req.params.id, {
   attributes: { exclude: ['password'] }
 });

 if (!user) {
   return res.status(404).json({
     success: false,
     message: 'Utente non trovato'
   });
 }

 res.json({
   success: true,
   message: 'Utente recuperato con successo',
   data: user.toSafeJSON()
 });
}));

/**
* @swagger
* /api/users:
*   post:
*     summary: Crea nuovo utente
*     description: Crea un nuovo utente nel sistema (solo admin)
*     tags: [Users]
*     security:
*       - bearerAuth: []
*     requestBody:
*       required: true
*       content:
*         application/json:
*           schema:
*             $ref: '#/components/schemas/UserRequest'
*           examples:
*             adminUser:
*               summary: Utente amministratore
*               value:
*                 username: admin2
*                 email: admin2@example.com
*                 password: Admin123!
*                 first_name: John
*                 last_name: Admin
*                 role: admin
*                 is_active: true
*             operatorUser:
*               summary: Utente operatore
*               value:
*                 username: operator2
*                 email: operator2@example.com
*                 password: Operator123!
*                 first_name: Jane
*                 last_name: Operator
*                 role: operator
*                 is_active: true
*     responses:
*       201:
*         description: Utente creato con successo
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
*                   example: Utente creato con successo
*                 data:
*                   $ref: '#/components/schemas/User'
*       400:
*         description: Dati utente non validi o username/email già esistenti
*       401:
*         description: Token di accesso richiesto
*       403:
*         description: Permessi insufficienti (solo admin)
*/
router.post('/', validateUser, asyncHandler(async (req, res) => {
 const currentUser = await User.findByPk(req.user.id);
 if (!currentUser.hasPermission('create_users')) {
   return res.status(403).json({
     success: false,
     message: 'Permessi insufficienti'
   });
 }

 const userData = req.body;
 
 // Controlla se username o email esistono già
 const existingUser = await User.findOne({
   where: {
     [User.sequelize.Op.or]: [
       { username: userData.username },
       { email: userData.email }
     ]
   }
 });

 if (existingUser) {
   return res.status(400).json({
     success: false,
     message: 'Username o email già esistenti'
   });
 }

 const user = await User.create(userData);

 logger.info('User created', {
   user_id: user.id,
   username: user.username,
   role: user.role,
   created_by: req.user.username
 });

 res.status(201).json({
   success: true,
   message: 'Utente creato con successo',
   data: user.toSafeJSON()
 });
}));

/**
* @swagger
* /api/users/{id}:
*   put:
*     summary: Aggiorna utente
*     description: Aggiorna i dati di un utente esistente
*     tags: [Users]
*     security:
*       - bearerAuth: []
*     parameters:
*       - in: path
*         name: id
*         required: true
*         schema:
*           type: integer
*         description: ID dell'utente
*     requestBody:
*       required: true
*       content:
*         application/json:
*           schema:
*             $ref: '#/components/schemas/UserUpdateRequest'
*     responses:
*       200:
*         description: Utente aggiornato con successo
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
*                   example: Utente aggiornato con successo
*                 data:
*                   $ref: '#/components/schemas/User'
*       404:
*         description: Utente non trovato
*       400:
*         description: Dati non validi o tentativo di auto-disattivazione
*       401:
*         description: Token di accesso richiesto
*       403:
*         description: Permessi insufficienti
*/
router.put('/:id', validateUserUpdate, asyncHandler(async (req, res) => {
 const currentUser = await User.findByPk(req.user.id);
 const targetUserId = parseInt(req.params.id);
 
 // Gli utenti possono modificare solo il proprio profilo, tranne gli admin
 if (targetUserId !== req.user.id && !currentUser.hasPermission('update_users')) {
   return res.status(403).json({
     success: false,
     message: 'Permessi insufficienti'
   });
 }

 const user = await User.findByPk(targetUserId);
 if (!user) {
   return res.status(404).json({
     success: false,
     message: 'Utente non trovato'
   });
 }

 const updateData = { ...req.body };
 
 // Solo gli admin possono modificare il ruolo
 if (!currentUser.hasPermission('update_users') && updateData.role) {
   delete updateData.role;
 }

 // Non permettere di disattivare se stesso
 if (targetUserId === req.user.id && updateData.is_active === false) {
   return res.status(400).json({
     success: false,
     message: 'Non puoi disattivare il tuo account'
   });
 }

 await user.update(updateData);

 logger.info('User updated', {
   user_id: user.id,
   username: user.username,
   updated_by: req.user.username,
   changes: Object.keys(updateData)
 });

 res.json({
   success: true,
   message: 'Utente aggiornato con successo',
   data: user.toSafeJSON()
 });
}));

/**
* @swagger
* /api/users/{id}:
*   delete:
*     summary: Elimina utente
*     description: Elimina un utente dal sistema (soft delete, solo admin)
*     tags: [Users]
*     security:
*       - bearerAuth: []
*     parameters:
*       - in: path
*         name: id
*         required: true
*         schema:
*           type: integer
*         description: ID dell'utente
*     responses:
*       200:
*         description: Utente eliminato con successo
*         content:
*           application/json:
*             schema:
*               $ref: '#/components/schemas/Success'
*       404:
*         description: Utente non trovato
*       400:
*         description: Tentativo di eliminare se stesso
*       401:
*         description: Token di accesso richiesto
*       403:
*         description: Permessi insufficienti (solo admin)
*/
router.delete('/:id', asyncHandler(async (req, res) => {
 const currentUser = await User.findByPk(req.user.id);
 if (!currentUser.hasPermission('delete_users')) {
   return res.status(403).json({
     success: false,
     message: 'Permessi insufficienti'
   });
 }

 const targetUserId = parseInt(req.params.id);
 
 // Non permettere di eliminare se stesso
 if (targetUserId === req.user.id) {
   return res.status(400).json({
     success: false,
     message: 'Non puoi eliminare il tuo account'
   });
 }

 const user = await User.findByPk(targetUserId);
 if (!user) {
   return res.status(404).json({
     success: false,
     message: 'Utente non trovato'
   });
 }

 await user.destroy(); // Soft delete

 logger.info('User deleted', {
   user_id: user.id,
   username: user.username,
   deleted_by: req.user.username
 });

 res.json({
   success: true,
   message: 'Utente eliminato con successo'
 });
}));

/**
* @swagger
* /api/users/{id}/toggle:
*   patch:
*     summary: Attiva/disattiva utente
*     description: Cambia lo stato attivo di un utente
*     tags: [Users]
*     security:
*       - bearerAuth: []
*     parameters:
*       - in: path
*         name: id
*         required: true
*         schema:
*           type: integer
*         description: ID dell'utente
*     requestBody:
*       required: true
*       content:
*         application/json:
*           schema:
*             type: object
*             required:
*               - is_active
*             properties:
*               is_active:
*                 type: boolean
*                 description: Stato attivo dell'utente
*                 example: true
*     responses:
*       200:
*         description: Stato utente modificato con successo
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
*                   example: Utente attivato con successo
*                 data:
*                   $ref: '#/components/schemas/User'
*       404:
*         description: Utente non trovato
*       400:
*         description: Tentativo di disattivare se stesso
*       401:
*         description: Token di accesso richiesto
*       403:
*         description: Permessi insufficienti (solo admin)
*/
router.patch('/:id/toggle', asyncHandler(async (req, res) => {
 const currentUser = await User.findByPk(req.user.id);
 if (!currentUser.hasPermission('update_users')) {
   return res.status(403).json({
     success: false,
     message: 'Permessi insufficienti'
   });
 }

 const targetUserId = parseInt(req.params.id);
 const { is_active } = req.body;
 
 // Non permettere di disattivare se stesso
 if (targetUserId === req.user.id && is_active === false) {
   return res.status(400).json({
     success: false,
     message: 'Non puoi disattivare il tuo account'
   });
 }

 const user = await User.findByPk(targetUserId);
 if (!user) {
   return res.status(404).json({
     success: false,
     message: 'Utente non trovato'
   });
 }

 await user.update({ is_active });

 logger.info('User toggled', {
   user_id: user.id,
   username: user.username,
   is_active,
   toggled_by: req.user.username
 });

 res.json({
   success: true,
   message: `Utente ${is_active ? 'attivato' : 'disattivato'} con successo`,
   data: user.toSafeJSON()
 });
}));

/**
* @swagger
* /api/users/{id}/reset-password:
*   post:
*     summary: Reset password utente
*     description: Resetta la password di un utente (solo admin)
*     tags: [Users]
*     security:
*       - bearerAuth: []
*     parameters:
*       - in: path
*         name: id
*         required: true
*         schema:
*           type: integer
*         description: ID dell'utente
*     requestBody:
*       required: true
*       content:
*         application/json:
*           schema:
*             type: object
*             required:
*               - new_password
*             properties:
*               new_password:
*                 type: string
*                 minLength: 8
*                 pattern: '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`])'
*                 description: Nuova password
*                 example: NewPassword123!
*     responses:
*       200:
*         description: Password resettata con successo
*         content:
*           application/json:
*             schema:
*               $ref: '#/components/schemas/Success'
*       404:
*         description: Utente non trovato
*       400:
*         description: Password non valida
*       401:
*         description: Token di accesso richiesto
*       403:
*         description: Permessi insufficienti (solo admin)
*/
router.post('/:id/reset-password', asyncHandler(async (req, res) => {
 const currentUser = await User.findByPk(req.user.id);
 if (!currentUser.hasPermission('update_users')) {
   return res.status(403).json({
     success: false,
     message: 'Permessi insufficienti'
   });
 }

 const { new_password } = req.body;
 
 if (!new_password || new_password.length < 8) {
   return res.status(400).json({
     success: false,
     message: 'Password deve essere almeno 8 caratteri'
   });
 }

 const user = await User.findByPk(req.params.id);
 if (!user) {
   return res.status(404).json({
     success: false,
     message: 'Utente non trovato'
   });
 }

 await user.update({ password: new_password });

 logger.info('Password reset', {
   user_id: user.id,
   username: user.username,
   reset_by: req.user.username
 });

 res.json({
   success: true,
   message: 'Password resettata con successo'
 });
}));

/**
* @swagger
* /api/users/statistics:
*   get:
*     summary: Statistiche utenti
*     description: Ottieni statistiche sugli utenti del sistema
*     tags: [Users]
*     security:
*       - bearerAuth: []
*     responses:
*       200:
*         description: Statistiche utenti recuperate
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
*                   example: Statistiche utenti recuperate
*                 data:
*                   type: object
*                   properties:
*                     total_users:
*                       type: integer
*                       description: Totale utenti
*                     active_users:
*                       type: integer
*                       description: Utenti attivi
*                     recent_logins:
*                       type: integer
*                       description: Login negli ultimi 7 giorni
*                     by_role:
*                       type: array
*                       items:
*                         type: object
*                         properties:
*                           role:
*                             type: string
*                           count:
*                             type: string
*                           active_count:
*                             type: string
*       401:
*         description: Token di accesso richiesto
*       403:
*         description: Permessi insufficienti (solo admin)
*/
router.get('/statistics', asyncHandler(async (req, res) => {
 const currentUser = await User.findByPk(req.user.id);
 if (!currentUser.hasPermission('view_users')) {
   return res.status(403).json({
     success: false,
     message: 'Permessi insufficienti'
   });
 }

 const stats = await User.getStatistics();

 res.json({
   success: true,
   message: 'Statistiche utenti recuperate',
   data: stats
 });
}));

/**
* @swagger
* /api/users/me/statistics:
*   get:
*     summary: Statistiche utente corrente
*     description: Ottieni statistiche dell'utente autenticato
*     tags: [Users]
*     security:
*       - bearerAuth: []
*     responses:
*       200:
*         description: Statistiche utente recuperate
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
*                   example: Statistiche utente recuperate
*                 data:
*                   type: object
*                   properties:
*                     total_rules_created:
*                       type: integer
*                     active_rules:
*                       type: integer
*                     last_rule_created:
*                       type: object
*                     account_age_days:
*                       type: integer
*       401:
*         description: Token di accesso richiesto
*/
router.get('/me/statistics', asyncHandler(async (req, res) => {
 const user = await User.findByPk(req.user.id);
 const stats = await user.getStatistics();

 res.json({
   success: true,
   message: 'Statistiche utente recuperate',
   data: stats
 });
}));

module.exports = router;