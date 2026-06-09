const express    = require('express');
const router     = express.Router();
const auth       = require('../controllers/authController');
const authMiddleware = require('../middleware/auth');

router.post('/register', auth.register);
router.post('/login',    auth.login);
router.get('/profile',   authMiddleware, auth.profile);

module.exports = router;
