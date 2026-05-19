const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/AuthController');
const upload = require('../config/multer');

// Register routes
router.get('/register', AuthController.getRegister);
router.post('/register', (req, res, next) => {
  upload.single('profilePic')(req, res, function (err) {
    if (err) {
      return res.status(400).send(err.message);
    }
    next();
  });
}, AuthController.postRegister);

// Login routes
router.get('/login', AuthController.getLogin);
router.post('/login', AuthController.postLogin);

// Google auth route
router.post('/auth/google', AuthController.googleAuth);

// Logout route
router.get('/logout', AuthController.logout);

module.exports = router;
