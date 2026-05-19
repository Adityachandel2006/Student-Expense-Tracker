const express = require('express');
const router = express.Router();
const UserController = require('../controllers/UserController');
const auth = require('../middleware/auth');
const upload = require('../config/multer');

// Profile routes
router.get('/profile', auth, UserController.getProfile);
router.post('/profile/update', auth, (req, res, next) => {
  upload.single('profilePic')(req, res, function (err) {
    if (err) {
      return res.redirect('/profile?error=' + encodeURIComponent(err.message));
    }
    next();
  });
}, UserController.updateProfile);

module.exports = router;
