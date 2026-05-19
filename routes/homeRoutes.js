const express = require('express');
const router = express.Router();
const HomeController = require('../controllers/HomeController');

// Home route
router.get('/', HomeController.getHome);

module.exports = router;
