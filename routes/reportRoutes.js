const express = require('express');
const router = express.Router();
const ReportController = require('../controllers/ReportController');
const auth = require('../middleware/auth');

// Report route
router.get('/report', auth, ReportController.getReport);

module.exports = router;
