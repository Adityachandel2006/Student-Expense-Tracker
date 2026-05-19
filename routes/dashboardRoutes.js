const express = require('express');
const router = express.Router();
const DashboardController = require('../controllers/DashboardController');
const auth = require('../middleware/auth');

// Dashboard route
router.get('/dashboard', auth, DashboardController.getDashboard);

// Budget routes
router.post('/set-budget', auth, DashboardController.setBudget);
router.post('/dashboard/set-budget', auth, DashboardController.setBudget);
router.post('/reset-budget', auth, DashboardController.resetBudget);
router.post('/dashboard/reset-budget', auth, DashboardController.resetBudget);

module.exports = router;
