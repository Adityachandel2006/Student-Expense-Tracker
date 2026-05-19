const express = require('express');
const router = express.Router();
const ExpenseController = require('../controllers/ExpenseController');
const auth = require('../middleware/auth');

// Expense routes
router.post('/add-expense', auth, ExpenseController.addExpense);
router.post('/edit-expense/:id', auth, ExpenseController.editExpense);
router.post('/delete/:id', auth, ExpenseController.deleteExpense);

module.exports = router;
