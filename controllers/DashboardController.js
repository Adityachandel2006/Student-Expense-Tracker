const Expense = require('../models/Expense');
const { calculateTotals, parseBudget } = require('../utils/calculations');

class DashboardController {
  // Render dashboard
  static getDashboard = async (req, res) => {
    try {
      const userExpenses = await Expense.find({ userId: req.user._id });

      const { total, monthTotal } = calculateTotals(userExpenses);
      const budget = parseBudget(req.user.budget);

      res.render('dashboard', {
        expenses: userExpenses,
        total: total,
        monthTotal: monthTotal,
        budget: budget,
        user: req.user
      });
    } catch (err) {
      console.error('Dashboard error:', err);
      res.status(500).send('Error loading dashboard');
    }
  };

  // Set budget
  static setBudget = async (req, res) => {
    try {
      const budget = Number(req.body.budget);

      if (Number.isFinite(budget) && budget > 0) {
        req.user.budget = budget;
        await req.user.save();
      }

      res.redirect('/dashboard');
    } catch (err) {
      console.error('Set budget error:', err);
      res.redirect('/dashboard');
    }
  };

  // Reset budget
  static resetBudget = async (req, res) => {
    try {
      req.user.budget = null;
      await req.user.save();
      res.redirect('/dashboard');
    } catch (err) {
      console.error('Reset budget error:', err);
      res.redirect('/dashboard');
    }
  };
}

module.exports = DashboardController;
