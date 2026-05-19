const Expense = require('../models/Expense');
const { calculateCategoryTotals, getTopCategory } = require('../utils/calculations');

class ReportController {
  // Render report
  static getReport = async (req, res) => {
    try {
      const userExpenses = await Expense.find({ userId: req.user._id });

      const { total, categoryTotals } = calculateCategoryTotals(userExpenses);
      const topCategory = getTopCategory(categoryTotals);

      res.render('report', {
        expenses: userExpenses,
        total: total,
        topCategory: topCategory,
        user: req.user
      });
    } catch (err) {
      console.error('Report error:', err);
      res.status(500).send('Error loading report');
    }
  };
}

module.exports = ReportController;
