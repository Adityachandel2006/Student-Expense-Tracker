const Expense = require('../models/Expense');

class ExpenseController {
  // Add new expense
  static addExpense = async (req, res) => {
    try {
      const newExpense = new Expense({
        userId: req.user._id,
        title: req.body.title,
        amount: req.body.amount,
        category: req.body.category,
        date: req.body.date
      });

      await newExpense.save();
      res.redirect('/dashboard');
    } catch (err) {
      console.error('Add expense error:', err);
      res.redirect('/dashboard');
    }
  };

  // Edit expense
  static editExpense = async (req, res) => {
    try {
      const { title, amount, category, date } = req.body;
      await Expense.findOneAndUpdate(
        { _id: req.params.id, userId: req.user._id },
        { title, amount, category, date }
      );
      res.redirect('/dashboard');
    } catch (err) {
      console.error('Edit expense error:', err);
      res.redirect('/dashboard');
    }
  };

  // Delete expense
  static deleteExpense = async (req, res) => {
    try {
      await Expense.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
      res.redirect('/dashboard');
    } catch (err) {
      console.error('Delete expense error:', err);
      res.redirect('/dashboard');
    }
  };
}

module.exports = ExpenseController;
