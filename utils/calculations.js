const calculateTotals = (expenses) => {
  let total = 0;
  let monthTotal = 0;

  const currentMonth = new Date().getMonth();

  expenses.forEach((exp) => {
    total += Number(exp.amount);

    const expDate = new Date(exp.date);

    if (expDate.getMonth() === currentMonth) {
      monthTotal += Number(exp.amount);
    }
  });

  return { total, monthTotal };
};

const calculateCategoryTotals = (expenses) => {
  let total = 0;
  let categoryTotals = {};

  expenses.forEach((e) => {
    total += Number(e.amount);
    categoryTotals[e.category] = (categoryTotals[e.category] || 0) + Number(e.amount);
  });

  return { total, categoryTotals };
};

const getTopCategory = (categoryTotals) => {
  let topCategory = 'None';
  let maxAmount = 0;

  for (let category in categoryTotals) {
    if (categoryTotals[category] > maxAmount) {
      maxAmount = categoryTotals[category];
      topCategory = category;
    }
  }

  return topCategory;
};

const parseBudget = (budget) => {
  const parsedBudget = Number(budget);
  return Number.isFinite(parsedBudget) && parsedBudget > 0 ? parsedBudget : null;
};

module.exports = {
  calculateTotals,
  calculateCategoryTotals,
  getTopCategory,
  parseBudget
};
