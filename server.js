const express = require("express");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

/* ---------------- MIDDLEWARE ---------------- */

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    secret: "expense-secret",
    resave: false,
    saveUninitialized: true,
  })
);

/* ---------------- FILE PATHS ---------------- */

const USERS_FILE = "./data/users.json";
const EXP_FILE = "./data/expenses.json";

/* ---------------- FILE FUNCTIONS ---------------- */

function readFile(file) {
  try {
    const data = fs.readFileSync(file);
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function saveFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function updateUser(userId, updates) {
  const users = readFile(USERS_FILE);
  const normalizedUserId = Number(userId);
  const userIndex = users.findIndex((u) => Number(u.id) === normalizedUserId);

  if (userIndex === -1) {
    return null;
  }

  users[userIndex] = {
    ...users[userIndex],
    ...updates,
  };

  saveFile(USERS_FILE, users);
  return users[userIndex];
}

/* ---------------- AUTH MIDDLEWARE ---------------- */

function auth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

/* ---------------- ROUTES ---------------- */

app.get("/", (req, res) => {
  res.render("home");
});

/* ---------- LOGIN ---------- */

app.get("/login", (req, res) => {
  res.render("login");
});

/* ---------- REGISTER ---------- */

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const users = readFile(USERS_FILE);

  const hashed = await bcrypt.hash(req.body.password, 10);

  users.push({
    id: Date.now(),
    username: req.body.username,
    password: hashed,
    budget: null,
  });

  saveFile(USERS_FILE, users);

  res.redirect("/login");
});

/* ---------- LOGIN ---------- */

app.post("/login", async (req, res) => {
  const users = readFile(USERS_FILE);

  const user = users.find((u) => u.username === req.body.username);

  if (!user) {
    return res.json({ success: false, error: "User not found" });
  }

  const match = await bcrypt.compare(req.body.password, user.password);

  if (!match) {
    return res.json({ success: false, error: "Wrong password" });
  }

  req.session.user = user;

  res.json({ success: true });
});

/* ---------- LOGOUT ---------- */

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

/* ---------- DASHBOARD ---------- */

app.get("/dashboard", auth, (req, res) => {
  const expenses = readFile(EXP_FILE);
  const userExpenses = expenses.filter((exp) => exp.userId === req.session.user.id);

  let total = 0;
  let monthTotal = 0;

  const currentMonth = new Date().getMonth();

  userExpenses.forEach((exp) => {
    total += Number(exp.amount);

    const expDate = new Date(exp.date);

    if (expDate.getMonth() === currentMonth) {
      monthTotal += Number(exp.amount);
    }
  });

  const parsedBudget = Number(req.session.user.budget);
  const budget = Number.isFinite(parsedBudget) && parsedBudget > 0 ? parsedBudget : null;

  res.render("dashboard", {
    expenses: userExpenses,
    total: total,
    monthTotal: monthTotal,
    budget: budget,
  });
});

/* ---------- SET/RESET BUDGET ---------- */

function handleSetBudget(req, res) {
  const budget = Number(req.body.budget);

  if (!Number.isFinite(budget) || budget <= 0) {
    return res.redirect("/dashboard");
  }

  const updatedUser = updateUser(req.session.user.id, { budget });
  if (updatedUser) {
    req.session.user = updatedUser;
  }
  req.session.save(() => res.redirect("/dashboard"));
}

function handleResetBudget(req, res) {
  const updatedUser = updateUser(req.session.user.id, { budget: null });
  if (updatedUser) {
    req.session.user = updatedUser;
  }
  req.session.save(() => res.redirect("/dashboard"));
}

app.post("/set-budget", auth, handleSetBudget);
app.post("/dashboard/set-budget", auth, handleSetBudget);
app.post("/reset-budget", auth, handleResetBudget);
app.post("/dashboard/reset-budget", auth, handleResetBudget);

/* ---------- ADD EXPENSE ---------- */

app.post("/add-expense", auth, (req, res) => {
  const expenses = readFile(EXP_FILE);

  const newExpense = {
    id: Date.now(),
    userId: req.session.user.id,
    title: req.body.title,
    amount: req.body.amount,
    category: req.body.category,
    date: req.body.date,
  };

  expenses.push(newExpense);

  saveFile(EXP_FILE, expenses);

  res.redirect("/dashboard");
});

/* ---------- DELETE EXPENSE ---------- */

app.post("/delete/:id", auth, (req, res) => {
  let expenses = readFile(EXP_FILE);

  expenses = expenses.filter((exp) => exp.id != req.params.id);

  saveFile(EXP_FILE, expenses);

  res.redirect("/dashboard");
});

/* ---------- REPORT ---------- */

app.get("/report", auth, (req, res) => {
  const expenses = readFile(EXP_FILE);
  const userExpenses = expenses.filter((exp) => exp.userId === req.session.user.id);

  let total = 0;
  let categoryTotals = {};

  userExpenses.forEach((e) => {
    total += Number(e.amount);
    categoryTotals[e.category] = (categoryTotals[e.category] || 0) + Number(e.amount);
  });

  let topCategory = "None";
  let maxAmount = 0;

  for (let category in categoryTotals) {
    if (categoryTotals[category] > maxAmount) {
      maxAmount = categoryTotals[category];
      topCategory = category;
    }
  }

  res.render("report", {
    expenses: userExpenses,
    total: total,
    topCategory: topCategory,
  });
});

/* ---------- SERVER ---------- */

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
