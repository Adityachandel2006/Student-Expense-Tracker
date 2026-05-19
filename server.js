require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

// Import configuration
const connectDatabase = require('./config/database');

// Import routes
const homeRoutes = require('./routes/homeRoutes');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const expenseRoutes = require('./routes/expenseRoutes');
const reportRoutes = require('./routes/reportRoutes');

// Initialize Express app
const app = express();

// Connect to MongoDB
connectDatabase();

/* ==================== MIDDLEWARE ==================== */

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/images/default-avatar.png', (req, res) => res.redirect('/images/default-avatar.svg'));
app.use(cookieParser());

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

/* ==================== ROUTES ==================== */

app.use('/', homeRoutes);
app.use('/', authRoutes);
app.use('/', userRoutes);
app.use('/', dashboardRoutes);
app.use('/', expenseRoutes);
app.use('/', reportRoutes);

/* ==================== ERROR HANDLING ==================== */

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

/* ==================== SERVER START ==================== */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
