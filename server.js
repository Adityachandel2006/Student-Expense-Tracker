require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const { OAuth2Client } = require('google-auth-library');

const User = require('./schemas/User');
const Expense = require('./schemas/Expense');

const app = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/* ---------------- DATABASE CONNECTION ---------------- */

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

/* ---------------- MIDDLEWARE ---------------- */

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.use('/images/default-avatar.png', (req, res) => res.redirect('/images/default-avatar.svg'));
app.use(cookieParser());

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* ---------------- MULTER UPLOAD CONFIG ---------------- */

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and WebP are allowed.'), false);
  }
};

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: fileFilter
});

/* ---------------- AUTH MIDDLEWARE ---------------- */

const auth = async (req, res, next) => {
  const token = req.cookies.jwt;
  
  if (!token) {
    return res.redirect("/login");
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      res.clearCookie('jwt');
      return res.redirect("/login");
    }
    
    req.user = user;
    next();
  } catch (err) {
    res.clearCookie('jwt');
    return res.redirect("/login");
  }
};

/* ---------------- ROUTES ---------------- */

app.get("/", (req, res) => {
  res.render("home");
});

/* ---------- REGISTER ---------- */

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res, next) => {
  upload.single('profilePic')(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      return res.status(400).send("File upload error: " + err.message);
    } else if (err) {
      return res.status(400).send(err.message);
    }
    next();
  });
}, async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    
    if (password !== confirmPassword) {
      return res.status(400).send("Passwords do not match");
    }
    
    if (password.length < 6) {
      return res.status(400).send("Password must be at least 6 characters long");
    }
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).send("User or email already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    let profilePicPath = '/images/default-avatar.svg'; // Make sure you add a default avatar or it'll just be a broken image link. You can change this logic.
    if (req.file) {
      profilePicPath = '/uploads/' + req.file.filename;
    }

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      profilePic: profilePicPath
    });

    await newUser.save();
    res.redirect("/login");
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).send("Error registering user");
  }
});

/* ---------- LOGIN ---------- */

app.get("/login", (req, res) => {
  res.render("login", { googleClientId: process.env.GOOGLE_CLIENT_ID });
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user || !user.password) {
      return res.json({ success: false, error: "User not found or invalid login method" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.json({ success: false, error: "Wrong password" });
    }

    // Generate JWT
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    
    // Set cookie
    res.cookie('jwt', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }); // 1 day

    res.json({ success: true });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ---------- GOOGLE LOGIN ---------- */

app.post("/auth/google", async (req, res) => {
  try {
    const { token } = req.body;
    
    // Verify Google Token
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const googleId = payload['sub'];
    const email = payload['email'];
    const username = payload['name'] || email;
    const profilePic = payload['picture'];

    // Find or Create User
    let user = await User.findOne({ googleId });
    
    if (!user) {
      if (email) {
        user = await User.findOne({ email });
      }

      if (user) {
        // Link existing manual account with Google
        user.googleId = googleId;
        await user.save();
      } else {
        // Create new user
        user = new User({
          username: username,
          email: email,
          googleId: googleId,
          profilePic: profilePic
        });
        await user.save();
      }
    }

    // Generate JWT
    const jwtToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    
    // Set cookie
    res.cookie('jwt', jwtToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }); // 1 day

    res.json({ success: true });
  } catch (error) {
    console.error("Google Auth error:", error);
    res.status(401).json({ success: false, error: "Invalid Google token" });
  }
});


/* ---------- PROFILE ---------- */

app.get("/profile", auth, (req, res) => {
  res.render("profile", {
    user: req.user,
    successMsg: req.query.success,
    errorMsg: req.query.error
  });
});

app.post("/profile/update", auth, (req, res, next) => {
  upload.single('profilePic')(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      return res.redirect("/profile?error=File+upload+error:+" + encodeURIComponent(err.message));
    } else if (err) {
      return res.redirect("/profile?error=" + encodeURIComponent(err.message));
    }
    next();
  });
}, async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    
    // Check if new username or email is already taken by someone else
    const existingUser = await User.findOne({
      _id: { $ne: req.user._id },
      $or: [{ username }, { email: email ? email : null }]
    });
    
    if (existingUser) {
      return res.redirect("/profile?error=Username+or+Email+already+exists");
    }

    req.user.username = username;
    req.user.email = email || req.user.email; // Only update if provided

    // Handle password update if provided 
    if (password) {
      if (password !== confirmPassword) {
        return res.redirect("/profile?error=Passwords+do+not+match");
      }
      if (password.length < 6) {
        return res.redirect("/profile?error=Password+must+be+at+least+6+characters");
      }
      req.user.password = await bcrypt.hash(password, 10);
    }

    // Handle profile picture update
    if (req.file) {
      req.user.profilePic = '/uploads/' + req.file.filename;
    }

    await req.user.save();
    res.redirect("/profile?success=Profile+updated+successfully");

  } catch (err) {
    console.error("Profile update error:", err);
    res.redirect("/profile?error=Server+error+updating+profile");
  }
});

/* ---------- LOGOUT ---------- */

app.get("/logout", (req, res) => {
  res.clearCookie('jwt');
  res.redirect("/login");
});

/* ---------- DASHBOARD ---------- */

app.get("/dashboard", auth, async (req, res) => {
  try {
    const userExpenses = await Expense.find({ userId: req.user._id });

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

    const parsedBudget = Number(req.user.budget);
    const budget = Number.isFinite(parsedBudget) && parsedBudget > 0 ? parsedBudget : null;

    res.render("dashboard", {
      expenses: userExpenses,
      total: total,
      monthTotal: monthTotal,
      budget: budget,
      user: req.user
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).send("Error loading dashboard");
  }
});

/* ---------- SET/RESET BUDGET ---------- */

async function handleSetBudget(req, res) {
  try {
    const budget = Number(req.body.budget);

    if (Number.isFinite(budget) && budget > 0) {
      req.user.budget = budget;
      await req.user.save();
    }

    res.redirect("/dashboard");
  } catch (err) {
    console.error("Set budget error:", err);
    res.redirect("/dashboard");
  }
}

async function handleResetBudget(req, res) {
  try {
    req.user.budget = null;
    await req.user.save();
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Reset budget error:", err);
    res.redirect("/dashboard");
  }
}

app.post("/set-budget", auth, handleSetBudget);
app.post("/dashboard/set-budget", auth, handleSetBudget);
app.post("/reset-budget", auth, handleResetBudget);
app.post("/dashboard/reset-budget", auth, handleResetBudget);

/* ---------- ADD EXPENSE ---------- */

app.post("/add-expense", auth, async (req, res) => {
  try {
    const newExpense = new Expense({
      userId: req.user._id,
      title: req.body.title,
      amount: req.body.amount,
      category: req.body.category,
      date: req.body.date,
    });

    await newExpense.save();
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Add expense error:", err);
    res.redirect("/dashboard");
  }
});

/* ---------- EDIT EXPENSE ---------- */

app.post("/edit-expense/:id", auth, async (req, res) => {
  try {
    const { title, amount, category, date } = req.body;
    await Expense.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { title, amount, category, date }
    );
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Edit expense error:", err);
    res.redirect("/dashboard");
  }
});

/* ---------- DELETE EXPENSE ---------- */

app.post("/delete/:id", auth, async (req, res) => {
  try {
    await Expense.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Delete expense error:", err);
    res.redirect("/dashboard");
  }
});

/* ---------- REPORT ---------- */

app.get("/report", auth, async (req, res) => {
  try {
    const userExpenses = await Expense.find({ userId: req.user._id });

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
      user: req.user
    });
  } catch (err) {
    console.error("Report error:", err);
    res.status(500).send("Error loading report");
  }
});

/* ---------- SERVER ---------- */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
