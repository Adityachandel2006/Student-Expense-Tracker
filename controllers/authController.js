const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

class AuthController {
  // Render register page
  static getRegister = (req, res) => {
    res.render('register');
  };

  // Handle user registration
  static postRegister = async (req, res) => {
    try {
      const { username, email, password, confirmPassword } = req.body;

      if (password !== confirmPassword) {
        return res.status(400).send('Passwords do not match');
      }

      if (password.length < 6) {
        return res.status(400).send('Password must be at least 6 characters long');
      }

      // Check if user already exists
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        return res.status(400).send('User or email already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      let profilePicPath = '/images/default-avatar.svg';
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
      res.redirect('/login');
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).send('Error registering user');
    }
  };

  // Render login page
  static getLogin = (req, res) => {
    res.render('login', { googleClientId: process.env.GOOGLE_CLIENT_ID });
  };

  // Handle user login
  static postLogin = async (req, res) => {
    try {
      const { username, password } = req.body;

      const user = await User.findOne({ username });

      if (!user || !user.password) {
        return res.json({ success: false, error: 'User not found or invalid login method' });
      }

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.json({ success: false, error: 'Wrong password' });
      }

      // Generate JWT
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

      // Set cookie
      res.cookie('jwt', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });

      res.json({ success: true });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  };

  // Handle Google OAuth authentication
  static googleAuth = async (req, res) => {
    try {
      const { token } = req.body;

      // Verify Google Token
      const ticket = await googleClient.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID
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
      res.cookie('jwt', jwtToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });

      res.json({ success: true });
    } catch (error) {
      console.error('Google Auth error:', error);
      res.status(401).json({ success: false, error: 'Invalid Google token' });
    }
  };

  // Handle logout
  static logout = (req, res) => {
    res.clearCookie('jwt');
    res.redirect('/login');
  };
}

module.exports = AuthController;
