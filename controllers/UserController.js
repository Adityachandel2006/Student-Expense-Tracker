const bcrypt = require('bcrypt');
const User = require('../models/User');

class UserController {
  // Render user profile
  static getProfile = (req, res) => {
    res.render('profile', {
      user: req.user,
      successMsg: req.query.success,
      errorMsg: req.query.error
    });
  };

  // Update user profile
  static updateProfile = async (req, res) => {
    try {
      const { username, email, password, confirmPassword } = req.body;

      // Check if new username or email is already taken by someone else
      const existingUser = await User.findOne({
        _id: { $ne: req.user._id },
        $or: [{ username }, { email: email ? email : null }]
      });

      if (existingUser) {
        return res.redirect('/profile?error=Username+or+Email+already+exists');
      }

      req.user.username = username;
      req.user.email = email || req.user.email;

      // Handle password update if provided
      if (password) {
        if (password !== confirmPassword) {
          return res.redirect('/profile?error=Passwords+do+not+match');
        }
        if (password.length < 6) {
          return res.redirect('/profile?error=Password+must+be+at+least+6+characters');
        }
        req.user.password = await bcrypt.hash(password, 10);
      }

      // Handle profile picture update
      if (req.file) {
        req.user.profilePic = '/uploads/' + req.file.filename;
      }

      await req.user.save();
      res.redirect('/profile?success=Profile+updated+successfully');
    } catch (err) {
      console.error('Profile update error:', err);
      res.redirect('/profile?error=Server+error+updating+profile');
    }
  };
}

module.exports = UserController;
