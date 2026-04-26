const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    unique: true,
    sparse: true // Allows multiple users without an email (if they registered before this feature)
  },
  password: {
    type: String,
    // Password is not required if the user logs in with Google
    required: function() {
      return !this.googleId;
    }
  },
  budget: {
    type: Number,
    default: null
  },
  profilePic: {
    type: String, // Store the path to the uploaded file
    default: '/images/default-avatar.svg'
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true // Allows multiple users without a googleId
  }
});

module.exports = mongoose.model('User', userSchema);
