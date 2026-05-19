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
    sparse: true
  },
  password: {
    type: String,
    required: function() {
      return !this.googleId;
    }
  },
  budget: {
    type: Number,
    default: null
  },
  profilePic: {
    type: String,
    default: '/images/default-avatar.svg'
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true
  }
});

module.exports = mongoose.model('User', userSchema);
