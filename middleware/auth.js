const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      res.clearCookie('jwt');
      return res.redirect('/login');
    }

    req.user = user;
    next();
  } catch (err) {
    res.clearCookie('jwt');
    return res.redirect('/login');
  }
};

module.exports = auth;
