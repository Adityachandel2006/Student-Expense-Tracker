const multer = require('multer');

const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).send('File upload error: ' + err.message);
  } else if (err) {
    return res.status(400).send(err.message);
  }
  next();
};

module.exports = handleMulterError;
