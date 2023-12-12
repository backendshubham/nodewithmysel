// authMiddleware.js
const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Token not provided' });
  }

  jwt.verify(token, 'aaaabbbbcccc', (err, decoded) => {
    if (err) {
      console.error('Error verifying token:', err);
      return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }

    req.userId = decoded.data.id; // Add the user ID to the request for later use
    next();
  });
}
  
module.exports = {
  verifyToken,
};
