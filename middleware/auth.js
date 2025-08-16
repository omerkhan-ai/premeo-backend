// middleware/auth.js
const { verifyToken } = require('../utils/auth'); // Adjust path if needed

const auth = (req, res, next) => {
  // 1. Get token from header
  const authHeader = req.header('Authorization');

  // Check if Authorization header exists and starts with 'Bearer '
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access denied. No token provided or invalid format.' });
  }

  // 2. Extract the token (remove 'Bearer ' prefix)
  const token = authHeader.substring(7); // 'Bearer '.length = 7

  try {
    // 3. Verify the token
    const decoded = verifyToken(token);
    // 4. Attach user info (from token payload) to the request object for use in subsequent middleware/routes
    req.user = decoded.user;
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    // Token is invalid (expired, malformed, etc.)
    console.error('Token verification error:', err.message); // Log for debugging
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
};

module.exports = auth;