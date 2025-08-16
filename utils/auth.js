// utils/auth.js
const jwt = require('jsonwebtoken');

// Get the secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is not defined in environment variables.');
}

// Function to generate a JWT for a user
const generateToken = (userId) => {
  // Payload: data to include in the token (usually user ID)
  const payload = {
    user: {
      id: userId // Mongoose _id
    }
  };

  // Options: expiration time, issuer, etc.
  const options = {
    expiresIn: '1h', // Token expires in 1 hour
    issuer: 'PremEO-Dashboard' // Identify the issuer
    // You can add audience (aud) if needed
  };

  // Sign the token with the secret
  return jwt.sign(payload, JWT_SECRET, options);
};

// Function to verify a JWT (returns decoded payload or throws error)
const verifyToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
};

module.exports = {
  generateToken,
  verifyToken
};