// models/AdminUser.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const adminUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true, // Ensure usernames are unique
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6 // Enforce a minimum password length
  }
}, {
  timestamps: true // Adds createdAt and updatedAt fields
});

// --- Middleware to Hash Password Before Saving ---
// This runs automatically before saving a new user or updating the password
adminUserSchema.pre('save', async function (next) {
  const user = this;
  // Only hash the password if it's new or has been modified
  if (!user.isModified('password')) return next();

  try {
    // Generate a salt (complexity factor 12)
    const salt = await bcrypt.genSalt(12);
    // Hash the password using the salt
    const hash = await bcrypt.hash(user.password, salt);
    // Replace the plain text password with the hash
    user.password = hash;
    next();
  } catch (error) {
    return next(error);
  }
});

// --- Method to Compare Password ---
// This adds a method to user instances to check passwords
adminUserSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    // 'this' refers to the user document
    // Compare the provided password with the stored hash
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    return isMatch;
  } catch (error) {
    throw error;
  }
};

const AdminUser = mongoose.model('AdminUser', adminUserSchema);

module.exports = AdminUser;