const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define our model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
});

// On save hook, encrypt password
// Before saving a model, run this function
userSchema.pre('save', function(next) {
  // Get access to user model
  const user = this;

  // Generate a salt then run callback
  bcrypt.genSalt(10, function(err, salt) {
    if (err) {
      return next(err);
    }

    // Hash password using salt
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) {
        return next(err);
      }

      // Overwrite plaintext password with encrypted one
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidate, callback) {
  bcrypt.compare(candidate, this.password, function(err, isMatch) {
    if (err) {
      return callback(err);
    }

    callback(null, isMatch);
  });
};

// Create model class
const ModelClass = mongoose.model('user', userSchema);

// Export model
module.exports = ModelClass;
