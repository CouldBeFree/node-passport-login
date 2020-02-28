const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

const User = require('../models/User');

// Login Page
router.get('/login', (req, res) => res.render('login'));

// Register Page
router.get('/register', (req, res) => res.render('register'));

// Register handle
router.post('/register', async (req, res, next) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];

  // Check required fields
  if(!name || !email || !password || !password2){
    errors.push({ msg: 'Please fill in all fields' })
  }

  // Check passwords match
  if(!password2 !== !password){
    errors.push({ msg: 'Passwords do not match' })
  }

  // Check pass length
  if(password.length < 6){
    errors.push({ msg: 'Password should be at least 6 characters' })
  }

  if(errors.length > 0){
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    })
  } else {
    try {
      const user = await User.findOne({ email: email });

      if(user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        })
      } else {
        const newUser = await new User({
          name,
          email,
          password
        });

        // Hash password
        bcrypt.genSalt(10, (err, salt) =>
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if(err) throw err;
            // Set password to hashed
            newUser.password = hash;
            // Save the user
            newUser.save()
              .then(user => {
                req.flash('success_msg', 'You are now registered');
                res.redirect('/users/login')
              })
              .catch(err => console.log(err))
        }))
      }
    } catch (e) {
      console.log(e)
    }
  }
});

// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
